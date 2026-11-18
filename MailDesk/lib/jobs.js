'use strict';
/**
 * 极简内存任务管理器（批量收验证码用）
 *
 * 为什么放内存：
 *  - 一次扫描 100 个账号要 3 分钟，任务状态只是过程数据，不需要跨重启保留
 *  - 落盘就要考虑并发写、崩溃恢复、清理，收益却近乎为零
 *
 * 安全约束：
 *  - 用 Map 存 job，键受 /^[a-z0-9-]{8,64}$/ 白名单约束（__proto__ 之类一律拒绝）
 *  - 只保留最近 MAX_JOBS 个任务；state==='running' 的 job 永远不回收，
 *    否则全局幂等锁引用的对象会消失，用户此后每次点批量都被告知"已有任务"
 *  - 已结束的任务超过 TTL_MS(10 分钟) 自动清理
 *  - 另有 ≤15 分钟的硬时限：超时只「请求取消 + 标记 draining」，
 *    终态由扫描器的 try/finally 落，防止卡死的 job 永久占住单例锁
 *
 * 在途事务计数（beginTransaction / endTransaction / drainTransactions /
 * isDraining / requestShutdown）：
 *  微软的 refresh_token 每次兑换都会轮换，旧值当场作废。进程退出时必须
 *  等在途的兑换把新值写进加密账户库，否则重启后旧值已失效、账号永久报废。
 *  这也解释了为什么「取消 / 硬时限」不能立刻把 job 置终态对外：
 *  前端一见 state !== 'running' 就会停止轮询、提示"任务已结束"，
 *  用户随即关窗口 —— 恰好落在写盘窗口里就丢令牌。所以 drain 期间
 *  state 必须保持 'running'，另外用 draining / drained 两个标志表达真实进度。
 *  job.state 允许的值：running / draining / done / cancelled / failed，
 *  其中 draining 只用于标记收尾语义；对外仍报 running，理由见上。
 */
const crypto = require('crypto');

const MAX_JOBS = 5;
// 已结束任务的保留时长（10 分钟）
const TTL_MS = 10 * 60 * 1000;

/* ---------------- running 硬时限（按任务规模动态算） ----------------
 *
 * 硬时限的本意是「防止一个卡死的 job 永久占住单例锁」，而不是「限制用户
 * 扫描多少账号」。以前它写死 15 分钟，而实际规模是：最多 300 个账号 /
 * 每账号 25 秒超时 / 并发 3 —— 队列最坏 300/3×25s ≈ 42 分钟。
 * 也就是说用户选满 300 个账号时，**正常流程**必然被 15 分钟截断：前面的
 * 结果保留、后面的账号根本没扫，界面上只是多一行"硬时限已终止"。
 * 反过来，只扫 1 个账号时 15 分钟又过于宽松——一个卡死的单账号任务要
 * 白占单例锁 15 分钟。写死一个与规模无关的值，两头都错。
 *
 * 所以改成按 (队列长度 × 单账号超时 + 余量) 动态推导，并钳在
 * [MIN, MAX] 之间：
 *  - MIN：小任务也有兜底余量（建连、令牌落盘、onItem 回调都在超时之外）
 *  - MAX：即使调用方传来一个被恶意构造的超大 total，也不会撑成"无限期
 *    占用"。上限必须存在：expireRunning 是单例锁唯一的兜底释放路径。
 *
 * 余量按比例给（不够就补足 1 分钟）：真实耗时里还有每次账号切换的建连
 * 开销与令牌写盘，纯按最坏值卡得太紧会在大任务末尾误杀。
 */
const RUNNING_HARD_LIMIT_MIN_MS = 10 * 60 * 1000;
const RUNNING_HARD_LIMIT_MAX_MS = 60 * 60 * 1000;
// 调用方没给单账号超时时的保守假设（与 bulk-scan 的 DEFAULT_TIMEOUT_MS 一致）
const ASSUMED_PER_ACCOUNT_MS = 25 * 1000;
// 余量取最坏值的 10%，至少 1 分钟：300 账号的最坏值 42 分钟 → 46 分钟硬限。
// 这 4 分钟覆盖每个账号的建连开销、令牌轮换写盘和 onItem 回调，
// 这些都在单账号 25 秒超时之外，纯按最坏值卡死会在任务末尾误杀。
const HARD_LIMIT_MARGIN_RATIO = 0.1;
const HARD_LIMIT_MARGIN_MIN_MS = 60 * 1000;

/**
 * 按任务规模推导 running 硬时限（纯函数，便于单测）。
 *
 * @param {number} total        账号总数
 * @param {number} perAccountMs 单账号超时（ms），非法值退回 25 秒
 * @param {number} concurrency  并发数，非法值按 1（= 最保守，上限最大）
 * @returns {number} 毫秒，落在 [RUNNING_HARD_LIMIT_MIN_MS, RUNNING_HARD_LIMIT_MAX_MS]
 */
function runningHardLimitMs(total, perAccountMs, concurrency) {
  const n = Math.max(0, parseInt(total, 10) || 0);
  const rawPer = Number(perAccountMs);
  const per = Number.isFinite(rawPer) && rawPer > 0 ? rawPer : ASSUMED_PER_ACCOUNT_MS;
  // 并发取 1 是保守方向：算出来的上限更大，绝不会因为参数写错而提前误杀
  const lanes = Math.max(1, parseInt(concurrency, 10) || 1);
  const worst = Math.ceil(n / lanes) * per;
  const margin = Math.max(HARD_LIMIT_MARGIN_MIN_MS, Math.ceil(worst * HARD_LIMIT_MARGIN_RATIO));
  const wanted = worst + margin;
  return Math.min(RUNNING_HARD_LIMIT_MAX_MS, Math.max(RUNNING_HARD_LIMIT_MIN_MS, wanted));
}

/** 硬限的展示文案（分钟；不足 1 分钟向上取整，避免显示成 0） */
function hardLimitText(ms) {
  const minutes = Math.max(1, Math.ceil(Number(ms) / 60000));
  return minutes + ' 分钟';
}

const SAFE_JOB_ID = /^[a-z0-9-]{8,64}$/;

const jobs = new Map(); // id -> job
const deadlineTimers = new Map(); // id -> unref'd timer
// type -> job：从 createJob 一直保持到扫描器 finally 调 finishJob。
// 即使 cancel 把 state 改成 cancelled，飞行中的最多 3 个账号还在跑；
// 这期间必须继续占住单例锁，否则用户立刻再点一次就是 6 条并发连接，
// 正好撞上微软限流。
const activeRuns = new Map();

/* ---------------- 在途事务计数（令牌落盘保护） ---------------- */

// 正在进行、且成功后可能会写账户库的工作单元数量。
// 只要 > 0，退出就必须等它归零（小额超时兜底），否则可能丢轮换令牌。
let inflight = 0;
// 归零时唤醒所有 drainTransactions 等待者
const drainWaiters = new Set();
// 是否已请求退出（只置 true、不复位：退出是不可逆的）
let shutdownRequested = false;

function notifyDrained() {
  if (inflight > 0) return;
  for (const fn of [...drainWaiters]) {
    drainWaiters.delete(fn);
    // 传 true：drainTransactions 的 resolve 值表示"是否等到了清零"
    try { fn(true); } catch { /* 等待者自身出错不影响其他 */ }
  }
}

/**
 * 标记一个在途事务开始。
 * 必须覆盖「token 兑换 + vault 写回」的完整调用（例如整个 scanAccount），
 * 只包网络请求是不够的：新令牌是兑换返回之后才写盘的。
 * 返回一个幂等的结束函数，便于在 finally 里无脑调用。
 */
function beginTransaction() {
  inflight += 1;
  let ended = false;
  return function endOnce() {
    if (ended) return;      // 幂等：重复调用不会把计数减成负数
    ended = true;
    inflight = Math.max(0, inflight - 1);
    notifyDrained();
  };
}

/** 结束一个在途事务（与 beginTransaction 返回的函数等价，供不需要句柄的调用方使用） */
function endTransaction() {
  inflight = Math.max(0, inflight - 1);
  notifyDrained();
}

/**
 * 等在途事务清零，最多等 timeoutMs 毫秒。
 * 没有在途事务时立即返回（默认同步 resolve），正常退出不会变慢。
 * 超时返回 false（调用方据此在日志里提示"可能有未落盘令牌"），不死等。
 *
 * @param {number} timeoutMs
 * @param {{waitTicks?: boolean}} opts
 *   waitTicks=true 时，即使当前没有在途事务也先让出一轮事件循环再复查一次。
 *   用途：退出流程里，某个 worker 可能刚通过取消检查、还没登记事务，
 *   这一让正好给它把事务登记进来的机会（否则会"刚归零就退出"漏掉它）。
 *   用 setImmediate 而不是 setTimeout，避免依赖定时器精度。
 */
function drainTransactions(timeoutMs = 15000, opts = {}) {
  if (inflight === 0 && !(opts && opts.waitTicks)) return Promise.resolve(true);
  const ms = Number.isFinite(Number(timeoutMs)) ? Math.max(0, Number(timeoutMs)) : 0;
  return new Promise(resolve => {
    let done = false;
    let timer = null;
    const finish = ok => {
      if (done) return;
      done = true;
      drainWaiters.delete(finish);
      if (timer) clearTimeout(timer);
      // finish 会收到 notifyDrained 传来的 true，或超时自己的 false
      resolve(ok === true);
    };
    drainWaiters.add(finish);
    // 兜底：网络栈半死时也不能让 Ctrl+C 永远挂住。
    // 注意不要 unref：shutdown 期间 server.close() 之后可能就只剩这个定时器，
    // unref 会让进程在给落盘留出窗口之前自然退出，正是要避免的情形。
    timer = setTimeout(() => finish(false), ms);
    // 注册期间可能刚好清零（微任务窗口），补一次检查
    if (inflight === 0) {
      if (opts && opts.waitTicks) setImmediate(() => { if (inflight === 0) finish(true); });
      else finish(true);
    }
  });
}

/** 当前在途事务数（给退出提示用） */
function pendingTransactions() {
  return inflight;
}

/**
 * 是否还有在途事务（= 还有可能写账户库的兑换没走完）。
 * 给"能不能安全离开"这类询问用；不改变任何状态。
 */
function isDraining() {
  return inflight > 0;
}

/**
 * 全局退出请求：让所有 running job 在下一个账号边界停止取新任务。
 * 不直接改 job.state —— 终态只能由 startScanJob 的 finally 落，
 * 这样 drain 期间前端看到的仍是 running，不会提前停止轮询。
 */
function requestShutdown() {
  shutdownRequested = true;
  let n = 0;
  for (const j of jobs.values()) {
    if (j.state === 'running' && !j.cancelRequested) {
      j.cancelRequested = true;
      j.current = '';
      j.error = j.error || '服务正在退出，已停止派发新账号';
      j.draining = true;
      n += 1;
    }
  }
  return n;
}

/** 是否已请求全局退出（退出标志一旦置位不再复位） */
function isShutdownRequested() {
  return shutdownRequested;
}

function isSafeId(id) {
  return typeof id === 'string' && SAFE_JOB_ID.test(id);
}

/**
 * 硬时限到期：只请求取消并进入 draining，绝不在这里落终态。
 *
 * 为什么不能直接 state='failed' + finishedAt=now：
 * scanJobView() 会立刻把终态吐给前端，前端见 state !== 'running' 就停止
 * 轮询、显示"任务已结束"。可此时 runPool 的 finally 还没执行，后台仍有
 * 最多 concurrency 个账号在跑，随时可能写账户库。用户看到"已结束"就关窗口，
 * 正好把一次 refresh_token 轮换卡在内存里 → 账号永久失效。
 *
 * 真正收尾（state / finishedAt）交给 startScanJob 的 finally。
 *
 * 文案里的分钟数必须来自**这个 job 实际用的**硬限（job.hardLimitMs），
 * 否则用户看到"超过 15 分钟"却明明才扫了几分钟，会以为程序坏了。
 */
function expireRunning(j) {
  if (!j || j.state !== 'running') return;
  j.cancelRequested = true;
  j.draining = true;
  j.current = '';
  const limit = jobHardLimitMs(j);
  j.error = '任务超过 ' + hardLimitText(limit) + '硬时限，已强制终止';
}

/**
 * 某个 job 的硬限。job 上没记（旧对象 / 测试里手工构造）就按它的 total 现算，
 * 绝不退回一个与规模无关的写死值。
 */
function jobHardLimitMs(j) {
  const own = Number(j && j.hardLimitMs);
  if (Number.isFinite(own) && own > 0) return own;
  return runningHardLimitMs(j && j.total);
}

function prune() {
  const now = Date.now();

  for (const [id, j] of [...jobs]) {
    if (j.state === 'running') {
      const st = Date.parse(j.startedAt) || 0;
      // 注意：绝不在这里 delete 一个 running job，只做超时标记
      if (st && now - st > jobHardLimitMs(j)) expireRunning(j);
      continue;
    }
    const end = j.finishedAt ? Date.parse(j.finishedAt) : 0;
    if (end && now - end > TTL_MS) {
      jobs.delete(id);
      const t = deadlineTimers.get(id);
      if (t) { clearTimeout(t); deadlineTimers.delete(id); }
    }
  }

  // 数量上限：按开始时间从旧到新淘汰；running 一律跳过
  if (jobs.size > MAX_JOBS) {
    const finished = [...jobs.values()]
      .filter(j => j.state !== 'running')
      .sort((a, b) => (Date.parse(a.startedAt) || 0) - (Date.parse(b.startedAt) || 0));
    let excess = jobs.size - MAX_JOBS;
    for (const j of finished) {
      if (excess <= 0) break;
      jobs.delete(j.id);
      const t = deadlineTimers.get(j.id);
      if (t) { clearTimeout(t); deadlineTimers.delete(j.id); }
      excess -= 1;
    }
  }
}

/**
 * 新建任务。返回的是活引用，调用方直接读写，status 读到的就是最新状态。
 *
 * opts.perAccountMs / opts.concurrency：用于推导这次的硬时限（任务规模越大，
 * 允许跑得越久）。不传就按默认的 25 秒 / 并发 1 保守估算——宁愿上限偏大，
 * 也不要因为漏传参数把正常任务误杀。
 *
 * @param {string} type
 * @param {number} total
 * @param {{perAccountMs?:number, concurrency?:number}} [opts]
 */
function createJob(type, total, opts = {}) {
  prune();
  const o = (opts && typeof opts === 'object') ? opts : {};
  const job = {
    id: crypto.randomUUID(),          // 36 位小写十六进制 + 连字符，符合白名单
    type: String(type || 'job'),
    state: 'running',                 // running | done | cancelled | failed
    total: Math.max(0, parseInt(total, 10) || 0),
    done: 0,
    ok: 0,
    failed: 0,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    cancelRequested: false,
    current: '',
    results: [],
    errors: [],
    error: '',
    // 这次的硬时限。记在 job 上而不是每次现算：prune() 用的是 total，
    // 而 total 会随着"账户已被删除"逐条收缩，用收缩后的值去算会让硬限
    // 在任务跑到一半时突然变小，提前把还在正常跑的 job 杀掉。
    hardLimitMs: runningHardLimitMs(total, o.perAccountMs, o.concurrency),
    // draining：正在收尾（已请求取消，但仍有账号在飞 / 还在写账户库）
    // drained ：finally 已跑完、finishJob 已调用，结果不再变化
    draining: false,
    drained: false,
  };
  jobs.set(job.id, job);

  // 即使没有任何 status 轮询，硬时限也会生效。unref 避免拖住进程退出。
  const timer = setTimeout(() => {
    expireRunning(job);
    deadlineTimers.delete(job.id);
  }, job.hardLimitMs);
  if (typeof timer.unref === 'function') timer.unref();
  deadlineTimers.set(job.id, timer);
  activeRuns.set(job.type, job);

  return job;
}

/** 扫描器 finally 调用：飞行中的账号全部结束后才释放单例锁 */
function finishJob(job) {
  // 标记为已收尾。scanJobView().drained 由它驱动，前端据此才可安全关闭。
  job.drained = true;
  job.draining = false;
  if (activeRuns.get(job.type) === job) activeRuns.delete(job.type);
  const t = deadlineTimers.get(job.id);
  if (t) { clearTimeout(t); deadlineTimers.delete(job.id); }
}

function getJob(id) {
  if (!isSafeId(id)) return null;
  return jobs.get(id) || null;
}

/** 当前仍占着单例锁的任务（含取消后正在收尾的），没有就返回 null */
function findRunning(type) {
  const key = type || 'job';
  const j = activeRuns.get(key);
  if (j && jobs.has(j.id)) return j;
  if (j) activeRuns.delete(key);       // 已被 TTL / 数量上限清掉
  // 兜底：状态还是 running 但没在 activeRuns 里（例如外部强制改状态）
  for (const other of jobs.values()) {
    if (other.state === 'running' && (!type || other.type === type)) return other;
  }
  return null;
}

function listJobs() {
  return [...jobs.values()];
}

/**
 * 固定并发跑一批任务。
 *
 * - 返回的数组与 items 同序（results[i] 对应 items[i]）
 * - isCancelled() 在「每个任务开始前」检查；一旦为真就停止取新任务，
 *   已在飞行中的最多 concurrency 个会自然结束
 * - worker 抛出的异常会被收成 { ok:false, error }，不会中断整批
 *
 * @param {Array} items
 * @param {number} concurrency
 * @param {(item:any, index:number)=>Promise<any>} worker
 * @param {{onItem?:(result:any, item:any, index:number)=>any, isCancelled?:()=>boolean}} opts
 */
async function runPool(items, concurrency, worker, opts = {}) {
  const list = Array.isArray(items) ? items : [];
  const onItem = typeof opts.onItem === 'function' ? opts.onItem : null;
  const isCancelled = typeof opts.isCancelled === 'function' ? opts.isCancelled : () => false;

  const results = new Array(list.length);
  const lanes = Math.max(1, Math.min(parseInt(concurrency, 10) || 1, Math.max(1, list.length)));

  let next = 0;
  let stopped = false;

  const lane = async () => {
    while (true) {
      if (stopped) return;
      if (isCancelled()) { stopped = true; return; }
      const i = next;
      next += 1;
      if (i >= list.length) return;

      let r = null;
      try {
        r = await worker(list[i], i);
        if (r == null) r = { ok: false, error: '单账号处理异常', reason: '' };
      } catch {
        r = { ok: false, error: '单账号处理异常', reason: '' };
      }
      results[i] = r;
      if (onItem) {
        try { await onItem(r, list[i], i); } catch { /* 回调自身出错不影响流程 */ }
      }
    }
  };

  await Promise.all(Array.from({ length: lanes }, () => lane()));
  return results;
}

module.exports = {
  createJob, getJob, findRunning, finishJob, listJobs, runPool,
  isSafeId, expireRunning,
  // 在途事务计数 + 退出协调
  beginTransaction, endTransaction, drainTransactions, pendingTransactions,
  requestShutdown, isDraining, isShutdownRequested,
  // 硬时限推导（纯函数，自检直接测它，不必等真定时器）
  runningHardLimitMs, hardLimitText, jobHardLimitMs,
  MAX_JOBS, TTL_MS, SAFE_JOB_ID,
  RUNNING_HARD_LIMIT_MIN_MS, RUNNING_HARD_LIMIT_MAX_MS,
  ASSUMED_PER_ACCOUNT_MS, HARD_LIMIT_MARGIN_RATIO, HARD_LIMIT_MARGIN_MIN_MS,
};
