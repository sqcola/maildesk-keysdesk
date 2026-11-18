'use strict';
/**
 * MailDesk 服务端
 *
 * 安全设计（对照前一版本工具发现的问题逐条修正）：
 *  1. 绑定 127.0.0.1，只监听回环
 *  2. 启动时生成随机 token，前端必须带 Authorization 头 —— 阻断第三方网页跨域调用
 *  3. CORS 只允许 http://127.0.0.1:<本端口>，不用通配符
 *  4. 静态文件路径严格校验，阻断路径穿越
 *  5. 凭据 AES-256-GCM 加密落盘，不存浏览器 localStorage
 *  6. 无第三方依赖（除用户自己放的），无 CDN，无 SRI 风险
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { URL } = require('url');

const { Vault } = require('./lib/vault');
const { History } = require('./lib/history');
const mail = require('./lib/mail');
const { sendMail } = require('./lib/smtp');
const { extractCode } = require('./lib/code-extractor');
const { scanAccount, isSafeMailbox } = require('./lib/bulk-scan');
const jobs = require('./lib/jobs');
const {
  BUILTIN_MAP,
  normalizePlatforms,
  displayName,
  MAX_PLATFORMS,
} = require('./lib/platforms');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.MAILDESK_DATA_DIR || path.join(ROOT, 'data');

/**
 * 密钥目录（K2：密钥与密文分离）。
 *
 * 密钥单独放在数据目录之外，拷走整个 data/ 只能拿到解不开的密文。
 * 解析顺序有意如此：
 *  1. MAILDESK_KEY_DIR —— 显式指定的最高优先级
 *  2. MAILDESK_DATA_DIR —— 设了它就意味着"这是个测试/自定义部署"，
 *     密钥继续跟数据同目录，保持既有测试的语义完全不变
 *  3. ~/.maildesk    —— 真实运行走这里
 */
const KEY_DIR = process.env.MAILDESK_KEY_DIR
  || (process.env.MAILDESK_DATA_DIR ? DATA_DIR : path.join(os.homedir(), '.maildesk'));

/* ============================================================
 * F1-1：实例锁（单实例运行）
 * ============================================================
 *
 * 为什么需要它：双击两次 start.bat 时，第二个进程因 EADDRINUSE 顺延到 2132 照样
 * 会起来。两个实例共用同一份 accounts.enc / vault.key，各自在内存里持有一份快照，
 * 于是：
 *   · 写盘互相覆盖（A 写 51 条、B 写 1 条 → 最终只剩 1 条）；
 *   · 首装时两个进程可能各生成一把 vault.key，后 rename 的赢，输的那个进程
 *     之后用内存里那把**已经不在磁盘上**的密钥加密，落盘即永久解不开；
 *   · refresh_token 轮换写回互相打回旧值，账号当场报废。
 * vault.save() 的 tmp 名已经改成 pid 唯一（见 lib/vault.js），那只解决了
 * "同一时刻写盘互相撕碎文件"；解决不了"两个实例互相覆盖内存状态"，所以锁要加。
 *
 * 健壮性要求（规格明确要求）：
 *  · 锁文件里有 pid + 启动时间 + 随机 token；
 *  · 锁里的 pid 已不存在 / 已死 → 判为**陈旧锁**，直接覆盖。上次崩溃残留的锁
 *    文件绝不能让服务永久起不来（那比多开一次更糟：用户会以为程序坏了）；
 *  · pid 存在但属于别的进程（pid 复用）→ 也算"活着"，宁可让用户手工删锁，
 *    也不要在可能真有实例在跑的时候放第二个进来 —— 判断错方向的代价是不对称的；
 *  · 同一 pid 重复加载本模块（测试里 delete require.cache 后重新 require）不算冲突，
 *    锁里的 pid 等于 process.pid 就认作自己；
 *  · 任何**写不了锁文件**的情况（只读盘、权限不足、目录不可写）只打警告，
 *    绝不阻断启动 —— 锁是防护，不是功能依赖。
 */
const LOCK_FILE = path.join(DATA_DIR, 'server.lock');
// 本进程持有的锁信息（含唯一 token）。只有 token 对得上才允许删锁，
// 避免"我退出时把下一任实例的锁删了"。
let ownLockInfo = null;
let lockReleased = false;

/** 读锁文件；不存在 / 不是 JSON / 不是对象 → null（按无锁处理） */
function readInstanceLock() {
  try {
    const o = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
    return (o && typeof o === 'object' && !Array.isArray(o)) ? o : null;
  } catch {
    return null;
  }
}

/**
 * pid 是否还活着。
 * process.kill(pid, 0) 不发信号，只做存在性检查：
 *   ESRCH → 进程不存在；EPERM → 存在但不属于我们（仍是活的）；
 * 其它错误（如 EINVAL）保守地当作"活着"，理由同上：宁可拒绝启动。
 */
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    if (e && e.code === 'EPERM') return true;
    if (e && e.code === 'ESRCH') return false;
    return true;
  }
}

/**
 * 抢锁。成功返回 true；发现另一个活实例则抛 code=INSTANCE_RUNNING。
 * 用 'wx' 打开（不存在才创建）而不是 existsSync + 写：两个进程同时启动时，
 * existsSync 那条路会让双方都以为"没有锁"然后各写各的，锁当场失效。
 * 抢不到（EEXIST）时再读锁判断是活实例还是陈旧锁，最多重试 3 次。
 */
function acquireInstanceLock() {
  let info;
  try {
    info = {
      pid: process.pid,
      startedAt: new Date().toISOString(),
      token: crypto.randomBytes(8).toString('hex'),
    };
  } catch (e) {
    return false;
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    let fd = -1;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fd = fs.openSync(LOCK_FILE, 'wx', 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify(info, null, 2), 'utf8');
        fs.fsyncSync(fd);
      } finally {
        try { fs.closeSync(fd); } catch { /* 忽略 */ }
      }
      ownLockInfo = info;
      lockReleased = false;
      return true;
    } catch (e) {
      if (fd >= 0) { try { fs.closeSync(fd); } catch { /* 忽略 */ } }

      // 写不了锁文件（只读盘 / 权限）：不阻断启动，只警告一次。
      // EEXIST 之外的错误都不是"有实例在跑"，没有理由让服务起不来。
      if (e.code !== 'EEXIST') {
        try {
          console.warn('[lock] 无法写入实例锁 ' + LOCK_FILE + '（' + (e.code || e.message) + '），已跳过单实例检查');
        } catch { /* 控制台可能已关闭 */ }
        return false;
      }

      const cur = readInstanceLock();
      // 锁文件内容损坏（崩溃时写了半截）：当作陈旧锁覆盖。
      if (!cur) {
        try { fs.rmSync(LOCK_FILE, { force: true }); } catch { /* 忽略 */ }
        continue;
      }

      // 同一个 pid 不是冲突：测试里 delete require.cache 后重新 require 会走到这里。
      if (cur.pid === process.pid) {
        ownLockInfo = info;
        lockReleased = false;
        try { fs.writeFileSync(LOCK_FILE, JSON.stringify(info, null, 2), 'utf8'); } catch { /* 忽略 */ }
        return true;
      }

      if (pidAlive(cur.pid)) {
        const err = new Error(
          '已有 MailDesk 实例在运行（pid ' + cur.pid
          + '，启动于 ' + (cur.startedAt || '未知时间') + '）。\n'
          + '两个实例共用同一份账户库会互相覆盖写入，可能丢失或损坏 refresh_token，\n'
          + '所以这里拒绝启动。请先关闭那个实例（或关掉它的窗口）。\n'
          + '如果确认那个进程已经不在了，删除锁文件后重试：\n'
          + '  ' + LOCK_FILE + '\n'
          + '（确实需要同时跑两个实例时，可设 MAILDESK_FORCE_START=1 跳过本检查，\n'
          + '  但两个实例写同一份账户库仍可能互相覆盖，风险自负。）'
        );
        err.code = 'INSTANCE_RUNNING';
        err.lock = cur;
        throw err;
      }

      // 陈旧锁：pid 已不存在，覆盖。
      try {
        console.warn('[lock] 发现陈旧锁（pid ' + cur.pid + ' 已不存在），已接管');
      } catch { /* 忽略 */ }
      try { fs.rmSync(LOCK_FILE, { force: true }); } catch { /* 忽略 */ }
    }
  }

  // 三次都没抢到（有人在反复创建/删除）：不阻断启动。
  try { console.warn('[lock] 反复争用实例锁失败，已跳过单实例检查'); } catch { /* 忽略 */ }
  return false;
}

/** 释放锁：只删自己那把（token 必须一致），绝不误删下一任实例的锁 */
function releaseInstanceLock() {
  if (lockReleased || !ownLockInfo) return;
  lockReleased = true;
  try {
    const cur = readInstanceLock();
    if (cur && cur.token === ownLockInfo.token && cur.pid === ownLockInfo.pid) {
      fs.rmSync(LOCK_FILE, { force: true });
    }
  } catch { /* 尽力而为：残留的锁下次会被判成陈旧锁覆盖 */ }
}

// 强制跳过锁检查的逃生口。仅在明确知道自己在做什么时使用（见上面的提示文案）。
// 注意它只跳过"检查"，不改变任何写盘行为。
//
// 冲突时**不在这里抛**：require('./server') 的调用方（自检、脚本）应该在
// start() 那个显式入口拿到这个错误，而不是在模块加载时被一个未捕获异常打死。
// 采集错误、让 start() 拒绝，语义更清楚，也让静态 require 保持无副作用。
let instanceLockError = null;
if (process.env.MAILDESK_FORCE_START === '1') {
  try { console.warn('[lock] MAILDESK_FORCE_START=1：已跳过单实例检查'); } catch { /* 忽略 */ }
} else {
  try {
    acquireInstanceLock();
  } catch (e) {
    instanceLockError = e;
  }
}

// 退出时删锁。'exit' 是最后一道：shutdown() 里也会显式释放一次（更早，
// 这样用户在 pid 还没回收时就能重新启动）。
process.on('exit', releaseInstanceLock);

const vault = new Vault(DATA_DIR, KEY_DIR);
// 验证码历史：与账户库共用 vault.key 加密，文件落在 DATA_DIR（绝不能进 public/，
// 那里的一切都会被 serveStatic 当静态文件吐出去）
const history = new History(vault, path.join(DATA_DIR, 'history.enc'));

/**
 * 把轮换后的 refresh_token 立刻写回账户库。
 *
 * 这是唯一允许写 refresh_token 的入口：微软每次刷新都会换新令牌，
 * 旧值在服务端当场失效，晚写一步、或者不写，账号就永久报废。
 * lib/mail.js 只持有这个不透明回调，不依赖 Vault，也不认识加密格式。
 */
mail.setRefreshTokenPersister(async (account, newRefreshToken, previousRefreshToken) => {
  const id = account && account.id;
  if (!id) throw new Error('账户对象缺少 id，无法写回 refresh_token');

  // vault.updateRefreshToken 内部是读-改-写 + 原子落盘（tmp + rename），
  // 只改 secrets.refreshToken 一个字段，不会碰 clientId / password / 迁移标记。
  const r = vault.updateRefreshToken(id, newRefreshToken, previousRefreshToken);

  if (r.skipped && r.reason === 'account-not-found') {
    // 刷新途中账户被删了：没有可写的地方，凭据也随之作废，不算失败
    return r;
  }
  if (!r.applied && r.reason === 'vault-has-different-token') {
    // 库里的值比我们手里的新（多开进程 / 重新导入）。
    // 不要覆盖；把库里的现值交给上层，让后续调用改用真正有效的那个。
    if (r.currentToken) account.secrets.refreshToken = r.currentToken;
    return r;
  }
  if (!r.applied) throw new Error('写回 refresh_token 未生效：' + (r.reason || 'unknown'));
  return r;
});

// 每次启动生成新的会话 token
const SESSION_TOKEN = crypto.randomBytes(32).toString('hex');
// 预转成 Buffer 并记录字节长度：timingSafeEqual 要求两侧字节数一致，
// 用字符串 length 比较在多字节输入下会抛 RangeError。
const SESSION_TOKEN_BUF = Buffer.from(SESSION_TOKEN, 'utf8');
const SESSION_TOKEN_BYTES = SESSION_TOKEN_BUF.length;

/* ============================================================
 * H1：握手鉴权（本机秘密 + 浏览器 cookie）
 * ============================================================
 *
 * 问题：原来 handshake 无条件返回 SESSION_TOKEN。token 只挡得住第三方网页
 * （CORS/Host 校验对它们有效），挡不住本机任意进程和本机其他 Windows 账户——
 * 它们连 127.0.0.1:2131 是通的，一次 GET 就能拿 token，随后读全部邮件、
 * 以用户身份发信、删改账户。
 *
 * 三种可选方案与取舍（为什么选方案 1）：
 *
 *  方案 1（采用）：握手要出示一个只存在当前用户账户目录里的秘密。
 *    - 秘密放 KEY_DIR/handshake（生产环境就是 ~/.maildesk/handshake，权限 0600），
 *      和 vault.key 同一层保护：本机其他 Windows 账户读不到（NTFS 用户目录 ACL）；
 *    - 浏览器不能直接读文件，所以给一个一次性引导页：用户把文件内容粘贴进去，
 *      服务端校验通过后下发 HttpOnly + SameSite=Strict 的 cookie（一年），
 *      之后前端 fetch 会自动带上 cookie，app.js 一行都不用改；
 *    - 放弃了什么：首次使用（以及换浏览器/清 cookie 后）要粘贴一次 64 位字符串。
 *      这是本轮唯一无法消除的交互成本，换来的是"没有这个秘密就拿不到 token"。
 *
 *  方案 2（放弃）：send / message 等高危 action 加 confirm 字段。
 *    - 最实用、但**前端 app.js 不在本次可改范围内**：它调 api('send', {...}) 时
 *      不会带 confirm，服务端一加 401，用户就永远发不出信，且界面上没有输入 PIN 的入口。
 *      "记住 15 分钟"同理，宽限期状态最终还是得有前端配合首次确认。
 *    - 若将来允许改前端，建议补上：服务端记住最近一次确认的 source（本进程内存），
 *      首次确认后 15 分钟内免确认。现在硬加只会把功能弄坏。
 *
 *  方案 3（放弃）：只在 README 写威胁模型边界。
 *    - README 不在本次可改范围（用户明确只许改 server.js / vault.js）；
 *    - 而且文档不改变任何一行可执行路径 —— 这报告的漏洞依旧可被利用。
 *      威胁模型的说明改写在下面这段注释里，README 需要汇总阶段补引用。
 *
 * 明确威胁模型边界（务必如实写在 README）：
 *   本机**其他 Windows 账户**读不到 ~/.maildesk/vault.key 和 ~/.maildesk/handshake，
 *   因此既解不开 accounts.enc，也拿不到 API token。
 *   但与 MailDesk **同用户**运行的任意代码（恶意脚本、被投毒的依赖）可以读到这两个
 *   文件，从而完全控制账户库 —— 这条路无法用应用层鉴权堵住，唯一防线是操作系统账户
 *   边界和"不要在这个账户下运行来路不明的程序"。
 *   data/accounts.enc 在部分机器上的 ACL 是 Authenticated Users:(M)，即本机其他账户
 *   可读密文；没有 vault.key 时它只是一堆解不开的字节，但**不要**把它和 key 放一起。
 *
 * 残余风险（方案 1 自身的边界，如实记录）：
 *   浏览器的 cookie 罐按**主机名**分区，**不区分端口**。因此本机另一个账户若在
 *   127.0.0.1 的别的端口上起了 HTTP 服务，而用户又主动访问了它，该服务就能读到
 *   本服务下发的 maildesk_hs cookie 并据此换到 SESSION_TOKEN。
 *   它比"直接读文件"多了一步诱骗用户访问，且需要另一个账户能在本机监听回环端口，
 *   但确实不是零。真要堵死只能改前端（把 token 放 sessionStorage、彻底不用 cookie），
 *   而 app.js 不在本次可改范围。写在这里是为了不给后来者一个错误的"已彻底解决"印象。
 */

const HANDSHAKE_FILE = path.join(KEY_DIR, 'handshake');
const HANDSHAKE_COOKIE = 'maildesk_hs';
// 一年。服务重启不失效（秘密持久化在 HANDSHAKE_FILE 里），换浏览器/清 cookie 才需要重来。
const HANDSHAKE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;
// 引导失败的冷却。秘密是 256 位随机，穷举本来就不可能，这里只是让"有人在试"
// 在耗时和日志上显形。
// 为什么计连续失败次数而不是"失败一次就冷却"：正常用户第一次也常常粘错
// （多带了空格、只复制了半行），立刻冷却会让他看到"尝试过于频繁"而不知所措。
// 允许连错 3 次再开始冷却，既不影响正常纠错，也不给暴力尝试留免费额度。
const BOOTSTRAP_COOLDOWN_MS = 750;
const BOOTSTRAP_FREE_TRIES = 3;
let bootstrapFails = 0;
let bootstrapBlockedUntil = 0;

/**
 * 读或创建本机握手秘密。
 *
 * 为什么持久化而不是每次启动重新生成：cookie 要跨重启继续有效，否则用户每次开服务
 * 都得重新粘贴一次 —— 那就退化成了"每次发信都要输 PIN"，方案 2 被否掉的理由同样适用。
 *
 * 文件读取失败/内容损坏时重新生成（覆盖写），代价只是用户重做一次引导，
 * 不会影响 accounts.enc 或 vault.key —— 这两者与本文件完全独立。
 */
function loadOrCreateHandshakeSecret() {
  try {
    const s = fs.readFileSync(HANDSHAKE_FILE, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(s)) return s;
  } catch { /* 不存在或读不了：往下走生成分支 */ }

  const s = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(KEY_DIR, { recursive: true });
  // 与 vault.key 同样的原子写：tmp + fsync + rename。
  // 半截文件会让下次启动认不出来而重新生成，虽然不致命，但没有理由留这个窗口。
  const tmp = HANDSHAKE_FILE + '.tmp-' + process.pid + '-' + Date.now();
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeSync(fd, s + '\n');
    fs.fsyncSync(fd);
  } finally {
    try { fs.closeSync(fd); } catch { /* 忽略 */ }
  }
  try {
    fs.renameSync(tmp, HANDSHAKE_FILE);
  } catch (e) {
    try { fs.rmSync(tmp, { force: true }); } catch { /* 忽略 */ }
    throw e;
  }
  try { fs.chmodSync(HANDSHAKE_FILE, 0o600); } catch { /* Windows 上语义有限 */ }
  tightenWindowsAcl(HANDSHAKE_FILE);
  return s;
}

/**
 * Windows 上 chmod 基本无效（实际仍是继承来的 ACL），用 icacls 尽力把文件收成
 * "只有当前用户"。分两步且顺序不能反：
 *   1. 先 /grant:r 当前用户 —— 这一步失败就直接返回，绝不继续；
 *   2. 再 /inheritance:r 去掉继承 ACE。
 * 反过来做的话，一旦第 2 步生效、第 1 步失败，文件就只剩 Owner 的 READ_CONTROL/WRITE_DAC，
 * 下次启动读不到秘密只能重新生成（不丢数据，但用户要重做引导）。
 * 任何失败都吞掉：这个文件已经在用户目录里，默认 ACL 通常本来就够。
 */
function tightenWindowsAcl(file) {
  if (process.platform !== 'win32') return;
  try {
    const user = os.userInfo().username;
    if (!user) return;
    const { execFileSync } = require('child_process');
    // 用 execFileSync + 参数数组，不经过 shell：用户名/路径含空格或特殊字符时不会被解释
    execFileSync('icacls', [file, '/grant:r', user + ':F'], { stdio: 'ignore', timeout: 5000 });
    execFileSync('icacls', [file, '/inheritance:r'], { stdio: 'ignore', timeout: 5000 });
  } catch { /* 尽力而为，失败不阻断启动 */ }
}

const HANDSHAKE_SECRET = loadOrCreateHandshakeSecret();
// 注意 cookie 名不要改成 __Host- / __Secure- 前缀：带保留前缀而不带 Secure 属性时，
// 浏览器会**静默丢弃**整条 Set-Cookie，表现出来就是"授权成功但刷新后又要授权"。
// 本地是 http://127.0.0.1，Secure cookie 同样会被丢掉，所以这里必须用普通名字。
// cookie 里放的不是秘密本身，而是它的 HMAC：
//  - 秘密只在文件和服务端内存里，浏览器 cookie 库（同用户可以读）拿到的是派生值；
//  - 派生值仍然只由秘密决定，所以比较 cookie 等价于校验秘密，且不把秘密写进浏览器。
const HANDSHAKE_COOKIE_VALUE = crypto.createHmac('sha256', Buffer.from(HANDSHAKE_SECRET, 'utf8'))
  .update('maildesk/handshake-cookie/v1')
  .digest('hex');

/** 常量时间字符串比较。长度不同直接 false —— timingSafeEqual 长度不等会抛异常 */
function safeEqualStr(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a), 'utf8');
  const bb = Buffer.from(String(b == null ? '' : b), 'utf8');
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** 从 Cookie 头里取 maildesk_hs 并校验。SameSite=Strict 保证第三方网页带不上它。 */
function hasHandshakeCookie(req) {
  const raw = req.headers['cookie'];
  if (!raw) return false;
  for (const part of String(raw).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() !== HANDSHAKE_COOKIE) continue;
    return safeEqualStr(part.slice(i + 1).trim(), HANDSHAKE_COOKIE_VALUE);
  }
  return false;
}

/**
 * 命令行/脚本用的握手头。
 * 之所以两种凭据都认：浏览器能自动带 cookie（前端零改动），
 * 而脚本不会管 cookie 罐，直接读文件传头最自然。两者校验的是**同一个秘密**。
 */
function hasHandshakeHeader(req) {
  const v = req.headers['x-maildesk-handshake'];
  if (!v) return false;
  return safeEqualStr(String(v).trim(), HANDSHAKE_SECRET);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

/* ---------------- 工具 ---------------- */

function json(res, code, obj, origin) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...(origin ? {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '600',
    } : {}),
  });
  res.end(body);
}

/**
 * 请求体读取失败。带 code 是为了让最外层 catch 能把三类错误分开：
 *   BODY_TOO_LARGE   → 413
 *   BODY_INVALID     → 400（JSON 解析失败 / 连接中断）
 * HTTP 响应里绝不回原始 message，它可能带着解析器内部细节。
 */
function bodyError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = e => {
      if (settled) return;
      settled = true;
      reject(e);
    };
    req.on('data', c => {
      if (settled) return;
      size += c.length;
      if (size > limit) {
        // 返回 413 而不是直接把连接 destroy 掉。
        // 以前先 reject 再 destroy，客户端看到的是"连接被重置"，
        // 完全看不出是请求体太大；而且 reject 之后若 end 事件仍到达，
        // resolve/reject 会被调用第二次（Promise 会吞掉，但语义是坏的）。
        fail(bodyError('BODY_TOO_LARGE', '请求体过大'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      let parsed;
      try { parsed = JSON.parse(raw); }
      catch { return reject(bodyError('BODY_INVALID', 'JSON 解析失败')); }
      // 非对象一律 400。
      //
      // 原来直接把它交给各 action：body 是 null / 字符串 / 数字时，
      // 第一行 `b.something` 就抛 TypeError，被最外层 catch 归成 500，
      // 用户看到 "Cannot read properties of null (reading 'mode')" —— 既暴露内部
      // 实现，又把"请求格式不对"错报成"服务器坏了"。
      // 在入口统一挡住，语义只有一种：请求体必须是 JSON 对象。
      // （数组也挡掉：本服务的每个 action 都按对象取值，没有一个是收数组的。）
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return reject(bodyError('BODY_INVALID', '请求体必须是 JSON 对象'));
      }
      resolve(parsed);
    });
    req.on('error', e => fail(bodyError('BODY_INVALID', '请求体读取失败：' + (e && e.message))));
  });
}

function serveStatic(req, res, urlPath) {
  // 解码失败必须兜住：畸形百分号编码（/%zz、/%E0%A4%A）会让 decodeURIComponent 抛
  // URIError，若冒泡出去就是 uncaughtException，整个进程退出。
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  // 归一化并确保目标在 PUBLIC_DIR 内（防路径穿越）
  const rel = decoded.replace(/^\/+/, '') || 'index.html';
  const target = path.resolve(PUBLIC_DIR, rel);
  const base = path.resolve(PUBLIC_DIR);

  if (target !== base && !target.startsWith(base + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Forbidden');
  }
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not Found');
  }

  const ext = path.extname(target).toLowerCase();
  const body = fs.readFileSync(target);
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': body.length,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // 无 SRI 问题：所有资源都是本地文件
    //
    // 全部 no-cache，不做 max-age。原因是本工具的代码会随开发迭代变化，
    // 而 ETag/Last-Modified 缺失时 `max-age=300` 会让浏览器在 5 分钟内
    // 完全不再请求 app.js / style.css，用户看到的界面和磁盘上的代码对不上，
    // 排查时会误判成"改动没生效"或"代码有 bug"。本地静态文件重传成本可忽略。
    // no-cache 仍允许条件请求（带 If-None-Match 时会 304），不影响性能。
    'Cache-Control': 'no-cache, must-revalidate',
    // 页面本身没有内联脚本，不需要 'unsafe-inline'
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
  });
  res.end(body);
}

/* ---------------- 路由 ---------------- */

const VALID_ENDPOINTS = new Set(['auto', 'consumers', 'common', 'organizations', 'live']);

function normalizeEndpoint(v) {
  const s = String(v || '').trim().toLowerCase();
  return VALID_ENDPOINTS.has(s) ? s : 'auto';
}

function accountPublic(a) {  const s = a.secrets || {};
  return {
    id: a.id,
    email: a.email,
    label: a.label || '',
    group: a.group || '默认',
    endpoint: s.endpoint || 'auto',
    hasTenant: !!s.tenant,
    hasClientId: !!s.clientId,
    hasRefreshToken: !!s.refreshToken,
    clientIdHint: s.clientId ? s.clientId.slice(0, 8) + '…' : '',
    status: a.status || 'unknown',
    // statusMessage 是**落库**的字段：老版本曾把底层 e.message 原样写进去
    // （含本地路径）。只在写入点脱敏挡不住库里已有的记录，所以出口也过一遍。
    statusMessage: redactErrorText(a.statusMessage || '', 120),
    lastCheckedAt: a.lastCheckedAt || null,
    createdAt: a.createdAt || null,
    note: a.note || '',
    // 老账户没有这两个字段（平台标注是后加的）。这里必须给出 [] / {}，
    // 不能把 undefined 透出去 —— 前端直接 (...).includes / Object.keys 会崩。
    // 而且必须是**字符串数组**：库里/导入的数据可能混着数字、null、嵌套数组，
    // 透到前端会让 pfKeys() 之类的前端辅助函数拿到非字符串直接抛。
    platforms: Array.isArray(a.platforms)
      ? a.platforms.filter(k => typeof k === 'string' && k)
      : [],
    platformNames: (a.platformNames && typeof a.platformNames === 'object' && !Array.isArray(a.platformNames))
      ? a.platformNames : {},
  };
}

/* ---------------- 批量收验证码 ---------------- */

// 实测：并发 3 时 100 账号约 188 秒；并发 9 只降到 175 秒，
// 但单账号延迟从 5.6 秒涨到 15.8 秒。瓶颈在微软侧限流，
// 所以这个值硬编码在服务端，不暴露给前端、也不做自动扩展。
const SCAN_CONCURRENCY = 3;
const SCAN_MAX_IDS = 300;
const SCAN_MAX_RESULTS = 800;
const SCAN_MAX_CODES = 20;
const SCAN_TEXT_LIMIT = 200;
// 单账号扫描超时。jobs 的硬时限要按它推导（见 jobs.runningHardLimitMs），
// 所以必须只有一个定义处——否则改这里的值，硬限还按旧值算。
const SCAN_ACCOUNT_TIMEOUT_MS = 25000;
// 退出时等令牌落盘的上限。单个账号超时 25 秒，但真正危险的只有
// 「已拿到新令牌、还没写盘」那一小段，15 秒足够覆盖并发 3 的收尾。
const DRAIN_TIMEOUT_MS = 15000;

function scanInt(v, fallback, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

function scanText(v, limit = SCAN_TEXT_LIMIT) {
  return String(v == null ? '' : v).slice(0, limit);
}

// 退出进行中标志：置位后不再启动新的批量任务（server.close 只挡新连接，
// 挡不住已经在处理中的那个请求）。权威值在 jobs 里，这里只做镜像，
// 这样测试里单独 require server.js 时行为也一致。
let isShuttingDown = false;

function shuttingDown() {
  return isShuttingDown || (typeof jobs.isShutdownRequested === 'function' && jobs.isShutdownRequested());
}

/* ---- 结果文案脱敏 ----
 * error 是服务端字符串：底层异常里可能带本地绝对路径（ENOENT ... D:\...），
 * 也可能带 refresh_token（M.C 开头的长串）或 GUID 形状的 client_id。
 * 这些一律不能进 HTTP 响应。
 * 注意：下面两个带 /g 的正则只用于 String.replace，绝不能拿去做 .test()/.exec()，
 * 否则 lastIndex 会在多次调用间残留。
 */
const RE_REFRESH_TOKEN = /M\.C[A-Za-z0-9+/=._~-]{16,}/g;
const RE_GUID = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;
const RE_UNC_PATH = /\\\\[^\s"'`)<>,;]+/g;

/**
 * 剥掉本地绝对路径与凭据片段，只留可读的相对描述。
 * 先按已知根目录精确替换（DATA_DIR / ROOT 是本项目最长前缀，
 * 替换掉之后 ENOENT 里的文件名仍然是可读的），再兜底处理任意盘符路径。
 */
function redactPaths(v) {
  let s = String(v == null ? '' : v);
  for (const root of [DATA_DIR, ROOT, PUBLIC_DIR]) {
    if (!root) continue;
    // 带分隔符的一并吃掉，避免留下开头的 "\"
    s = s.split(root + path.sep).join('');
    s = s.split(root).join('');
  }
  // 兜底：任意盘符绝对路径（C:\... / D:/...），含中文与空格之外的一切字符
  s = s.replace(/[A-Za-z]:[\\/][^\s"'`)<>,;]*/g, '<本地路径>');
  // UNC 路径 \\server\share\...
  s = s.replace(RE_UNC_PATH, '<本地路径>');
  // 常见 POSIX 绝对路径（用户可能在 Linux 上跑）
  s = s.replace(/\/(?:home|root|Users|tmp|var|usr|opt|mnt|srv|Volumes|private)\/[^\s"'`)<>,;]*/g, '<本地路径>');
  return s;
}

function redactErrorText(v, limit = SCAN_TEXT_LIMIT) {
  let s = String(v == null ? '' : v);
  s = s.replace(RE_REFRESH_TOKEN, '<令牌已隐藏>');
  s = s.replace(RE_GUID, '<标识已隐藏>');
  s = redactPaths(s);
  return s.slice(0, limit);
}

/** 响应边界：results[] 里失败条目的 error / reason 也都补齐 + 脱敏 */
function scanResultForResponse(r) {
  if (!r || typeof r !== 'object') return {};
  return {
    ...r,
    error: redactErrorText(r.error || r.reason || ''),
    reason: redactErrorText(r.reason || ''),
  };
}

/** 响应边界：errors[] 同时带 error 和 reason，且两个字段都脱敏 */
function scanErrorForResponse(e) {
  if (!e || typeof e !== 'object') return { error: '未知错误', reason: '未知错误' };
  return {
    ...e,
    error: redactErrorText(e.error || e.reason || '未知错误'),
    reason: redactErrorText(e.reason || '未知错误'),
  };
}

/**
 * ids 必须在碰账户库之前校验完。账户库读取会全量 AES 解密，
 * 拿着 40 万个 id 逐条查库会把事件循环冻住几分钟。
 * 返回 { useAll, ids } 或 { error }。
 */
function validateScanIds(raw) {
  if (raw === undefined) return { useAll: true, ids: [] };
  if (!Array.isArray(raw)) return { error: 'ids 必须是字符串数组' };
  if (raw.length > SCAN_MAX_IDS) return { error: '一次最多扫描 300 个账户' };
  for (const id of raw) {
    if (typeof id !== 'string' || id.length < 1 || id.length > 64) {
      return { error: 'ids 含非法账户 id（须为 1..64 字符的字符串）' };
    }
  }
  return { useAll: raw.length === 0, ids: raw };
}

/**
 * 只读账户库顶层的 id 集合，不解密 blob。
 * 扫描途中账户被删时用它跳过；文件正在被 refresh_token 轮换写入时
 * 读盘可能短暂失败，返回 null 让调用方退回内存快照，不至于崩掉。
 */
function storedAccountIds() {
  try {
    const p = path.join(DATA_DIR, 'accounts.enc');
    const st = fs.statSync(p);
    const stamp = p + '|' + st.mtimeMs + ':' + st.size;
    if (storedAccountIds.cache && storedAccountIds.cache.stamp === stamp) {
      return storedAccountIds.cache.ids;
    }
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    const ids = new Set();
    for (const a of (raw && raw.accounts) || []) {
      if (a && typeof a.id === 'string') ids.add(a.id);
    }
    storedAccountIds.cache = { stamp, ids };
    return ids;
  } catch {
    return null;
  }
}
storedAccountIds.cache = null;

/**
 * 一次真实的 IMAP 操作成功了，说明账号此刻是好的——把状态校正过来。
 *
 * 之前只有 account.check / account.checkAll 会写状态，读信路径（folders /
 * messages / message）不会。结果是：全部检测时某账号被微软瞬时拒绝、被标成
 * 异常，之后用户点开它却能正常读信，界面上的"异常"却一直不变。
 * 用户看到的是"邮件能读但显示异常"，只能再跑一次全部检测才能纠正。
 *
 * 只写元数据，绝不碰 secrets —— 这几条路径上 acc 是刷新前的快照，
 * 整条 upsert 会把刚写回的轮换 refresh_token 覆盖成旧值。
 */
function markAccountHealthy(account, detail) {
  if (!account || !account.id) return;
  // 已经是 ok 就不重复落盘；多数情况下这里没有写入成本
  if (account.status === 'ok') return;
  const fields = {
    status: 'ok',
    statusMessage: detail ? String(detail).slice(0, 120) : '可用',
    lastCheckedAt: new Date().toISOString(),
  };
  try {
    vault.updateMeta(account.id, fields);
    Object.assign(account, fields);
  } catch (e) {
    // 状态校正失败不能影响读信——它只是个展示层信息
    console.error('[status] 校正账号状态失败：' + (e && e.message));
  }
}

/** 结果里的 code 对象：只允许契约字段，且按 uid 降序 */
function scanCodeView(c) {
  const uid = Number(c && c.uid);
  return {
    uid: Number.isInteger(uid) ? uid : 0,
    code: scanText(c && c.code, 32),
    confidence: Number(c && c.confidence) || 0,
    keyword: scanText(c && c.keyword),
    subject: scanText(c && c.subject),
    from: scanText(c && c.from),
    date: (c && typeof c.date === 'string') ? c.date.slice(0, 64) : null,
  };
}

function scanResultView(r) {
  const codes = (Array.isArray(r && r.codes) ? r.codes : [])
    .slice(0, SCAN_MAX_CODES)
    .map(scanCodeView)
    // 组内只按 IMAP UID 排：Date 头是发件人可控的，不能让它决定复制顺序
    .sort((a, b) => b.uid - a.uid);
  return {
    ok: !!(r && r.ok),
    codes,
    scanned: Number(r && r.scanned) || 0,
    // error 是细节（"单账号扫描超时（25 秒），已断开连接"），
    // reason 是归类（"网络超时或连接被重置"）。前端优先展示 error。
    // 两个都要脱敏：底层文案可能含路径或令牌片段。
    error: redactErrorText(r && r.error),
    reason: redactErrorText(r && r.reason),
  };
}

/**
 * account.check / account.checkAll 的响应边界。
 *
 * 为什么必须单独做：mail.checkAccount 在失败分支里把底层 `e.message` 原样
 * 放进 result.error（见 lib/mail.js 的 catch），而这条 message 可能正是
 * REFRESH_TOKEN_PERSIST_FAILED —— 里面拼了写盘异常的原文，含本地绝对路径。
 * 它随后又被写进 statusMessage 存库、再经 accountPublic 回到前端。
 * 这两条路径此前都没过 redactErrorText，是 scanResultForResponse 之外的漏网。
 */
function checkResultForResponse(r) {
  if (!r || typeof r !== 'object') return r;
  const out = { ...r };
  // 只在字段本来就有时替换：成功结果没有 error/reason，凭空加键会改变响应形状
  if (out.error != null) out.error = redactErrorText(out.error);
  if (out.reason != null) out.reason = redactErrorText(out.reason);
  return out;
}

/** statusMessage 会落库并长期显示，同样要脱敏；长度沿用 120 的老上限 */
function checkStatusMessage(r) {
  return redactErrorText((r && (r.reason || r.error)) || '检测失败', 120);
}

/**
 * 最坏耗时的粗估：队列长度 × 单账号超时 / 并发。
 * 只用于"创建任务时告知用户大概要多久"，不是承诺——真实耗时取决于网络。
 * 单独抽出来是为了让它和 jobs.runningHardLimitMs 用同一组输入，
 * 两边算法一旦分叉，用户看到的 ETA 就会和实际的硬限对不上。
 */
function scanWorstCaseMs(total) {
  const n = Math.max(0, parseInt(total, 10) || 0);
  return Math.ceil(n / SCAN_CONCURRENCY) * SCAN_ACCOUNT_TIMEOUT_MS;
}

function scanJobView(j) {
  const start = Date.parse(j.startedAt) || Date.now();
  const end = j.state === 'running' ? Date.now() : (Date.parse(j.finishedAt || '') || Date.now());
  const elapsedMs = Math.max(0, end - start);
  let etaMs = null;
  if (j.done > 0) {
    // 已请求取消（含硬时限 / 退出）时不会再有新结果，报 0 比报一个假 ETA 好
    if (j.state !== 'running' || j.cancelRequested) etaMs = 0;
    else {
      const v = Math.round(elapsedMs / j.done * Math.max(0, j.total - j.done));
      etaMs = Number.isFinite(v) ? Math.max(0, v) : null;
    }
  }
  // drained 只有 finishJob 之后才为 true。drain 期间 state 仍是 'running'
  // （前端现有的 `state !== 'running'` 判断因此不会提前停止轮询），
  // 想显示"正在收尾"就额外看 draining / drained。
  return {
    id: j.id,
    state: j.state,
    total: j.total,
    done: j.done,
    ok: j.ok,
    failed: j.failed,
    current: j.current,
    // 当前账户的逐封进度，让前端能显示"正在读取第 3/8 封"而在长任务里不干等。
    // phase: connect | list | read | done
    currentPhase: j.currentPhase || '',
    currentDone: Number.isInteger(j.currentDone) ? j.currentDone : 0,
    currentTotal: Number.isInteger(j.currentTotal) ? j.currentTotal : 0,
    currentFound: Number.isInteger(j.currentFound) ? j.currentFound : 0,
    elapsedMs,
    etaMs,
    // 这次任务实际用的硬限。前端据此显示"最迟 X 分钟会被兜底终止"，
    // 不再依赖任何写死的 15 分钟文案（那个值已经不存在了）。
    hardLimitMs: jobs.jobHardLimitMs(j),
    results: j.results.map(scanResultForResponse),
    errors: j.errors.map(scanErrorForResponse),
    // 硬时限 / 退出时的说明文案（前端此前完全看不到）
    error: redactErrorText(j.error || ''),
    draining: !!j.draining,
    drained: !!j.drained,
  };
}

/* ---------------- 平台标注：两条入口共用的合并逻辑 ---------------- */

/**
 * 把「当前标注」与「本次提交的标注」按 mode 合并，返回新的 {keys, names}。
 *
 * 为什么必须抽出来共用：单账户（account.update）走 normalizePlatforms，
 * 批量（accounts.platforms.set）是手写循环，两条路径的语义实测已经分叉：
 *   | platforms: null       | 单账户清空 []      | 批量 400            |
 *   | 库里 "Github" + add github | —            | 重复插入两颗 chip   |
 *   | __proto__ 显示名       | 保留               | 丢失                |
 * 分叉本身比任何一条具体差异都更危险：用户在两个入口看到的是同一个界面概念。
 *
 * 关键细节：
 *  1. `cur` 先归一化一遍再合并。老数据里可能同时躺着 'Github' 和 'github'
 *     （旧版本没做小写归一），不收拾的话 add 会插进第三份。
 *  2. add 撞到 50 上限时**只拒绝新增，不截断已有项**。原来的
 *     `nextKeys.slice(0, MAX_PLATFORMS)` 会永久删掉历史数据的第 51-60 项 ——
 *     用户只是想"再加一个平台"，结果丢了 10 个。
 *  3. 写 platformNames 一律用 Object.defineProperty。直接赋值时
 *     `nextNames['__proto__'] = x` 会走原型 setter，属性静默消失
 *     （实测 JSON.stringify 出来是 {}），与 platforms.js:106 保持一致。
 */
function applyPlatformMode(curKeys, curNames, addKeys, addNames, mode) {
  // 当前值先归一化：去重、转小写、截断、坏类型剔除。
  const base = normalizePlatforms(Array.isArray(curKeys) ? curKeys : []);
  const rawNames = (curNames && typeof curNames === 'object' && !Array.isArray(curNames)) ? curNames : {};
  // addNames / addKeys 也兜一层：本函数是两条入口的唯一合并点，
  // 调用方将来传错类型时这里返回空结果，而不是抛 TypeError 变成 500。
  const inNames = (addNames && typeof addNames === 'object' && !Array.isArray(addNames)) ? addNames : {};
  const inKeys = Array.isArray(addKeys) ? addKeys.filter(k => typeof k === 'string' && k) : [];

  const setKey = (obj, k, v) => {
    Object.defineProperty(obj, k, { value: v, enumerable: true, configurable: true, writable: true });
  };

  /**
   * 只保留 nextKeys 里、且是**自定义平台**的显示名。
   *
   * 三条规则都必须有：
   *  - 不在 nextKeys 里的键是垃圾（历史遗留 / 被去掉的平台），留着只会越积越多；
   *  - 内置平台的显示名不落盘（从 BUILTIN_MAP 取），否则内置表改名后
   *    库里的旧名字会盖住新名字；
   *  - 自定义名先看"本次提交是否真的带来了大小写信息"。
   *    前端改为提交 key 之后（本规格 F2 的改动），提交上来的 'vercel' 与 key
   *    一模一样，此时**必须保留库里已有的 'Vercel'**，否则用户什么都没改、
   *    光点一下完成，界面上的 Vercel 就变成了小写 vercel。
   *    而老前端提交显示名 'Vercel'（≠ key）时应当以提交的为准。
   * 键先按原样查，查不到再按小写匹配 —— 兼容老数据里没归一化过的键。
   */
  const pickNames = (keys) => {
    const out = {};
    for (const k of keys) {
      if (BUILTIN_MAP[k]) continue;
      const hasIn = Object.prototype.hasOwnProperty.call(inNames, k);
      const incoming = hasIn ? inNames[k] : undefined;
      let existing;
      if (Object.prototype.hasOwnProperty.call(rawNames, k)) existing = rawNames[k];
      else {
        const up = Object.keys(rawNames).find(x => String(x).toLowerCase() === k);
        if (up !== undefined) existing = rawNames[up];
      }
      // 提交值只有在"与 key 不同"时才算携带了大小写信息
      const informative = typeof incoming === 'string' && incoming && incoming !== k;
      const chosen = informative
        ? incoming
        : (typeof existing === 'string' && existing ? existing : incoming);
      if (typeof chosen === 'string' && chosen) setKey(out, k, chosen);
    }
    return out;
  };

  if (mode === 'replace') {
    // replace：**只留这次提交的**（inKeys 已由调用方归一化）。
    // 注意这里绝不能拿 base.platforms —— 那是库里现有的标注，
    // 用它就是"把当前值再写一遍"，用户的提交会被完全忽略（updated 恒为 0）。
    const nextKeys = inKeys.slice();
    return { keys: nextKeys, names: pickNames(nextKeys) };
  }

  if (mode === 'add') {
    const nextKeys = base.platforms.slice();
    const seen = new Set(nextKeys);
    for (const k of inKeys) {
      // 已经存在：自定义名不覆盖用户当前的显示名（用户可能先加了 'Vercel'
      // 又批量加一次 'vercel'，不该把大小写改掉）
      if (seen.has(k)) continue;
      if (nextKeys.length >= MAX_PLATFORMS) {
        // 只拒绝这一条及其后的新增，已有项一个不动
        break;
      }
      seen.add(k);
      nextKeys.push(k);
    }
    return { keys: nextKeys, names: pickNames(nextKeys) };
  }

  // remove：只减不增。inKeys 为空是合法操作（前端"去掉所选"什么都没勾）。
  const drop = new Set(inKeys);
  const nextKeys = base.platforms.filter(k => !drop.has(k));
  return { keys: nextKeys, names: pickNames(nextKeys) };
}

/**
 * 平台 key 比较：先排序再比，不依赖插入顺序。
 *
 * 原来用 JSON.stringify 比较，键序不同就判成"有变化"：
 * 用户什么都没改，也会把 100 条密文重新加密一遍并落盘。
 */
function samePlatformNames(a, b) {
  const ka = Object.keys(a || {}).sort();
  const kb = Object.keys(b || {}).sort();
  if (ka.length !== kb.length) return false;
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false;
    if (a[ka[i]] !== b[kb[i]]) return false;
  }
  return true;
}

/** 归属到某个 action 的提示文案（损坏条目告警等）。不改契约字段，只多一个 warn。 */
function corruptedWarn() {
  const n = vault.corruptedEntries().length;
  return n > 0 ? ('有 ' + n + ' 条账户无法解密，已排除') : '';
}

/** 把 warn 并进响应对象（为空时不加键，保持原有响应形状） */
function withWarn(obj, warn) {
  return warn ? { ...obj, warn } : obj;
}

/* ---------------- 验证码历史 ---------------- */

/**
 * 从 from 里取域名。from 可能是 "noreply@github.com" 或 "GitHub <noreply@github.com>"。
 * 取最后一个 @ 之后的部分，转小写，去掉尾部 > 与标点。
 * 返回的串还要过 History 的白名单正则，这里只做提取。
 */
function senderDomainOf(from) {
  const s = String(from == null ? '' : from);
  const m = /@([^\s>]+)/g;
  let last = '';
  let hit;
  while ((hit = m.exec(s)) !== null) last = hit[1];
  return last.toLowerCase().replace(/[>"'`),;:.\]]+$/, '').replace(/^[<(\[]+/, '');
}

/**
 * 把 job.results 里 ok 账户的 codes 转成 history items。
 * 只放契约里的 8 个字段 + 仅用于算 id 的 uid；subject/from 等攻击者可控内容一律不进历史。
 */
function historyItemsFromJob(job) {
  const out = [];
  const results = Array.isArray(job && job.results) ? job.results : [];
  for (const r of results) {
    if (!r || !r.ok) continue;
    const accountId = r.id;
    const accountEmail = r.email;
    const codes = Array.isArray(r.codes) ? r.codes : [];
    for (const c of codes) {
      if (!c || !c.code) continue;
      out.push({
        accountId,
        accountEmail,
        code: c.code,
        senderDomain: senderDomainOf(c.from),
        receivedAt: (typeof c.date === 'string') ? c.date : null,
        confidence: c.confidence,
        usedAt: null,
        uid: c.uid,               // 只参与算 id，不落盘
      });
    }
    if (out.length >= SCAN_MAX_RESULTS * SCAN_MAX_CODES) break;
  }
  return out;
}

/** 响应边界：只回那 8 个字段，一条都不许多 */
function historyItemView(it) {
  return {
    id: String(it && it.id || '').slice(0, 64),
    accountId: String(it && it.accountId || '').slice(0, 64),
    accountEmail: String(it && it.accountEmail || '').slice(0, 320),
    code: String(it && it.code || '').slice(0, 16),
    senderDomain: String(it && it.senderDomain || '').slice(0, 253),
    receivedAt: (it && typeof it.receivedAt === 'string') ? it.receivedAt : null,
    usedAt: (it && typeof it.usedAt === 'string') ? it.usedAt : null,
    confidence: Number(it && it.confidence) || 0,
  };
}

/**
 * CSV 单元格转义。
 *
 * 两件事：
 *  1. RFC 4180：含逗号 / 引号 / 换行 / 前后空格时用引号包裹，内部引号翻倍；
 *  2. **公式注入中和**：以 = + - @ 或制表符/回车开头的单元格，Excel / WPS 打开时
 *     会当公式执行。真实载体不是平台名，而是导入的邮箱和 group 列（都没有字符限制）：
 *     `=cmd|'/c calc'!A1` 这类值原样写进 CSV，用户双击打开就被执行。
 *
 * 顺序不能反：前缀的 `'` 必须在**加引号之前**插入，否则会插到引号外面，
 * 变成 `'=HYPERLINK(...)` 这样一个既不是合法 CSV、Excel 又不认的单引号。
 * 正确结果是 `"'=..."`（单引号在双引号里面）。
 *
 * 这个函数同时服务 historyExportText 与 accounts.exportPlatforms，修一处覆盖两处。
 *
 * 注意：危险前缀的正则必须写在函**数体内**。selftest.js 会用
 * /function csvCell\([\s\S]*?\n\}/ 把它单独抽出来 eval，引用模块作用域的常量
 * 在那时会变成 ReferenceError。
 */
function csvCell(v) {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\r\n]/.test(s) || /^\s|\s$/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/** 导出文本：只返回字符串，不写文件、不触发下载（前端自己拿去复制） */
function historyExportText(items, format) {
  const rows = items.map(historyItemView);
  if (format === 'csv') {
    const head = ['accountEmail', 'code', 'receivedAt', 'usedAt'].join(',');
    const lines = rows.map(it => [
      csvCell(it.accountEmail),
      csvCell(it.code),
      csvCell(it.receivedAt || ''),
      csvCell(it.usedAt ? '已用' : '未用'),
    ].join(','));
    return [head, ...lines].join('\r\n');
  }
  // txt：邮箱 \t 验证码 \t 时间 \t 状态
  return rows.map(it => [
    it.accountEmail, it.code, it.receivedAt || '', it.usedAt ? '已用' : '未用',
  ].join('\t')).join('\n');
}

/** 后台跑批；HTTP 请求不等它，立刻返回 jobId */
function startScanJob(job, byId, items, opts) {
  // 槽位数组保证 results 始终按输入 ids 顺序输出，不按完成时间
  const slots = new Array(items.length);
  // index -> 该账号的在途事务结束函数。事务必须覆盖「token 兑换 + vault 写回」
  // 的完整生命周期，只有结果真正落进 job.results 之后才允许结束。
  const pendingTx = new Map();
  const rebuild = () => {
    const done = slots.filter(Boolean).slice(0, SCAN_MAX_RESULTS);
    job.results = done.map(x => x.result);
    // error 是细节、reason 是归类：两个都带上，前端才有具体原因可显示。
    // （以前只给 reason，用户永远看到"网络超时或连接被重置"这种泛化文案。）
    job.errors = done.filter(x => !x.result.ok).map(x => ({
      id: x.result.id,
      email: x.result.email,
      error: x.result.error || x.result.reason || '未知错误',
      reason: x.result.reason || '未知错误',
    }));
  };
  const closeTx = index => {
    const end = pendingTx.get(index);
    if (!end) return;
    pendingTx.delete(index);
    try { end(); } catch { /* 结束函数是幂等的，异常不影响流程 */ }
  };

  (async () => {
    try {
      await jobs.runPool(items, SCAN_CONCURRENCY, async (item, index) => {
        const acc = byId.get(item.id);
        if (!acc) return { skipped: true };

        // 账户可能在扫描途中被删；不逐条全库解密，只读 id 列表
        const still = storedAccountIds();
        if (still && !still.has(item.id)) return { skipped: true };

        // 在途事务必须覆盖整个 scanAccount：token 兑换在它内部，
        // 轮换后的 refresh_token 也是它返回前才写进账户库的。
        // 只包 IMAP 那一段的话，写盘窗口仍然暴露在退出/崩溃之下。
        pendingTx.set(index, jobs.beginTransaction());
        job.current = item.email;
        job.currentPhase = '';
        try {
          let r;
          try {
            // 逐封进度回调：让前端显示"正在读取第 3/8 封"。
            // 只写 job 上的展示字段，不加锁、不 await，成本可忽略。
            const onProgress = (p) => {
              if (!p) return;
              job.currentPhase = p.phase;
              job.currentDone = p.done;
              job.currentTotal = p.total;
              job.currentFound = p.found;
            };
            r = await scanAccount(acc, { ...opts, onProgress });
          } catch {
            // 不让底层异常文案（可能含路径/令牌片段）流到结果里
            r = { ok: false, codes: [], scanned: 0, error: '账号扫描失败，请稍后重试', reason: '未知错误' };
          }
          return { skipped: false, raw: r };
        } catch (e) {
          // 理论上走不到（上面已兜住 scanAccount 的一切异常），留作保险：
          // 不结束事务会让退出时白等 15 秒。
          closeTx(index);
          throw e;
        }
      }, {
        isCancelled: () => job.cancelRequested || job.state !== 'running',
        onItem: (out, item, index) => {
          try {
            if (!out || out.skipped) {
              // 已删除/已不存在的账户跳过：收缩 total，保证 done 最终等于 total
              job.total = Math.max(0, job.total - 1);
              return;
            }
            const result = { id: item.id, email: item.email, ...scanResultView(out.raw) };
            slots[index] = { result };
            job.done += 1;
            if (result.ok) job.ok += 1;
            else job.failed += 1;
            rebuild();
          } finally {
            // 结果已经落进 job.results（或已确认跳过），该账号的令牌也早就写完了：
            // 到这里才结束在途事务，drainTransactions 的语义才是"全部收尾"。
            closeTx(index);
          }
        },
      });
    } catch {
      // 走到这里说明 runPool 整体异常（极罕见）：只记原因，终态统一在 finally 落
      if (!job.error) job.error = '批量扫描异常终止';
      job.cancelRequested = true;
    } finally {
      // 保险：无论从哪条路径退出，都不留下悬空事务拖慢退出
      for (const index of [...pendingTx.keys()]) closeTx(index);
      job.current = '';
      // 终态只在这里写。cancel / expireRunning / requestShutdown 一律只置
      // cancelRequested + draining，绝不提前把 state 改成终态 —— 否则前端
      // 会在飞行中的账号还没收尾时就显示"任务已结束"，用户随即关窗口丢令牌。
      if (job.state === 'running') {
        // 有说明文案（硬时限 / 退出 / 整体异常）就是 failed，纯用户取消才是 cancelled
        if (job.cancelRequested && !job.error) job.state = 'cancelled';
        else if (job.error) job.state = 'failed';
        else job.state = 'done';
      }
      if (!job.finishedAt) job.finishedAt = new Date().toISOString();
      // 验证码历史必须在 finishJob 之前写完：finishJob 之后 drained 就变 true，
      // 前端看到终态就会去读历史，那时还没有数据就成了"扫完啥也没有"。
      // 历史写入失败绝不能让 job 失败 —— 包一层 try/catch，只记日志。
      try {
        const hItems = historyItemsFromJob(job);
        if (hItems.length) {
          const r = history.upsertMany(hItems);
          if (r.rejected) console.error('[history] 有 ' + r.rejected + ' 条结果未通过字段校验，已丢弃');
        }
      } catch (e) {
        console.error('[history] 写入验证码历史失败：' + (e && e.message));
      }
      // 飞行中的账号全部结束后才释放单例锁，并置 drained
      jobs.finishJob(job);
    }
  })();
}

async function handleApi(req, res, url, origin) {
  const action = url.searchParams.get('action') || '';

  /* ---- 握手 ----
   * H1：不再无条件发 token。三条合法路径：
   *  1. 已经引导过（cookie 有效）—— 浏览器正常流程走这里，app.js 无需改动；
   *  2. 带 X-MailDesk-Handshake: <本机秘密> —— 给脚本 / 命令行用
   *     （curl -H "X-MailDesk-Handshake: $(cat ~/.maildesk/handshake)" ...）；
   *  3. 刚用秘密完成引导，同一响应里直接下发 token。
   * 三条都拿不到秘密 = 本机其他账户 / 沙箱进程 —— 这正是要挡住的对象。
   */
  if (action === 'handshake') {
    if (hasHandshakeCookie(req) || hasHandshakeHeader(req)) {
      return json(res, 200, { ok: true, token: SESSION_TOKEN }, origin);
    }
    return json(res, 401, {
      ok: false,
      code: 'HANDSHAKE_REQUIRED',
      error: '需要先完成本机授权：在浏览器打开本服务的首页，粘贴授权码',
      handshakeFile: '~/.maildesk/handshake',
    }, origin);
  }

  /* ---- 引导：用本机秘密换 cookie ----
   * 只接受同源请求（Sec-Fetch-Site: same-origin）。
   * 为什么这条足够：另一种攻击面是"用户误开了恶意网页，那个网页跨站 POST 到本机"，
   * 浏览器会带 Sec-Fetch-Site: cross-site，直接拒绝；而且跨站请求也读不到响应，
   * 更带不上我们要求的 JSON 体（预检会失败）。本机其他账户压根读不到秘密文件。
   */
  if (action === 'handshake.bootstrap') {
    // 引导失败要节流：秘密是 256 位，穷举不现实，但重复失败说明有人在试，
    // 让它慢下来并在日志里留痕，比什么都不做好。
    // 连错 3 次才开始冷却（见 BOOTSTRAP_FREE_TRIES 的注释）。
    if (Date.now() < bootstrapBlockedUntil) {
      return json(res, 429, { ok: false, error: '尝试过于频繁，请稍后再试' }, origin);
    }
    const site = String(req.headers['sec-fetch-site'] || '');
    // 直接地址栏访问（'none'）不会走到这个 POST；这里只认同源 fetch。
    // 兜底：个别老浏览器不发 Sec-Fetch-Site（Safari 16.4 之前），
    // 这时退回到"Origin 必须正好是本服务自己的源"。`origin` 参数传进来时
    // 已经过 handleRequest 的白名单校验（只可能是 http://127.0.0.1:PORT 或
    // http://localhost:PORT），所以非空就等价于同源。
    // 两条都不满足 → 拒绝。拒绝本身不进入冷却（见下）。
    if (site !== 'same-origin' && !(site === '' && origin)) {
      return json(res, 403, {
        ok: false,
        error: '只接受来自本服务页面的授权请求（Sec-Fetch-Site 校验失败）',
      }, origin);
    }
    let b;
    try { b = await readBody(req); } catch { b = null; }
    const secret = String((b && (b.secret || b.code)) || '').trim();
    if (!safeEqualStr(secret, HANDSHAKE_SECRET)) {
      bootstrapFails++;
      if (bootstrapFails >= BOOTSTRAP_FREE_TRIES) bootstrapBlockedUntil = Date.now() + BOOTSTRAP_COOLDOWN_MS;
      console.error('[handshake] 引导失败：授权码不正确（来源 ' + (req.socket.remoteAddress || '?') + '）');
      return json(res, 401, { ok: false, error: '授权码不正确：请打开 ' + HANDSHAKE_FILE + ' 复制整行内容' }, origin);
    }
    bootstrapFails = 0;
    // cookie 里放 HMAC 派生值而不是秘密本身；HttpOnly 让页面脚本拿不到它，
    // SameSite=Strict 让第三方页面带不上它。
    // 不加 Secure：本地是 http://127.0.0.1，带 Secure 的 cookie 在明文 HTTP 上
    // 会被浏览器丢弃，用户就永远引导不成功。回环流量不出本机。
    res.setHeader('Set-Cookie',
      HANDSHAKE_COOKIE + '=' + HANDSHAKE_COOKIE_VALUE
      + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + HANDSHAKE_COOKIE_MAX_AGE);
    return json(res, 200, { ok: true, token: SESSION_TOKEN }, origin);
  }

  // ---- 其余全部需要 token ----
  const auth = req.headers['authorization'] || '';
  const provided = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const providedBuf = Buffer.from(provided, 'utf8');
  const okToken = providedBuf.length === SESSION_TOKEN_BYTES &&
    crypto.timingSafeEqual(providedBuf, SESSION_TOKEN_BUF);
  if (!okToken) {
    return json(res, 401, { ok: false, error: '未授权：缺少或错误的访问令牌' }, origin);
  }

  try {
    switch (action) {
      /* ---- 账户列表 ---- */
      case 'accounts': {
        const list = vault.all().map(accountPublic);
        // 损坏条目被 all() 跳过了，但**文件里的原始数据仍在**（隔离区）。
        // 不告警的话，用户只会看到"100 个账号变成 99 个"而毫无头绪 ——
        // 这是 corruptedEntries() 之前在整个 server.js 里 0 次调用的直接后果。
        return json(res, 200, withWarn({ ok: true, accounts: list }, corruptedWarn()), origin);
      }

      /* ---- 新增账户 ---- */
      case 'account.add': {
        const b = await readBody(req);
        if (!b.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email)) {
          return json(res, 400, { ok: false, error: '邮箱格式不正确' }, origin);
        }
        if (!b.clientId || !b.refreshToken) {
          return json(res, 400, { ok: false, error: '必须提供 client_id 和 refresh_token（微软已禁用密码登录）' }, origin);
        }
        const exists = vault.all().find(a => a.email.toLowerCase() === b.email.toLowerCase());
        if (exists) {
          return json(res, 409, { ok: false, error: '该邮箱已存在' }, origin);
        }
        const acc = {
          id: crypto.randomUUID(),
          email: b.email.trim(),
          label: (b.label || '').trim(),
          group: (b.group || '默认').trim(),
          note: (b.note || '').trim(),
          status: 'unknown',
          createdAt: new Date().toISOString(),
          secrets: {
            clientId: b.clientId.trim(),
            refreshToken: b.refreshToken.trim(),
            endpoint: normalizeEndpoint(b.endpoint),
            tenant: b.tenant ? String(b.tenant).trim().slice(0, 100) : '',
          },
        };
        vault.upsert(acc);
        return json(res, 200, { ok: true, account: accountPublic(acc) }, origin);
      }

      /* ---- 批量导入 ---- */
      case 'account.import': {
        const b = await readBody(req);
        const text = String(b.text || '');
        const defaultGroup = (b.group || '导入').trim();
        const existing = new Set(vault.all().map(a => a.email.toLowerCase()));
        const added = [];
        const skipped = [];
        const invalid = [];
        const toAdd = [];

        for (const rawLine of text.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#')) continue;
          // 支持分隔符：----  |  ,  \t  空格
          const parts = line.split(/\s*-{2,}\s*|\s*\|\s*|\t|\s*,\s*/).map(s => s.trim()).filter(Boolean);
          if (parts.length < 3) { invalid.push(rawLine); continue; }

          // 按内容识别列，不能按位置。
          // 号商常见格式是 email----密码----client_id----refresh_token 四列，
          // 按位置取会把密码当 client_id、把 client_id 当 refresh_token，
          // 结果每个账号都报 AADSTS7000012 / 9002313，而凭证其实完好。
          const email = parts[0];
          const rest = parts.slice(1);
          const guidLike = s => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);

          // refresh_token 通常是最长的那段；M.C 开头是 MSA 账号的典型特征。
          // 但老的简短测试格式（如 a----cid----rt）也要兼容，找不到长段就退回按位置取。
          let refreshToken = '';
          let rtIdx = -1;
          for (let i = 0; i < rest.length; i++) {
            const v = rest[i];
            if (v.length > refreshToken.length && v.length >= 40) { refreshToken = v; rtIdx = i; }
          }
          if (rtIdx === -1) {
            rtIdx = rest.length - 1;
            refreshToken = rest[rtIdx] || '';
          }

          // client_id 是 GUID，且不是 refresh_token 自身
          let clientId = '';
          const guidCandidates = rest.filter((v, i) => i !== rtIdx && guidLike(v));
          if (guidCandidates.length) {
            clientId = guidCandidates[0];
          } else {
            // 没有 GUID：退回原顺序（兼容老的两列/三列格式）
            const fallback = rest.filter((v, i) => i !== rtIdx);
            clientId = fallback[0] || '';
          }

          // 剩下的短字符串当作密码
          const password = rest.find((v, i) => i !== rtIdx && v !== clientId && !guidLike(v)) || '';

          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { invalid.push(rawLine); continue; }
          if (!clientId || !refreshToken) { invalid.push(rawLine); continue; }
          if (existing.has(email.toLowerCase())) { skipped.push(email); continue; }

          const acc = {
            id: crypto.randomUUID(),
            email,
            label: '',
            group: defaultGroup,
            note: '',
            status: 'unknown',
            createdAt: new Date().toISOString(),
            secrets: { clientId, refreshToken, password, endpoint: 'auto', tenant: '' },
          };
          toAdd.push(acc);
          existing.add(email.toLowerCase());
          added.push(email);
        }

        // 一次性落盘：逐条 upsert 是 O(N²) 磁盘写入
        if (toAdd.length) vault.upsertMany(toAdd);

        return json(res, 200, {
          ok: true,
          addedCount: added.length,
          skippedCount: skipped.length,
          invalidCount: invalid.length,
          added, skipped, invalid: invalid.slice(0, 20),
        }, origin);
      }

      /* ---- 更新账户 ---- */
      case 'account.update': {
        const b = await readBody(req);
        // 先算好要写什么，再决定写哪几条路径。
        // 全部走 updateMeta / updateSecrets，**绝不** upsert(acc)：
        // acc 是 find() 读到的完整快照，upsert 是浅合并，会把整份 secrets
        // 换回快照里的旧副本 —— 只要在这两次读之间发生过一次 refresh_token
        // 轮换（微软每刷必换、旧值当场失效），用户改个标签就能让账号报废。
        const meta = {};
        // 空串 / 纯空白按"用户想清空"处理，但清空凭据几乎永远是误操作：
        // 实测传 refreshToken: "   " 时旧代码 `if (b.refreshToken)` 守卫放行
        // （空格串是真值），trim 成 "" 写进库，令牌当场清空、账号只能重新导入。
        // 所以这里显式拒绝，而不是静默写空。
        const secrets = {};

        if (b.label !== undefined) meta.label = String(b.label == null ? '' : b.label).slice(0, 100);
        if (b.group !== undefined) meta.group = String(b.group == null ? '' : b.group).slice(0, 50);
        if (b.note !== undefined) meta.note = String(b.note == null ? '' : b.note).slice(0, 500);

        if (b.clientId !== undefined) {
          const v = String(b.clientId == null ? '' : b.clientId).trim();
          if (!v) return json(res, 400, { ok: false, error: 'clientId 不能为空' }, origin);
          secrets.clientId = v;
        }
        if (b.refreshToken !== undefined) {
          const v = String(b.refreshToken == null ? '' : b.refreshToken).trim();
          if (!v) return json(res, 400, { ok: false, error: 'refresh_token 不能为空' }, origin);
          secrets.refreshToken = v;
        }
        if (b.endpoint !== undefined) secrets.endpoint = normalizeEndpoint(b.endpoint);
        if (b.tenant !== undefined) secrets.tenant = String(b.tenant == null ? '' : b.tenant).trim().slice(0, 100);

        const exists = vault.find(b.id);
        if (!exists) return json(res, 404, { ok: false, error: '账户不存在' }, origin);

        if (b.platforms !== undefined) {
          // platforms: null 时 normalizePlatforms 给的是空列表 —— 与批量入口的
          // "空 platforms → 400" 是两件不同的事：这里是"清空这个账户的标注"，
          // 是用户点 × 逐个删完之后本来就会走到的一条合法路径，不是误传。
          const curKeys = Array.isArray(exists.platforms) ? exists.platforms : [];
          const curNames = (exists.platformNames && typeof exists.platformNames === 'object' && !Array.isArray(exists.platformNames))
            ? exists.platformNames : {};
          const incoming = normalizePlatforms(b.platforms);
          // 单账户的语义一直是"整份替换"，所以固定用 replace；
          // 合并规则本身与批量入口共用，避免两条路径再次分叉。
          const merged = applyPlatformMode(curKeys, curNames, incoming.platforms, incoming.platformNames, 'replace');
          meta.platforms = merged.keys;
          meta.platformNames = merged.names;
        }

        // 两条独立写入路径：元数据与 secrets 各自只碰自己的字段。
        // 顺序无所谓（都是读-改-写 + 原子落盘），但分开调用的意义在于：
        // 只改 label 时**完全不会**碰 secrets，绝不会覆盖轮换后的令牌。
        let wrote = false;
        if (Object.keys(meta).length) {
          if (!vault.updateMeta(b.id, meta)) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
          wrote = true;
        }
        if (Object.keys(secrets).length) {
          if (!vault.updateSecrets(b.id, secrets)) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
          wrote = true;
        }

        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        // 凭据变了就丢掉内存里的 token 缓存：否则下次读信用的是旧 client_id
        // 换来的 access_token。没改凭据时不清，避免无谓地重新走一次 OAuth。
        if (wrote && (secrets.clientId !== undefined || secrets.refreshToken !== undefined)) {
          mail.clearTokenCache(acc.id);
        }
        return json(res, 200, { ok: true, account: accountPublic(acc) }, origin);
      }

      /* ---- 删除账户 ---- */
      case 'account.remove': {
        const b = await readBody(req);
        const raw = Array.isArray(b.ids) ? b.ids : [b.id];

        // 逐条 vault.remove 是 O(N²)：每次全库解密 + 全量加密落盘。
        // 删 100 个账号要 100 次全库读写，能把服务卡死几十秒。
        // vault.removeMany 早就写好了，之前一直没用上。
        const ids = raw
          .filter(id => typeof id === 'string' && id)
          .slice(0, 500);            // 上限：前端一次最多传 500 个 id

        const before = new Set(vault.all().map(a => a.id));
        const hit = ids.filter(id => before.has(id));   // 只统计真实存在的

        if (hit.length) vault.removeMany(hit);

        // 返回真实删除数，不是"传了几个 id"
        return json(res, 200, { ok: true, removed: hit.length, requested: ids.length }, origin);
      }

      /* ---- 平台标注：批量配置 ---- */
      case 'accounts.platforms.set': {
        const b = await readBody(req);
        // mode 缺省是 400，不是 'replace'。
        // replace 是**破坏性**的（原有标注全部清除且不可恢复），缺省成它意味着
        // 前端某次漏传 mode、或脚本手写少了这个字段，就直接抹掉一批账户的标注。
        // 前端每次都会显式传 mode，所以收紧缺省值不影响正常流程。
        const mode = b.mode;
        if (mode !== 'replace' && mode !== 'add' && mode !== 'remove') {
          return json(res, 400, {
            ok: false,
            error: "mode 必填，只能是 'replace' / 'add' / 'remove'",
          }, origin);
        }
        if (!Array.isArray(b.ids)) {
          return json(res, 400, { ok: false, error: 'ids 必须是数组' }, origin);
        }
        const ids = [...new Set(b.ids
          .filter(id => typeof id === 'string' && id && id.length <= 64))]
          .slice(0, 500);            // 上限：与 account.remove 保持一致
        if (!ids.length) {
          return json(res, 400, { ok: false, error: 'ids 不能为空' }, origin);
        }

        // 规格 §3.4：空 ids 或空 platforms 返回 400，**remove 除外**。
        // remove 的空集合是合法空操作（前端"去掉所选"什么都没勾时可以照常提交），
        // 所以只在 replace / add 下拒绝空 platforms。
        const incoming = normalizePlatforms(b.platforms);
        if (!incoming.platforms.length && mode !== 'remove') {
          return json(res, 400, { ok: false, error: 'platforms 不能为空' }, origin);
        }

        const current = vault.all();
        const wanted = new Set(ids);     // 用 Set：wanted.includes 在循环里是 O(N·M)
        let updated = 0;

        // 绝不能循环 vault.upsert：那是 O(N²)（每次 upsert 全库解密 + 全量加密落盘），
        // 100 个账户能卡死几十秒。这里用一次 upsertMany —— 它内部 all() 一次、save() 一次。
        // 但 upsertMany 是浅合并，所以每个账户的新 platforms 必须在这里算好再传进去。
        const targets = [];
        for (const acc of current) {
          if (!wanted.has(acc.id)) continue;

          const cur = Array.isArray(acc.platforms) ? acc.platforms.filter(k => typeof k === 'string') : [];
          const curNames = (acc.platformNames && typeof acc.platformNames === 'object' && !Array.isArray(acc.platformNames))
            ? { ...acc.platformNames } : {};

          // 合并规则与单账户入口共用同一个函数（F1-6）：两条路径的语义分叉
          // 比任何一条具体差异都更危险。
          const merged = applyPlatformMode(cur, curNames, incoming.platforms, incoming.platformNames, mode);
          const nextKeys = merged.keys;
          const nextNames = merged.names;

          // 没有实际变化就不写：避免为了一个空操作把 100 条密文重新加密一遍
          const sameKeys = nextKeys.length === cur.length && nextKeys.every((k, i) => k === cur[i]);
          // 键序无关的比较（F1-10）：原来用 JSON.stringify，插入顺序不同就判成
          // "有变化"，一次空提交也会重写全库。
          const sameNames = samePlatformNames(nextNames, curNames);
          if (sameKeys && sameNames) continue;

          targets.push({ id: acc.id, platforms: nextKeys, platformNames: nextNames });
          updated++;
        }

        if (targets.length) vault.upsertMany(targets);

        // 损坏条目不会被计入 updated（它们根本不在 vault.all() 里），
        // 所以批量操作"选了 10 个却只更新 9 个"时，warn 是唯一的解释。
        return json(res, 200, withWarn({
          ok: true, updated, mode, requested: ids.length,
        }, corruptedWarn()), origin);
      }

      /* ---- 平台标注：已用平台计数（给筛选器） ---- */
      case 'accounts.platformStats': {
        // 只要已用过的平台，不含内置全集：没被任何账户用到的平台出现在
        // 筛选器里点下去永远是空列表，是纯粹的噪声。
        const counts = new Map();
        for (const acc of vault.all()) {
          const list = Array.isArray(acc.platforms) ? acc.platforms : [];
          const names = (acc.platformNames && typeof acc.platformNames === 'object') ? acc.platformNames : {};
          // 老数据里存的 key 不一定归一化过（旧版本直接落盘、或外部工具改过文件），
          // 不归一化的话 'Github' 和 'github' 会各占一行计数，点进去只命中一半。
          const normalized = normalizePlatforms(
            list.filter(k => typeof k === 'string' && k)
          );
          // 归一化只带出自定义平台的显示名（"显示名"就是 key 自己的小写形式）。
          // 合并顺序**必须是库里的原值覆盖归一化产物**：库里存的是用户输入的
          // 原始大小写（'Vercel'），而 normalizePlatforms(['vercel']) 给出的
          // platformNames.vercel 是小写 'vercel' —— 反过来合并会让用户明明存的
          // 是大写，筛选器里却显示小写。
          const displaySrc = { ...normalized.platformNames, ...names };
          for (const k of normalized.platforms) {
            const e = counts.get(k);
            if (e) e.count++;
            else counts.set(k, { key: k, name: displayName(k, displaySrc), count: 1 });
          }
        }
        // 计数降序；同数按名字排，保证同一份数据每次返回的顺序稳定
        // （前端 select 每次全量重建，顺序抖动会让用户点错）。
        const stats = [...counts.values()].sort((a, b2) =>
          b2.count - a.count || String(a.name).localeCompare(String(b2.name), 'zh-Hans-CN'));
        // 损坏条目不在 all() 里，它们的平台也就不会被计数 —— 必须告诉用户，
        // 否则"GitHub 明明有 5 个，筛选器只显示 4"永远查不出原因。
        return json(res, 200, withWarn({ ok: true, stats }, corruptedWarn()), origin);
      }

      /* ---- 平台标注：导出 CSV 清单 ---- */
      case 'accounts.exportPlatforms': {
        // 只取元数据，**绝不碰 a.secrets**。这个接口导出的是"哪个邮箱注册了
        // 哪些服务"，够敏感了，不能因为走后门把 refresh_token 一起带出去。
        //
        // 筛选（F1-8）：界面上有搜索框和平台筛选，导出却固定全量 ——
        // 用户筛出 12 个点导出，拿到的还是 100 行。
        //   ids       → 只导出这些账户
        //   platform  → 只导出含该平台的账户
        //   两者都传  → 取交集
        //   都不传    → 全量（向后兼容，老前端不带任何参数照常工作）
        //
        // 请求体是**可选**的：前端 api('accounts.exportPlatforms') 不带 body，
        // 也就是一个 GET。readBody 直接读 GET 请求会永远等不到 data 事件而挂住，
        // 所以有/无请求体必须分开走：没有 body 就当作"无筛选条件"。
        const hasBody = req.method === 'POST' || req.headers['content-length'] !== undefined
          || req.headers['transfer-encoding'] !== undefined;
        const b = hasBody ? await readBody(req) : {};
        const all = vault.all();

        let idFilter = null;
        if (b.ids !== undefined && b.ids !== null) {
          if (!Array.isArray(b.ids)) {
            return json(res, 400, { ok: false, error: 'ids 必须是数组' }, origin);
          }
          idFilter = new Set(b.ids
            .filter(id => typeof id === 'string' && id)
            .slice(0, 500));
          if (!idFilter.size) {
            return json(res, 400, { ok: false, error: 'ids 不能为空' }, origin);
          }
        }

        let platformFilter = null;
        if (b.platform !== undefined && b.platform !== null && b.platform !== '') {
          if (typeof b.platform !== 'string' || b.platform.length > 80) {
            return json(res, 400, { ok: false, error: 'platform 不合法' }, origin);
          }
          // 前端筛选器里存的可能是 key（'github'）也可能是显示名（'X / Twitter'），
          // 先归一化，两种都能命中；顺带吃掉大小写差异。
          const n = normalizePlatforms(b.platform);
          if (!n.platforms.length) {
            return json(res, 400, { ok: false, error: 'platform 不能为空' }, origin);
          }
          platformFilter = new Set(n.platforms);
        }

        let list = all;
        if (idFilter) list = list.filter(a => idFilter.has(a.id));
        if (platformFilter) {
          list = list.filter(a => {
            const n = normalizePlatforms(
              (Array.isArray(a.platforms) ? a.platforms : []).filter(k => typeof k === 'string' && k)
            );
            return n.platforms.some(k => platformFilter.has(k));
          });
        }

        const rows = list.map(a => {
          const keys = Array.isArray(a.platforms) ? a.platforms.filter(k => typeof k === 'string' && k) : [];
          const names = (a.platformNames && typeof a.platformNames === 'object') ? a.platformNames : {};
          // 导出前归一化：显示名用内置表的正确大小写，避免同一平台在 CSV 里
          // 出现 'Github' / 'github' 两种拼法（筛选器看到的是一行）。
          const n = normalizePlatforms(keys);
          // 同 platformStats：库里的原始大小写优先，归一化只做兜底。
          const displaySrc = { ...n.platformNames, ...names };
          return [
            csvCell(a.email || ''),
            csvCell(a.label || ''),
            csvCell(a.group || '默认'),
            // 平台之间用 '; ' 而不是 ','：CSV 逗号分隔符会和平台列表打架
            csvCell(n.platforms.map(k => displayName(k, displaySrc)).join('; ')),
            csvCell(String(n.platforms.length)),
          ].join(',');
        });
        const head = ['邮箱', '标签', '分组', '平台', '平台数量'].join(',');
        // BOM：Excel 双击打开 UTF-8 CSV 不带 BOM 会按系统代码页解，中文全乱码
        const text = '\uFEFF' + [head, ...rows].join('\r\n');
        // \u635F\u574F\u6761\u76EE\u65E2\u4E0D\u5728 count \u91CC\u4E5F\u4E0D\u4F1A\u51FA\u73B0\u5728\u5BFC\u51FA\u7ED3\u679C\u91CC \u2014\u2014 \u7528\u6237\u62FF\u5BFC\u51FA\u5BF9\u8D26\u65F6
        // "\u5C11\u4E86 N \u884C"\u5FC5\u987B\u6709\u89E3\u91CA\u3002
        return json(res, 200, withWarn({ ok: true, text, count: list.length }, corruptedWarn()), origin);
      }

      /* ---- 检查单个账户 ---- */
      case 'account.check': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const r = await mail.checkAccount(acc);
        // 只写元数据：acc 是刷新前读的快照，整条 upsert 会把刚轮换的
        // refresh_token 覆盖回旧值（续命失败，账号当场报废）。
        const meta = {
          status: r.ok ? 'ok' : (r.reason && r.reason.includes('封禁') ? 'banned' : 'failed'),
          statusMessage: r.ok ? `可用，收件箱 ${r.exists} 封` : checkStatusMessage(r),
          lastCheckedAt: new Date().toISOString(),
        };
        vault.updateMeta(acc.id, meta);
        Object.assign(acc, meta);
        return json(res, 200, { ok: true, result: checkResultForResponse(r), account: accountPublic(acc) }, origin);
      }

      /* ---- 批量检查 ---- */
      case 'account.checkAll': {
        const b = await readBody(req);
        const ids = Array.isArray(b.ids) && b.ids.length
          ? b.ids
          : vault.all().map(a => a.id);

        // 先在内存里跑完所有检测，最后一次性落盘。
        // 逐条 vault.upsert 是 O(N²) 写入，100 条能把服务卡住几十秒。
        const snapshot = new Map(vault.all().map(a => [a.id, a]));
        const results = [];
        const CONCURRENCY = 5;

        for (let i = 0; i < ids.length; i += CONCURRENCY) {
          const batch = ids.slice(i, i + CONCURRENCY);
          const part = await Promise.all(batch.map(async id => {
            const acc = snapshot.get(id);
            if (!acc) return { id, ok: false, error: '账户不存在' };
            const r = await mail.checkAccount(acc);
            return { id, email: acc.email, acc, ...r };
          }));
          results.push(...part);
        }

        // 统一回写（只写一次），并且跳过在此期间被删除的账户
        const stillExists = new Set(vault.all().map(a => a.id));
        const updates = [];
        const metaPairs = [];
        for (const r of results) {
          if (!r.acc) continue;
          if (!stillExists.has(r.id)) continue; // 已被删除，不要写回
          const acc = r.acc;
          const meta = {
            status: r.ok ? 'ok' : (r.reason && r.reason.includes('封禁') ? 'banned' : 'failed'),
            statusMessage: r.ok ? `可用，收件箱 ${r.exists} 封` : checkStatusMessage(r),
            lastCheckedAt: new Date().toISOString(),
          };
          Object.assign(acc, meta);
          // 只回写元数据。acc 是刷新前读的快照，upsert 整条会把
          // 这轮写入的轮换 refresh_token 覆盖成旧值。
          metaPairs.push({ id: acc.id, fields: meta });
          updates.push(acc);
        }
        if (metaPairs.length) vault.updateMetaMany(metaPairs);

        return json(res, 200, {
          ok: true,
          results: results.map(({ acc, ...rest }) => checkResultForResponse(rest)),
          total: results.length,
        }, origin);
      }

      /* ---- 文件夹 ---- */
      case 'folders': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const folders = await mail.listFolders(acc);
        // IMAP 通了就说明这个账号此刻可用：把可能残留的"异常"状态改正过来
        markAccountHealthy(acc, '可用');
        return json(res, 200, { ok: true, folders }, origin);
      }

      /* ---- 邮件列表 ---- */
      case 'messages': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const msgs = await mail.listMessages(acc, { mailbox: b.mailbox || 'INBOX', limit: b.limit || 20 });
        // 能列出邮件说明 IMAP 通了，校正掉可能残留的异常状态
        markAccountHealthy(acc, `可用，收件箱 ${msgs.length} 封`);
        return json(res, 200, { ok: true, messages: msgs }, origin);
      }

      /* ---- 邮件正文 ---- */
      case 'message': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const msg = await mail.getMessage(acc, { mailbox: b.mailbox || 'INBOX', uid: b.uid });
        markAccountHealthy(acc, '可用');
        return json(res, 200, { ok: true, message: msg }, origin);
      }

      /* ---- 发送邮件 ---- */
      case 'send': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const to = (Array.isArray(b.to) ? b.to : String(b.to || '').split(/[,;]/))
          .map(s => String(s).trim()).filter(s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s));
        if (!to.length) return json(res, 400, { ok: false, error: '收件人格式不正确' }, origin);
        if (!b.subject && !b.text && !b.html) {
          return json(res, 400, { ok: false, error: '邮件内容为空' }, origin);
        }

        const t = await mail.getAccessToken(acc, { scope: mail.SCOPE_BOTH });
        const r = await sendMail(acc, t.accessToken, {
          to,
          subject: String(b.subject || ''),
          text: b.text ? String(b.text) : '',
          html: b.html ? String(b.html) : '',
        });
        return json(res, 200, { ok: true, ...r }, origin);
      }

      /* ---- 抓取验证码（便捷功能）---- */
      case 'codes': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const mailbox = b.mailbox || 'INBOX';
        const scan = Math.min(Math.max(parseInt(b.scan, 10) || 15, 1), 50);
        const msgs = await mail.listMessages(acc, { mailbox, limit: scan });

        // 列表接口不返回正文，逐封按需取（只取有希望的，最多 8 封，避免拉爆）
        const candidates = msgs.slice(0, 8);
        const out = [];
        for (const m of candidates) {
          try {
            const full = await mail.getMessage(acc, { mailbox, uid: m.uid });
            const combined = [full.subject, full.text, full.html].join('\n');
            const r = extractCode(combined);
            if (r) {
              out.push({
                uid: m.uid,
                code: r.code,
                confidence: r.confidence,
                keyword: r.keyword,
                subject: full.subject,
                from: full.from,
                date: full.date,
              });
            }
          } catch { /* 单封失败不影响其他 */ }
        }
        // 按时间倒序，最新的在最前
        out.sort((a, b2) => String(b2.date || '').localeCompare(String(a.date || '')));
        return json(res, 200, { ok: true, codes: out, scanned: candidates.length }, origin);
      }

      /* ---- 单封邮件的验证码 ---- */
      case 'message.code': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const msg = await mail.getMessage(acc, { mailbox: b.mailbox || 'INBOX', uid: b.uid });
        const combined = [msg.subject, msg.text, msg.html].join('\n');
        const r = extractCode(combined);
        return json(res, 200, { ok: true, code: r ? r.code : null, confidence: r ? r.confidence : 0 }, origin);
      }

      /* ---- 端点诊断：告诉你这个 token 应该在哪个端点用 ---- */
      case 'account.diagnose': {
        const b = await readBody(req);
        const acc = vault.find(b.id);
        if (!acc) return json(res, 404, { ok: false, error: '账户不存在' }, origin);
        const s = acc.secrets || {};

        const tries = [];
        const candidates = [
          { key: 'consumers', label: '个人账号' },
          { key: 'common', label: '通用' },
          { key: 'organizations', label: '企业/学校' },
          { key: 'live', label: '旧版 MSA' },
        ];
        // 如果填了 tenant，先单独试它
        if (s.tenant) candidates.unshift({ key: 'tenant', label: '指定租户 ' + s.tenant });

        for (const c of candidates) {
          try {
            // 必须走 refreshAccountToken：内部会串行化并把轮换后的
            // refresh_token 写回账户库，直接调 refreshAccessToken 会让账号当场报废。
            const r = await mail.refreshAccountToken(acc, {
              endpoint: c.key === 'tenant' ? 'consumers' : c.key,
              tenant: c.key === 'tenant' ? s.tenant : undefined,
            });
            tries.push({
              endpoint: c.key,
              label: c.label,
              ok: true,
              scope: r.scope,
              expiresIn: r.expiresIn,
            });
            // 成功一个就够了
            break;
          } catch (e) {
            tries.push({
              endpoint: c.key,
              label: c.label,
              ok: false,
              aadsts: e.aadsts || '',
              code: e.oauthError || e.code || '',
              // 端点诊断的整个价值就在于把微软的原文摆给用户看，所以这里
              // 不像其他路径那样换固定文案；但**必须**过脱敏：
              // REFRESH_TOKEN_PERSIST_FAILED 的 message 里拼了写盘异常原文，
              // 含本地绝对路径；token 兑换失败的 message 里还可能带令牌片段。
              message: redactErrorText(e.message, 260),
            });
            // 写盘失败与端点无关：再试下一个端点只会把新令牌也一起烧掉。
            // 立刻停手，把"凭据已轮换但没保存"这个事实如实报给用户。
            if (e.code === 'REFRESH_TOKEN_PERSIST_FAILED' ||
                e.code === 'REFRESH_TOKEN_NO_PERSISTER') {
              break;
            }
          }
        }

        const winner = tries.find(t => t.ok);
        return json(res, 200, {
          ok: true,
          working: winner ? winner.endpoint : null,
          workingLabel: winner ? winner.label : null,
          tries,
          hint: winner
            ? `这个账号应该用 ${winner.endpoint} 端点（${winner.label}）`
            : '所有端点都失败。如果所有尝试都报 AADSTS7000012，说明 token 来自某个具体企业租户，' +
              '需要在账号信息里填写 tenant ID；如果报 invalid_grant 或 AADSTS70000，说明 token 本身已失效。',
        }, origin);
      }

      /* ---- 批量收验证码：启动 ---- */
      case 'codes.scan.start': {
        // 退出进行中就别再起新任务：否则它会在 drain 之后仍在写账户库
        if (shuttingDown()) {
          return json(res, 503, { ok: false, error: '服务正在退出，请重新启动后再试' }, origin);
        }
        const b = await readBody(req);
        if (!b || typeof b !== 'object' || Array.isArray(b)) {
          return json(res, 400, { ok: false, error: '请求体必须是 JSON 对象' }, origin);
        }

        // ids 校验必须在任何账户库读取之前；字符串 "abc" 不能靠 String() 兜底
        const checked = validateScanIds(b.ids);
        if (checked.error) return json(res, 400, { ok: false, error: checked.error }, origin);

        let group = '';
        if (b.group !== undefined) {
          if (typeof b.group !== 'string' || b.group.length > 100) {
            return json(res, 400, { ok: false, error: 'group 参数不合法' }, origin);
          }
          group = b.group.trim();
        }
        let mailbox = 'INBOX';
        if (b.mailbox !== undefined) {
          if (!isSafeMailbox(b.mailbox)) {
            return json(res, 400, { ok: false, error: 'mailbox 参数不合法（含控制字符或格式不合法）' }, origin);
          }
          mailbox = b.mailbox.trim();
        }
        const perAccount = scanInt(b.perAccount, 8, 1, 20);
        const onlyUnread = b.onlyUnread === true;

        // 全局幂等锁：同一时刻只允许一个 running job。
        // 起第二个任务会用 6+ 并发撞微软限流，账号可能被标记。
        const running = jobs.findRunning('codes.scan');
        if (running) {
          return json(res, 200, {
            ok: true,
            jobId: running.id,
            total: running.total,
            reused: true,
            // 跟随已有任务时把它的硬限也带上：前端不重新计算，避免两边算法分叉
            hardLimitMs: jobs.jobHardLimitMs(running),
          }, origin);
        }

        // 一次性快照：全程不再调 vault.find（它每次都全库 AES 解密）
        const all = vault.all();
        const byId = new Map(all.map(a => [a.id, a]));
        let list;
        if (checked.useAll) {
          list = group ? all.filter(a => (a.group || '默认') === group) : all;
        } else {
          list = checked.ids.map(id => byId.get(id)).filter(Boolean);
        }
        list = list.filter(a => a && a.status !== 'deleted');
        if (list.length > SCAN_MAX_IDS) {
          return json(res, 400, { ok: false, error: '一次最多扫描 300 个账户' }, origin);
        }

        const items = list.map(a => ({ id: a.id, email: String(a.email || '').slice(0, 200) }));
        // 硬时限按任务规模推导（300 个账号的队列最坏要 42 分钟，写死 15 分钟
        // 必然误杀）。参数从上面这几个常量算，不另设一份数字。
        const job = jobs.createJob('codes.scan', items.length, {
          perAccountMs: SCAN_ACCOUNT_TIMEOUT_MS,
          concurrency: SCAN_CONCURRENCY,
        });
        startScanJob(job, byId, items, { mailbox, perAccount, onlyUnread, timeoutMs: SCAN_ACCOUNT_TIMEOUT_MS });
        // hardLimitMs / etaWorstMs：让前端（和 README 的使用者）能事先看到
        // "这活最坏要多久、什么时候会被兜底终止"。以前这两个数只存在于
        // 服务端注释里，用户选满 300 个账号时对 15 分钟截断毫无预期。
        return json(res, 200, {
          ok: true,
          jobId: job.id,
          total: job.total,
          hardLimitMs: jobs.jobHardLimitMs(job),
          etaWorstMs: scanWorstCaseMs(job.total),
        }, origin);
      }

      /* ---- 批量收验证码：进度 ---- */
      case 'codes.scan.status': {
        const b = await readBody(req);
        const job = jobs.getJob(b.jobId);
        if (!job || job.type !== 'codes.scan') {
          return json(res, 404, { ok: false, error: '任务不存在或已过期' }, origin);
        }
        return json(res, 200, { ok: true, job: scanJobView(job) }, origin);
      }

      /* ---- 批量收验证码：取消 ---- */
      case 'codes.scan.cancel': {
        const b = await readBody(req);
        const job = jobs.getJob(b.jobId);
        if (!job || job.type !== 'codes.scan') {
          return json(res, 404, { ok: false, error: '任务不存在或已过期' }, origin);
        }
        // cancelled 表示「本次调用确实发出了取消请求」；重复取消返回 false。
        // 注意不立刻改 state 为 cancelled：activeRuns 要一直占着单例锁，
        // 直到飞行中的账号全部收尾，避免取消后立刻重开造成 6+ 并发。
        // 同理也不写 finishedAt / 不置终态：cancel 只是请求，
        // 终态由 startScanJob 的 finally 落，期间对外仍是 running + draining=true。
        const cancellable = job.state === 'running' && !job.cancelRequested;
        if (cancellable) {
          job.cancelRequested = true;
          job.draining = true;
          job.current = '';
        }
        return json(res, 200, {
          ok: true,
          cancelled: cancellable,
          state: job.state,
          draining: !!job.draining,
          drained: !!job.drained,
        }, origin);
      }

      /* ---- 验证码历史：列表 ---- */
      case 'history.list': {
        const b = await readBody(req);
        if (!b || typeof b !== 'object' || Array.isArray(b)) {
          return json(res, 400, { ok: false, error: '请求体必须是 JSON 对象' }, origin);
        }
        let q = '';
        if (b.q !== undefined && b.q !== null) {
          if (typeof b.q !== 'string') {
            return json(res, 400, { ok: false, error: 'q 必须是字符串' }, origin);
          }
          if (b.q.length > 100) {
            return json(res, 400, { ok: false, error: 'q 长度不能超过 100' }, origin);
          }
          q = b.q.trim().toLowerCase();
        }
        let accountId = '';
        if (b.accountId !== undefined && b.accountId !== null && b.accountId !== '') {
          if (typeof b.accountId !== 'string' || b.accountId.length > 64) {
            return json(res, 400, { ok: false, error: 'accountId 不合法' }, origin);
          }
          accountId = b.accountId;
        }
        const onlyUnused = b.onlyUnused === true;
        const limit = scanInt(b.limit, 100, 1, 500);
        let sinceHours = null;
        if (b.sinceHours !== undefined && b.sinceHours !== null && b.sinceHours !== '') {
          const n = parseInt(b.sinceHours, 10);
          if (!Number.isFinite(n)) {
            return json(res, 400, { ok: false, error: 'sinceHours 必须是数字' }, origin);
          }
          sinceHours = Math.min(Math.max(n, 1), 168);   // 钳制 1..168
        }
        const cutoff = sinceHours === null ? null : Date.now() - sinceHours * 3600 * 1000;

        // 逐条过 historyItemView，返回的字段集合被钉死在契约的 8 个
        const all = history.all().map(historyItemView).filter(it => {
          if (accountId && it.accountId !== accountId) return false;
          if (onlyUnused && it.usedAt !== null) return false;
          if (cutoff !== null) {
            // receivedAt 为 null 的条目无从判龄，按"新"处理保留
            if (it.receivedAt) {
              const t = Date.parse(it.receivedAt);
              if (Number.isFinite(t) && t < cutoff) return false;
            }
          }
          if (q) {
            const hay = (it.code + '\n' + it.accountEmail + '\n' + it.senderDomain).toLowerCase();
            if (!hay.includes(q)) return false;
          }
          return true;
        });
        return json(res, 200, {
          ok: true,
          items: all.slice(0, limit),
          total: all.length,
        }, origin);
      }

      /* ---- 验证码历史：标记已用 / 未用 ---- */
      case 'history.mark': {
        const b = await readBody(req);
        if (!b || typeof b !== 'object' || Array.isArray(b)) {
          return json(res, 400, { ok: false, error: '请求体必须是 JSON 对象' }, origin);
        }
        const ids = b.ids;
        if (!Array.isArray(ids) || ids.length < 1 || ids.length > 500) {
          return json(res, 400, { ok: false, error: 'ids 必须是 1..500 项的字符串数组' }, origin);
        }
        for (const id of ids) {
          if (typeof id !== 'string' || id.length < 1 || id.length > 64) {
            return json(res, 400, { ok: false, error: 'ids 含非法条目（须为 1..64 字符的字符串）' }, origin);
          }
        }
        const r = history.mark(ids, b.used !== false);
        return json(res, 200, { ok: true, updated: r.updated }, origin);
      }

      /* ---- 验证码历史：清理 ---- */
      case 'history.clear': {
        const b = await readBody(req);
        if (!b || typeof b !== 'object' || Array.isArray(b)) {
          return json(res, 400, { ok: false, error: '请求体必须是 JSON 对象' }, origin);
        }
        let olderThanHours;
        if (b.olderThanHours !== undefined && b.olderThanHours !== null && b.olderThanHours !== '') {
          const n = Number(b.olderThanHours);
          if (!Number.isFinite(n) || n <= 0) {
            return json(res, 400, { ok: false, error: 'olderThanHours 必须是正数' }, origin);
          }
          olderThanHours = n;
        }
        const r = history.clear({ olderThanHours });
        return json(res, 200, { ok: true, removed: r.removed }, origin);
      }

      /* ---- 验证码历史：导出文本 ---- */
      case 'history.export': {
        const b = await readBody(req);
        if (!b || typeof b !== 'object' || Array.isArray(b)) {
          return json(res, 400, { ok: false, error: '请求体必须是 JSON 对象' }, origin);
        }
        const format = b.format === 'csv' ? 'csv' : (b.format === 'txt' || b.format === undefined || b.format === null ? 'txt' : '');
        if (!format) {
          return json(res, 400, { ok: false, error: "format 只能是 'txt' 或 'csv'" }, origin);
        }
        // 导出内容同样过一遍字段校验：history.all() 已经从盘上做了白名单清洗，
        // historyItemView 再把字段集合钉死，避免将来有人往 items 里加字段就跟着导出去。
        const items = history.all().map(historyItemView);
        const text = historyExportText(items, format);
        return json(res, 200, { ok: true, text, count: items.length }, origin);
      }

      default:
        return json(res, 400, { ok: false, error: '未知的 action：' + action }, origin);
    }
  } catch (e) {
    // 三类错误分开处理，**任何情况下都不把 e.message 回给客户端**。
    //
    // 原来这里直接 `error: e.message`，实测三种泄露/误判：
    //   body = null      → 500 "Cannot read properties of null (reading 'mode')"
    //   JSON 解析失败    → 500（本该 400）
    //   vault 读失败     → 500 + "C:\Users\ADMINI~1\...\accounts.enc.tmp"
    // 绝对路径不但是信息泄露，还让用户完全看不出该修什么。原始信息只进终端日志。
    // 这与同文件 handleRequest 里 handleApi 的 .catch 是同一个约定。
    console.error(`[${action}]`, (e && e.stack) || e);

    if (e && e.code === 'BODY_TOO_LARGE') {
      return json(res, 413, { ok: false, error: '请求体过大（上限 2MB）' }, origin);
    }
    if (e && e.code === 'BODY_INVALID') {
      // readBody 的两种失败：JSON 语法错、或不是对象（null / 数组 / 标量）。
      // 两者都是客户端的错，400 而不是 500。
      return json(res, 400, { ok: false, error: '请求体格式不正确：必须是合法的 JSON 对象' }, origin);
    }
    if (e && (e.code === 'VAULT_READ_FAILED' || e.code === 'VAULT_KEY_INVALID'
      || e.code === 'VAULT_KEY_MISMATCH')) {
      // 账户库读不出来：确实是我们这边的问题（500），但只给固定文案。
      // 具体情况（文件结构损坏 / 密钥不匹配）在终端日志里，那里能看到路径。
      return json(res, 500, {
        ok: false,
        error: '账户库读取失败，请查看终端日志（数据文件未被修改，备份仍在）',
        reason: (mail.classifyError ? mail.classifyError(e) : '') || '',
      }, origin);
    }
    // 其余一律 500 + 固定文案。reason 是归类后的提示，不含路径与令牌片段。
    return json(res, 500, {
      ok: false,
      error: '服务器内部错误，详见终端日志',
      reason: (mail.classifyError ? mail.classifyError(e) : '') || '',
    }, origin);
  }
}

/* ---------------- 握手引导页 ---------------- */

/**
 * 引导页 HTML。
 *
 * 为什么由 server.js 动态吐而不是放进 public/：
 * 本次改动范围被钉死在 server.js / vault.js，前端目录不能动；
 * 而且这个页面必须知道自己的 CSP nonce，静态文件做不到。
 *
 * CSP 用 nonce 而不是 'unsafe-inline'：页面里只有一段内联脚本，
 * 用 nonce 既能跑又保持 script-src 里没有 unsafe-inline（security-test 也在断言这点）。
 */
function bootstrapPage(nonce) {
  const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailDesk · 本机授权</title>
<style>
 body{font:14px/1.7 system-ui,"Segoe UI",sans-serif;background:#f5f6f8;color:#1f2430;margin:0;padding:48px 16px}
 .card{max-width:640px;margin:0 auto;background:#fff;border:1px solid #dde3ec;border-radius:10px;padding:24px 28px}
 h1{font-size:18px;margin:0 0 8px}
 p{margin:8px 0;color:#3c4455}
 code,textarea{font-family:ui-monospace,Consolas,monospace}
 code{background:#eef2f8;padding:1px 5px;border-radius:4px;font-size:13px}
 textarea{width:100%;box-sizing:border-box;height:64px;margin:10px 0;padding:8px;border:1px solid #c9d2e0;border-radius:6px;font-size:13px;resize:vertical}
 button{background:#2f6fed;color:#fff;border:0;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer}
 button[disabled]{opacity:.55;cursor:default}
 .err{color:#b42318;min-height:20px;margin-top:8px}
 .ok{color:#067647}
 .hint{font-size:12.5px;color:#667085}
</style></head><body><div class="card">
<h1>MailDesk 需要一次本机授权</h1>
<p>这个工具管着真实邮箱的凭据，所以启动后要先证明"你本人坐在这台电脑前"。
授权码只存在你的用户目录里，本机其他账户读不到：</p>
<p><code>${escHtml(HANDSHAKE_FILE)}</code></p>
<p>用记事本打开它（或在终端里 <code>type "%USERPROFILE%\\.maildesk\\handshake"</code>），
把整行 64 位字符粘贴到下面。只需做一次，之后这个浏览器会记住。</p>
<textarea id="code" spellcheck="false" autocomplete="off" placeholder="粘贴 64 位授权码"></textarea>
<button id="go">授权</button>
<div class="err" id="msg" role="alert"></div>
<p class="hint">不想用浏览器？脚本可以直接带请求头：
<code>curl -H "X-MailDesk-Handshake: $(cat ~/.maildesk/handshake)" "http://127.0.0.1:2131/api?action=handshake"</code></p>
</div>
<script nonce="${nonce}">
(function(){
  var btn = document.getElementById('go');
  var box = document.getElementById('code');
  var msg = document.getElementById('msg');
  btn.addEventListener('click', function(){
    var v = box.value.trim();
    if (!v) { msg.className = 'err'; msg.textContent = '请先粘贴授权码'; return; }
    btn.disabled = true; msg.className = ''; msg.textContent = '正在校验…';
    // X-MailDesk-Bootstrap 是自定义头：跨站请求带它必然触发预检，
    // 而本服务的 CORS 白名单只放行自己这个端口，预检过不去。
    fetch('/api?action=handshake.bootstrap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-MailDesk-Bootstrap': '1' },
      body: JSON.stringify({ secret: v })
    }).then(function(r){ return r.json().then(function(d){ return { s: r.status, d: d }; }); })
      .then(function(x){
        btn.disabled = false;
        if (x.s === 200 && x.d && x.d.ok) {
          msg.className = 'ok'; msg.textContent = '授权成功，正在进入…';
          location.replace('/');
        } else {
          msg.className = 'err';
          msg.textContent = (x.d && x.d.error) || ('授权失败（HTTP ' + x.s + '）');
        }
      }).catch(function(){ btn.disabled = false; msg.className = 'err'; msg.textContent = '无法连接本地服务'; });
  });
  box.addEventListener('keydown', function(e){ if (e.key === 'Enter') btn.click(); });
})();
</script>
</body></html>`;
}

/** 吐引导页。安全头与静态页保持一致，只把内联脚本放行方式换成 nonce */
function sendBootstrapPage(res) {
  const nonce = crypto.randomBytes(18).toString('base64');
  const body = Buffer.from(bootstrapPage(nonce), 'utf8');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length,
    // 授权状态随时可能变（用户刚点了授权），任何中间缓存都不该留副本。
    // 同时保留 no-cache 字样：与静态页的缓存策略保持一致，也让"本地静态资源
    // 一律可重新校验"这条既有约定对该页面同样成立。
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
  });
  res.end(body);
}

/* ---------------- 退出 ---------------- */

/**
 * 统一退出路径。
 *
 * 为什么不能只 server.close()：它只等 HTTP 连接，不等后台的跑批 IIFE，
 * 更不等 mail.getAccessToken() 里那条 https.request。若进程恰好死在
 * 「微软已返回新 refresh_token」到「vault.updateRefreshToken 写盘」之间的
 * 微任务窗口，新令牌只存在于内存，旧令牌又已在服务端作废 → 账号永久失效。
 *
 * 顺序：置退出标志 → 请求所有 job 停止派发 → 停止收新连接 → 等在途事务归零
 *       → 退出。没有在途事务时 drainTransactions 立刻返回，正常退出不变慢。
 *
 * 本函数是**整个文件里唯一**调用 process.exit 的地方（见断言）。
 *
 * @param {string} reason  日志里的退出原因
 * @param {number} code    进程退出码（异常路径必须非 0）
 */
async function shutdown(reason, code = 0) {
  // 重入保护：连按两次 Ctrl+C、或信号与未捕获异常同时到来时只走一次。
  // 用与"退出进行中"同一个标志，避免再引入第二个互斥变量。
  if (isShuttingDown) {
    // 这里也不能让 console 抛出去（控制台已关闭时 write 会 EPIPE）：
    // 一旦变成 unhandledRejection，又会回到本函数，形成自激循环。
    try { console.log('\n已在退出流程中，在途令牌仍在落盘，请勿强制关闭窗口…'); } catch { /* 忽略 */ }
    return;
  }
  isShuttingDown = true;

  try {
    console.log('\n正在退出' + (reason ? '（' + reason + '）' : '') + '…');
  } catch { /* 控制台可能已关闭 */ }

  // 让所有 running job 在下一个账号边界停止；已开始的账号会跑完并落盘
  try { jobs.requestShutdown(); } catch { /* 忽略 */ }

  // 先停止接收新请求。server.close() 的回调不等在途事务，所以不能靠它兜底。
  try {
    server.close(() => { /* 连接已全部关闭，真正的等待在下面 */ });
  } catch { /* 可能从未 listen 过 */ }

  const pending = jobs.pendingTransactions();
  if (pending > 0) {
    // 这句话必须明确：用户看到"正在退出"就去叉窗口，正好把令牌丢掉
    try { console.log('正在等待 ' + pending + ' 个令牌兑换落盘，请勿强制关闭窗口…'); } catch { /* 忽略 */ }
  }

  // 等在途事务归零。
  // 必须做两轮：runPool 的某个 lane 可能刚通过 isCancelled() 检查、还没登记
  // 事务就被这次退出截住了（检查与 beginTransaction 之间没有原子性）。
  // 第一轮若报告"已归零"却其实还有 lane 在途，紧接着的第二轮会把它们等回来 ——
  // 而第二轮在没有新事务时是同步立即返回的，正常退出的耗时不受影响。
  // 第二个参数 waitTicks：真的还有在途时先让出一轮事件循环，
  // 给那个 lane 把事务登记进来的机会，避免"刚归零就退出"漏掉它。
  let drained = true;
  try {
    drained = await jobs.drainTransactions(DRAIN_TIMEOUT_MS);
    if (drained) drained = await jobs.drainTransactions(DRAIN_TIMEOUT_MS, { waitTicks: true });
  } catch (e) {
    drained = false;
  }

  if (!drained) {
    const left = jobs.pendingTransactions();
    try {
      console.error(
        '警告：等待 ' + DRAIN_TIMEOUT_MS + 'ms 后仍有 ' + left +
        ' 个令牌兑换未落盘，这些账号可能需要重新导入。'
      );
    } catch { /* 控制台可能已关闭 */ }
    // 超时说明状态已不确定，即使原本是正常退出也要用非 0 码
    if (code === 0) code = 1;
  } else if (pending > 0) {
    try { console.log('令牌已全部落盘，安全退出。'); } catch { /* 忽略 */ }
  }

  // 锁在**所有**落盘动作之后才释放：drain 期间还在写 refresh_token，
  // 这时候放第二个实例进来正好撞上"两个进程互相覆盖内存状态"。
  // 放在 process.exit 之前、而不是依赖 'exit' 事件，是为了保证顺序明确。
  releaseInstanceLock();

  process.exit(code);
}

/* ---------------- 启动 ---------------- */

const server = http.createServer((req, res) => {
  // 最外层兜底：任何同步异常都不能让进程退出。
  // 之前 /%zz 这类畸形路径会让 decodeURIComponent 抛出 URIError，
  // 冒泡成 uncaughtException 直接杀死服务。
  try {
    handleRequest(req, res);
  } catch (e) {
    console.error('[request] 未捕获异常:', e && e.message);
    try {
      if (!res.headersSent) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end('Bad Request');
    } catch { /* 连接可能已断开 */ }
  }
});

function handleRequest(req, res) {
  let url;
  try {
    url = new URL(req.url, 'http://127.0.0.1');
  } catch {
    // 畸形请求行（如 GET http://x:bad HTTP/1.1）会让 new URL 抛 TypeError
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  // Host 头校验：防 DNS rebinding。
  // rebinding 攻击下浏览器认为请求同源、不走 CORS 检查，
  // 唯一能拦住的就是服务端自己核对 Host。
  const host = String(req.headers.host || '');
  const expectedHosts = PORT
    ? [`127.0.0.1:${PORT}`, `localhost:${PORT}`]
    : [];
  if (expectedHosts.length && !expectedHosts.includes(host)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Forbidden: invalid Host header');
  }

  const origin = req.headers.origin;

  // CORS 白名单：只接受来自本端口 127.0.0.1 / localhost 的跨域请求。
  // 注意：绝不回退成 '*' —— 否则任意网页都能跨域调用本地 API。
  // 无 Origin 头的请求（同源页面 fetch、curl）本来就不需要 CORS 头。
  let allowedOrigin = null;
  if (origin) {
    try {
      const o = new URL(origin);
      const okHost = (o.hostname === '127.0.0.1' || o.hostname === 'localhost');
      const okPort = o.port === String(PORT);
      allowedOrigin = (okHost && okPort) ? origin : null;
    } catch { allowedOrigin = null; }
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      ...(allowedOrigin ? {
        'Access-Control-Allow-Origin': allowedOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '600',
        'Vary': 'Origin',
      } : {}),
      'Content-Length': 0,
    });
    return res.end();
  }

  if (url.pathname.startsWith('/api')) {
    return handleApi(req, res, url, allowedOrigin)
      .catch(e => {
        console.error('[api]', e && e.message);
        // 对外只给归类后的提示，原始 message 只进本地日志（可能含路径等内部细节）
        json(res, 500, {
          ok: false,
          error: '服务器内部错误，详见终端日志',
          reason: (mail.classifyError ? mail.classifyError(e) : '') || '',
        }, null);
      });
  }

  if (req.method !== 'GET') {
    res.writeHead(405);
    return res.end();
  }

  /* ---- 首页拦截（H1 的浏览器侧）----
   * 没通过授权就不给首页：否则用户会看到一个"打不开账号列表、只弹一句错误"的界面，
   * 完全不知道要做什么。给出授权页，里面写着授权码文件和用法。
   * 已经授权过的浏览器照常拿 index.html —— 原有使用流程一个字都不变。
   */
  if (url.pathname === '/' || url.pathname === '/index.html') {
    if (hasHandshakeCookie(req)) return serveStatic(req, res, url.pathname);
    return sendBootstrapPage(res);
  }

  return serveStatic(req, res, url.pathname);
}

let PORT = 0;

/**
 * 固定端口。
 *
 * 早先用 listen(0) 让系统随机分配，结果是每次重启网址都变，
 * 用户存的书签立刻就失效，也没法在别的窗口里记住地址。
 *
 * 现在固定 2131（早期版本用过，好记），被占用时顺延到 2132、2133…
 * 最多试 10 个。如果全被占用，报清楚原因而不是悄悄换一个随机端口。
 * 设环境变量 MAILDESK_PORT 可以完全覆盖。
 */
const DEFAULT_PORT = 2131;
const PORT_TRIES = 10;

function listenOn(port) {
  return new Promise((resolve, reject) => {
    const onError = e => {
      server.removeListener('listening', onListening);
      reject(e);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve(server.address().port);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, '127.0.0.1');
  });
}

function start() {
  return new Promise((resolve, reject) => {
    // 实例锁冲突：连端口都不用试。放在最前面，避免出现"端口顺延成功之后
    // 才发现不该启动"的半启动状态。
    if (instanceLockError) return reject(instanceLockError);

    const envPort = parseInt(process.env.MAILDESK_PORT, 10);
    const want = Number.isInteger(envPort) && envPort > 0 && envPort < 65536 ? envPort : DEFAULT_PORT;

    (async () => {
      let bound = null;
      let lastErr = null;
      const tries = Number.isInteger(envPort) ? 1 : PORT_TRIES;   // 指定了端口就只试那一个

      for (let i = 0; i < tries; i++) {
        const p = want + i;
        if (p > 65535) break;
        try {
          bound = await listenOn(p);
          break;
        } catch (e) {
          lastErr = e;
          if (e.code !== 'EADDRINUSE') throw e;   // 权限之类的问题直接抛
        }
      }

      if (!bound) {
        const msg = lastErr && lastErr.code === 'EADDRINUSE'
          ? `端口 ${want}${tries > 1 ? '~' + (want + tries - 1) : ''} 都被占用，请关掉占用端口的程序，或用 MAILDESK_PORT 指定其它端口`
          : `无法启动服务：${(lastErr && lastErr.message) || '未知错误'}`;
        console.error('\n  [ERROR] ' + msg + '\n');
        throw new Error(msg);
      }

      PORT = bound;
      const addr = `http://127.0.0.1:${PORT}`;
      // 启动横幅只用 ASCII：Windows cmd 默认 GBK 代码页，
      // 中文和制表符会显示成乱码。start.bat 会先 chcp 65001，
      // 但用户也可能直接 node server.js，所以这里保持纯 ASCII 更稳。
      console.log('');
      console.log('  +------------------------------------------------+');
      console.log('  |            MailDesk  -  Mail Manager           |');
      console.log('  +------------------------------------------------+');
      console.log('');
      console.log('  URL      : ' + addr);
      console.log('  Data dir : ' + DATA_DIR);
      console.log('  Key dir  : ' + KEY_DIR);
      // 首次打开浏览器会被要求粘贴这个文件里的授权码（H1）。
      // 打印出来是为了让用户第一眼就知道去哪找，而不是对着授权页猜。
      console.log('  Auth file: ' + HANDSHAKE_FILE);
      if (bound !== want) {
        console.log('  Note     : port ' + want + ' was busy, using ' + bound);
      }
      console.log('');
      console.log('  Press Ctrl+C to stop.');
      console.log('');
      resolve(addr);
    })().catch(reject);
  });
}

if (require.main === module) {
  start().catch(e => {
    // 实例锁冲突不是"启动失败"级别的错误，给出完整提示而不是一行 message：
    // 用户双击第二次 start.bat 是最常见的触发方式，他需要知道要关掉哪一个。
    if (e && e.code === 'INSTANCE_RUNNING') {
      console.error('\n  [ERROR] ' + e.message + '\n');
      process.exit(2);
    }
    console.error('启动失败：', e.message);
    // 启动阶段没有在途事务，直接走统一退出（异步函数，但 drain 会立刻返回）
    shutdown('启动失败', 1);
  });

  // 全部走同一个 shutdown()：先用 requestShutdown 让后台跑批在账号边界停下，
  // 再等在途的 refresh_token 兑换落盘。裸的 process.exit 会丢令牌。
  process.on('SIGINT', () => { shutdown('SIGINT'); });
  process.on('SIGTERM', () => { shutdown('SIGTERM'); });
  process.on('SIGHUP', () => { shutdown('SIGHUP'); });
  // Windows：关闭控制台窗口 / 关机 / 注销发的是 SIGBREAK，没有它就只有 SIGINT
  process.on('SIGBREAK', () => { shutdown('SIGBREAK'); });

  // 兜底：任何未捕获的同步异常都不许把进程直接打死。
  // Node 26 默认会把 unhandledRejection 升级成致命异常，二者都必须接管，
  // 否则后台刷新中途的一个意外异常就等于丢掉一次已轮换的令牌。
  process.on('uncaughtException', e => {
    try { console.error('[uncaughtException]', (e && e.stack) || e); } catch { /* 忽略 */ }
    // 不继续跑：状态已不确定。但先给在途事务一个落盘窗口，再以非 0 码退出。
    shutdown('未捕获异常', 1);
  });
  process.on('unhandledRejection', reason => {
    const msg = (reason && (reason.stack || reason.message)) || String(reason);
    try { console.error('[unhandledRejection]', msg); } catch { /* 忽略 */ }
    shutdown('未处理的 Promise 拒绝', 1);
  });
}

module.exports = {
  start,
  SESSION_TOKEN,
  // 供自检/脚本使用：授权码文件路径与秘密本身。
  // 暴露秘密给同进程代码没有额外风险 —— require 到这个模块的代码本来就能读 SESSION_TOKEN。
  HANDSHAKE_FILE,
  HANDSHAKE_SECRET,
  HANDSHAKE_COOKIE,
  HANDSHAKE_COOKIE_VALUE,
};
