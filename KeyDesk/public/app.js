'use strict';
/**
 * KeyDesk 前端
 *
 * 三条硬规矩：
 *  1. 任何进入 innerHTML 的字符串都必须过 esc()。本页面的数据全部来自
 *     用户自己录入，但"用户自己录的"不等于"可信任的 HTML"——粘贴一段
 *     带 <img onerror> 的恢复码文本同样会执行。
 *  2. token 只存 JS 内存，不进 localStorage / sessionStorage / cookie。
 *     页面刷新即失效，重新握手。
 *  3. 没有内联脚本、没有 onclick 属性、没有内联 style。
 *     CSP 是 script-src 'self'; style-src 'self'。
 */

/* ============ 状态 ============ */

const state = {
  token: null,
  initialized: false,
  locked: true,
  items: [],            // Summary[]
  codes: new Map(),     // id -> {code, period, remaining, expiresAt}
  currentId: null,
  currentEntry: null,   // Detail
  codeTimer: null,      // 5s 轮询
  tickTimer: null,      // 1s 倒计时重绘
  serverNow: 0,         // 服务端时间基准（ms），倒计时靠它校准
  serverNowAt: 0,       // 收到 serverNow 时的本地 performance.now()
  q: '',
  group: '',
  includeArchived: false,
  pollBusy: false,
  // 轮询撞上「已有一发在飞」时的补单标记。
  // 倒计时跨 0 的那一秒正好落在一次未完成的请求里时，这次刷新会被丢掉，
  // 界面就停在「0 秒后刷新」+ 旧码 —— 这是最容易被误用的一刻（用户以为是新码）。
  // 不能静默丢弃，必须在 finally 里补一次。
  pollPending: false,
  lastPollAt: 0,        // 上次发起轮询的本地时刻，给预取做节流
  recoveryView: new Map(),  // setId -> codes[] | 'loading'
  revealTimer: null,    // 显示密钥后的 30 秒自动隐藏倒计时
};

/* ============ DOM ============ */

const $ = id => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toast(msg, type = 'ok') {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast show ' + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3200);
}

/**
 * 屏幕阅读器播报。toast 是视觉反馈，读屏用户看不见；
 * 复制/标记这类"没有页面结构变化"的操作必须走 aria-live 才有人知道成功了。
 * #srStatus 由 A3 建（§2.2），不存在时静默跳过，不能让前端因为缺一个
 * 纯无障碍元素就抛异常。
 */
function announce(msg) {
  const el = $('srStatus');
  if (!el) return;
  // 同一个字符串连播两次时，部分读屏器不会重读；末尾补一个零宽空格破重。
  el.textContent = el.textContent === msg ? msg + '​' : msg;
}

/**
 * 验证码的显示格式：六位码中间加一个空格（`123 456`）。
 * 三家主流验证器（Aegis / Bitwarden / 2FAGuard）都是这么显示的，
 * 因为 6 个连排数字在屏幕上很难一眼分组读出来。
 *
 * 注意：**只有显示层用它**。复制必须用 c.code 原值 —— 剪贴板里带空格
 * 粘到登录框里会直接被判为错误码，这类错误用户很难自己发现。
 */
function fmtCode(code) {
  const s = String(code == null ? '' : code);
  return s.length === 6 ? s.slice(0, 3) + ' ' + s.slice(3) : s;
}

/* ============ API ============ */

async function api(action, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;

  let res;
  try {
    res = await fetch('/api?action=' + encodeURIComponent(action), {
      method: body === undefined ? 'GET' : 'POST',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
    });
  } catch {
    throw new Error('无法连接本地服务，确认 KeyDesk 仍在运行');
  }

  let data;
  try { data = await res.json(); }
  catch { throw new Error('服务器返回了无法解析的内容'); }

  if (res.status === 423) {
    // 任何请求撞上 423 都说明库已经锁了：回到锁屏，别让用户对着
    // 一个"看起来还开着"的界面继续点。
    // 把后端的 error 原样透传下去：服务端已经区分了「空闲超时自动锁」
    // 和「已锁定，请先解锁」，前端再压成同一句话等于把这条信息白扔了。
    onLocked(data && data.error);
    const e = new Error(data.error || '密钥库已锁定');
    e.status = 423;
    throw e;
  }

  if (!res.ok || data.ok === false) {
    const err = new Error(data.error || ('请求失败 HTTP ' + res.status));
    err.status = res.status;
    err.code = data.code || '';
    throw err;
  }
  return data;
}

/* ============ 时间校准 ============ */

/**
 * 服务端返回 now 时记下它，之后的倒计时都用这个基准推。
 * 不直接用本地时钟：两台机器的时间差几十秒时，剩余秒数会算错，
 * 用户看到的倒计时和实际换码时刻对不上。
 */
function syncServerTime(nowValue) {
  // 服务端返回的是毫秒时间戳（数字），不是 ISO 字符串。
  // Date.parse(数字) 返回 NaN，会让这个函数每次都静默 return ——
  // 时间校准从来没生效过，本机时钟偏差时倒计时会算错甚至卡在 0 秒反复轮询。
  // 两种都接受，兼容将来服务端改回 ISO 的情况。
  const t = typeof nowValue === 'number' ? nowValue : Date.parse(nowValue);
  if (!Number.isFinite(t)) return;
  state.serverNow = t;
  state.serverNowAt = performance.now();
}

function serverNowMs() {
  if (!state.serverNowAt) return Date.now();
  return state.serverNow + (performance.now() - state.serverNowAt);
}

/** 距离下一次换码还有多少秒（至少 0） */
function remainingFor(item) {
  const expires = Date.parse(item.expiresAt);
  if (!Number.isFinite(expires)) return item.remaining;
  return Math.max(0, Math.ceil((expires - serverNowMs()) / 1000));
}

/* ============ 锁屏流程 ============ */

function showLockView(which) {
  $('lockscreen').hidden = false;
  $('app').hidden = true;
  $('formSetup').hidden = which !== 'setup';
  $('formUnlock').hidden = which !== 'unlock';
  $('formRecovery').hidden = which !== 'recovery';
  $('setupDone').hidden = which !== 'done';
}

async function refreshLockState() {
  let st;
  try {
    st = await api('vault.status');
  } catch (e) {
    $('lockSub').textContent = '无法读取密钥库状态：' + e.message;
    showLockView('unlock');
    return;
  }
  state.initialized = st.initialized;
  state.locked = st.locked;

  if (!st.initialized) {
    $('lockSub').textContent = '首次使用，请设置一个主口令来创建密钥库。';
    showLockView('setup');
    $('setupPass').focus();
    return;
  }
  if (!st.locked) {
    enterApp();
    return;
  }
  $('lockSub').textContent = '密钥库已锁定。输入主口令解锁。';
  showLockView('unlock');
  $('unlockPass').focus();
}

/**
 * 回到锁屏。
 *
 * reason 是后端 423 响应里的 error 文案，也可能是一个 `'manual'` 标记（按钮主动锁）。
 * 为什么要把原因分开写：
 *  - 「空闲超时」是用户离开了一阵，他不知道发生了什么，必须先告诉他"不是被入侵"；
 *  - 「已锁定」是他自己刚锁的，说同样的话只是噪音；
 *  - 「服务重启」更要在解锁后提示他码可能是旧的。
 * 三种情况压成同一句「密钥库已锁定」时，用户无从判断是不是出事了。
 */
function onLocked(reason) {
  // 保留选中项 id：它只是 entryId（uuid），不含任何密钥材料，
  // 留在内存里零风险，但换来解锁后还停在原来那个条目上 ——
  // 空闲锁定多半发生在"正准备输入验证码"的时候，重新找一遍很烦。
  const keepId = state.currentId;

  // 先 toast 再切屏：锁屏是整屏覆盖，#toast 在锁屏下面。
  // 如果先 showLockView 再 toast，这条提示永远不会被看见。
  const msg = reason === 'manual' ? '已锁定'
    : (reason && String(reason).includes('空闲')) ? '因空闲超时已自动锁定'
    : (reason && String(reason).includes('重启')) ? '服务已重启，需要重新解锁'
    : '密钥库已锁定';

  state.locked = true;
  state.token = null;
  state.items = [];
  state.codes.clear();
  state.currentEntry = null;
  state.recoveryView.clear();
  state.pollPending = false;
  stopTimers();
  clearRevealTimer();

  toast(msg, reason === 'manual' ? 'ok' : 'warn');

  $('app').hidden = true;
  $('lockscreen').hidden = false;
  $('lockSub').textContent = msg + '。请输入主口令。';
  showLockView('unlock');
  state.currentId = keepId;
  // 重新握手：锁屏上的 status 请求也需要 token
  handshake().catch(() => { /* 下次操作会重试 */ });
}

async function handshake() {
  const hs = await api('handshake');
  state.token = hs.token;
}

/**
 * 主动锁定。按钮和 Ctrl+L 都走这里，避免两处逻辑分叉。
 * 请求失败也照样回锁屏：本地唯一记住 token 的地方是 state.token，
 * 锁屏就是把它丢掉。服务端就算没收到 lock，空闲超时也会兜住。
 */
async function lockNow() {
  try {
    await api('vault.lock', {});
  } catch (e) {
    // 423 说明 api() 里已经走过一次 onLocked 并 toast 过了，
    // 这里再调一次会让"已锁定"弹两遍。
    if (e && e.status === 423) return;
    /* 其它错误（服务已退出等）：下面照样回锁屏 */
  }
  onLocked('manual');
}

/* ============ 进入主界面 ============ */

async function enterApp() {
  state.locked = false;
  $('lockscreen').hidden = true;
  $('app').hidden = false;
  await Promise.all([loadList(), loadSettingsInfo()]);
  startTimers();
  // 上次是被空闲超时锁掉的（onLocked 保留了 currentId）：
  // 用户当时正在看某个条目，解锁后直接把他放回去，
  // 而不是让他重新在列表里找一遍。loading 期间列表已经重新拉过了，
  // 这里只需补一次详情请求。
  if (state.currentId && !state.currentEntry &&
      state.items.some(x => x.id === state.currentId)) {
    openEntry(state.currentId);
  }
}

function stopTimers() {
  if (state.codeTimer) { clearInterval(state.codeTimer); state.codeTimer = null; }
  if (state.tickTimer) { clearTimeout(state.tickTimer); state.tickTimer = null; }
}

function startTimers() {
  stopTimers();
  // 5s 轮询新码（页面可见时才轮）
  state.codeTimer = setInterval(pollCodes, 5000);
  // 1s 重绘倒计时（纯本地计算，不发请求）
  const tick = () => {
    renderCountdowns();
    // 用 setTimeout 而不是 setInterval：重绘耗时不会累积成漂移
    state.tickTimer = setTimeout(tick, 1000);
  };
  state.tickTimer = setTimeout(tick, 1000);
}

/* ============ 列表 ============ */

async function loadList() {
  const body = { includeArchived: state.includeArchived };
  if (state.q) body.q = state.q;
  if (state.group) body.group = state.group;

  let data;
  try { data = await api('entries.list', body); }
  catch (e) {
    if (e.status === 423) return;
    toast('加载列表失败：' + e.message, 'err');
    return;
  }
  state.items = data.items || [];
  renderList();
  renderStats();
  await pollCodes();
  if (state.currentId) {
    // 当前详情的条目可能被删了
    if (!state.items.some(x => x.id === state.currentId)) {
      state.currentId = null;
      state.currentEntry = null;
      renderDetail();
    }
  }
}

function renderStats() {
  const total = state.items.length;
  let unused = 0;
  let stale = 0;
  for (const it of state.items) {
    unused += it.recovery.unused;
    if (it.recovery.stale) stale++;
  }
  $('statEntries').textContent = String(total);
  $('statCodes').textContent = String(unused);
  $('statStale').textContent = String(stale);
}

function iconHtml(it) {
  return '<div class="entry-icon" data-icon="' + esc(it.iconColor || '') +
    '">' + esc(it.iconText || '') + '</div>';
}

/**
 * 把 data-icon 上记录的颜色写到 CSSOM。
 * 为什么不用 style="background:..."：CSP 是 style-src 'self'，
 * 内联 style 属性会被浏览器直接拦掉（图标会变成透明）。
 * 通过 element.style 赋值走的是 CSSOM，不受 style-src 限制。
 */
function applyIconColors(root) {
  for (const el of root.querySelectorAll('[data-icon]')) {
    const c = el.getAttribute('data-icon') || '';
    el.style.background = /^#[0-9a-fA-F]{6}$/.test(c) ? c : '#24292f';
  }
}

function renderList() {
  const host = $('entryList');
  // listbox 容器只需要设置一次；放这里是为了不依赖 A3 是否已经加上这些属性。
  host.setAttribute('role', 'listbox');
  host.setAttribute('tabindex', '0');
  // 重建列表会打断键盘焦点和文本选区，所以先记下焦点在哪一行（P0-3）。
  // renderList 仍然保留给"条目增删 / 搜索变化"这类结构真的变了的场景，
  // 每 5 秒的轮询已经改走 updateCodesInPlace，不再进这里。
  const act = document.activeElement;
  // 焦点是否原本就在列表内部（含容器本身）。用在函数末尾判断是否需要兜底收回。
  const hadFocusInList = !!(act && (act === host || host.contains(act)));
  const focusId = (act && act.dataset && act.dataset.id) || null;

  if (!state.items.length) {
    host.innerHTML = '<div class="empty">没有匹配的条目<br><small>换个关键词，或新增一个</small></div>';
    // 搜索把列表清空时焦点不该跟着消失：把它收到容器上，
    // 用户接着按 ↑/↓ 或改搜索词都还能继续，不用再摸鼠标。
    if (hadFocusInList) host.focus({ preventScroll: true });
    return;
  }

  const parts = [];
  for (const it of state.items) {
    const active = it.id === state.currentId ? ' active' : '';
    const arch = it.archived ? ' archived' : '';
    const code = state.codes.get(it.id);
    const hasTotp = it.hasTotp;

    let right;
    if (hasTotp) {
      const rem = code ? remainingFor(code) : (it.period || 30);
      const pct = code ? Math.round((rem / (code.period || 30)) * 100) : 100;
      // P1-1：10s/5s → 7s/3s。7 秒是 Aegis / Bitwarden 的共识值，
      // 10 秒开始变黄时用户还来得及再点一次"复制"，7 秒才真正进入"马上要换了"的紧迫感。
      const cls = rem <= 3 ? 'crit' : (rem <= 7 ? 'low' : '');
      const dim = code ? '' : ' dim';
      const shown = code ? esc(fmtCode(code.code)) : '—';
      right =
        // data-code-id 是 pollCodes 原地更新码文字时的定位锚点（P0-3）。
        // 少了它就只能靠重建 innerHTML 来换码，焦点和选区全丢。
        '<span class="entry-code' + dim + '" data-code-id="' + esc(it.id) + '">' + shown + '</span>' +
        '<span class="mini-count ' + cls + '"><i data-bar="' + esc(it.id) +
          '" data-pct="' + pct + '"></i></span>';
    } else {
      right = '<span class="entry-code dim">' +
        (it.recovery.total ? esc(it.recovery.unused + '/' + it.recovery.total) : '—') +
        '</span>';
    }

    parts.push(
      // role="option" + tabindex="-1"：列表整体是一个 listbox（容器由 renderList 设
      // tabindex=0 和 role=listbox）。如果每行都 tabindex=0，用 Tab 穿过列表要点
      // 几十下才能到详情区；listbox 模式下 Tab 一次进列表，方向键内部移动，
      // 这是 WAI-ARIA 对可选择列表的标准做法（roving tabindex）。
      // -1 而不是省略：行仍然要能被程序 focus()，否则鼠标点一行之后
      // 方向键就接不上了（点击一个不可聚焦的 div 不会移动焦点）。
      '<div class="entry-item' + active + arch + '" role="option"' +
        ' tabindex="-1"' +
        ' aria-selected="' + (active ? 'true' : 'false') + '"' +
        ' data-id="' + esc(it.id) + '">' +
        iconHtml({
          iconColor: (it.icon && it.icon.color) || '#24292f',
          iconText: (it.icon && it.icon.text) || String(it.issuer || '?').slice(0, 2).toUpperCase(),
        }) +
        '<div class="entry-info">' +
          '<div class="entry-issuer">' + (it.pinned ? '<span class="pin-mark">📌 </span>' : '') + esc(it.issuer) + '</div>' +
          '<div class="entry-account">' + esc(it.account || it.group || it.type) + '</div>' +
        '</div>' +
        '<div class="entry-right">' + right + '</div>' +
      '</div>'
    );
  }
  host.innerHTML = parts.join('');
  applyIconColors(host);
  // 进度条宽度也走 CSSOM：从 data-pct 读初始值
  for (const el of host.querySelectorAll('[data-bar]')) {
    const pct = Number(el.getAttribute('data-pct'));
    if (Number.isFinite(pct)) el.style.width = Math.max(0, Math.min(100, pct)) + '%';
  }

  // 重建之后把焦点放回原来那一行（P0-3）。
  // 只在这一行还存在时才还原 —— 搜索把当前行过滤掉了就什么都不做，
  // 否则会把焦点硬塞到一个用户根本没在看的行上。
  if (focusId) {
    const again = host.querySelector('[data-id="' + cssEscape(focusId) + '"]');
    if (again) again.focus({ preventScroll: true });
  }
  // 焦点原本在列表里、但那一行已经没了（被搜索过滤掉）时，
  // 焦点会掉到 <body>，方向键从此失效 —— 用户会以为列表坏了。
  // 把焦点收回到容器上，方向键仍然可用。
  if (hadFocusInList && (!document.activeElement || document.activeElement === document.body)) {
    host.focus({ preventScroll: true });
  }
}

function renderCountdowns() {
  // 只改宽度和秒数，不重建 DOM —— 重建会让 hover / 焦点丢失
  // 预取只发一次：列表里每个有码的条目都会算到 rem <= 1，
  // 若在循环里直接发，20 个条目就是 20 次请求（虽然会被 pollBusy 挡下，
  // 但会连锁置一堆 pollPending）。用标记 + 循环外统一触发。
  let needPrefetch = false;
  for (const it of state.items) {
    if (!it.hasTotp) continue;
    const code = state.codes.get(it.id);
    if (!code) continue;
    const rem = remainingFor(code);
    const pct = Math.max(0, Math.min(100, Math.round((rem / (code.period || 30)) * 100)));
    const bar = document.querySelector('[data-bar="' + cssEscape(it.id) + '"]');
    if (bar) {
      bar.style.width = pct + '%';
      const box = bar.parentElement;
      if (box) {
        // P1-1：与列表初次渲染保持同一阈值（3 / 7），否则重建时和每秒重绘时
        // 颜色会在 5 秒和 7 秒之间来回跳一次。
        box.classList.toggle('low', rem <= 7 && rem > 3);
        box.classList.toggle('crit', rem <= 3);
      }
    }
    // P1-4：提前 1 秒预取，而不是等到 rem <= 0。
    // 到 0 才请求意味着"新码已经生效、旧码已经作废"的那一瞬间界面上还是旧码，
    // 用户正好在这一秒抄下去就是错码。提前 1 秒发出去，等响应回来时新码刚好生效。
    if (rem <= 1) needPrefetch = true;
  }
  // 800ms 节流：rem 由 ceil 算出，会在 1 和 0 之间来回跳，
  // 不加节流会在同一秒内连发好几次请求；而且刚预取完、
  // 新码已经到手时不该再发一次（lastPollAt 就是干这个的）。
  if (needPrefetch && Date.now() - state.lastPollAt > 800) pollCodes();
  renderDetailCountdown();
}

function cssEscape(s) {
  return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
}

/* ============ 验证码轮询 ============ */

async function pollCodes() {
  if (state.locked) return;
  if (document.visibilityState !== 'visible') return;   // 后台不轮询
  if (state.pollBusy) {
    // P1-4：不能静默丢弃。倒计时跨 0 的那一秒如果正好撞上一次未完成的请求，
    // 这一发被 return 掉之后就没有任何人在刷新了 —— 界面停在「0 秒后刷新」+ 旧码，
    // 而这一刻恰好是用户最可能抄下错码的时候。记一个补单标记，finally 里再发。
    state.pollPending = true;
    return;
  }
  state.pollBusy = true;
  state.lastPollAt = Date.now();
  try {
    const data = await api('otp.codes', {});
    syncServerTime(data.now);
    state.codes.clear();
    for (const c of data.items || []) state.codes.set(c.id, c);
    // P0-3：这里原来调 renderList()，等于每 5 秒把整个列表的 innerHTML 重写一遍。
    // 后果是键盘焦点（正在用方向键浏览的人）、文本选区（正在复制账号的人）、
    // :hover 状态和滚动位置每 5 秒被打回原处 —— 一个"每 5 秒抖一下"的界面。
    // 码变了只需要改那两处文字，DOM 结构一个字都没变，没有任何理由重建。
    updateCodesInPlace();
    renderDetailCodes();
  } catch (e) {
    if (e.status !== 423) {
      // 轮询失败不弹 toast：每 5 秒一条会把界面刷爆
      console.warn('[otp.codes]', e.message);
    }
  } finally {
    state.pollBusy = false;
    if (state.pollPending) {
      state.pollPending = false;
      // 用 setTimeout(0) 而不是直接递归：递归会在同一个微任务链里层层加深，
      // 而且失败时（例如网络断了）会变成紧密重试。让出一个宏任务，
      // 打回事件循环，失败自然会被 5 秒定时器兜住。
      setTimeout(pollCodes, 0);
    }
  }
}

/**
 * 只把新的码文字写回已有节点，不动 DOM 结构。
 * 列表行和详情大码都走这里，这样轮询就完全不碰 innerHTML。
 */
function updateCodesInPlace() {
  for (const it of state.items) {
    if (!it.hasTotp) continue;
    const c = state.codes.get(it.id);
    if (!c) continue;
    const el = document.querySelector('[data-code-id="' + cssEscape(it.id) + '"]');
    // 显示用 fmtCode（带空格分组），但状态里存的仍是原值，复制走原值。
    if (!el) continue;
    el.textContent = fmtCode(c.code);
    // 首次渲染时若还没有码，这一格是「—」+ .dim（灰掉）。
    // 现在码到了，必须把 .dim 摘掉，否则真实码会一直是灰的 ——
    // 以前靠重建 innerHTML 顺手"修好"，改成就地更新后这一步得自己补。
    el.classList.remove('dim');
  }
}

// 标签页重新可见时立刻补一次，避免切回来看到过期码
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && !state.locked) pollCodes();
});

/* ============ 详情 ============ */

async function openEntry(id) {
  state.currentId = id;
  // 换条目时旧条目可能还挂着一个"显示密钥"的自动隐藏倒计时，
  // 它会在新条目的面板上触发 hide()，把刚渲染出来的界面抹成"已隐藏"。
  clearRevealTimer();
  renderList();
  try {
    const data = await api('entries.get', { id });
    state.currentEntry = data.entry;
    state.recoveryView.clear();
  } catch (e) {
    if (e.status !== 423) toast('打开失败：' + e.message, 'err');
    return;
  }
  renderDetail();
}

function renderDetail() {
  const host = $('detail');
  const e = state.currentEntry;

  // 每次整块重绘详情都会把 #secretBody / #passBody 换成空壳，
  // 旧的自动隐藏倒计时此时只会去 hide() 一个已经不在屏幕上的节点，
  // 但更重要的是：它还占着 state.revealTimer，会让下一次显示密钥
  // 的 clearRevealTimer() 清掉"别人的"定时器。统一在这里作废。
  clearRevealTimer();

  if (!e) {
    $('currentTitle').textContent = '选择一个条目';
    $('currentBadge').textContent = '';
    host.innerHTML = '<div class="placeholder">选择左侧条目查看详情</div>';
    return;
  }

  $('currentTitle').textContent = e.issuer + (e.account ? ' · ' + e.account : '');
  $('currentBadge').textContent = e.archived ? '已归档' : '';
  $('currentBadge').className = 'badge' + (e.archived ? ' warn' : '');

  const parts = [];

  // ---- TOTP 面板 ----
  if (e.hasTotp) {
    const code = state.codes.get(e.id);
    // clamp 到 period：服务端时钟比本地基准慢哪怕 0.5ms，ceil 会算出 31。
    // 进度条已 clamp，但"31 秒后刷新"这个文本没有，会短暂显示出错误的秒数。
    const rawRem = code ? remainingFor(code) : (e.totp ? e.totp.period : 30);
    const rem = Math.min(e.totp ? e.totp.period : 30, Math.max(0, rawRem));
    // clamp 到 100：剩余秒数可能因为 ceil 取整算出 31（服务端时钟比本地慢 1ms 时），
    // 不 clamp 会让进度条宽度变成 103% 溢出容器。
    const pct = code ? Math.min(100, Math.max(0, Math.round((rem / (code.period || 30)) * 100))) : 100;
    // 倒计时条的 transition 时长要由周期决定（P1-5）。
    // CSS 侧只声明 transition-property: width / timing-function: linear，
    // 时长交给 JS 注入 —— 周期可以是 10..120 秒，写死 .9s 时 120 秒周期下
    // 宽度每秒只变 0.83%，视觉上像卡住不动；而 10 秒周期下 .9s 又会让
    // 条子跑得比秒数快。按「每步走 1/30 格、0.9 秒走完」折算即 period/30*0.9。
    const period = (e.totp ? e.totp.period : 30) || 30;
    const ringDur = (period / 30 * 0.9).toFixed(2) + 's';
    parts.push(
      '<div class="code-panel">' +
        // data-code-id 让 pollCodes 能原地改这个节点（P0-3 的锚点之一）。
        // role/aria-label 在 renderDetailCountdown 里每秒更新为「验证码 123 456，点击复制」。
        '<div class="code-display" id="bigCode" role="button" tabindex="0"' +
          ' data-code-id="' + esc(e.id) + '"' +
          ' aria-label="验证码，点击复制" title="点击复制">' +
          // P1-2：显示分组 123 456，但 state.codes 里存的仍是原值，复制走原值。
          (code ? esc(fmtCode(code.code)) : '······') +
        '</div>' +
        '<div class="code-meta-col">' +
          '<div class="code-hint">' + esc(e.totp ? e.totp.algorithm : '') + ' · ' +
            (e.totp ? e.totp.digits : 6) + ' 位 · ' + period + ' 秒</div>' +
          '<div class="code-ring" id="codeRing"><i id="ringBar" data-ring="' + esc(e.id) +
            '" data-dur="' + esc(ringDur) + '"></i></div>' +
          '<div class="code-secs" id="codeSecs">' + rem + ' 秒后刷新</div>' +
        '</div>' +
      '</div>'
    );
  }

  // ---- 基本信息 ----
  const kv = [];
  kv.push(['类型', typeLabel(e.type)]);
  kv.push(['名称', e.issuer]);
  if (e.account) kv.push(['账号', e.account]);
  if (e.group) kv.push(['分组', e.group]);
  if (e.url) kv.push(['网址', e.url]);
  if (e.tags && e.tags.length) kv.push(['标签', e.tags.join(', ')]);
  if (e.lastUsedAt) kv.push(['上次验证', fmtTime(e.lastUsedAt)]);
  kv.push(['创建', fmtTime(e.createdAt)]);
  kv.push(['更新', fmtTime(e.updatedAt)]);

  parts.push(
    '<div class="section">' +
      '<div class="section-head"><h3>基本信息</h3>' +
        '<div class="head-actions">' +
          '<button class="btn btn-sm" id="btnEdit">编辑</button>' +
          '<button class="btn btn-sm" id="btnArchive">' + (e.archived ? '取消归档' : '归档') + '</button>' +
          '<button class="btn btn-sm btn-danger" id="btnDelete">删除</button>' +
        '</div>' +
      '</div>' +
      '<div class="section-body">' +
        '<dl class="field-grid">' +
          kv.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') +
        '</dl>' +
        (e.note ? '<div class="mt-12"><div class="note-label">备注</div>' +
          '<div class="note-text">' + esc(e.note) + '</div></div>' : '') +
      '</div>' +
    '</div>'
  );

  // ---- TOTP 操作 ----
  if (e.hasTotp) {
    parts.push(
      '<div class="section">' +
        '<div class="section-head"><h3>TOTP 密钥</h3>' +
          '<div class="head-actions">' +
            '<button class="btn btn-sm" id="btnShowQr">二维码</button>' +
            '<button class="btn btn-sm" id="btnRevealSecret">显示密钥</button>' +
          '</div>' +        '</div>' +
        '<div class="section-body" id="secretBody">' +
          '<span class="set-sub">密钥默认隐藏。显示后请勿截图外传。</span>' +
        '</div>' +
      '</div>'
    );
  }

  // ---- 恢复码 ----
  if (e.recovery && e.recovery.sets && e.recovery.sets.length) {
    const setBlocks = e.recovery.sets.map(s => {
      const cur = s.supersededAt === null;
      const view = state.recoveryView.get(s.id);
      let body;
      if (view === 'loading') {
        body = '<div class="codes-hidden">加载中…</div>';
      } else if (Array.isArray(view)) {
        body = '<div class="code-grid">' + view.map(c => {
          const used = c.usedAt !== null;
          // 一个 chip 里放两个命中区（标记 / 复制），所以外层不能用 <button>：
          // HTML 不允许 <button> 嵌套 <button>，浏览器会把内层标签拆到外面，
          // 结果是标记按钮跑到 chip 之外、点击区域全乱。
          // 改成 div 容器 + 两个真 button，键盘 Tab 能分别停在两个动作上，
          // 读屏器也能分别读出「标记为已用」和「复制」。
          // 容器给 role="group" 而不是 role="button"：如果给 button，
          // 里面的两个 button 就成了按钮里的按钮，读屏器会先播报一个
          // 没有实际动作的"按钮"，反而更糊涂。
          const usedLabel = used ? fmtDate(c.usedAt) : '';
          // 标记按钮的可见内容只有一个 ○ / ✓，读屏器读出来就是"圆圈"/"对勾"，
          // 完全说明不了它是干什么的 —— 必须给 aria-label 把动作说全。
          const markLabel = s.trackUsage
            ? (used ? '标记为未使用' : '标记为已使用')
            : '此组不追踪使用状态';
          return '<div class="code-chip' + (used ? ' used' : '') + '" role="group"' +
            ' data-code="' + esc(c.id) + '"' +
            ' data-set="' + esc(s.id) + '"' +
            ' data-used="' + (used ? '1' : '0') + '"' +
            // P0-1 的核心：把明文放到 data-value 上，复制区才有东西可复制。
            // 之前 chip 上只有 codeId，前端手里根本没有码本身，
            // 所以"复制"这个核心动作根本无从实现。
            ' data-value="' + esc(c.value) + '">' +
            '<button type="button" class="chip-mark"' +
              // P0-2：disabled 只加在标记区。之前整个 chip 被 disabled，
              // trackUsage:false 的组既不能标记也不能复制，是纯死 UI ——
              // 而"打开这个页面把码抄下来"恰恰是这类组唯一的用法。
              (s.trackUsage ? '' : ' disabled') +
              ' aria-pressed="' + (used ? 'true' : 'false') + '"' +
              ' aria-label="' + esc(markLabel) + '"' +
              ' title="' + esc(markLabel) + '">' +
              (used ? '✓' : '○') +
            '</button>' +
            '<button type="button" class="chip-copy"' +
              ' title="点击复制恢复码' + (used ? '（已于 ' + esc(usedLabel) + ' 标记使用）' : '') + '">' +
              esc(c.value) +
            '</button>' +
            // P0-4：store.js 一直返回 usedAt，前端只用了 `!== null`，
            // 用户看不出这个码是哪天用掉的 —— 想判断"这批码是不是该换了"
            // 必须知道时间。只用 title 不够（触屏没有 hover），必须落到文字。
            // 放在 .chip-copy 之外而不是里面（A1 的 CSS 把它当 chip 的 flex 子项，
            // 且 .used 会整块加删除线）：塞进复制按钮里会被划掉，
            // 读屏器也会把日期和码连着念成一串。
            (used ? '<span class="chip-used-at">已用 · ' + esc(usedLabel) + '</span>' : '') +
          '</div>';
        }).join('') + '</div>';
      } else {
        body = '<div class="codes-hidden">' +
          '<button class="btn btn-sm" data-reveal-set="' + esc(s.id) + '">查看 ' +
          s.codeCount + ' 个恢复码</button>' +
          '<div class="set-sub mt-6">' +
          (s.unusedCount) + ' 个未使用</div></div>';
      }

      return '<div class="set-block' + (cur ? ' current' : '') + '">' +
        '<div class="set-head">' +
          '<div>' +
            '<div class="set-title">' + (cur ? '当前代' : '历史代') +
              (s.label ? ' · ' + esc(s.label) : '') + '</div>' +
            '<div class="set-sub">' + fmtDate(s.createdAt) +
              ' · ' + s.codeCount + ' 个 · 剩 ' + s.unusedCount +
              (s.supersededAt ? ' · 已被 ' + fmtDate(s.supersededAt) + ' 的替代' : '') + '</div>' +
          '</div>' +
          '<div class="set-actions">' +
            (cur ? '' : '<button class="btn btn-sm" data-make-current="' + esc(s.id) + '">设为当前</button>') +
            '<button class="btn btn-sm" data-edit-set="' + esc(s.id) + '">编辑</button>' +
            '<button class="btn btn-sm btn-danger" data-del-set="' + esc(s.id) + '">删除</button>' +
          '</div>' +
        '</div>' +
        body +
      '</div>';
    }).join('');

    parts.push(
      '<div class="section">' +
        '<div class="section-head"><h3>恢复码</h3>' +
          '<div class="head-actions">' +
            // 打印视图（§2.4 的 print.recovery）。
            // 恢复码最实际的使用场景是"打印出来锁进抽屉"：断网、手机丢了、
            // 电脑坏了的时候，屏幕上的码一个都用不上。这个按钮是唯一能把码
            // 落到纸上的路径，所以放在最显眼的 head-actions 第一位。
            '<button class="btn btn-sm" id="btnPrintRecovery">打印</button>' +
            '<button class="btn btn-sm btn-primary" id="btnAddSet">＋ 加一组</button>' +
          '</div>' +
        '</div>' +
        '<div class="section-body">' + setBlocks + '</div>' +
      '</div>'
    );
  } else if (e.type !== 'note') {
    parts.push(
      '<div class="section">' +
        '<div class="section-head"><h3>恢复码</h3>' +
          '<div class="head-actions"><button class="btn btn-sm btn-primary" id="btnAddSet">＋ 加一组</button></div>' +
        '</div>' +
        '<div class="section-body"><div class="codes-hidden">还没有记录恢复码</div></div>' +
      '</div>'
    );
  }

  // ---- 密码 ----
  if (e.passwordSet) {
    parts.push(
      '<div class="section">' +
        '<div class="section-head"><h3>密码</h3>' +
          '<div class="head-actions"><button class="btn btn-sm" id="btnRevealPass">显示密码</button></div>' +
        '</div>' +
        '<div class="section-body" id="passBody">' +
          '<span class="set-sub">已保存一个密码。显示后请勿截图外传。</span>' +
        '</div>' +
      '</div>'
    );
  }

  host.innerHTML = parts.join('');
  bindDetailEvents();
  renderDetailCodes();
}

function renderDetailCodes() {
  const e = state.currentEntry;
  if (!e || !e.hasTotp) return;
  const code = state.codes.get(e.id);
  const big = $('bigCode');
  // 「已复制」的 1.5 秒内不要覆盖：轮询/预取正好在这个窗口里到了新码的话，
  // 会把刚出现的原地反馈瞬间抹掉，用户看到的还是数字，以为没复制上。
  if (big && code && !big.classList.contains('copied-inline')) big.textContent = fmtCode(code.code);
  renderDetailCountdown();
}

function renderDetailCountdown() {
  const e = state.currentEntry;
  if (!e || !e.hasTotp) return;
  const code = state.codes.get(e.id);
  if (!code) return;
  const rem = remainingFor(code);
  const period = code.period || 30;
  const pct = Math.max(0, Math.min(100, Math.round((rem / period) * 100)));

  const bar = document.querySelector('[data-ring]');
  if (bar) {
    // P1-5：transition 时长按 period 折算，只在和上次不同的时候写，
    // 避免每秒给 CSSOM 赋同一个值（部分浏览器会因此重启过渡）。
    const dur = bar.getAttribute('data-dur') || '';
    if (dur && bar.style.transitionDuration !== dur) bar.style.transitionDuration = dur;
    bar.style.width = pct + '%';
  }
  const ring = $('codeRing');
  if (ring) {
    // P1-1：7s / 3s（与列表一致）
    ring.classList.toggle('low', rem <= 7 && rem > 3);
    ring.classList.toggle('crit', rem <= 3);
  }
  const secs = $('codeSecs');
  if (secs) secs.textContent = rem + ' 秒后刷新';
  // 主码的 aria-label 也要跟着换：它是 role="button"，读屏用户听到的
  // 只有 label，不会去读里面的数字。
  const big = $('bigCode');
  if (big) big.setAttribute('aria-label', '验证码 ' + fmtCode(code.code) + '，点击复制');
}

function bindDetailEvents() {
  const e = state.currentEntry;

  const big = $('bigCode');
  if (big) {
    big.addEventListener('click', () => copyCode(e.id));
    big.addEventListener('keydown', ev => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); copyCode(e.id); }
    });
  }

  const bEdit = $('btnEdit');
  if (bEdit) bEdit.addEventListener('click', () => openEntryModal(e));

  const bArch = $('btnArchive');
  if (bArch) bArch.addEventListener('click', () => toggleArchive(e));

  const bDel = $('btnDelete');
  if (bDel) bDel.addEventListener('click', () => deleteEntry(e));

  const bQr = $('btnShowQr');
  if (bQr) bQr.addEventListener('click', () => showQr(e));

  const bSecret = $('btnRevealSecret');
  if (bSecret) bSecret.addEventListener('click', () => revealSecret(e, 'totp'));

  const bPass = $('btnRevealPass');
  if (bPass) bPass.addEventListener('click', () => revealSecret(e, 'password'));

  const bAddSet = $('btnAddSet');
  if (bAddSet) bAddSet.addEventListener('click', () => addRecoverySet(e));

  const bPrint = $('btnPrintRecovery');
  if (bPrint) bPrint.addEventListener('click', () => printRecovery(e));
}

/**
 * 恢复码格子的点击用「一次绑定、长驻」的委托，绑在 #detail 上。
 * 之前写在 bindDetailEvents 里每次渲染都 addEventListener，
 * 结果监听器越堆越多，标一个码会触发 N 次请求。
 */
function bindDetailDelegation() {
  $('detail').addEventListener('click', async ev => {
    const e = state.currentEntry;
    if (!e) return;
    const chip = ev.target.closest('[data-code]');
    if (chip) {
      // 一个 chip 两个动作，按命中的子区区分：
      //   .chip-mark → 标记已用（会写库）
      //   其余主体   → 复制（只读，最常用，所以占更大面积）
      // 之前的实现整块只做标记，导致"恢复码管理工具"最核心的动作——
      // 把码复制出来去用——在界面上根本不存在。
      if (ev.target.closest('.chip-mark')) {
        // trackUsage:false 的组没有标记能力；button 的 disabled 属性
        // 本身会吞掉点击，这里再判一次是为了防止将来把 disabled 换成
        // aria-disabled 时行为悄悄变掉。
        if (chip.querySelector('.chip-mark') &&
            chip.querySelector('.chip-mark').disabled) return;
        await toggleCodeUsed(e, chip.getAttribute('data-set'), chip.getAttribute('data-code'),
          chip.getAttribute('data-used') === '1');
      } else {
        // 恢复码明文在 data-value 上（P0-1 时补的），不是 textContent ——
        // textContent 里混着「✓」和「已用 · 2026/11/09」这些小字，
        // 拿它去复制会粘出一串垃圾。
        const val = chip.getAttribute('data-value') || '';
        // 空值直接判失败，不要拿空字符串去覆盖用户的剪贴板：
        // 那种"复制成功了但粘出来是空的"比明确报错更难排查。
        if (!val) { toast('这个码没有可取的值，请重新展开恢复码', 'err'); return; }
        const ok = await copyText(val);
        if (!ok) {
          toast('复制失败，请手动选中', 'err');
        } else {
          chip.classList.add('copied');
          setTimeout(() => chip.classList.remove('copied'), 1500);
          announce(e.issuer ? '已复制 ' + e.issuer + ' 的恢复码' : '已复制恢复码');
          toast('已复制恢复码');
        }
      }
      return;
    }
    const revealBtn = ev.target.closest('[data-reveal-set]');
    if (revealBtn) {
      await revealSet(e, revealBtn.getAttribute('data-reveal-set'));
      return;
    }
    const mk = ev.target.closest('[data-make-current]');
    if (mk) {
      await makeCurrentSet(e, mk.getAttribute('data-make-current'));
      return;
    }
    const del = ev.target.closest('[data-del-set]');
    if (del) {
      await deleteSet(e, del.getAttribute('data-del-set'));
      return;
    }
    const ed = ev.target.closest('[data-edit-set]');
    if (ed) {
      await editSet(e, ed.getAttribute('data-edit-set'));
    }
  });
}

function typeLabel(t) {
  if (t === 'totp') return 'TOTP';
  if (t === 'recovery-only') return '仅恢复码';
  if (t === 'note') return '备注';
  return t;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '/' + pad(d.getMonth() + 1) + '/' + pad(d.getDate());
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return fmtDate(iso) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

/* ============ 打印恢复码 ============ */

/**
 * 把后端生成的打印片段塞进 #printRoot 再调 window.print()。
 *
 * 为什么片段由后端生成而不是前端拼：恢复码是明文秘密，前端拼 HTML
 * 意味着要在 JS 里再走一遍整组码；后端已经有一份（它就是这些码的 owner），
 * 让它在一次请求里直接产出可打印片段，前端只负责放进容器和触发打印。
 *
 * 片段是后端用 escapeHtml() 过的（§3 A5），所以这里可以 innerHTML。
 * 但仍然做一次兜底检查：万一将来后端改坏了、或者 printRecovery 被换掉，
 * 不至于把脚本注进页面 —— 这段代码跑在已解锁的最高权限上下文里。
 */
async function printRecovery(e) {
  if (!e) return;
  let data;
  try {
    data = await api('print.recovery', { entryId: e.id });
  } catch (err) {
    if (err.status !== 423) toast('无法生成打印视图：' + err.message, 'err');
    return;
  }

  const html = String(data.html || '');
  // 打印片段只允许是文本/表格/分区，不该出现 script、事件属性或 javascript: URL。
  if (/<script|on\w+\s*=|javascript:/i.test(html)) {
    toast('打印内容中含有可疑标签，已拒绝', 'err');
    return;
  }

  const root = $('printRoot');
  if (!root) {
    // #printRoot 由 A3 提供（§3 A3-7）。还没加时退回到"打开新窗口打印"：
    // 不能因为缺一个容器就让"把码打印到纸上"这条唯一的离线路径消失。
    const w = window.open('', '_blank');
    if (!w || !w.document) { toast('浏览器拦截了新窗口，请允许弹窗', 'err'); return; }
    w.document.write('<!doctype html><meta charset="utf-8"><title>恢复码</title>' +
      '<style>@page{margin:20mm}body{font:14pt/1.8 system-ui}</style>' + html);
    w.document.close();
    w.focus();
    w.print();
    return;
  }

  root.innerHTML = html;
  // 打印前必须确保容器在打印媒体下可见、屏幕上不可见 —— 这由 A1 的
  // .print-only / @media print 负责（§3 A1），这里只负责内容。
  // 用 requestAnimationFrame 等一帧再 print：innerHTML 之后立刻 print，
  // 部分浏览器会用打印前的旧布局，出现空白页。
  requestAnimationFrame(() => {
    try { window.print(); }
    catch { toast('无法调起打印对话框', 'err'); }
    // 打印对话框关掉后清空，#printRoot 里不该留着明文码过夜。
    setTimeout(() => { root.innerHTML = ''; }, 300);
  });
}

/* ============ 复制 ============ */

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // 非安全上下文或权限被拒时的兜底
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'visually-hidden';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch { return false; }
  }
}

async function copyCode(id) {
  const c = state.codes.get(id);
  if (!c) { toast('验证码还没加载出来', 'warn'); return; }
  // P1-2：复制必须用未分组的原值。state.codes 里存的就是服务端给的原值，
  // 只有显示层经过 fmtCode —— 这里一旦用 fmtCode 包一下，
  // 用户粘进登录框的就是「123 456」，会被判为错误码，且极难自己发现。
  const ok = await copyText(c.code);
  if (!ok) { toast('复制失败，请手动选中', 'err'); return; }

  // P1-3：反馈要原地做。#bigCode 就在用户眼睛盯着的地方，
  // 而 toast 在屏幕底部 —— 复制验证码时视线在码上，底部那条提示经常被完全忽略，
  // 用户会连点两三次、或者以为没复制成功而手抄。
  const big = $('bigCode');
  if (big) {
    big.textContent = '已复制';
    big.classList.add('copied-inline');
    clearTimeout(big._copyT);
    // 还原时按「当前最新的码」重算，而不是把旧文字串塞回去：
    // 1.5 秒内很可能正好跨过一次换码（轮询或预取），塞回旧串等于
    // 把已经过期的码显示在最显眼的位置 —— 那正是最危险的一刻。
    big._copyT = setTimeout(() => {
      const now = state.codes.get(id);
      big.textContent = now ? fmtCode(now.code) : '';
      big.classList.remove('copied-inline');
    }, 1500);
  }

  // toast 里带上账号：3-4 个 GitHub 号并存时，「已复制 123456」根本没说清是哪一个。
  // 这正是复制错账号验证码的常见成因（凭据本身是对的，只是对错了账号）。
  const e = state.currentEntry;
  const who = e ? (e.issuer || '') + (e.account ? ' · ' + e.account : '') : '';
  toast(who ? '已复制 ' + who + ' 的验证码' : '已复制验证码');
  announce(who ? '已复制 ' + who + ' 的验证码' : '已复制验证码');
}

/* ============ 条目操作 ============ */

async function toggleArchive(e) {
  try {
    await api('entries.archive', { ids: [e.id], archived: !e.archived });
    toast(e.archived ? '已取消归档' : '已归档');
    await loadList();
    if (state.currentId) await openEntry(state.currentId);
  } catch (err) {
    if (err.status !== 423) toast('操作失败：' + err.message, 'err');
  }
}

async function deleteEntry(e) {
  const ok = await confirmDialog('删除条目',
    '确定删除「' + e.issuer + (e.account ? ' · ' + e.account : '') + '」？\n\n' +
    'TOTP 密钥和恢复码会一起删除，无法恢复。', true);
  if (!ok) return;
  try {
    await api('entries.remove', { ids: [e.id] });
    toast('已删除');
    state.currentId = null;
    state.currentEntry = null;
    renderDetail();
    await loadList();
  } catch (err) {
    if (err.status !== 423) toast('删除失败：' + err.message, 'err');
  }
}

async function revealSecret(e, field) {
  const what = field === 'totp' ? 'TOTP 密钥' : '密码';
  const ok = await confirmDialog('显示' + what,
    '即将显示「' + e.issuer + '」的' + what + '。\n\n' +
    (field === 'totp'
      ? 'TOTP 密钥不可轮换：任何人拿到它都能永久生成你的验证码。'
      : '密码会以明文显示在屏幕上。'), false);
  if (!ok) return;

  let data;
  try {
    data = await api('secrets.reveal', { id: e.id, field, confirm: true });
  } catch (err) {
    if (err.status !== 423) toast('无法显示：' + err.message, 'err');
    return;
  }

  const host = field === 'totp' ? $('secretBody') : $('passBody');
  if (!host) return;

  const hide = () => {
    clearRevealTimer();
    host.innerHTML = '<span class="set-sub">已隐藏。再次点击上方按钮可重新显示。</span>';
  };

  // P2：显示后自动隐藏（对齐 Aegis 的 getTapToRevealTime() = 30 秒）。
  // 之前的实现显示后永不隐藏，明文密钥就一直挂在屏幕上：用户点完去做别的事，
  // 或者开着页面走开，密钥就对着整个房间 / 整场录屏敞着了。
  // 这是纯前端约束，不能指望用户自己记得点「隐藏」。
  host.innerHTML = '<code class="code-mono">' + esc(data.value) + '</code>' +
    '<div class="set-sub mt-6" data-reveal-left></div>' +
    '<div class="btn-row mt-12">' +
    '<button class="btn btn-sm" data-copy-secret="1">复制</button>' +
    '<button class="btn btn-sm" data-hide-secret="1">隐藏</button>' +
    '</div>';

  const copyBtn = host.querySelector('[data-copy-secret]');
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      const okc = await copyText(data.value);
      toast(okc ? '已复制' : '复制失败', okc ? 'ok' : 'err');
      if (okc) announce('已复制' + what);
      // 复制完立刻收起明文：这一串已经进剪贴板了，
      // 继续挂在屏幕上只剩被拍照 / 录屏的风险。
      hide();
    });
  }
  const hideBtn = host.querySelector('[data-hide-secret]');
  if (hideBtn) hideBtn.addEventListener('click', hide);

  // 倒计时只改那一个小节点，绝不重建整块 —— 每秒重写 innerHTML 会把
  // 用户正按在「复制」按钮上的焦点打掉，30 秒里能打断 30 次。
  const leftEl = host.querySelector('[data-reveal-left]');
  let left = 30;
  const tickReveal = () => {
    left -= 1;
    if (left <= 0) { hide(); return; }
    // 最后 5 秒才显示剩余秒数：一上来就读秒很吵，但只剩几秒时
    // 用户需要知道"快没了"，否则正在手抄的时候明文会突然消失。
    if (leftEl) leftEl.textContent = left <= 5 ? left + ' 秒后自动隐藏' : '';
    state.revealTimer = setTimeout(tickReveal, 1000);
  };
  if (leftEl) leftEl.textContent = '';
  state.revealTimer = setTimeout(tickReveal, 1000);
}

/** 清掉「显示密钥」的自动隐藏倒计时。切条目 / 锁定 / 重新显示时必须调，
 *  否则旧定时器会在新内容上触发一次 hide()，把刚显示出来的东西抹掉。 */
function clearRevealTimer() {
  if (state.revealTimer) {
    clearTimeout(state.revealTimer);
    state.revealTimer = null;
  }
}

async function showQr(e) {
  let secret;
  try {
    const r = await api('secrets.reveal', { id: e.id, field: 'totp', confirm: true });
    secret = r.value;
  } catch (err) {
    if (err.status !== 423) toast('无法读取密钥：' + err.message, 'err');
    return;
  }

  // 前端拼 otpauth URI 太容易和服务端算法不一致，直接让后端生成
  const algo = e.totp ? e.totp.algorithm : 'SHA1';
  const digits = e.totp ? e.totp.digits : 6;
  const period = e.totp ? e.totp.period : 30;
  const label = e.issuer ? encodeURIComponent(e.issuer) + ':' + encodeURIComponent(e.account || '')
    : encodeURIComponent(e.account || '');
  let uri = 'otpauth://totp/' + label + '?secret=' + encodeURIComponent(secret);
  if (e.issuer) uri += '&issuer=' + encodeURIComponent(e.issuer);
  if (algo !== 'SHA1') uri += '&algorithm=' + algo;
  if (digits !== 6) uri += '&digits=' + digits;
  if (period !== 30) uri += '&period=' + period;

  try {
    const r = await api('qr.svg', { text: uri });
    // 服务端返回的是它自己生成的 SVG 字符串（只有 rect/svg 元素，没有脚本）。
    // 这里用 innerHTML 是必要的，但先挡掉任何 <script / on* 属性：
    // 即便服务端将来被改坏，也不至于把一段脚本注进页面。
    if (/<script|on\w+\s*=|javascript:/i.test(r.svg)) {
      throw new Error('返回的 SVG 中含有可疑内容，已拒绝渲染');
    }
    $('qrHost').innerHTML = r.svg;
    $('qrHost').classList.remove('qr-fallback');
    $('qrFallback').hidden = true;
    $('qrUri').textContent = uri;
    openModal('modalQr');
  } catch (err) {
    if (err.status === 423) return;   // 锁定态由全局处理，不弹提示

    // 二维码生成失败（最常见原因是 otpauth URI 超过 210 字节的容量上限，
    // 而这在合法字段长度下是可能发生的：64 字符中文 issuer + 长 account）。
    // 不能只弹个 toast 就完事——那样用户完全没法把这条导入手机。
    // 兜底：打开弹窗，直接给可复制的 otpauth URI，用户可以用别的工具
    // （手机上的验证器 App 通常支持粘贴 URI）完成迁移。
    $('qrHost').innerHTML = '';
    $('qrHost').classList.add('qr-fallback');
    $('qrFallback').hidden = false;
    $('qrUri').textContent = uri;
    openModal('modalQr');
    toast('条目信息过长，无法生成二维码；已改为提供文本密钥，可复制后手动导入', 'warn');
  }
}

/* ============ 恢复码操作 ============ */

async function revealSet(e, setId) {
  state.recoveryView.set(setId, 'loading');
  renderDetail();
  try {
    const data = await api('recovery.reveal', { entryId: e.id, setId, confirm: true });
    state.recoveryView.set(setId, data.codes);
  } catch (err) {
    state.recoveryView.delete(setId);
    if (err.status !== 423) toast('无法查看恢复码：' + err.message, 'err');
  }
  renderDetail();
}

async function toggleCodeUsed(e, setId, codeId, currentlyUsed) {
  try {
    await api('recovery.markCodes', {
      entryId: e.id, setId, codeIds: [codeId], used: !currentlyUsed,
    });
    // 本地更新缓存，避免整块重新请求
    const arr = state.recoveryView.get(setId);
    if (Array.isArray(arr)) {
      const item = arr.find(c => c.id === codeId);
      if (item) item.usedAt = currentlyUsed ? null : new Date().toISOString();
    }
    // 更新列表里的计数
    const li = state.items.find(x => x.id === e.id);
    if (li && li.recovery) {
      li.recovery.unused = Math.max(0, li.recovery.unused + (currentlyUsed ? 1 : -1));
    }
    renderStats();
    renderDetail();
  } catch (err) {
    if (err.status !== 423) toast('标记失败：' + err.message, 'err');
  }
}

async function makeCurrentSet(e, setId) {
  try {
    await api('recovery.setCurrent', { entryId: e.id, setId });
    toast('已设为当前代');
    await openEntry(e.id);
    await loadList();
  } catch (err) {
    if (err.status !== 423) toast('操作失败：' + err.message, 'err');
  }
}

async function deleteSet(e, setId) {
  const ok = await confirmDialog('删除恢复码组',
    '确定删除这一组恢复码？\n\n已保存的码会一起消失，无法恢复。', true);
  if (!ok) return;
  try {
    await api('recovery.removeSet', { entryId: e.id, setId, confirm: true });
    state.recoveryView.delete(setId);
    toast('已删除');
    await openEntry(e.id);
    await loadList();
  } catch (err) {
    if (err.status !== 423) toast('删除失败：' + err.message, 'err');
  }
}

async function editSet(e, setId) {
  const set = (e.recovery.sets || []).find(s => s.id === setId);
  if (!set) return;

  const label = await promptDialog('编辑恢复码组', '标签（可留空）', set.label || '');
  if (label === null) return;
  const track = await confirmDialog('使用追踪',
    '是否追踪这一组恢复码的使用状态？\n\n开启后可以逐个标记已用，避免重复尝试。', false, '开启追踪', '不追踪');

  try {
    await api('recovery.updateSet', {
      entryId: e.id, setId, label, trackUsage: track,
    });
    toast('已更新');
    await openEntry(e.id);
  } catch (err) {
    if (err.status !== 423) toast('更新失败：' + err.message, 'err');
  }
}

async function addRecoverySet(e) {
  const res = await recoveryInputDialog();
  if (!res) return;
  try {
    await api('recovery.addSet', {
      entryId: e.id,
      label: res.label,
      createdAt: res.createdAt || undefined,
      trackUsage: res.trackUsage,
      text: res.text,
    });
    toast('已添加一组恢复码');
    await openEntry(e.id);
    await loadList();
  } catch (err) {
    if (err.status !== 423) toast('添加失败：' + err.message, 'err');
  }
}

/* ============ 对话框 ============ */

let confirmResolve = null;

function openModal(id) {
  $(id).classList.add('show');
}

function closeModal(id) {
  $(id).classList.remove('show');
  if (id === 'modalConfirm' && confirmResolve) {
    const r = confirmResolve;
    confirmResolve = null;
    r(false);
  }
}

function confirmDialog(title, message, danger, okText, cancelText) {
  return new Promise(resolve => {
    $('confirmTitle').textContent = title;
    $('confirmMessage').textContent = message;
    $('confirmErr').textContent = '';
    const okBtn = $('confirmOk');
    okBtn.textContent = okText || '确定';
    okBtn.className = 'btn ' + (danger ? 'btn-danger' : 'btn-primary');
    const cancelBtn = document.querySelector('#modalConfirm .modal-foot .btn:not(#confirmOk)');
    if (cancelBtn && cancelText) cancelBtn.textContent = cancelText;

    confirmResolve = resolve;
    openModal('modalConfirm');

    const handler = () => {
      okBtn.removeEventListener('click', handler);
      const r = confirmResolve;
      confirmResolve = null;
      closeModal('modalConfirm');
      if (r) r(true);
    };
    okBtn.addEventListener('click', handler, { once: true });
  });
}

function promptDialog(title, label, value, opts) {
  return new Promise(resolve => {
    // 复用确认弹窗的壳，但把正文换成一个输入框
    $('confirmTitle').textContent = title;
    const msg = $('confirmMessage');
    msg.innerHTML = '';
    const lab = document.createElement('label');
    lab.textContent = label;
    lab.className = 'prompt-label';
    const inp = document.createElement('input');
    // 口令类输入必须是 password：type=text 会让口令明文挂在屏幕上，
    // 旁边站个人、或者屏幕共享时直接就被看走了。
    inp.type = (opts && opts.password) ? 'password' : 'text';
    if (opts && opts.password) inp.autocomplete = 'new-password';
    inp.value = value || '';
    inp.maxLength = 64;
    msg.appendChild(lab);
    msg.appendChild(inp);

    $('confirmErr').textContent = '';
    const okBtn = $('confirmOk');
    okBtn.textContent = '确定';
    okBtn.className = 'btn btn-primary';

    openModal('modalConfirm');
    inp.focus();
    inp.select();

    let settled = false;
    const done = val => {
      if (settled) return;
      settled = true;
      okBtn.removeEventListener('click', onClick);
      msg.innerHTML = '';
      $('confirmMessage').textContent = '';
      closeModal('modalConfirm');
      resolve(val);
    };
    const onClick = () => done(inp.value);
    okBtn.addEventListener('click', onClick, { once: true });

    // 关闭/取消时 resolve(null)：调用方用 null 判断"用户放弃"
    confirmResolve = () => { if (!settled) { settled = true; msg.innerHTML = ''; resolve(null); } };
  });
}

function recoveryInputDialog() {
  return new Promise(resolve => {
    $('confirmTitle').textContent = '添加一组恢复码';
    const msg = $('confirmMessage');
    msg.innerHTML = '';

    const hint = document.createElement('div');
    hint.className = 'hint';
    hint.textContent = '粘贴恢复码文本，每行一个，也支持空格/逗号分隔。重复的码会自动去重。';

    const lab1 = document.createElement('label');
    lab1.textContent = '标签（可选，如「2026-11 生成」）';
    lab1.className = 'prompt-label';
    const inpLabel = document.createElement('input');
    inpLabel.type = 'text';
    inpLabel.maxLength = 64;

    const lab2 = document.createElement('label');
    lab2.textContent = '恢复码';
    lab2.className = 'prompt-label';
    const ta = document.createElement('textarea');
    ta.rows = 7;
    ta.placeholder = 'abcd-efgh\nijkl-mnop';
    ta.setAttribute('spellcheck', 'false');

    const chkWrap = document.createElement('label');
    chkWrap.className = 'chk';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = true;
    chkWrap.appendChild(chk);
    chkWrap.appendChild(document.createTextNode(' 追踪使用状态'));

    msg.appendChild(hint);
    msg.appendChild(lab1);
    msg.appendChild(inpLabel);
    msg.appendChild(lab2);
    msg.appendChild(ta);
    msg.appendChild(chkWrap);

    $('confirmErr').textContent = '';
    const okBtn = $('confirmOk');
    okBtn.textContent = '添加';
    okBtn.className = 'btn btn-primary';

    openModal('modalConfirm');
    ta.focus();

    let settled = false;
    const cleanup = () => { msg.innerHTML = ''; $('confirmMessage').textContent = ''; };
    const done = val => {
      if (settled) return;
      settled = true;
      okBtn.removeEventListener('click', onClick);
      cleanup();
      closeModal('modalConfirm');
      resolve(val);
    };
    const onClick = () => {
      if (!ta.value.trim()) {
        $('confirmErr').textContent = '请粘贴至少一个恢复码';
        return;
      }
      done({ label: inpLabel.value.trim(), text: ta.value, trackUsage: chk.checked });
    };
    okBtn.addEventListener('click', onClick, { once: true });

    confirmResolve = () => { if (!settled) { settled = true; cleanup(); resolve(null); } };
  });
}

/* ============ 新增 / 编辑条目 ============ */

let editingId = null;

function openEntryModal(e) {
  editingId = e ? e.id : null;
  $('entryModalTitle').textContent = e ? '编辑条目' : '新增条目';
  $('entryErr').textContent = '';
  $('parsePreview').textContent = '';
  $('fOtpauth').value = '';
  $('fOtpauth').disabled = !!e;   // 编辑时不建议整体重解析，密钥单独改

  if (e) {
    $('fType').value = e.type;
    $('fIssuer').value = e.issuer || '';
    $('fAccount').value = e.account || '';
    $('fGroup').value = e.group || '';
    $('fSecret').value = '';       // 不回填密钥：要改就重新粘贴
    $('fAlgo').value = e.totp ? e.totp.algorithm : 'SHA1';
    $('fDigits').value = String(e.totp ? e.totp.digits : 6);
    $('fPeriod').value = String(e.totp ? e.totp.period : 30);
    $('fNote').value = e.note || '';
    $('fRecoveryText').value = '';
    $('fSecret').placeholder = e.hasTotp ? '留空则保持原密钥不变' : 'JBSWY3DPEHPK3PXP';
    $('entryHint').innerHTML = '编辑时留空密钥表示保持原值。其它字段可直接修改。';
  } else {
    $('fType').value = 'totp';
    $('fIssuer').value = '';
    $('fAccount').value = '';
    $('fGroup').value = '';
    $('fSecret').value = '';
    $('fAlgo').value = 'SHA1';
    $('fDigits').value = '6';
    $('fPeriod').value = '30';
    $('fNote').value = '';
    $('fRecoveryText').value = '';
    $('fSecret').placeholder = 'JBSWY3DPEHPK3PXP';
    $('entryHint').innerHTML =
      '可以直接粘贴 <code>otpauth://</code> URI 或裸 Base32 密钥，其余字段会自动填好。';
  }
  openModal('modalEntry');
  $('fOtpauth').focus();
}

async function doParse() {
  const raw = $('fOtpauth').value.trim();
  if (!raw) { $('parsePreview').textContent = '先粘贴内容'; $('parsePreview').className = 'err muted'; return; }

  try {
    const data = await api('otp.check', { input: raw });
    const n = data.normalized;
    if (n.issuer) $('fIssuer').value = n.issuer;
    if (n.account) $('fAccount').value = n.account;
    $('fSecret').value = n.secret;
    $('fAlgo').value = n.algorithm;
    $('fDigits').value = String(n.digits);
    $('fPeriod').value = String(n.period);
    if (!$('fGroup').value && n.issuer) $('fGroup').value = n.issuer;
    if (!$('fIssuer').value) { $('entryErr').textContent = ''; }

    // 预览卡（.preview-card，A1 已在 §2.1 定义）。
    // 原来把「算法 · 位数 · 周期 · 当前码」挤成一行 .err.muted 文本，
    // 用户要核对的关键信息是那 6 位码，混在句子里根本扫不出来。
    // 拆开后码独占一行 32px，参数和提示各一行小字。
    // 每一段都过 esc()：issuer/account 来自粘贴的文本，属于未转义输入。
    const p = data.preview || {};
    $('parsePreview').innerHTML =
      '<div class="preview-card">' +
        '<div class="pv-meta">' + esc(n.algorithm) + ' · ' + esc(n.digits) + ' 位 · ' +
          esc(n.period) + ' 秒</div>' +
        // 预览码同样按 fmtCode 分组显示；这里只是显示，不参与复制。
        '<div class="pv-code">' + esc(p.code ? fmtCode(p.code) : '') + '</div>' +
        '<div class="pv-hint">' + esc((p.remaining != null ? p.remaining + ' 秒后刷新' : '') +
          (n.issuer ? ' · ' + n.issuer : '') + (n.account ? ' · ' + n.account : '')) + '</div>' +
      '</div>';
    $('parsePreview').className = '';
  } catch (e) {
    $('parsePreview').innerHTML = '';
    $('parsePreview').textContent = '解析失败：' + e.message;
    $('parsePreview').className = 'err';
  }
}

async function saveEntry() {
  const errEl = $('entryErr');
  errEl.textContent = '';

  const type = $('fType').value;
  const issuer = $('fIssuer').value.trim();
  if (!issuer) { errEl.textContent = '名称不能为空'; return; }

  const entry = {
    type,
    issuer,
    account: $('fAccount').value.trim(),
    group: $('fGroup').value.trim(),
    note: $('fNote').value,
  };

  if (editingId) entry.id = editingId;

  // 密钥：编辑时留空表示不改。服务端对「totp 字段未提供或 secret 为空」
  // 会沿用 existing 的密钥（见 store.js 的 vTotp），所以这里什么都不用传。
  const secretRaw = $('fSecret').value.trim();
  if (secretRaw) {
    entry.totp = {
      secret: secretRaw,
      algorithm: $('fAlgo').value,
      digits: Number($('fDigits').value),
      period: Number($('fPeriod').value),
    };
  } else if (type === 'totp') {
    // 只把算法参数带过去；secret 缺省 → 服务端继承原密钥
    entry.totp = {
      algorithm: $('fAlgo').value,
      digits: Number($('fDigits').value),
      period: Number($('fPeriod').value),
    };
  }

  if (type === 'totp' && !entry.totp && !editingId) {
    errEl.textContent = 'TOTP 类型必须填密钥';
    return;
  }

  const recText = $('fRecoveryText').value.trim();
  // 新增时把恢复码作为一组一起提交：先建条目，再 addSet。
  // 编辑时不在这里处理：恢复码有独立的增删改接口（addSet / removeSet），
  // 混进 upsert 会让"改个备注却新建了一组码"变成可能。
  const recTextTmp = (!editingId && recText) ? recText : null;

  try {
    const data = await api('entries.upsert', { entry });
    const id = data.entry.id;

    if (recTextTmp) {
      try {
        await api('recovery.addSet', { entryId: id, text: recTextTmp, trackUsage: true });
      } catch (e) {
        toast('条目已保存，但恢复码添加失败：' + e.message, 'warn');
      }
    }

    closeModal('modalEntry');
    toast(editingId ? '已保存' : '已新增');
    await loadList();
    await openEntry(id);
  } catch (e) {
    if (e.status !== 423) errEl.textContent = e.message;
  }
}

/* ============ 设置 ============ */

async function loadSettingsInfo() {
  try {
    const [st, bi] = await Promise.all([api('vault.status'), api('backup.info')]);
    $('fIdle').value = String(st.idleTimeoutSec);
    $('vaultInfo').textContent =
      '密钥库：' + st.vaultPath + '\n' +
      '条目 ' + bi.entries + ' 个 · 修订 ' + bi.revision + ' · 文件 ' + fmtSize(bi.size) + '\n' +
      '备份 ' + (bi.backups || []).length + ' 份';
    $('vaultInfo').textContent = $('vaultInfo').textContent.replace(/\n/g, ' ');
  } catch { /* 忽略 */ }
}

function fmtSize(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

async function saveIdle() {
  const v = $('fIdle').value.trim();
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 86400) {
    $('settingsErr').textContent = '空闲时间必须是 0..86400 的整数';
    return;
  }
  try {
    await api('vault.settings', { idleTimeoutSec: n });
    $('settingsErr').textContent = '';
    toast('已保存');
  } catch (e) {
    if (e.status !== 423) $('settingsErr').textContent = e.message;
  }
}

async function changePass() {
  const oldP = $('fOldPass').value;
  const newP = $('fNewPass').value;
  const errEl = $('settingsErr');
  errEl.textContent = '';
  if (!oldP || !newP) { errEl.textContent = '两个口令都要填'; return; }
  if (newP.length < 8) { errEl.textContent = '新口令至少 8 个字符'; return; }
  try {
    const data = await api('vault.changePassphrase', { oldPassphrase: oldP, newPassphrase: newP });
    $('fOldPass').value = '';
    $('fNewPass').value = '';
    // 备份里裹的是旧口令派生的 KEK。删不掉就说明旧口令**仍然能打开当前库**,
    // 不能只在 toast 上说"口令已修改"就把这件事盖过去。
    if (data && data.staleBackups && data.staleBackups.length) {
      toast('口令已修改，但 ' + data.staleBackups.length + ' 个旧备份删除失败：旧口令仍可能有效。请手动删除 ' + data.staleBackups.join('、'), 'err');
    } else {
      toast('口令已修改');
    }
  } catch (e) {
    if (e.status !== 423) errEl.textContent = e.message;
  }
}

async function regenRecovery() {
  const p = $('fRegenPass').value;
  const errEl = $('settingsErr');
  errEl.textContent = '';
  if (!p) { errEl.textContent = '请输入当前口令'; return; }
  try {
    const data = await api('vault.regenerateRecovery', { passphrase: p });
    $('fRegenPass').value = '';
    $('regenRecoveryKey').textContent = data.recoveryKey;
    $('settingsRecovery').hidden = false;
    if (data && data.staleBackups && data.staleBackups.length) {
      toast('新恢复密钥已生成，但 ' + data.staleBackups.length + ' 个旧备份删除失败：旧恢复密钥仍可能有效。请手动删除 ' + data.staleBackups.join('、'), 'err');
    } else {
      toast('新恢复密钥已生成，请立刻保存', 'warn');
    }
  } catch (e) {
    if (e.status !== 423) errEl.textContent = e.message;
  }
}

/* ============ 导出 ============ */

async function doExport() {
  const ok = await confirmDialog('导出 otpauth',
    '将导出全部 TOTP 条目的 otpauth URI（含明文密钥）。\n\n' +
    '仅用于迁移到别的验证器。拿到这份文本等于拿到全部验证码。', true);
  if (!ok) return;
  try {
    const data = await api('entries.export', { confirm: true });
    if (!data.items.length) { toast('没有可导出的 TOTP 条目', 'warn'); return; }
    const blob = new Blob([data.text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'keydesk-otpauth-' + new Date().toISOString().slice(0, 10) + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast('已导出 ' + data.items.length + ' 条');
  } catch (e) {
    if (e.status !== 423) toast('导出失败：' + e.message, 'err');
  }
}

/**
 * 加密导出包（§2.4 的 export.encrypted）。
 *
 * 为什么必须有这条路径：README 自己承认只有 otpauth 明文导出，
 * 也就是用户手上不可能有第二份**加密**副本 —— 备份策略被迫退化成
 * "拷 vault.enc"，而 .bak.1/.2/.3 全在同一个目录，磁盘坏了全没。
 * 明文导出不能当备份用（拿到就拿到全部密钥）。
 *
 * 口令用 promptDialog 收：不落 DOM 属性、不进 URL、用完立即清空变量。
 * 不把它塞进表单后再读，是因为那样明文口令会在 input 的 value 里留到弹窗关闭。
 */
async function doEncryptedExport() {
  const p1 = await promptDialog('加密导出备份包',
    '设置一个导出包口令（至少 8 个字符，可与主口令不同）', '', { password: true });
  if (p1 === null) return;
  if (!p1 || p1.length < 8) { toast('导出包口令至少 8 个字符', 'warn'); return; }

  try {
    const data = await api('export.encrypted', { passphrase: p1 });
    // 服务端只回路径和大小，不回密文内容（见 server.js 的注释）。
    // 这里也就不该再想办法去读文件 —— 用户拿走的是磁盘上的那个包。
    toast('已导出加密包：' + data.path + '（' + fmtSize(data.bytes) + '）');
    announce('已导出加密备份包');
    $('vaultInfo').textContent = '最近导出：' + data.path + ' · ' + fmtSize(data.bytes);
  } catch (e) {
    if (e.status !== 423) toast('加密导出失败：' + e.message, 'err');
  }
}

/* ============ 审计视图 ============ */

const AUDIT_LABEL = {
  'no-totp': '无 TOTP 密钥',
  'no-recovery': '无恢复码',
  'stale-recovery': '恢复码过期',
  'no-password': '无密码',
};

/**
 * P2：审计视图。"需更新"那个统计数字一直在，但用户点不进去看是哪些条目 ——
 * 一个只能看到数量、看不到名字的告警等于没有告警。
 * 后端 audit.list（A5）只做过滤，数据早已具备（summarize() 已输出
 * recovery.setCount / stale），前端这边只负责展示。
 *
 * 容器 #auditList 由 A3 提供（§2.2 之外的补充，见报告）。它不存在时
 * 降级成"把问题条目筛进列表"，仍然可达 —— 不能因为缺一个容器就让这个
 * 功能整体消失。
 */
async function showAudit() {
  let data;
  try {
    data = await api('audit.list', {});
  } catch (e) {
    if (e.status === 423) return;
    // 后端还没实现这个 action（A5 并行中）时，用列表摘要兜底：
    // 数据等价，只是要客户端自己算。字段名按 store.js 的 summarize() 实际输出
    // （passwordSet 而不是 hasPassword —— summarize 是白名单构造，字段名不能猜）。
    const items = state.items.map(it => {
      const problems = [];
      if (!it.hasTotp) problems.push('no-totp');
      if (!it.recovery || it.recovery.setCount === 0) problems.push('no-recovery');
      else if (it.recovery.stale) problems.push('stale-recovery');
      if (!it.passwordSet) problems.push('no-password');
      return { id: it.id, issuer: it.issuer, account: it.account, problems };
    }).filter(x => x.problems.length);
    data = { items };
  }

  const items = data.items || [];
  const host = $('auditList');
  if (!host) {
    // 没有容器时退回搜索：把有问题的条目名拼成一个搜索词做不到，
    // 直接 toast 出数量并聚焦列表，至少让用户知道去哪儿找。
    toast(items.length ? '有 ' + items.length + ' 个条目需要处理' : '全部条目都健康', 'warn');
    return;
  }

  if (!items.length) {
    host.innerHTML = '<div class="empty">全部条目都健康：有 TOTP、未过期的恢复码和密码。</div>';
    return;
  }

  host.innerHTML = '<div class="audit-list">' + items.map(it => {
    // 所有值都必须过 esc()：issuer / account 是用户自己录入的，
    // 粘贴一段带标签的 issuer 一样会进 innerHTML。
    return '<div class="audit-row" data-id="' + esc(it.id) + '">' +
      '<div class="audit-main">' +
        '<div class="entry-issuer">' + esc(it.issuer) + '</div>' +
        '<div class="entry-account">' + esc(it.account || '') + '</div>' +
      '</div>' +
      '<div class="audit-badges">' +
        (it.problems || []).map(p =>
          '<span class="audit-badge">' + esc(AUDIT_LABEL[p] || p) + '</span>').join('') +
      '</div>' +
    '</div>';
  }).join('') + '</div>';

  // 点一行直接打开那个条目：审计的下一步永远是"去修它"，
  // 让用户自己再回列表里搜一遍是没必要的摩擦。
  for (const row of host.querySelectorAll('.audit-row')) {
    row.addEventListener('click', () => {
      const id = row.getAttribute('data-id');
      // 只关掉真正包着审计列表的那个弹窗 —— 别把用户同时开着的
      // 设置 / 二维码弹窗一起关掉，那样会丢失他填了一半的内容。
      const m = host.closest('.modal');
      if (m && m.classList.contains('show')) closeModal(m.id);
      openEntry(id);
    });
  }
}

/* ============ 事件绑定 ============ */

function bindGlobalEvents() {
  // 锁屏表单
  $('formSetup').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('setupErr').textContent = '';
    const p1 = $('setupPass').value;
    const p2 = $('setupPass2').value;
    if (p1.length < 8) { $('setupErr').textContent = '口令至少 8 个字符'; return; }
    if (p1 !== p2) { $('setupErr').textContent = '两次输入的口令不一致'; return; }
    const btn = $('btnSetup');
    btn.disabled = true;
    btn.textContent = '正在创建…';
    try {
      const data = await api('vault.setup', { passphrase: p1 });
      $('newRecoveryKey').textContent = data.recoveryKey;
      showLockView('done');
      $('setupPass').value = '';
      $('setupPass2').value = '';
      state.initialized = true;
      state.locked = false;
    } catch (e) {
      $('setupErr').textContent = e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = '创建密钥库';
    }
  });

  // 「我已保存」不再直接进主界面，而是展开回填确认。
  //
  // 原来的按钮是零摩擦的：点一下就过，用户 100% 会直接点 —— 那恰恰是这个
  // 流程里唯一真正失败的地方。三个月后真要恢复时才发现当时没抄，而这时
  // 库已建好、密钥只在屏幕上出现过一次，已经没有任何补救办法。
  // 回填 3 段把"看过"变成"抄过"，代价约 20 秒（Apple 的恢复密钥流程
  // 也是强制回填，原文 "To complete setup, confirm your recovery key."）。
  $('btnSetupDone').addEventListener('click', () => {
    // 密钥从 DOM 读而不是从变量读：它是 setup 时写进 #newRecoveryKey 的
    // 唯一副本，重新显示/刷新都走同一个节点，不会出现两份不同步。
    const shown = ($('newRecoveryKey').textContent || '').trim();
    if (!shown) { toast('恢复密钥没有显示出来，请重新创建', 'err'); return; }
    const box = $('confirmRecovery');
    if (!box) { enterApp(); return; }   // 结构缺失时退回旧路径，不要卡住用户
    $('confirmRecoveryErr').textContent = '';
    for (const i of [1, 2, 3]) { const el = $('confirmRecSeg' + i); if (el) el.value = ''; }
    box.hidden = false;
    $('btnSetupDone').hidden = true;
    const first = $('confirmRecSeg1');
    if (first) first.focus();
  });

  // 输入即大写 + 4 位自动跳格。粘贴一整把密钥进第一格时 maxlength 只留 4 位，
  // 但用户多半是"一位一位抄"，所以按长度推进焦点就够了，不做复杂的分发。
  for (const i of [1, 2, 3]) {
    const el = $('confirmRecSeg' + i);
    if (!el) continue;
    el.addEventListener('input', () => {
      el.value = el.value.toUpperCase().replace(/[^A-Z2-7]/g, '');
      if (el.value.length === 4 && i < 3) { const nx = $('confirmRecSeg' + (i + 1)); if (nx) nx.focus(); }
      $('confirmRecoveryErr').textContent = '';
    });
    el.addEventListener('keydown', ev => {
      // 退格回到上一格：抄错时不用拿鼠标点回去
      if (ev.key === 'Backspace' && !el.value && i > 1) {
        const pv = $('confirmRecSeg' + (i - 1)); if (pv) { pv.focus(); pv.setSelectionRange(pv.value.length, pv.value.length); }
      }
      if (ev.key === 'Enter') { ev.preventDefault(); $('btnConfirmRecovery').click(); }
    });
  }

  $('btnShowRecoveryAgain').addEventListener('click', () => {
    // 逃生门：抄错了还能再看一遍，否则用户会永久卡在初始化界面
    // （此时库已建好，退回不去也进不来）。
    const box = $('confirmRecovery');
    if (box) box.hidden = true;
    $('btnSetupDone').hidden = false;
    $('btnSetupDone').textContent = '我已保存，进入';
  });

  $('btnConfirmRecovery').addEventListener('click', async () => {
    const shown = ($('newRecoveryKey').textContent || '').trim();
    const segs = shown.replace(/[\s-]/g, '');
    if (segs.length !== 26) { toast('恢复密钥长度异常，请重新创建', 'err'); return; }
    // 抽第 2、5、7 段（字符区间 4-8 / 16-20 / 24-26）。
    // 不从第一段开始抽，是因为开头四个字符最容易被"扫一眼"糊弄过去；
    // 分散抽取才真正逼着人把整串抄下来。第 7 段只有 2 位（26 = 4×6 + 2），
    // 输入框虽然给了 4 位宽，用户只会填 2 位，按实际长度比对即可。
    const want = [segs.slice(4, 8), segs.slice(16, 20), segs.slice(24, 26)];
    const bad = [];
    for (let k = 0; k < 3; k++) {
      const got = (($('confirmRecSeg' + (k + 1)).value || '')).toUpperCase();
      if (got !== want[k]) bad.push(k + 1);
    }
    if (bad.length) {
      $('confirmRecoveryErr').textContent =
        '第 ' + bad.join('、') + ' 段和刚才显示的不一致。请检查抄写，或点「重新显示恢复密钥」再看一遍。';
      const f = $('confirmRecSeg' + bad[0]);
      if (f) { f.focus(); f.select(); }
      return;
    }
    await enterApp();
  });

  $('formUnlock').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('unlockErr').textContent = '';
    const btn = $('btnUnlock');
    btn.disabled = true;
    btn.textContent = '解锁中…';
    try {
      await api('vault.unlock', { passphrase: $('unlockPass').value });
      $('unlockPass').value = '';
      await enterApp();
    } catch (e) {
      $('unlockErr').textContent = e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = '解锁';
    }
  });

  $('formRecovery').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('recoveryErr').textContent = '';
    const btn = $('btnRecovery');
    btn.disabled = true;
    btn.textContent = '解锁中…';
    try {
      await api('vault.unlockRecovery', { recoveryKey: $('recKey').value });
      $('recKey').value = '';
      await enterApp();
    } catch (e) {
      $('recoveryErr').textContent = e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = '用恢复密钥解锁';
    }
  });

  $('btnToRecovery').addEventListener('click', () => {
    $('recoveryErr').textContent = '';
    showLockView('recovery');
    $('recKey').focus();
  });
  $('btnBackToPass').addEventListener('click', () => {
    $('unlockErr').textContent = '';
    showLockView('unlock');
    $('unlockPass').focus();
  });

  // 搜索 / 筛选
  let searchTimer = null;
  $('search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = $('search').value.trim();
      loadList();
    }, 220);
  });
  $('groupFilter').addEventListener('change', () => {
    state.group = $('groupFilter').value;
    loadList();
  });
  $('chkArchived').addEventListener('change', () => {
    state.includeArchived = $('chkArchived').checked;
    loadList();
  });

  // 列表点击
  $('entryList').addEventListener('click', ev => {
    const row = ev.target.closest('[data-id]');
    if (!row) return;
    // 鼠标点在行上时，浏览器不会把焦点给一个 tabindex=-1 的 div。
    // 不手动聚焦的话，用户点完一行再按 ↓ 毫无反应（焦点还在 body 上）。
    row.focus({ preventScroll: true });
    openEntry(row.getAttribute('data-id'));
  });
  // P2：listbox 的方向键。
  // 行本身不再各自 tabindex（那会让 Tab 穿过列表要点几十下），
  // 改成容器 tabindex=0 + 焦点在行之间移动，这是 ARIA listbox 的标准交互：
  // Tab 进出列表一次，↑/↓ 在内部走，Enter/Space 打开。
  // 也必须保留旧行为（行自带焦点时的 Enter/Space）—— 鼠标点过的行会拿到焦点。
  $('entryList').addEventListener('keydown', ev => {
    const rows = Array.from($('entryList').querySelectorAll('[data-id]'));
    if (!rows.length) return;

    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      ev.preventDefault();
      const cur = ev.target.closest('[data-id]');
      let i = cur ? rows.indexOf(cur) : -1;
      if (i === -1) {
        // 焦点在容器上（用户刚 Tab 进来）：↓ 从当前选中行的下一行开始，
        // 没有选中行就从第一行开始。
        const sel = rows.findIndex(r => r.getAttribute('data-id') === state.currentId);
        i = ev.key === 'ArrowDown' ? Math.max(0, sel) : rows.length - 1;
        (rows[i] || rows[0]).focus();
        return;
      }
      i += ev.key === 'ArrowDown' ? 1 : -1;
      if (i < 0) i = rows.length - 1;          // 环绕：到顶再按上就跳到底
      if (i >= rows.length) i = 0;
      rows[i].focus();
      return;
    }

    if (ev.key === 'Enter' || ev.key === ' ') {
      const row = ev.target.closest('[data-id]');
      if (row) { ev.preventDefault(); openEntry(row.getAttribute('data-id')); }
    }
  });

  // P2：全局快捷键
  document.addEventListener('keydown', ev => {
    if (state.locked) return;
    // 弹窗打开时不抢键：Ctrl+C 在输入框里必须是"复制选中的文字"，
    // 不能被解读成"复制当前条目的验证码"。
    if (document.querySelector('.modal.show')) return;

    const t = ev.target;
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' ||
      t.isContentEditable);

    // "/" 聚焦搜索（GitHub / 各类列表页的通用约定）。
    // 输入框里按 "/" 必须是打出一个斜杠，不能抢。
    if (ev.key === '/' && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      ev.preventDefault();
      $('search').focus();
      $('search').select();
      return;
    }

    if (!(ev.ctrlKey || ev.metaKey) || ev.altKey) return;

    // Ctrl+C：复制当前条目的验证码（KeePassXC 的主交互）。
    // 只在"用户没有选中文字"时才接管 —— 选中了文字的人是想复制那段文字，
    // 这是浏览器的原生契约，抢它会让所有人都觉得这个页面坏了。
    if ((ev.key === 'c' || ev.key === 'C') && !ev.shiftKey) {
      const sel = window.getSelection && String(window.getSelection());
      if (typing || (sel && sel.length)) return;
      if (!state.currentId) return;
      ev.preventDefault();
      copyCode(state.currentId);
      return;
    }

    // Ctrl+L：立即锁定（浏览器的"聚焦地址栏"也是 Ctrl+L，
    // 但这是一个专门的本机密钥工具，锁定优先；preventDefault 挡掉地址栏行为）。
    if ((ev.key === 'l' || ev.key === 'L') && !ev.shiftKey) {
      ev.preventDefault();
      lockNow();
      return;
    }
  });

  // 顶部按钮
  $('btnAdd').addEventListener('click', () => openEntryModal(null));
  $('btnExport').addEventListener('click', doExport);
  // 加密导出入口。#btnExportEncrypted 由 A3 提供；还没有时把明文导出按钮
  // 改成「右键 / 长按之外的第二种选择」做不到，就明确降级：把一个
  // 组合入口挂到现有按钮的标题上并不合适，所以这里只在元素存在时绑定，
  // 并在报告里点名缺这个入口（加密备份是 P1 的导出策略核心，不该只能靠明文导出）。
  const btnExpEnc = $('btnExportEncrypted');
  if (btnExpEnc) {
    btnExpEnc.addEventListener('click', doEncryptedExport);
  } else {
    // 降级：设置弹窗里的「密钥库」信息块本来就是备份相关的位置，
    // 没有专门按钮时，用户仍能从那里触达（双击 / Enter 触发）。
    const info = $('vaultInfo');
    if (info) {
      info.style.cursor = 'pointer';
      info.title = '点击生成加密备份包';
      info.addEventListener('click', doEncryptedExport);
    }
  }

  // 审计入口。#btnAudit 由 A3 提供（§2.2 之外，见报告）；还没加时退回到
  // 点「需更新」那个统计块 —— 那本来就是用户在找的入口，
  // 而且 #statStale 是既有 id（§2.2 说不要改已有 id），一定能绑上。
  const btnAudit = $('btnAudit');
  if (btnAudit) {
    btnAudit.addEventListener('click', () => showAudit());
  } else {
    const stale = $('statStale');
    if (stale) {
      stale.style.cursor = 'pointer';
      stale.setAttribute('role', 'button');
      stale.setAttribute('tabindex', '0');
      stale.title = '查看需要处理的条目';
      stale.addEventListener('click', () => showAudit());
      stale.addEventListener('keydown', ev => {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); showAudit(); }
      });
    }
  }
  // 二维码弹窗里的"复制文本密钥"——二维码生成失败时的兜底路径
  $('btnCopyQrUri').addEventListener('click', async () => {
    const txt = $('qrUri').textContent || '';
    if (!txt) return;
    try {
      await navigator.clipboard.writeText(txt);
      toast('已复制文本密钥');
    } catch {
      toast('复制失败，请手动选中文本', 'warn');
    }
  });
  $('btnSettings').addEventListener('click', () => {
    $('settingsErr').textContent = '';
    $('settingsRecovery').hidden = true;
    loadSettingsInfo();
    openModal('modalSettings');
  });
  $('btnLock').addEventListener('click', lockNow);

  // 条目弹窗
  $('btnParse').addEventListener('click', doParse);
  $('fOtpauth').addEventListener('keydown', ev => {
    if (ev.key === 'Enter') { ev.preventDefault(); doParse(); }
  });
  $('btnSaveEntry').addEventListener('click', saveEntry);

  // 设置弹窗
  $('btnSaveIdle').addEventListener('click', saveIdle);
  $('btnChangePass').addEventListener('click', changePass);
  $('btnRegenRecovery').addEventListener('click', regenRecovery);

  // 弹窗关闭
  document.addEventListener('click', ev => {
    const closeBtn = ev.target.closest('[data-close]');
    if (closeBtn) {
      closeModal(closeBtn.getAttribute('data-close'));
      return;
    }
    // 点遮罩关闭
    if (ev.target.classList && ev.target.classList.contains('modal')) {
      closeModal(ev.target.id);
    }
  });
  document.addEventListener('keydown', ev => {
    if (ev.key === 'Escape') {
      const open = document.querySelector('.modal.show');
      if (open) closeModal(open.id);
    }
  });
}

/* ============ 启动 ============ */

async function boot() {
  bindGlobalEvents();
  bindDetailDelegation();
  try {
    await handshake();
  } catch (e) {
    $('lockSub').textContent = '无法连接本地服务：' + e.message;
    return;
  }
  await refreshLockState();
}

boot();
