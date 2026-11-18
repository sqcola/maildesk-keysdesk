'use strict';

/* ============ 内置平台表 ============
 * 与后端 lib/platforms.js 的 BUILTIN 必须逐字一致（key / name / color 三项）。
 * MailDesk 是零依赖、无构建的项目，前端不能 require，所以这里存同一份常量，
 * 汇总阶段会由测试比对两边。
 */
const PLATFORMS = [
  { key: 'google',    name: 'Google',      color: '#4285f4' },
  { key: 'github',    name: 'GitHub',      color: '#24292f' },
  { key: 'microsoft', name: 'Microsoft',   color: '#00a4ef' },
  { key: 'apple',     name: 'Apple',       color: '#333333' },
  { key: 'steam',     name: 'Steam',       color: '#171a21' },
  { key: 'discord',   name: 'Discord',     color: '#5865f2' },
  { key: 'telegram',  name: 'Telegram',    color: '#26a5e4' },
  { key: 'twitter',   name: 'X / Twitter', color: '#1d9bf0' },
  { key: 'facebook',  name: 'Facebook',    color: '#1877f2' },
  { key: 'reddit',    name: 'Reddit',      color: '#ff4500' },
  { key: 'twitch',    name: 'Twitch',      color: '#9146ff' },
  { key: 'netflix',   name: 'Netflix',     color: '#e50914' },
  { key: 'spotify',   name: 'Spotify',     color: '#1db954' },
  { key: 'amazon',    name: 'Amazon',      color: '#ff9900' },
  { key: 'paypal',    name: 'PayPal',      color: '#00457c' },
  { key: 'openai',    name: 'OpenAI',      color: '#10a37f' },
  { key: 'anthropic', name: 'Anthropic',   color: '#d97757' },
];

const PF_BY_KEY = new Map(PLATFORMS.map(p => [p.key, p]));

/* ---- chip 配色的计算 ----
 * 规格 §5 要求「chip 文字对底色 ≥ 4.5:1」。品牌色里只有少数几个够深能直接配白字
 * （GitHub #24292f 是 14.65:1、Steam #171a21 是 17.41:1），而 Google #4285f4 配白字
 * 只有 3.56:1、Spotify #1db954 只有 2.59:1、Amazon #ff9900 只有 2.14:1 —— 都不达标。
 * 所以统一走「品牌色 12% 浅底 + 压暗后的品牌色文字」，逐个颜色算到对比度达标为止。
 *
 * 描边的参照底色取列表行选中色 #dbe6fb（比白底更难压过）：chip 既要能和内容区分，
 * 也要在选中行/hover 行上不糊成一片。实测最低 3.10:1（见交付报告）。
 */
const PF_WHITE = [255, 255, 255];
const PF_BLACK = [0, 0, 0];
const PF_ROW_ACTIVE = '#dbe6fb';
const PF_CUSTOM_COLOR = '#5b6470';
const PF_NEUTRAL_TINT = 0.12;   // 底色 = 12% 品牌色 + 88% 白

function pfRgb(hex) {
  let h = String(hex == null ? '' : hex).replace('#', '');
  if (h.length === 3) h = h.split('').map(c => c + c).join('');
  if (!/^[0-9a-fA-F]{6}$/.test(h)) return [0, 0, 0];
  return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16));
}

function pfHex(rgb) {
  return '#' + rgb.map(v =>
    Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, '0')).join('');
}

/** sRGB 相对亮度（WCAG 2.1 定义） */
function pfLum([r, g, b]) {
  const lin = c => {
    const x = c / 255;
    return x <= 0.04045 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function pfContrast(a, b) {
  const x = Math.max(a, b);
  const y = Math.min(a, b);
  return (x + 0.05) / (y + 0.05);
}

function pfMix(a, b, t) {
  return a.map((v, i) => v * (1 - t) + b[i] * t);
}

/** 向黑色逐步加深，直到对 refLum 的对比度达标（每步 2%，最多 100 步） */
function pfDarkenUntil(rgb, refLum, target) {
  let out = rgb.slice();
  for (let i = 0; i < 100 && pfContrast(pfLum(out), refLum) < target; i++) {
    out = pfMix(out, PF_BLACK, 0.02);
  }
  return out;
}

function pfBuildPalette(color) {
  const brand = pfRgb(color);
  const bg = pfMix(PF_WHITE, brand, PF_NEUTRAL_TINT);
  const bgLum = pfLum(bg);
  return {
    brand: pfHex(brand),
    bg: pfHex(bg),
    fg: pfHex(pfDarkenUntil(brand, bgLum, 4.6)),
    bd: pfHex(pfDarkenUntil(brand, pfLum(pfRgb(PF_ROW_ACTIVE)), 3.1)),
  };
}

const PF_STYLE = new Map(PLATFORMS.map(p => [p.key, pfBuildPalette(p.color)]));
const PF_STYLE_CUSTOM = pfBuildPalette(PF_CUSTOM_COLOR);

/** 内联到 chip 上的三个 CSS 变量；--pf-color 是平台原色（左侧色条用） */
function pfStyle(key) {
  const s = PF_STYLE.get(String(key == null ? '' : key)) || PF_STYLE_CUSTOM;
  return `--pf-color:${s.brand};--pf-bg:${s.bg};--pf-fg:${s.fg};--pf-bd:${s.bd}`;
}

/**
 * 平台显示名：内置优先，其次 platformNames 里的原始写法，最后退回 key。
 * names 既可以是普通对象（服务端返回的 platformNames），也可以是 Map（弹窗里的暂存）。
 * 自定义平台必须显示用户输入的原样大小写（输入 Vercel 不能显示成 vercel）。
 *
 * 必须用 hasOwnProperty 而不是 names[k]：用户可以把平台命名成 'constructor'
 * 或 '__proto__'（后端 normalizePlatforms 会保留它们），直接取值会拿到
 * Object 原型上的函数，界面上就会出现一段源码文字。
 */
function pfName(key, names) {
  const k = String(key == null ? '' : key);
  const builtin = PF_BY_KEY.get(k);
  if (builtin) return builtin.name;
  let raw = null;
  if (names instanceof Map) {
    raw = names.get(k);
  } else if (names && typeof names === 'object' && !Array.isArray(names)) {
    raw = Object.prototype.hasOwnProperty.call(names, k) ? names[k] : null;
  }
  if (typeof raw === 'string' && raw.trim()) return raw;
  return k;
}

/** 只取字符串型的平台 key，并把 undefined / 非数组一律当成空（后端可能还没上线这个字段） */
function pfKeys(acc) {
  const list = acc && acc.platforms;
  if (!Array.isArray(list)) return [];
  return list.filter(k => typeof k === 'string' && k);
}

function pfNamesMap(acc) {
  const m = acc && acc.platformNames;
  return (m && typeof m === 'object' && !Array.isArray(m)) ? m : {};
}

/* ============ 状态 ============ */
const state = {
  token: null,
  accounts: [],
  currentId: null,
  currentMailbox: 'INBOX',
  messages: [],
  filterText: '',
  filterGroup: '',
  filterPlatform: '',  // 平台筛选：与 filterText / filterGroup 是「与」关系
  pfStats: [],         // accounts.platformStats 的结果；失败时保持空数组（筛选器只有"全部平台"）
  pfStatsSeq: 0,       // 平台统计的竞态守卫
  currentCode: null,   // 当前查看邮件的验证码
  autoCopy: true,      // 自动复制到剪贴板
  msgSeq: 0,           // 邮件列表加载序号（竞态守卫）
  folderSeq: 0,        // 文件夹加载序号（与 msgSeq 分开，否则会互相取消）
  openSeq: 0,          // 邮件详情加载序号
  openUid: null,       // 当前正在阅读的邮件 uid（列表里给它 .active）
  retryUid: null,      // 上一次打开失败的 uid，详情里"重试"用
  selected: new Set(), // 多选的账户 id，不能只存在 DOM 里（列表会全量重绘）
  scanJobId: null,     // 当前批量收码任务
  scanTimer: null,     // 1000ms 轮询定时器
  scanPolling: false,  // 防止两次 status 请求重叠
  scanCancelled: false,// 已请求取消，等服务端在账号边界停下
  scanBusy: false,     // start 请求在途时也占住入口，防止连点发两次 start
  scanFailStreak: 0,   // 连续失败的状态请求次数；成功一次清零，满 3 次才停轮询
  renderedAccounts: new Set(), // 结果板已建组的账户 key：只追加新组，永不重建
  scanGroups: new Map(),       // 结果板：保持服务端输入顺序，已渲染行永不重建
  scanFailures: new Map(),     // 结果板：已渲染的失败行
  scanKeysByEmail: new Map(),  // 用邮箱把 results / errors 的同一账户对齐
  scanKeysById: new Map(),
  scanKeySeq: 0,
  scanCodeCount: 0,
  scanBoardJobId: null,         // 结果板这块 DOM 当前属于哪个 jobId
  scanGroupsBox: null,         // 分组容器：只追加，永不重建已渲染行
  scanFailuresBox: null,
  scanFailureList: null,
  scanAutoCopyBackup: false,
  scanAutoCopyLocked: false,
  scanBoardDismissed: false,
  diagSeq: 0,          // 端点诊断的序号（竞态守卫：快速开两个账户的诊断）

  /* 验证码历史（独立视图）。items 是服务端返回的**当前筛选下**的那一页（≤500 条），
   * total 是同一筛选条件下的总数（可能大于 items.length）。
   * selected 只存 id：渲染会整表重绘，不能把勾选状态存在 DOM 里。 */
  history: {
    items: [],
    total: 0,
    selected: new Set(),
    seq: 0,             // 竞态守卫：切筛选时作废在途响应
    loading: false,
    writing: false,     // 标记在途：防止连点叠加写请求
    open: false,
    emptyReason: '',    // none | filtered | unknown | checking
    filters: { q: '', accountId: '', onlyUnused: false, sinceHours: '' },
  },
};

/* ============ 可变模块级状态（弹窗 / 菜单）============
 * 这两个不能用 const state 里的字段承载：一个是 Promise 的 resolve 句柄，
 * 一个是挂在 document / window 上的监听器闭包集合。
 * 声明放在最上面，是因为 closeModal()（通用确认弹窗要按取消结算）
 * 和 renderAccounts()（整表重绘要先关菜单）都要读它们，
 * 放在后面会踩 let 的暂时性死区。
 */
let pendingConfirm = null;   // { resolve } —— 同一时刻只允许一个 pending 确认
let openMenu = null;         // { id, root, item, anchor, onDocDown, onScroll, onResize, onFocusOut }
let pfPicker = null;         // 平台选择器的暂存状态（见 openPlatformPicker）

/**
 * 平台选择器的自增序号（竞态守卫）。
 *
 * 只有「完成」按钮会产生异步写请求，而弹窗可以被 Esc / 遮罩 / ✕ 在任何时刻关掉。
 * 没有这个序号时实测有三个后果：
 *   1. 点完成 → Esc → 请求回来照样写库 + toast 成功（用户以为取消了）
 *   2. 取消后再开另一个账户的弹窗 → 旧请求返回 → closeModal 把**新弹窗**关掉
 *   3. 旧请求把 #pfDone 的 disabled 状态留在新弹窗上
 * 每次打开 / 关闭弹窗都 ++，在途的提交发现序号变了就丢弃全部界面副作用。
 */
let pfPickerSeq = 0;

/* ============ API ============ */
async function api(action, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;

  const res = await fetch('/api?action=' + encodeURIComponent(action), {
    method: body === undefined ? 'GET' : 'POST',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  let data;
  try { data = await res.json(); }
  catch { throw new Error('服务器返回了无法解析的内容'); }

  if (!res.ok || data.ok === false) {
    // 把 HTTP 状态码挂到 Error 上：批量收码轮询要据此区分
    // "任务已丢失（404，服务重启过）" 和 "一次网络抖动（无限重试即可）"，
    // 只靠 message 文本判断太脆。
    const err = new Error(data.error || ('请求失败 HTTP ' + res.status));
    err.status = res.status;
    // ok:false 是服务端明确拒绝（任务不存在/已过期也算），不是网络抖动
    err.apiOkFalse = !!(data && data.ok === false);
    err.code = data && data.code != null ? String(data.code) : '';
    // 服务端同时给了 error（细节，如"单账号扫描超时（25 秒），已断开连接"）
    // 和 reason（归类，如"网络超时或连接被重置"），两者都已脱敏。
    // 以前只读 error，reason 算完就被丢掉；挂在这里供展示层在不改变
    // err.message 语义的前提下补充归类信息。
    err.reason = data && data.reason != null ? String(data.reason) : '';
    throw err;
  }
  return data;
}

/**
 * 统一的错误展示文案：以 err.message 为准，reason 只在**有内容且与 message
 * 不同**时追加在后面。
 *
 * 为什么单独抽一个函数：服务端在错误响应里同时给了 error（细节，如"单账号
 * 扫描超时（25 秒），已断开连接"）和 reason（归类，如"网络超时或连接被
 * 重置"），两个都脱敏过。此前前端只读 error，reason 算完就被丢掉 —— 于是
 * 500 类错误用户只能看到"服务器内部错误，详见终端日志"，而真正的归类
 * （超时 / 证书 / 令牌失效）就在响应里，却没人展示。
 *
 * 注意：绝不改写 err.message 本身。批量收码轮询等处按 message 文本做过
 * 判断，改语义会连带改坏那些分支。
 */
function errText(err, fallback) {
  const msg = err && err.message ? String(err.message) : (fallback || '未知错误');
  const reason = err && err.reason ? String(err.reason) : '';
  if (!reason || reason === msg) return msg;
  return msg + '（' + reason + '）';
}

/* ============ DOM 帮助 ============ */
const $ = id => document.getElementById(id);

/**
 * DOM 上只需要加一次的无障碍属性。放在 JS 里而不是 index.html，
 * 是因为这几处都是"功能存在才该宣告"的角色：
 * - #toast 是 role="status" + aria-live="polite"：成功提示不该打断读屏，
 *   但必须被念出来，否则整个应用对读屏用户是"点了没反应"。
 * - #pfErr 是 role="alert"：表单错误必须立刻打断，用户才不会在错误的
 *   前提下继续点「完成」。
 * HTML 里也能写，但这两个元素只在 JS 控制下才有内容，写在这里更内聚；
 * 重复调用是幂等的，bind() 里调一次即可。
 */
function initA11y() {
  const t = $('toast');
  if (t) {
    t.setAttribute('role', 'status');
    t.setAttribute('aria-live', 'polite');
    t.setAttribute('aria-atomic', 'true');
  }
  const pe = $('pfErr');
  if (pe) pe.setAttribute('role', 'alert');
  const ce = $('addErr');
  if (ce) ce.setAttribute('role', 'alert');
  const ie = $('importErr');
  if (ie) ie.setAttribute('role', 'alert');
  const cme = $('composeErr');
  if (cme) cme.setAttribute('role', 'alert');
  const de2 = $('diagErr');
  if (de2) de2.setAttribute('role', 'alert');
}

/**
 * 关键安全函数：所有来自邮件/用户输入的文本在插入 HTML 前必须转义。
 * 上一版工具就是因为漏了这一步，导致任何人发一封 HTML 邮件
 * 就能在页面里执行脚本、读走全部凭据。
 */
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
 * 屏幕阅读器播报（#srStatus 见 index.html）。
 *
 * 为什么不能只靠 toast：toast 是视觉反馈，读屏用户看不见。而"已标记为已用"
 * "已清理 12 条"这类操作不改变页面结构（行还在、只是样式变了），
 * 读屏器不会主动重读，用户会觉得"点了没反应"。aria-live 是唯一的通知渠道。
 *
 * 同一个字符串连续播两次时部分读屏器不会重读，末尾补一个零宽空格破重。
 * 元素不存在时静默跳过：不能因为缺一个纯无障碍节点让功能整体抛错。
 */
function announce(msg) {
  const el = $('srStatus');
  if (!el) return;
  const s = String(msg == null ? '' : msg);
  el.textContent = el.textContent === s ? s + '\u200B' : s;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const pad = n => String(n).padStart(2, '0');
  if (sameDay) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (d.getFullYear() === now.getFullYear()) return `${d.getMonth() + 1}/${d.getDate()}`;
  return `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()}`;
}

function fmtSize(n) {
  if (!n) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}

/** 相对完整的本地时间，结果板里不能只显示月日，免得看不出是今天还是伪造的未来日期 */
function fmtCodeDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * 从 From 中取出发件人域名。
 * 不用邮箱地址的正则去"猜"整串：常见格式既有 Display <addr@dom> 也有裸地址，
 * 先取最后一对尖括号里的地址（没有则取整串），再取最后一个 @ 之后的部分。
 * 域名单独整列展示、绝不截断，避免 github.com.evil.com 的尾巴被 ellipsis 吞掉。
 *
 * 无论解析失败还是 from 为空，都必须返回「（未知发件人）」——
 * 留空字符串会让这一列看起来像"没有域名"，反而更安全可信的错觉。
 */
const UNKNOWN_SENDER = '（未知发件人）';
function senderDomain(from) {
  const raw = String(from == null ? '' : from).trim();
  if (!raw) return UNKNOWN_SENDER;
  const lt = raw.lastIndexOf('<');
  const gt = raw.lastIndexOf('>');
  const addr = (lt >= 0 && gt > lt) ? raw.slice(lt + 1, gt) : raw;
  const at = addr.lastIndexOf('@');
  const dom = at >= 0
    ? addr.slice(at + 1).trim().replace(/[;,]+$/, '').replace(/^>+/, '').trim()
    : '';
  if (!dom) return UNKNOWN_SENDER;
  return dom.toLowerCase();
}

/**
 * 域名最后两级加粗，让欺骗性后缀（如 github.com.evil.com）更显眼。
 * 例如 github.com.evil.com → "github.com." 正常字重 + "evil.com" 加粗，
 * 用户一眼看到真正的主域是 evil.com，不是被前缀诱导的 github.com。
 * 所有片段都必须过 esc()，域名来自邮件 From 头，是攻击者完全可控的字符串。
 */
function domainHtml(domain) {
  const str = String(domain == null ? '' : domain);
  if (!str || str === UNKNOWN_SENDER) return esc(UNKNOWN_SENDER);
  const parts = str.split('.').filter(Boolean);
  if (parts.length < 2) return esc(str);
  const tail = esc(parts.slice(-2).join('.'));
  const headParts = parts.slice(0, -2);
  const head = headParts.length ? esc(headParts.join('.') + '.') : '';
  return `${head}<b>${tail}</b>`;
}

/**
 * 弹窗开关。
 * 新加的 #modalConfirm / #modalDiagnose 在 HTML 上带 hidden 属性（首屏不闪），
 * 而样式里 [hidden] { display:none !important } 会盖掉 .modal.show，
 * 所以打开时必须先摘掉 hidden、关闭时再写回去。老弹窗没有 hidden 属性，
 * 摘/写都是幂等的，不影响它们。
 *
 * `.app` 上的 inert（F2-10）：实测弹窗打开时，弹窗外仍有 64 个元素可以被 Tab
 * 聚焦——焦点跑到被遮住的侧栏和工具栏上，键盘 / 读屏用户会彻底迷路。
 * inert 一行就把整块背景移出可聚焦树和无障碍树，Chrome/Edge/Safari 都支持。
 * 弹窗本身是 .app 的兄弟节点，不会被一起 inert。
 *
 * 关闭时把焦点还给触发元素：焦点若留在已经被隐藏的弹窗里，浏览器会把它
 * 扔到 <body>，键盘用户下一次 Tab 要从页面顶部重新开始。
 */
function openModal(id) {
  const el = $(id);
  if (!el) return;
  // 记住是谁打开的（同一时刻只记最近一次，弹窗不会嵌套到需要栈的程度）
  if (!el._pfOpener && document.activeElement && document.activeElement !== document.body) {
    el._pfOpener = document.activeElement;
  }
  el.hidden = false;
  el.classList.add('show');
  setAppInert(true);
}
function closeModal(id) {
  const el = $(id);
  if (!el) return;
  el.classList.remove('show');
  el.hidden = true;
  // 确认弹窗被 ✕ / 取消 / 遮罩 / Esc 关掉时，一律按"取消"结算
  if (id === 'modalConfirm') settleConfirm(false);
  // 关掉诊断弹窗后，在途的诊断响应不能再写回这块 DOM（否则下次打开会闪出旧结果）
  if (id === 'modalDiagnose') state.diagSeq++;
  // 关掉平台选择器就丢掉暂存的选择：下次打开必须从当前账户的真实状态开始，
  // 否则一次取消过的勾选会静默留在下一次的提交里。
  if (id === 'modalPlatforms') {
    pfPicker = null;
    // 作废在途提交的全部界面副作用（见 pfPickerSeq 的注释）。
    // 提请求这件事拦不住（已经发出去了），但至少不改库以外的任何东西：
    // 不 toast、不关新弹窗、不动新弹窗的按钮。
    pfPickerSeq++;
    // 错误信息属于这次打开的弹窗，关掉就清；留到下次打开会显示一条
    // 与用户当前操作毫无关系的红字。
    const errEl = $('pfErr');
    if (errEl) errEl.textContent = '';
  }
  // 只有这一层弹窗都不在了，才把背景恢复成可交互：
  // 确认弹窗可以叠在平台选择器上（askConfirm 从 picker 里调用），
  // 关掉上层时把 .app 解 inert 不会影响下层弹窗（它本来就不在 .app 里）。
  setAppInert(!!document.querySelector('.modal.show'));
  // 焦点还给触发元素，避免掉到 <body>
  const opener = el._pfOpener;
  el._pfOpener = null;
  if (opener && opener.isConnected) {
    try { opener.focus({ preventScroll: true }); } catch { /* 元素已不可聚焦，忽略 */ }
  }
}

/** 背景是否对键盘 / 读屏不可交互。用属性而不是直接改 .inert，兼容旧浏览器 */
function setAppInert(on) {
  const app = document.querySelector('.app');
  if (!app) return;
  if (on) app.setAttribute('inert', '');
  else app.removeAttribute('inert');
}

/* ============ 剪贴板 ============ */
/**
 * 复制到剪贴板。
 * 优先用 Clipboard API；它在非 https/非 localhost 环境会失败，
 * 所以保留 execCommand 兜底。两种方式都在本地完成，不经过网络。
 */
async function copyText(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* 落到兜底 */ }

  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

/** 复制并提示 */
async function copyWithToast(text, label) {
  const ok = await copyText(text);
  if (ok) {
    toast('已复制' + (label ? '：' + label : ''));
    return true;
  }
  toast('复制失败，请手动选择文本', 'err');
  return false;
}

/* ============ 复制按钮的即时反馈 ============ */
/**
 * 复制成功后把按钮短暂切成"已复制 ✓"。
 * 用户每天复制上百次，"点了到底成没成"不能只靠底部 toast——
 * 视线在按钮上，toast 在屏幕底部。
 *
 * 宽度用 CSS min-width 锁死（见 style.css 的 .copied），否则文案变长
 * 会把整条工具栏推一下，在密集操作里非常烦人。
 * 连点时先清掉上一个计时器，否则旧的回调会把新的反馈提前抹掉。
 */
function flashCopied(btn, ms = 1200) {
  if (!btn) return;
  clearTimeout(btn._copyTimer);
  if (btn._copyText === undefined) btn._copyText = btn.textContent;
  btn.textContent = '已复制 ✓';
  btn.classList.add('copied');
  btn._copyTimer = setTimeout(() => {
    btn.classList.remove('copied');
    btn.textContent = btn._copyText;
    btn._copyText = undefined;
  }, ms);
}

/* ============ 长任务的实时计时器 ============ */
/**
 * 给按钮挂一个每 200ms 刷新一次的文案：用户能看到秒数在走，
 * 就知道"程序还在干活"，而不是盯着一个不动的"检测中…"怀疑卡死。
 *
 * label(elapsedMs) 返回要显示的文案；返回 null 表示"这一拍不改文案"
 * （例如已经进入下一阶段、由调用方自己接管）。
 *
 * 返回的 stop() 幂等，且必须放在 finally 里调用——
 * 请求抛错时若漏了 clearInterval，按钮会永远停在"正在扫描（40s）"。
 */
function startTicker(btn, label) {
  const t0 = Date.now();
  let stopped = false;
  const tick = () => {
    if (stopped) return;
    const ms = Date.now() - t0;
    const text = label(ms);
    if (text != null) btn.textContent = text;
  };
  // 不立刻跑第一拍：调用方刚设的"连接中…"应该先被用户看到一眼，
  // 200ms 后才切成带秒数的阶段文案。
  const timer = setInterval(tick, 200);
  return function stop() {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
  };
}

/** 秒数保留一位小数：200ms 一跳，一位小数刚好每次都在变 */
function fmtSec(ms) {
  return (Math.max(0, ms) / 1000).toFixed(1) + 's';
}

/* ============ 骨架屏 ============ */
/**
 * 先渲染 nothing，250ms 后仍未完成才插入骨架。
 *
 * 为什么必须延迟：邮件通常 30-80ms 就回来了。无条件插骨架会
 * 在每一封邮件、每一次刷新时闪一下灰块，比"加载中…"刺眼得多。
 * 只有真的慢（网络抖、服务忙）才让它出现，这时它才有意义。
 *
 * 不新增 state 时序字段：每个调用点自己持有 token，
 * 通过闭包比较"我还是不是最新那次"（与 msgSeq/openSeq 同一思路）。
 */
function showSkeletonLater(box, html, isStale, delay = 250) {
  const timer = setTimeout(() => {
    if (isStale()) return;
    if (box) box.innerHTML = html;
  }, delay);
  return () => clearTimeout(timer);
}

/** 邮件列表骨架：5 行，宽度刻意不等宽，看起来像真实邮件而不是表格 */
function skeletonMessagesHtml() {
  const widths = [
    [68, 84, 52],
    [54, 76, 40],
    [72, 88, 60],
    [48, 70, 44],
    [64, 80, 56],
  ];
  return widths.map(([a, b, c]) =>
    `<div class="skel-msg">
       <div class="skel-bar" style="width:${a}%"></div>
       <div class="skel-bar" style="width:${b}%"></div>
       <div class="skel-bar" style="width:${c}%"></div>
     </div>`).join('');
}

/** 正文骨架：标题 + 3 条 meta + 6 行不等宽正文，全部顶部对齐 */
function skeletonDetailHtml() {
  const body = [96, 88, 94, 62, 90, 74];
  return `<div class="mail-detail skel-detail">
    <div class="skel-bar skel-title" style="width:70%"></div>
    <div class="skel-bar skel-meta" style="width:34%"></div>
    <div class="skel-bar skel-meta" style="width:45%"></div>
    <div class="skel-bar skel-meta" style="width:28%"></div>
    <div class="skel-gap"></div>
    ${body.map(w => `<div class="skel-bar skel-body" style="width:${w}%"></div>`).join('')}
  </div>`;
}

/** 结构化错误态：标题 + 原因 + 重试按钮（data-retry 由容器上的委托处理） */
function errorStateHtml(title, message, retryTarget) {
  return `<div class="state state-error">
    <div class="state-title">${esc(title)}</div>
    <div class="state-desc">${esc(message)}</div>
    <button class="btn btn-sm" type="button" data-retry="${esc(retryTarget)}">重试</button>
  </div>`;
}

/* ============ 渲染：验证码面板 ============ */
function renderCodePanel(codes) {
  const box = $('codePanel');
  if (!codes.length) {
    box.classList.remove('show');
    return;
  }
  box.innerHTML = `
    <div class="code-panel-head">
      <span>找到 ${codes.length} 个验证码</span>
      <button class="code-panel-close" id="codePanelClose">✕</button>
    </div>
    <div class="code-panel-list">
      ${codes.map(c => `
        <div class="code-row">
          <span class="code-row-value">${esc(c.code)}</span>
          <span class="code-row-meta" title="${esc(c.subject)}">${esc(c.from || '')}</span>
          <span class="code-row-time">${esc(fmtDate(c.date))}</span>
          <button class="code-row-copy">复制</button>
        </div>`).join('')}
    </div>`;
  box.classList.add('show');

  $('codePanelClose').onclick = () => box.classList.remove('show');
  // 单账户面板也用闭包固定码值：data-* 只承载 id/索引，不承载邮件内容。
  // 复制成功后按钮就地切成"已复制 ✓"，不再只靠底部 toast。
  box.querySelectorAll('.code-row-copy').forEach((btn, i) => {
    const code = codes[i] && codes[i].code;
    btn.onclick = async ev => {
      ev.stopPropagation();
      const ok = await copyWithToast(code, code);
      if (ok) flashCopied(btn);
    };
  });
  box.querySelectorAll('.code-row').forEach((row, i) => {
    const code = codes[i] && codes[i].code;
    row.onclick = () => copyWithToast(code);
  });
}

/* ============ 渲染：账户列表 ============ */

/**
 * 单个账户是否命中当前筛选。renderAccounts 与 filteredAccountIds 必须用
 * 完全相同的条件，否则"全选当前筛选"会选进看不见的行。
 * 三个条件是「与」关系：关键词 且 分组 且 平台。
 *
 * pf === '__none__' 是「未标注」：没有任何平台 key 的账户。
 * 这是个保留值，用户的自定义平台 key 不可能是它（key 由 trim 后的原文小写而来，
 * 这里的下划线是前端自己造的选择器值，不会写进库）。
 */
const PF_FILTER_NONE = '__none__';

function matchesFilters(a, kw, grp, pf) {
  if (kw && !(a.email.toLowerCase().includes(kw) || (a.label || '').toLowerCase().includes(kw))) return false;
  if (grp && a.group !== grp) return false;
  // 老数据没有 platforms 字段（B1 上线前 / 从未标注过），按空数组处理
  if (pf === PF_FILTER_NONE) return pfKeys(a).length === 0;
  if (pf && !pfKeys(a).includes(pf)) return false;
  return true;
}

/** 与 renderAccounts 相同的筛选条件，用于"全选当前筛选" */
function filteredAccountIds() {
  const kw = state.filterText.toLowerCase();
  const grp = state.filterGroup;
  const pf = state.filterPlatform;
  return state.accounts.filter(a => matchesFilters(a, kw, grp, pf)).map(a => a.id);
}

/**
 * 选中集合只存 state.selected；这里仅同步计数、全选框和批量条的显隐。
 *
 * 全选框的状态必须是「当前可见行」的全选状态：过滤后如果可见行都选了，
 * 它才该打勾。用全量 accounts 判断的话，用户筛选出一个子集、
 * 只勾了这几行，全选框会一脸没选中的样子，点一下反而去取消别的账户。
 *
 * 计数显示的必须是「全部选中数」（批量操作也作用于全部选中，
 * 不是可见的那几行），但要额外提示其中有多少个不在当前筛选里，
 * 否则用户按可见行数核对数字会对不上，以为程序算错了。
 */
function updateSelectionUI() {
  const n = state.selected.size;
  const ids = filteredAccountIds();
  const visibleSelected = ids.filter(id => state.selected.has(id)).length;
  const hiddenSelected = n - visibleSelected;

  const all = $('chkSelectAll');
  all.checked = ids.length > 0 && visibleSelected === ids.length;
  all.indeterminate = visibleSelected > 0 && !all.checked;

  let selText = `已选 ${n} 个`;
  if (hiddenSelected > 0) selText += `（其中 ${hiddenSelected} 个不在当前筛选里）`;
  $('selCount').textContent = selText;
  $('selCount').title = hiddenSelected > 0
    ? `共选中 ${n} 个账户，其中 ${hiddenSelected} 个不在当前筛选结果中；批量操作仍会作用于它们`
    : '';
  $('bulkCount').textContent = n + ' 个';
  $('bulkBar').hidden = n === 0;
  // 批量操作作用于全部选中（含当前不可见的）；按钮上写明数字，
  // 避免用户"以为只扫了可见的 3 个"。
  const bulkBtn = $('btnBulkCodes');
  if (bulkBtn) {
    bulkBtn.title = hiddenSelected > 0
      ? `对全部选中的 ${n} 个账户收验证码（含 ${hiddenSelected} 个不在当前筛选里的）`
      : `对选中的 ${n} 个账户收验证码`;
  }
}

/**
 * 写入统计数字，只在数值真的变了时短暂高亮一下。
 *
 * 为什么不做 count-up 滚动：从 100 滚到 98 的中途会显示"99"，
 * 那一瞬间屏幕上的数字是错的，用户又恰好会在这个瞬间扫一眼。
 * 一次性高亮表达"这里更新了"，且任何时刻都只显示真实值。
 */
function setStatNum(id, value) {
  const el = $(id);
  if (!el) return;
  const next = String(value);
  if (el.textContent === next) {
    // 长度可能变化（0 → 0 不会，但 3 → 12 会），零值样式每帧都要同步
    if (id === 'statBad') el.classList.toggle('zero', next === '0');
    return;
  }
  el.textContent = next;
  if (id === 'statBad') el.classList.toggle('zero', next === '0');
  el.classList.remove('changed');
  // 强制重排以确保同一元素上连续的 class 变化能重放动画/高亮
  void el.offsetWidth;
  el.classList.add('changed');
  clearTimeout(el._changedTimer);
  el._changedTimer = setTimeout(() => el.classList.remove('changed'), 400);
}

function renderAccounts() {
  const list = $('accountList');
  const kw = state.filterText.toLowerCase();
  const grp = state.filterGroup;
  const pf = state.filterPlatform;
  // 整表重绘会销毁菜单所在的 DOM 节点：先干净关掉，别留下悬空的全局监听
  closeAccountMenu();
  updateSelectionUI();
  syncCopyEmailButton();
  // 检测 / 删除后状态会变（可用 ↔ 异常），工具栏徽章要跟着更新，
  // 否则侧栏统计已经变了、右上角还挂着旧的"可用"。
  applyCurrentStatus(state.currentId
    ? state.accounts.find(a => a.id === state.currentId) || null
    : null);

  const filtered = state.accounts.filter(a => matchesFilters(a, kw, grp, pf));

  // 统计。"异常 0" 不应该恒为红色，否则整个侧栏看起来一直在报错。
  setStatNum('statTotal', state.accounts.length);
  setStatNum('statOk', state.accounts.filter(a => a.status === 'ok').length);
  setStatNum('statBad', state.accounts.filter(a => a.status === 'failed' || a.status === 'banned').length);

  // 分组下拉
  const groups = [...new Set(state.accounts.map(a => a.group).filter(Boolean))];
  const sel = $('groupFilter');
  const prev = sel.value;
  sel.innerHTML = '<option value="">全部分组</option>' +
    groups.map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('');
  // 选中的分组消失了（删掉了它最后一个账户 / 改名）：select 必须回到"全部分组"，
  // 而且 state.filterGroup **也要一起复位**——只改 sel.value 的话界面显示
  // "全部分组"、matchesFilters 却还按旧分组过滤，列表直接空白，
  // 用户点一下"全部分组"才恢复，看起来像"筛选器自己坏了"。
  const stillExists = groups.includes(prev);
  sel.value = stillExists ? prev : '';
  if (!stillExists && state.filterGroup) state.filterGroup = '';

  renderPlatformFilter();

  if (!filtered.length) {
    list.innerHTML = state.accounts.length
      ? '<div class="empty">没有匹配的账户</div>'
      : '<div class="empty">还没有账户<br><small>点击“添加账户”开始</small></div>';
    return;
  }

  // 全量重绘会重置 scrollTop。100 个账户时，滚到第 80 个再筛选就跳回顶部，
  // 这里保存/恢复滚动位置。
  const keepScroll = list.scrollTop;

  list.innerHTML = filtered.map(a => {
    const statusCls = a.status === 'ok' ? 'ok' : (a.status === 'failed' || a.status === 'banned') ? 'bad' : 'unknown';
    const active = a.id === state.currentId ? ' active' : '';
    return `<div class="account-item${active}" data-id="${esc(a.id)}">
      <input class="account-check" type="checkbox" aria-label="选择 ${esc(a.email)}"${state.selected.has(a.id) ? ' checked' : ''}>
      <div class="dot ${statusCls}"></div>
      <div class="account-info">
        <div class="account-email">${esc(a.email)}</div>
        <div class="account-meta"${a.statusMessage ? ` title="${esc(a.statusMessage)}"` : ''}>${esc(a.group || '默认')}${a.statusMessage ? ' · ' + esc(a.statusMessage) : ''}</div>
        ${platformChipsHtml(a)}
      </div>
      <button class="account-menu" data-menu="${esc(a.id)}" title="更多">⋯</button>
    </div>`;
  }).join('');

  list.scrollTop = keepScroll;
}

/**
 * 列表行里的平台 chip（规格 §4.1）：最多 3 个，超出显示「+N」。
 * 没有任何平台时返回空字符串——绝不渲染空占位，100 行都空着会很丑。
 * 文字一律过 esc()：key 虽由后端归一化成小写，但 B1 上线前 / 异常数据里
 * 仍可能是任意字符串。
 *
 * 两个结构细节是别的修复项要求的，不要"简化"掉：
 * - 文字包在 <span class="pf-chip-t"> 里：flex 容器上的 text-overflow: ellipsis
 *   对匿名文本无效，窄窗口下 chip 被压扁时「×」会被裁到点不到（规格 F3-1）。
 *   CSS 那边的省略号挂在这个 span 上，前端不包就完全不起作用。
 * - 容器是 role="list" + 每个 chip role="listitem"：读屏用户听到的是
 *   "列表，3 项"而不是 3 个孤立的词。
 */
function platformChipsHtml(acc) {
  const keys = pfKeys(acc);
  if (!keys.length) return '';
  const names = pfNamesMap(acc);
  const shown = keys.slice(0, 3);
  const rest = keys.length - shown.length;
  const chips = shown.map(k =>
    `<span class="pf-chip" role="listitem" style="${pfStyle(k)}">` +
    `<span class="pf-chip-t">${esc(pfName(k, names))}</span></span>`
  ).join('');
  const restKeys = keys.slice(3);
  const restLabel = restKeys.map(k => pfName(k, names)).join('、');
  return `<div class="account-platforms" role="list" aria-label="平台标注（${keys.length} 个）">${chips}${
    // +N 也能聚焦：它是这些平台名唯一可读的位置（完整列表在 title 里，
    // 而 title 只有鼠标悬停才出现，键盘和读屏都拿不到）。
    // 用 <span tabindex="0"> 而不是 <button>：它不触发任何动作，按钮语义会误导；
    // 而且 style.css 里没有 button 重置，换成 button 会带出 UA 的边框和底色
    // （那个文件不归 F2 改，不能顺手给它加规则）。role="listitem" 让
    // aria-label 成为读屏能念出来的节点名。
    rest > 0
      ? `<span class="pf-more" role="listitem" tabindex="0" ` +
        `aria-label="另有 ${rest} 个平台：${esc(restLabel)}" ` +
        `title="${esc(restLabel)}">+${rest}</span>`
      : ''
  }</div>`;
}

/**
 * 侧栏平台筛选器（规格 §4.3）。选项来自 accounts.platformStats，显示「GitHub (12)」。
 * 统计拿不到时（B1 未实现 / 请求失败）只留「全部平台」，绝不弹错误框——
 * 筛选器是辅助功能，不是主流程。
 * 当前选中的平台即使已经不在统计里（最后一个标注被去掉了），也要保留一个
 * 「名称 (0)」选项：否则 select.value 会被浏览器重置成 ''，用户会看到
 * "筛选项自己跳回全部平台"，而他明明什么都没点。
 *
 * 「未标注 (N)」的计数从 state.accounts 本地算：服务端的 platformStats 只统计
 * 「被用到过的平台」，压根没有"零平台"这个概念，为此改服务端接口不值得。
 * 同时它也是"0 平台账户"唯一的入口——这类账户在任何平台筛选下都不出现。
 */
function renderPlatformFilter() {
  const sel = $('platformFilter');
  if (!sel) return;
  const cur = state.filterPlatform;
  const stats = Array.isArray(state.pfStats) ? state.pfStats : [];
  const opts = stats.filter(s => s && typeof s.key === 'string' && s.key);
  const hasCur = opts.some(s => s.key === cur);
  const noneCount = state.accounts.filter(a => pfKeys(a).length === 0).length;

  // 「未标注」永远在列表里（哪怕 0 个）：位置固定，用户不必等出现才找得到它。
  // 放在平台列表**之后**而不是之前：常用筛选要靠近"全部平台"，一眼可达。
  sel.innerHTML = '<option value="">全部平台</option>' + opts.map(s => {
    const n = Number(s.count) || 0;
    return `<option value="${esc(s.key)}">${esc(s.name || pfName(s.key))} (${n})</option>`;
  }).join('') + `<option value="${PF_FILTER_NONE}">未标注 (${noneCount})</option>` +
  // 只有 cur 既不是保留值、也不在统计里时才补「(0)」占位项
  (cur && cur !== PF_FILTER_NONE && !hasCur
    ? `<option value="${esc(cur)}">${esc(pfName(cur))} (0)</option>`
    : '');

  sel.value = cur || '';
}

/**
 * 只切换高亮行，不重建列表。
 * 点账户时若走整表重绘，100 个账户的滚动位置会归零——
 * 用户滚到第 80 个点开，列表立刻弹回顶部，下一个账户又要重新滚。
 */
function setActiveAccountRow(id) {
  const list = $('accountList');
  const prev = list.querySelector('.account-item.active');
  if (prev) prev.classList.remove('active');
  if (!id) return;
  // id 是 crypto.randomUUID()，形如 8-4-4-4-12，可以安全地放进属性选择器；
  // 仍用 CSS.escape 兜底，避免将来 id 换成别的格式时炸掉选择器。
  const next = list.querySelector(`[data-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (next) next.classList.add('active');
}

/* ============ 平台标注：详情面板 / 选择器 / 批量 / 导出 ============ */

/** 当前选中的账户对象（没有就 null） */
function currentAccount() {
  return state.currentId
    ? state.accounts.find(a => a.id === state.currentId) || null
    : null;
}

/**
 * 详情面板的平台编辑区（规格 §4.2）。
 *
 * 这套界面里没有独立的"账户详情页"——账户信息只出现在两处：
 * 侧栏列表行（.account-meta）和工具栏头部（#currentEmail + 状态徽章）。
 * 所以编辑区放在工具栏正下方（#pfEditor），紧贴 #currentEmail，
 * 属于账户信息区而不是邮件区（邮件区是 .content 里的 #msgList / #msgView）。
 *
 * 每次切账户 / 平台变更后都要调它：chips 带 × 直接删除，点 ＋ 打开选择器。
 */
function renderPlatformEditor() {
  const box = $('pfEditor');
  if (!box) return;
  const acc = currentAccount();
  // 历史视图打开时这块必须藏起来：它不属于邮件区，不会跟着 #mailContent 一起隐藏。
  // 不判断的话，历史页开着点侧栏账户，账户信息条会突然横在历史表格上面。
  if (!acc || state.history.open) {
    box.hidden = true;
    return;
  }
  box.hidden = false;

  const keys = pfKeys(acc);
  const names = pfNamesMap(acc);
  const chips = $('pfChips');
  chips.setAttribute('role', 'list');
  chips.setAttribute('aria-label', `平台标注（${keys.length} 个）`);
  chips.innerHTML = keys.length
    ? keys.map(k =>
        `<span class="pf-chip" role="listitem" style="${pfStyle(k)}">` +
        // pf-chip-t 承担省略号，见 platformChipsHtml 的注释
        `<span class="pf-chip-t">${esc(pfName(k, names))}</span>` +
        `<button class="pf-x" type="button" data-pf-remove="${esc(k)}" ` +
        `aria-label="移除 ${esc(pfName(k, names))}" title="移除">×</button></span>`
      ).join('')
    : '<span class="pf-empty">还没有标注任何平台</span>';
}

/** 详情面板里点 × ：用 remove 模式去掉这一项（不用 replace，避免清空后传空数组被拒） */
async function removePlatformFromCurrent(key) {
  const acc = currentAccount();
  if (!acc) return;
  await submitPlatforms([acc.id], [key], 'remove', {
    toastText: `已移除 ${pfName(key, pfNamesMap(acc))}`,
    button: null,
  });
}

/**
 * 平台选择器（规格 §4.2 / §4.4 共用）。
 *
 * opts: { bulk, ids, email, mode }
 * - 单账户：mode 固定 replace，sel 预填该账户现有平台
 * - 批量：mode 由三个 radio 决定，sel 从空开始（用户选"要加/要去掉/要改成什么"）
 *
 * 选择结果存在 pfPicker.sel（Map<归一化 key, 原始显示名>），
 * 归一化规则与后端一致：trim、小写、单条 40 字符、去重。
 */
function openPlatformPicker(opts) {
  const o = opts || {};
  const bulk = o.bulk === true;
  const ids = Array.isArray(o.ids) ? o.ids.slice() : [];

  // 新的一次打开 = 作废上一次所有在途提交的界面副作用。
  // 注意：这里**不**取消已经发出的写请求（拦不住），只保证它回来后
  // 不再 toast、不再关这个新弹窗、不再动这个新弹窗的按钮。
  pfPickerSeq++;

  pfPicker = {
    bulk,
    ids,
    mode: bulk ? 'add' : 'replace',
    sel: new Map(),
    email: String(o.email || ''),
  };

  if (!bulk) {
    const acc = state.accounts.find(a => a.id === ids[0]);
    const names = pfNamesMap(acc);
    for (const k of pfKeys(acc)) pfPicker.sel.set(k, pfName(k, names));
  }

  $('pfTitle').textContent = bulk ? '批量标注平台' : '平台账号';
  $('pfSub').textContent = bulk
    ? `将对选中的 ${ids.length} 个账户执行下面的操作。`
    : (pfPicker.email ? '标注这个邮箱注册过哪些服务' : '');
  $('pfSub').hidden = !$('pfSub').textContent;
  $('pfModes').hidden = !bulk;
  $('pfErr').textContent = '';
  $('pfCustomInput').value = '';

  // 批量模式下每次打开都回到默认的「加上」，避免上次的选择被静默沿用
  document.querySelectorAll('input[name="pfMode"]').forEach(el => {
    el.checked = el.value === 'add';
  });
  // seq 变了之后在途提交不会再碰按钮，所以这里敢无条件复位：
  // 否则上一次提交留下的 disabled / "保存中…" 会挂在这颗按钮上（F2-5 第 3 条）。
  const doneBtn = $('pfDone');
  if (doneBtn) { doneBtn.disabled = false; doneBtn.textContent = '完成'; }

  renderPickerGrid();
  openModal('modalPlatforms');
  // 焦点落点：单账户选第一个已选 chip 的 ×（用户可以立刻移除），
  // 没有已选项就落到自定义输入框。之前一律聚焦输入框，
  // 想取消一个已选平台必须先 Shift+Tab 一圈。
  const firstX = $('pfChosen').querySelector('.pf-x');
  const inp = $('pfCustomInput');
  if (firstX) firstX.focus({ preventScroll: true });
  else if (inp) inp.focus({ preventScroll: true });
}

/** 一个平台 key 是否已在选择里 */
function pfPickerHas(key) {
  return !!(pfPicker && pfPicker.sel.has(key));
}

/**
 * 内置平台网格。
 *
 * 首次调用建 DOM，之后**只切换 class / aria-pressed，不重建**（F2-10）。
 * 原来每次点一下都 innerHTML 重写整个网格，后果是：
 *   1. 刚被点的那颗按钮从文档里消失 → 焦点掉到 <body>，键盘用户每点一次
 *      都要重新 Tab 回来才能选下一个平台
 *   2. 17 个按钮（含内联 style 与 ✓ 子节点）全量重建，选 10 个平台就重建 10 次
 * 选中标记（✓）也改成预先建好、用 hidden 切换。
 */
function renderPickerGrid() {
  const grid = $('pfGrid');
  if (!grid || !pfPicker) return;

  // 只在「还没建」或「建出来的数量和 PLATFORMS 对不上」时才重写 innerHTML。
  // 用 .pf-option 计数而不是 grid.children.length：后者把将来可能插入的分组标题、
  // 分隔线也算进去，会让守卫永远为真（等于没守卫）。PLATFORMS 是冻结常量，
  // 数量变化只可能来自代码改动，那时重建一次正是想要的。
  const opts = grid.querySelectorAll('.pf-option');
  if (grid.dataset.built !== '1' || opts.length !== PLATFORMS.length) {
    // 文字直接放在按钮里（不再包一层 span）：.pf-option 自己的 style.css
    // 规则（inline-flex + gap + 省略号）已经覆盖了它，多余的一层会改变
    // --pf-fg 继承和 ellipsis 的落点。
    grid.innerHTML = PLATFORMS.map(p =>
      `<button type="button" class="pf-option" data-pf-key="${esc(p.key)}" ` +
      `style="${pfStyle(p.key)}" aria-pressed="false">` +
      `<span class="pf-dot" aria-hidden="true"></span>${esc(p.name)}` +
      `<span class="pf-tick" aria-hidden="true" hidden>✓</span>` +
      `</button>`
    ).join('');
    grid.dataset.built = '1';
  }

  // 只同步状态。顺序与 PLATFORMS 一致，所以可以直接遍历；
  // 仍然按 data-pf-key 校验一遍，避免将来网格里插入别的节点时静默错位。
  for (const btn of grid.querySelectorAll('.pf-option')) {
    const key = btn.dataset ? btn.dataset.pfKey : '';
    if (!key) continue;
    const on = pfPickerHas(key);
    btn.classList.toggle('on', on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    const tick = btn.querySelector('.pf-tick');
    if (tick) tick.hidden = !on;
  }
  renderPickerChosen();
}

/** 已选区：把所有选中项列成 chip（含自定义平台），可点 × 取消 */
function renderPickerChosen() {
  const box = $('pfChosen');
  if (!box || !pfPicker) return;
  const entries = [...pfPicker.sel.entries()];
  box.setAttribute('role', 'list');
  box.setAttribute('aria-label', `已选 ${entries.length} 个平台`);
  if (!entries.length) {
    box.innerHTML = '<span class="pf-empty">还没有选择平台</span>';
    return;
  }
  box.innerHTML = entries.map(([k, name]) =>
    // .pf-chips 的 flex/gap 由 F3-2 从 .pf-editor 限定里放开，这里直接用即可。
    // pf-chip-t 承担省略号（F3-1），不包的话长平台名会把 × 推出可视区。
    `<span class="pf-chip" role="listitem" style="${pfStyle(k)}">` +
    `<span class="pf-chip-t">${esc(name)}</span>` +
    `<button class="pf-x" type="button" data-pf-unpick="${esc(k)}" ` +
    `aria-label="取消 ${esc(name)}" title="取消">×</button></span>`
  ).join('');
}

/**
 * 把用户输入归一化成平台 key；空串返回 null。与后端 normalizePlatforms 同规则。
 *
 * 截断必须复刻后端 truncateSafe 的语义：39 个 'a' + 一个 emoji（41 码元）时，
 * 裸 slice(0, 40) 会留下孤立的高位代理 \ud83d —— 它写进 JSON 变成 U+FFFD，
 * 于是「前端算出的 key」和「后端归一化后的 key」再也对不上：
 * 选择器里高亮的是一颗，库里存的是另一颗。
 */
function normalizePlatformKey(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return null;
  let cut = s.slice(0, 40);
  // 截断点落在代理对中间（末尾是高位代理）→ 回退一个字符
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xD800 && last <= 0xDBFF) cut = cut.slice(0, -1);
  return cut.toLowerCase();
}

/**
 * 前端侧的「显示名 → 内置 key」反查，与后端 platforms.js 的 BUILTIN_NAME_MAP 同规则。
 * 提交走 key 之后这条路径是兜底：自定义平台里用户完全可能手打 "X / Twitter"，
 * 不收归一化的话它会作为一个自定义平台存进去，和内置的 twitter 并存。
 */
const PF_BY_NAME = new Map(PLATFORMS.map(p => [p.name.toLowerCase(), p.key]));
function builtinKeyOf(lower) {
  if (PF_BY_KEY.has(lower)) return lower;
  return PF_BY_NAME.get(lower) || lower;
}

/** 添加一个平台到选择（内置用内置显示名，自定义保留原始大小写） */
function pickerAdd(raw) {
  if (!pfPicker) return;
  let key = normalizePlatformKey(raw);
  if (!key) return;
  // 反查要在截断之后：手打的 "X / Twitter" 要落回内置 key，否则会和
  // 网格里点选的 twitter 变成两颗 chip（这正是 F2-1 的现场）
  key = builtinKeyOf(key);
  if (pfPicker.sel.has(key)) return;
  if (pfPicker.sel.size >= 50) {
    $('pfErr').textContent = '一个账户最多标注 50 个平台';
    return;
  }
  $('pfErr').textContent = '';
  const builtin = PF_BY_KEY.get(key);
  // 自定义平台必须保留用户输入的原样大小写（输入 MyBlog 不能变成 myblog）。
  // 同一个截断规则：别把 emoji 切半个。
  const original = builtin ? builtin.name : truncateForDisplay(String(raw).trim());
  pfPicker.sel.set(key, original);
  renderPickerGrid();
}

/** 显示名截断：与 normalizePlatformKey 同一套代理对规则（只是不做小写化） */
function truncateForDisplay(s) {
  let cut = String(s == null ? '' : s).slice(0, 40);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xD800 && last <= 0xDBFF) cut = cut.slice(0, -1);
  return cut;
}

/** 从选择里去掉一个 key */
function pickerRemove(key) {
  if (!pfPicker) return;
  pfPicker.sel.delete(key);
  renderPickerGrid();
}

/**
 * 提交 platforms.set。mode: replace / add / remove。
 *
 * 成功后重新拉账户列表和平台统计，让服务端归一化的结果（自定义名大小写、
 * 去重、截断）落地——本地不自己猜归一化结果，那会和后端规则慢慢分叉。
 * 只重拉列表不改 selected，批量操作后用户的勾选因此得以保留（可以接着做下一个动作）。
 *
 * 两个 try 必须分开（F2-4）：写请求成功、只是刷新界面失败时，
 * 数据**已经在库里了**。合成一个 try 的话 catch 会报"保存失败"，
 * 用户重试一次 → 第二次同样是"失败"，而实际上第一次就成功了；
 * 更糟的是他会以为没生效，转头手工去改，把已经对的结果又改一遍。
 *
 * opts:
 *   toastText  自定义成功文案
 *   button     提交期间禁用的按钮
 *   errEl      错误写到哪（不给就 toast）
 *   seqGuard   () => boolean，返回 false 表示这次提交已被新的弹窗取代，
 *              则跳过**全部**界面副作用（toast / errEl / 按钮）
 */
async function submitPlatforms(ids, platforms, mode, opts) {
  const o = opts || {};
  const btn = o.button || null;
  const alive = typeof o.seqGuard === 'function' ? o.seqGuard : () => true;
  if (btn) { btn.disabled = true; }

  // ---- 第一段：写。这里失败才是真的失败 ----
  let d;
  try {
    d = await api('accounts.platforms.set', { ids, platforms, mode });
  } catch (e) {
    const msg = e && e.message ? e.message : '保存失败';
    // 弹窗已被取代时不要动按钮：那颗按钮现在属于另一个弹窗，
    // 解锁它会让人以为"上一个操作自己结束了"（F2-5 第 3 条）。
    if (btn && alive()) btn.disabled = false;
    if (alive()) {
      if (o.errEl) o.errEl.textContent = msg;
      else toast(msg, 'err');
    }
    return null;
  }

  // ---- 第二段：刷新界面。写已成功，失败也不能说"保存失败" ----
  let refreshFailed = false;
  try {
    await Promise.all([loadAccounts(), loadPlatformStats()]);
  } catch {
    refreshFailed = true;
  }

  // 刷新失败时只报这一条，不要再补一条"已更新 N 个"把警告顶掉——
  // toast 只有一个槽位，后写的覆盖先写的，用户就看不见"列表是旧的"这件事了。
  if (alive()) {
    if (refreshFailed) {
      toast('已保存，但列表刷新失败，请手动刷新', 'warn');
    } else if (o.toastText) {
      toast(o.toastText);
    } else if (d && typeof d.updated === 'number') {
      toast(`已更新 ${d.updated} 个账户`);
    }
  }
  return d;
}

/** 批量条上的「标注平台」：打开选择器，多一个模式选择 */
function openBulkPlatformPicker() {
  if (!state.selected.size) { toast('请先选择账户', 'warn'); return; }
  openPlatformPicker({ bulk: true, ids: [...state.selected] });
}

/**
 * 选择器「完成」：按当前模式提交。
 *
 * 提交的是 **key 数组**，不是显示名数组（F2-1 第 2 处）。
 * 传显示名时，'X / Twitter' 会在服务端被 toLowerCase 成 'x / twitter' 存进库 ——
 * 内置平台的 key 是 'twitter'，于是同一颗平台多出一个假 key：
 * chip 没有品牌色、筛选器分成两项、批量「去掉 twitter」静默不生效。
 *
 * 但自定义平台的原样大小写**只能**靠显示名保住（服务端的规则是
 * 「trim 后的原文当显示名、toLowerCase 后当 key」）。所以线上发的是
 * payload：内置平台发 key，自定义平台发显示名。两边都走 normalizePlatforms，
 * 内置 key 命中 BUILTIN_MAP、自定义名反过来落回同一个 key，不会分叉。
 */
async function submitPlatformPicker() {
  if (!pfPicker) return;
  const mySeq = pfPickerSeq;              // 本次提交的身份，每个 await 后都校验
  const err = $('pfErr');
  err.textContent = '';

  const keys = [...pfPicker.sel.keys()];
  if (!keys.length) {
    err.textContent = '请先选择至少一个平台';
    return;
  }
  const isBulk = pfPicker.bulk;
  const mode = isBulk ? pfPicker.mode : 'replace';
  const ids = pfPicker.ids.slice();
  const btn = $('pfDone');

  // 显示名只用于文案：key → 显示名（内置走内置表，自定义回退到用户输入的原文）
  const names = keys.map(k => pfName(k, pfPicker.sel));
  const label = names.join('、');
  const verb = mode === 'add' ? '加上' : mode === 'remove' ? '去掉' : '改为';

  // 真正发给服务端的数组：内置发 key（绝不发 'X / Twitter'），
  // 自定义发显示名（否则 MyBlog 会永久变成 myblog）。
  const payload = keys.map(k => (PF_BY_KEY.has(k) ? k : pfName(k, pfPicker.sel)));

  // ---- 批量「改为」必须二次确认（F2-3）----
  // replace 会**清空**每个账户原有的全部标注，库里没有任何撤销机制、也没有备份。
  // 选了 80 个已标注的账户误点「改为」＝ 80 个账户的标注一起没了，
  // 而且这事在 toast 里只表现为一句"已更新 80 个账户"，看不出代价。
  if (mode === 'replace' && ids.length > 1) {
    const ok = await askConfirm({
      title: '批量替换平台',
      message: `将把 ${ids.length} 个账户的平台替换为 ${label}，原有标注会被清除且无法恢复。继续？`,
      okText: '替换',
      danger: true,
    });
    // 确认框可能开了很久（用户去看别的东西了）：回来发现弹窗已经被换掉，
    // 这次提交必须整个放弃，绝不能拿着旧的选择去写库。
    if (mySeq !== pfPickerSeq) return;
    if (!ok) return;
  }

  const toastText = isBulk
    ? null   // 批量按 d.updated 分档生成，见 submitPlatforms 之后的处理
    : `平台已更新：${label}`;

  // 批量文案要按「实际改了几个」而不是「选了几个」：选 6 个账户去掉它们
  // 本来就没有的 Reddit 时，服务端返回 updated: 0，而旧文案会说
  // "已为 6 个账户去掉 Reddit" —— 用户以为改了，实际一条都没动（F2-6）。
  const alive = () => mySeq === pfPickerSeq;

  btn.disabled = true;
  btn.textContent = '保存中…';
  let r;
  try {
    r = await submitPlatforms(ids, payload, mode, {
      toastText,
      button: btn,
      errEl: err,
      seqGuard: alive,
    });
  } finally {
    // 只有还是本次弹窗时才复位按钮文案；否则那颗按钮属于新弹窗
    if (alive()) { btn.disabled = false; btn.textContent = '完成'; }
  }

  if (!alive()) return;              // 期间 Esc / 换弹窗：结果一个字都不许写出去
  if (!r) return;                    // 写失败，错误已进 #pfErr

  // 批量模式：按 updated 分档说清楚到底改了几个
  if (isBulk) {
    const n = ids.length;
    const u = Number(r.updated) || 0;
    if (u === 0) {
      toast(mode === 'remove'
        ? `这些账户本来就没有 ${label}`
        : `这些账户已经是 ${label}，没有变化`, 'warn');
    } else if (u < n) {
      toast(`已更新 ${u} / ${n} 个账户（其余无变化）`, 'warn');
    } else {
      toast(`已为 ${u} 个账户${verb} ${label}`);
    }
  }

  closeModal('modalPlatforms');
}

/** 平台统计（侧栏筛选器数据源）。失败不弹窗：筛选器退回只有「全部平台」 */
async function loadPlatformStats() {
  const seq = ++state.pfStatsSeq;
  try {
    const d = await api('accounts.platformStats');
    if (seq !== state.pfStatsSeq) return;
    const stats = Array.isArray(d && d.stats) ? d.stats : [];
    state.pfStats = stats.filter(s => s && typeof s.key === 'string' && s.key);
  } catch {
    if (seq !== state.pfStatsSeq) return;
    state.pfStats = [];   // B1 未上线 / 请求失败：静默降级
  }
  renderPlatformFilter();
}

/** 导出平台清单（规格 §4.5）：CSV + UTF-8 BOM，Excel 双击不乱码 */
async function exportPlatforms() {
  const btn = $('btnExportPlatforms');
  if (btn) btn.disabled = true;
  try {
    const d = await api('accounts.exportPlatforms');
    const raw = String(d && d.text != null ? d.text : '');
    // BOM 只能有一个：服务端若已带，先剥掉再统一补，避免出现两个
    const text = '\uFEFF' + raw.replace(/^\uFEFF+/, '');
    const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const d0 = new Date();
    const pad = n => String(n).padStart(2, '0');
    const stamp = `${d0.getFullYear()}${pad(d0.getMonth() + 1)}${pad(d0.getDate())}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `邮箱平台清单-${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // revoke 必须延后：立刻 revoke 在部分浏览器会打断还没开始的下载
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    const n = Number(d && d.count) || 0;
    toast(`已导出 ${n} 个账户的平台清单`);
  } catch (e) {
    toast(errText(e, '导出失败'), 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ============ 验证码历史 ============ */
/*
 * 后端 history.* 四个 action 早就写好了，但前端一直没有入口（"history" 在
 * app.js 里出现 0 次），用户永远看不到这些记录。这一节把它接出来。
 *
 * 为什么做成独立视图而不是弹窗：
 *  - 它是一张需要反复筛选、多选、逐行操作的表，弹窗里既待不住，Esc 一按
 *    筛选条件全丢；
 *  - 与邮件区是并列的两种"浏览对象"，不是某个账户的附属面板。
 * 视图切换隐藏邮件区（.content / #codePanel / #pfEditor / #mailToolbar），
 * 但批量收码的进度与结果板保持原样：那是一次全局任务的进度，不属于
 * 某个账户，扫着码的时候切过来看历史仍然要能看到它。
 */
let histSearchTimer = null;

const HIST_LIMIT = 200;   // 契约上限 500；200 条已经远超一屏，再大只是拖慢解密

/** 历史页里的统一时间格式：必须带年份和日期，历史记录跨天很常见 */
function fmtHistTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** 把当前筛选条件描述成一句人话，用于等待态与空态（让用户知道为什么空） */
function histFilterParts() {
  const f = state.history.filters;
  const parts = [];
  const q = String(f.q || '').trim();
  if (q) parts.push(`搜索「${q}」`);
  if (f.accountId) {
    const acc = state.accounts.find(a => String(a.id) === String(f.accountId));
    parts.push('账户 ' + (acc && acc.email ? acc.email : '（已不在账户列表）'));
  }
  if (f.onlyUnused) parts.push('只看未用');
  if (f.sinceHours) {
    const n = Number(f.sinceHours);
    const label = n === 1 ? '1 小时' : n === 24 ? '24 小时'
      : n === 72 ? '3 天' : n === 168 ? '7 天' : n + ' 小时';
    parts.push('最近 ' + label);
  }
  return parts;
}

/** 当前是否存在任何筛选条件 */
function histHasFilters() {
  const f = state.history.filters;
  return !!(String(f.q || '').trim() || f.accountId || f.onlyUnused || f.sinceHours);
}

/**
 * 账户下拉的数据源。复用 state.accounts（不额外发请求），
 * 但当前选中账户已不在列表里时仍要保留一个选项：
 * 否则 select.value 被浏览器重置成 ''，界面显示"全部账户"、
 * state 里却还按旧 id 过滤，列表空得莫名其妙。
 */
function renderHistoryAccountFilter() {
  const sel = $('histAccount');
  if (!sel) return;
  const cur = state.history.filters.accountId;
  const opts = state.accounts.map(a => ({ id: String(a.id), email: String(a.email || '') }));
  const hasCur = opts.some(o => o.id === cur);
  sel.innerHTML = '<option value="">全部账户</option>' + opts.map(o =>
    `<option value="${esc(o.id)}">${esc(o.email)}</option>`
  ).join('') + (cur && !hasCur
    ? `<option value="${esc(cur)}">已不在列表的账户</option>`
    : '');
  sel.value = cur || '';
}

/** 打开历史视图：隐藏邮件区、把焦点交给视图容器、按当前筛选拉数据 */
function showHistoryView() {
  if (state.history.open) return;
  state.history.open = true;
  $('historyView').hidden = false;
  // 邮件区的三块：正文/列表、验证码面板、平台编辑区，外加属于"当前账户邮件"
  // 的工具栏。批量收码的进度和结果板不隐藏（那是一次全局任务的进度，
  // 不属于某个账户，扫着码切过来看历史仍然要看得到进度）。
  $('mailContent').hidden = true;
  $('mailToolbar').hidden = true;
  $('codePanel').hidden = true;
  $('pfEditor').hidden = true;
  const btn = $('btnHistory');
  btn.classList.add('active');
  btn.setAttribute('aria-pressed', 'true');
  renderHistoryAccountFilter();
  // 焦点进容器（tabindex="-1"）：键盘用户切页后不会还停在已被隐藏的邮件区，
  // 下一次 Tab 从历史页内部开始。
  try { $('historyView').focus({ preventScroll: true }); } catch { /* 忽略 */ }
  loadHistory();
}

/** 退出历史视图：恢复邮件区，焦点还给入口按钮 */
function hideHistoryView() {
  if (!state.history.open) return;
  state.history.open = false;
  // 在途响应作废：返回后它们不能再写历史页的 DOM
  state.history.seq++;
  $('historyView').hidden = true;
  $('mailContent').hidden = false;
  $('mailToolbar').hidden = false;
  // codePanel 的显隐由 .show 类决定，摘掉 hidden 即恢复原样
  $('codePanel').hidden = false;
  // pfEditor 的显隐取决于当前账户，交给它自己的渲染函数判断
  renderPlatformEditor();
  const btn = $('btnHistory');
  btn.classList.remove('active');
  btn.setAttribute('aria-pressed', 'false');
  if (btn.isConnected) {
    try { btn.focus({ preventScroll: true }); } catch { /* 忽略 */ }
  }
}

/** 状态行：平时显示汇总，加载/写入时显示"正在做什么"（over 参数为一次性文案） */
function renderHistoryStatus(over) {
  const el = $('historyStatus');
  if (!el) return;
  if (over !== undefined) {
    el.textContent = String(over);
    return;
  }
  const h = state.history;
  if (h.loading) {
    el.textContent = '正在读取验证码历史…';
    return;
  }
  const items = h.items;
  const unused = items.filter(it => !it.usedAt).length;
  let s = `共 ${h.total} 条`;
  if (h.total > items.length) s += `，显示最新 ${items.length} 条`;
  s += ` · 本页未用 ${unused} 条`;
  const parts = histFilterParts();
  if (parts.length) s += ' · 筛选：' + parts.join('、');
  el.textContent = s;
}

/** 历史列表加载中的骨架：只在真的慢了（>250ms）才出现，避免本地服务下闪烁 */
function histSkeletonHtml(text) {
  const rows = [72, 58, 80, 64, 76].map(w =>
    `<div class="hist-skel">
       <div class="skel-bar" style="width:34px"></div>
       <div class="skel-bar" style="width:${w}%"></div>
       <div class="skel-bar" style="width:88px"></div>
       <div class="skel-bar" style="width:${w - 20}%"></div>
     </div>`).join('');
  return `<div class="history-loading">${esc(text)}</div>${rows}`;
}

/**
 * 拉取列表。
 *
 * 每次请求带一个自增序号，响应回来时序号变了就整包丢弃：
 * 搜索框 250ms 防抖之后仍可能出现"先发的慢请求后到"，
 * 那时用户已经改了条件，写回去会让列表和输入框对不上。
 */
async function loadHistory() {
  if (!state.history.open) return;
  const seq = ++state.history.seq;
  const f = { ...state.history.filters };
  const parts = histFilterParts();
  const doing = parts.length
    ? `正在按筛选条件查询（${parts.join('、')}）…`
    : '正在读取验证码历史…';

  state.history.loading = true;
  renderHistoryStatus(doing);

  const box = $('historyList');
  box.innerHTML = `<div class="history-loading">${esc(doing)}</div>`;
  const cancelSkeleton = showSkeletonLater(
    box, histSkeletonHtml(doing), () => seq !== state.history.seq
  );

  const body = { limit: HIST_LIMIT };
  const q = String(f.q || '').trim();
  if (q) body.q = q;
  if (f.accountId) body.accountId = f.accountId;
  if (f.onlyUnused) body.onlyUnused = true;
  if (f.sinceHours) body.sinceHours = Number(f.sinceHours);

  try {
    const d = await api('history.list', body);
    if (seq !== state.history.seq || !state.history.open) return;
    cancelSkeleton();
    const items = Array.isArray(d && d.items) ? d.items : [];
    state.history.items = items;
    state.history.total = Number(d && d.total) || 0;
    // 空态原因必须在这一层定：渲染时再判断就分不清"还没收到过"还是"筛没了"
    state.history.emptyReason = items.length
      ? ''
      : (histHasFilters() ? 'filtered' : 'none');
    // 状态行要在渲染前退出 loading，否则 renderHistoryStatus 会继续写"正在读取…"。
    // seq 校验过才改：旧请求不能把新请求的 loading 抹掉。
    state.history.loading = false;
    renderHistory();
  } catch (e) {
    if (seq !== state.history.seq || !state.history.open) return;
    cancelSkeleton();
    state.history.loading = false;
    state.history.items = [];
    state.history.total = 0;
    state.history.emptyReason = 'error';
    renderHistoryError(e);
    renderHistoryStatus('读取失败');
    announce('读取验证码历史失败：' + ((e && e.message) || '未知错误'));
  } finally {
    if (seq === state.history.seq) {
      state.history.loading = false;
      updateHistSelectionUI();
    }
  }
}

/** 错误态：保留具体原因 + 重试按钮（重试走容器上的事件委托） */
function renderHistoryError(err) {
  // 只读 err.message：err.reason 是另一处在补的字段，历史页不依赖它，
  // 万一它没跟上（或将来被移除），这里照样能显示服务端给的 error 文案。
  $('historyList').innerHTML = errorStateHtml(
    '读取验证码历史失败',
    (err && err.message) || '未知错误',
    'history'
  );
}

/** 空态：说清楚为什么空，并给出下一步可点的动作 */
function renderHistoryEmpty() {
  const reason = state.history.emptyReason;
  const parts = histFilterParts();
  let title;
  let desc;
  let actions;
  if (reason === 'filtered') {
    title = '当前筛选没有匹配的记录';
    desc = '筛选条件：' + parts.join('、') +
      '。历史里可能确实没有这样的验证码，也可能是条件太严。';
    actions = '<button class="btn btn-sm" type="button" data-hist-action="reset">清空筛选</button>' +
      '<button class="btn btn-sm" type="button" data-hist-action="back">返回邮件</button>';
  } else {
    title = '还没有收到过验证码';
    // 历史只由批量收码写入：单封收取不会进历史。这一点必须说清楚，
    // 否则用户会以为自己的功能坏了。
    desc = '识别到的验证码会在「批量收码」任务结束后自动存进这里，只保留最近 7 天。' +
      '还没有记录，说明本机还没跑过批量收码，或者历史已经被清理。';
    actions = '<button class="btn btn-sm" type="button" data-hist-action="back">返回邮件</button>' +
      '<button class="btn btn-sm" type="button" data-hist-action="refresh">重新读取</button>';
  }
  $('historyList').innerHTML =
    `<div class="state history-empty">
       <div class="state-title">${esc(title)}</div>
       <div class="state-desc">${esc(desc)}</div>
       <div class="history-empty-actions">${actions}</div>
     </div>`;
}

/**
 * 渲染表格。
 *
 * 所有服务端字符串（accountEmail / code / senderDomain）必须过 esc()；
 * 发件域走 domainHtml()（内部已转义并加粗后两级），和结果板保持同一套
 * 防钓鱼展示。绝不把任何值直接拼进 innerHTML。
 */
function renderHistory() {
  renderHistoryStatus();
  const h = state.history;
  if (!h.items.length) {
    renderHistoryEmpty();
    updateHistSelectionUI();
    return;
  }

  const rows = h.items.map(it => {
    const id = String(it.id || '');
    const email = String(it.accountEmail || '');
    const code = String(it.code || '');
    const dom = String(it.senderDomain || '');
    const used = !!it.usedAt;
    const usedTitle = used ? '已用于 ' + fmtHistTime(it.usedAt) : '未标记为已用';
    return `<tr class="hist-row${used ? ' used' : ''}" data-hist-id="${esc(id)}">
      <td class="hist-col-check">
        <input type="checkbox" class="hist-check" data-hist-check="${esc(id)}"
               aria-label="选择 ${esc(email)} 的验证码 ${esc(code)}">
      </td>
      <td class="hist-col-email">${esc(email)}</td>
      <td class="hist-col-code">
        <code class="hist-code">${esc(code)}</code>
        <button class="hist-copy" type="button" data-hist-copy="${esc(id)}"
                aria-label="复制 ${esc(email)} 的验证码 ${esc(code)}">复制</button>
      </td>
      <td class="hist-col-domain">${dom ? domainHtml(dom) : esc(UNKNOWN_SENDER)}</td>
      <td class="hist-col-time">
        <time datetime="${esc(it.receivedAt || '')}">${esc(fmtHistTime(it.receivedAt) || '（未知时间）')}</time>
      </td>
      <td class="hist-col-state">
        <span class="hist-badge ${used ? 'used' : 'unused'}" title="${esc(usedTitle)}">${used ? '已用' : '未用'}</span>
      </td>
      <td class="hist-col-ops">
        <button class="hist-mark" type="button" data-hist-mark="${esc(id)}"
                data-hist-used="${used ? '0' : '1'}"
                aria-label="把 ${esc(email)} 的验证码 ${esc(code)} 标记为${used ? '未用' : '已用'}">${used ? '标为未用' : '标为已用'}</button>
      </td>
    </tr>`;
  }).join('');

  $('historyList').innerHTML =
    `<table class="hist-table" aria-label="验证码历史记录">
       <thead>
         <tr>
           <th scope="col" class="hist-col-check"><span class="visually-hidden">选择</span></th>
           <th scope="col" class="hist-col-email">邮箱</th>
           <th scope="col" class="hist-col-code">验证码</th>
           <th scope="col" class="hist-col-domain">发件域</th>
           <th scope="col" class="hist-col-time">收到时间</th>
           <th scope="col" class="hist-col-state">状态</th>
           <th scope="col" class="hist-col-ops">操作</th>
         </tr>
       </thead>
       <tbody>${rows}</tbody>
     </table>`;

  bindHistoryRows();
  updateHistSelectionUI();
}

/**
 * 行内事件用闭包冻结 id / code / email，而不是点击时从 dataset 回读。
 * 理由和结果板一样：重绘、以后可能的增量追加，都可能让 DOM 与数据错位；
 * 冻结之后"点哪行就是哪行"是结构上保证的。
 */
function bindHistoryRows() {
  const items = state.history.items;
  const trs = $('historyList').querySelectorAll('.hist-row');
  trs.forEach((tr, i) => {
    const it = items[i];
    if (!it) return;
    const id = String(it.id || '');
    const code = String(it.code || '');
    const email = String(it.accountEmail || '');

    const copyBtn = tr.querySelector('.hist-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', async ev => {
        ev.stopPropagation();
        const ok = await copyWithToast(code, `${email} 的 ${code}`);
        if (ok) {
          flashCopied(copyBtn);
          announce(`已复制 ${email} 的验证码 ${code}`);
        }
      });
    }

    const markBtn = tr.querySelector('.hist-mark');
    if (markBtn) {
      markBtn.addEventListener('click', ev => {
        ev.stopPropagation();
        const used = markBtn.getAttribute('data-hist-used') === '1';
        markHistory([id], used);
      });
    }

    const check = tr.querySelector('.hist-check');
    if (check) {
      check.addEventListener('change', () => {
        if (check.checked) state.history.selected.add(id);
        else state.history.selected.delete(id);
        updateHistSelectionUI();
      });
    }
  });
}

/**
 * 选中集合只存在 state.history.selected（渲染是全量重绘的，不能只信 DOM）。
 * 每页最多 200 行，全部渲染成复选框，不做虚拟滚动。
 */
function updateHistSelectionUI() {
  const h = state.history;
  const ids = h.items.map(it => String(it.id || ''));
  // 清掉已经不存在的 id：刷新后消失的行不该继续算进"已选"
  for (const id of [...h.selected]) if (!ids.includes(id)) h.selected.delete(id);
  const n = h.selected.size;

  const count = $('histSelCount');
  if (count) count.textContent = `已选 ${n} 条`;

  const all = $('histSelectAll');
  if (all) {
    all.checked = ids.length > 0 && n === ids.length;
    all.indeterminate = n > 0 && n < ids.length;
    all.disabled = ids.length === 0 || h.loading;
  }

  const busy = h.loading || h.writing;
  for (const id of ['btnHistMarkUsed', 'btnHistMarkUnused', 'btnHistCopySel']) {
    const b = $(id);
    if (b) b.disabled = busy || n === 0;
  }

  // 行高亮跟着选中走：只靠复选框，长表格里一眼看不出哪几行被选
  const list = $('historyList');
  if (list) {
    list.querySelectorAll('.hist-row').forEach(tr => {
      const on = h.selected.has(String(tr.getAttribute('data-hist-id') || ''));
      tr.classList.toggle('sel', on);
      const cb = tr.querySelector('.hist-check');
      if (cb && cb.checked !== on) cb.checked = on;
    });
  }
}

/** 标记若干条（单条也走这里，传一个元素的数组） */
async function markHistory(ids, used) {
  const h = state.history;
  if (h.writing || h.loading) return;
  const list = (Array.isArray(ids) ? ids : []).filter(x => typeof x === 'string' && x).slice(0, 500);
  if (!list.length) return;
  const verb = used ? '已用' : '未用';
  h.writing = true;
  updateHistSelectionUI();
  renderHistoryStatus(`正在把 ${list.length} 条标记为${verb}…`);
  announce(`正在标记 ${list.length} 条为${verb}`);
  try {
    const d = await api('history.mark', { ids: list, used });
    const n = Number(d && d.updated) || 0;
    // updated 是"真正发生变化的条数"：重复标记同一条返回 0，
    // 这不是失败，必须用不同的话说清楚，否则用户以为没生效。
    const msg = n > 0
      ? `已把 ${n} 条标记为${verb}`
      : `这 ${list.length} 条已经是${verb === '已用' ? '已用' : '未用'}状态`;
    toast(msg, n > 0 ? 'ok' : 'warn');
    announce(msg);
    list.forEach(id => h.selected.delete(id));
    await reloadHistory();
  } catch (e) {
    const msg = '标记失败：' + ((e && e.message) || '未知错误');
    toast(msg, 'err');
    announce(msg);
    renderHistoryStatus();
  } finally {
    h.writing = false;
    updateHistSelectionUI();
  }
}

/** 重新拉取并尽量保住滚动位置（标记/清理后调用，避免用户被弹回顶部） */
async function reloadHistory() {
  const wrap = $('historyListWrap');
  const keep = wrap ? wrap.scrollTop : 0;
  await loadHistory();
  if (wrap) wrap.scrollTop = keep;
}

/** 复制选中行的验证码（每行一个，去重后按列表顺序） */
async function copySelectedHistoryCodes() {
  const h = state.history;
  const picked = h.items.filter(it => h.selected.has(String(it.id || '')));
  if (!picked.length) { toast('请先选择记录', 'warn'); return; }
  const codes = [];
  const seen = new Set();
  for (const it of picked) {
    const c = String(it.code || '');
    if (c && !seen.has(c)) { seen.add(c); codes.push(c); }
  }
  if (!codes.length) { toast('选中的记录没有验证码', 'warn'); return; }
  const ok = await copyText(codes.join('\n'));
  if (ok) {
    const extra = codes.length < picked.length ? `（${picked.length - codes.length} 条重复，已去重）` : '';
    const msg = `已复制 ${codes.length} 个验证码${extra}`;
    toast(msg);
    announce(msg);
  } else {
    toast('复制失败，请手动选择文本', 'err');
    announce('复制选中验证码失败');
  }
}

/** 下载兜底：剪贴板两条路都失败时，至少把文本交给用户 */
function downloadHistoryText(text, format, count) {
  // CSV 加 UTF-8 BOM，Excel 双击打开才不乱码；TXT 不加（多数编辑器会把 BOM 显示成怪字符）。
  // BOM 只能有一个：服务端将来若自己也带，先剥掉再统一补。
  const body = String(text || '').replace(/^\uFEFF+/, '');
  const bom = format === 'csv' ? '\uFEFF' : '';
  const type = format === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
  const blob = new Blob([bom + body], { type });
  const url = URL.createObjectURL(blob);
  const d0 = new Date();
  const pad = n => String(n).padStart(2, '0');
  const stamp = `${d0.getFullYear()}${pad(d0.getMonth() + 1)}${pad(d0.getDate())}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = `验证码历史-${count}条-${stamp}.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/**
 * 导出（history.export）。
 * 后端返回的是一段文本，不写文件、不自己下载 —— 前端复制到剪贴板，
 * 复用 copyText()：它内部已有 execCommand 降级，两条路都失败才返回 false。
 * 失败时退成下载文件，而不是只弹一句"复制失败"把 500 行数据留在内存里。
 *
 * 注意：**导出的是全部历史，不受当前筛选影响**（后端契约如此），
 * 所以按钮文案写「导出全部」，避免用户以为导的是筛出来的那一页。
 */
async function exportHistory(format) {
  const fmt = format === 'csv' ? 'csv' : 'txt';
  const btn = fmt === 'csv' ? $('btnHistExportCsv') : $('btnHistExportTxt');
  const oldText = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '导出中…'; }
  renderHistoryStatus('正在生成' + fmt.toUpperCase() + '导出文本…');
  try {
    const d = await api('history.export', { format: fmt });
    const text = String(d && d.text != null ? d.text : '');
    const n = Number(d && d.count) || 0;
    if (!n && !text) {
      toast('没有可导出的历史记录', 'warn');
      announce('没有可导出的历史记录');
      return;
    }
    const ok = await copyText(text);
    if (ok) {
      const msg = `已复制 ${n} 条全部历史（${fmt.toUpperCase()}）到剪贴板`;
      toast(msg);
      announce(msg);
    } else {
      downloadHistoryText(text, fmt, n);
      const msg = `复制失败，已改为下载 ${fmt.toUpperCase()} 文件（共 ${n} 条）`;
      toast(msg, 'warn');
      announce(msg);
    }
  } catch (e) {
    const msg = '导出失败：' + ((e && e.message) || '未知错误');
    toast(msg, 'err');
    announce(msg);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = oldText; }
    renderHistoryStatus();
  }
}

/** 清理弹窗：先选范围，再走通用确认（危险操作不能一点就删） */
function openHistClear() {
  const err = $('histClearErr');
  if (err) err.textContent = '';
  openModal('modalHistClear');
}

async function doHistClear() {
  const scopeEl = $('histClearScope');
  const raw = scopeEl ? String(scopeEl.value || '') : '';
  const hours = raw ? Number(raw) : null;
  const label = hours
    ? (hours === 24 ? '早于 24 小时' : hours === 72 ? '早于 3 天'
      : hours === 168 ? '早于 7 天' : `早于 ${hours} 小时`)
    : '全部历史';
  const ok = await askConfirm({
    title: '确认清理验证码历史',
    message: `将清理${label}的记录。\n\n清理不可恢复，且不受当前筛选条件影响。`,
    okText: '清理',
    danger: true,
  });
  if (!ok) return;

  const btn = $('btnHistClearOk');
  const errEl = $('histClearErr');
  if (errEl) errEl.textContent = '';
  if (btn) { btn.disabled = true; btn.textContent = '清理中…'; }
  try {
    const body = hours ? { olderThanHours: hours } : {};
    const d = await api('history.clear', body);
    const n = Number(d && d.removed) || 0;
    closeModal('modalHistClear');
    const msg = n > 0 ? `已清理 ${n} 条验证码历史` : '没有符合条件的历史记录可清理';
    toast(msg, n > 0 ? 'ok' : 'warn');
    announce(msg);
    if (state.history.open) await reloadHistory();
  } catch (e) {
    const msg = (e && e.message) || '清理失败';
    // 错误留在弹窗里：这是用户在弹窗里发起的操作，关掉弹窗他就看不到原因了
    if (errEl) errEl.textContent = msg;
    toast('清理失败：' + msg, 'err');
    announce('清理失败：' + msg);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '清理'; }
  }
}

/** 清空筛选：三个控件和 state 一起复位，然后重新请求 */
function resetHistFilters() {
  state.history.filters = { q: '', accountId: '', onlyUnused: false, sinceHours: '' };
  if ($('histQ')) $('histQ').value = '';
  if ($('histOnlyUnused')) $('histOnlyUnused').checked = false;
  if ($('histSince')) $('histSince').value = '';
  renderHistoryAccountFilter();
  loadHistory();
}

/** 筛选变化后统一从这里走：保持"变化即请求" */
function applyHistFilters() {
  loadHistory();
}


function renderMessages() {
  const box = $('msgList');
  if (!state.currentId) {
    box.innerHTML = '<div class="placeholder">选择左侧账户查看邮件</div>';
    return;
  }
  if (!state.messages.length) {
    box.innerHTML = '<div class="placeholder">这个文件夹没有邮件</div>';
    return;
  }
  box.innerHTML = state.messages.map(m => {
    // 当前正在阅读的那一封：列表里必须有明确落点。
    // 用 state.openUid 而不是回读 DOM——renderMessages 是全量重绘的，
    // 重绘后必须能把 active 一起画回来（刷新、切文件夹后都走这条路）。
    const active = state.openUid != null && String(m.uid) === String(state.openUid);
    return `
    <div class="msg-item${m.seen ? '' : ' unread'}${active ? ' active' : ''}" data-uid="${esc(m.uid)}">
      <div class="msg-head">
        <span class="msg-from">${esc(m.fromName || m.from || '(未知发件人)')}</span>
        <span class="msg-date">${esc(fmtDate(m.date))}</span>
      </div>
      <div class="msg-subject">${esc(m.subject)}</div>
      <div class="msg-snippet">${esc(fmtSize(m.size))}</div>
    </div>`;
  }).join('');
}

/* ============ 渲染：邮件详情 ============ */
function renderMessage(msg) {
  const view = $('msgView');

  let bodyHtml;
  if (msg.html) {
    // 邮件 HTML 放进 sandbox iframe：即使含脚本也无法访问父页面/localStorage
    bodyHtml = `<iframe class="mail-frame" sandbox referrerpolicy="no-referrer" srcdoc="${esc(msg.html)}"></iframe>`;
  } else {
    // 纯文本：转义后按换行渲染，绝不拼进 innerHTML 的原样内容
    bodyHtml = `<pre class="mail-text">${esc(msg.text || '(无正文)')}</pre>`;
  }

  const attach = (msg.attachments || []).length
    ? `<div class="attachments">${msg.attachments.map(a =>
        `<span class="attach">📎 ${esc(a.filename)} <small>${esc(fmtSize(a.size))}</small></span>`).join('')}</div>`
    : '';

  // 验证码横幅：若这封邮件里能识别出验证码，突出显示并提供一键复制
  const codeBanner = state.currentCode
    ? `<div class="code-banner">
         <span class="code-label">验证码</span>
         <span class="code-value" id="codeValue">${esc(state.currentCode)}</span>
         <button class="btn btn-sm btn-primary" id="btnCopyCode">复制</button>
       </div>`
    : '<div class="code-banner none" id="codeBannerNone"><span class="code-label">未识别到验证码</span></div>';

  view.innerHTML = `
    <div class="mail-detail">
      <h3 class="mail-subject">${esc(msg.subject)}</h3>
      <div class="mail-meta">
        <div><b>发件人：</b>${esc(msg.fromName ? `${msg.fromName} <${msg.from}>` : msg.from)}</div>
        <div><b>收件人：</b>${esc(msg.to)}</div>
        <div><b>时间：</b>${esc(msg.date ? new Date(msg.date).toLocaleString() : '')}</div>
      </div>
      ${codeBanner}
      ${attach}
      ${bodyHtml}
    </div>`;

  const btn = $('btnCopyCode');
  if (btn) btn.onclick = async () => {
    const ok = await copyWithToast(state.currentCode, '验证码');
    if (ok) flashCopied(btn);
  };
}

/* ============ 加载 ============ */
async function loadAccounts() {
  const d = await api('accounts');
  state.accounts = d.accounts;
  // 清掉已不存在的账户，避免 selected 里留着幽灵 id 让计数虚高
  const valid = new Set(state.accounts.map(a => a.id));
  for (const id of [...state.selected]) if (!valid.has(id)) state.selected.delete(id);
  renderAccounts();
  // 列表刷新可能带来服务端归一化后的平台（自定义名大小写等），详情区要跟着重画
  renderPlatformEditor();
  // 历史页的账户筛选也来自这份列表：账户改名/删除后下拉必须跟上，
  // 否则会出现"筛选项指向一个已经不存在的 id、列表永远为空"。
  if (state.history.open) renderHistoryAccountFilter();
}

async function loadMessages() {
  if (!state.currentId) return;
  // 竞态守卫：快速切账户时，A 的响应可能晚于 B 到达并覆盖列表，
  // 导致"头部是 B、列表是 A"，点开还会用 B 的 id 配 A 的 uid 取到一封不相干的邮件。
  // 这里给每次加载一个递增序号，写回前校验自己是不是最新那次。
  const seq = ++state.msgSeq;
  const idAtStart = state.currentId;
  const mbAtStart = state.currentMailbox;

  // 先清空成一个空的占位（不是骨架）：本地服务通常 30-80ms 就返回，
  // 无条件画骨架只会在每次切账户/刷新时闪一下灰块。
  // 超过 250ms 还没回来才插入骨架，那时用户已经真的在等了。
  const box = $('msgList');
  box.innerHTML = '<div class="placeholder">加载中…</div>';
  const cancelSkeleton = showSkeletonLater(
    box, skeletonMessagesHtml(), () => seq !== state.msgSeq
  );
  try {
    const d = await api('messages', {
      id: idAtStart,
      mailbox: mbAtStart,
      limit: 30,
    });
    cancelSkeleton();
    if (seq !== state.msgSeq) return;   // 期间又发起了新的加载，丢弃这次结果
    state.messages = d.messages;
    renderMessages();
  } catch (e) {
    cancelSkeleton();
    if (seq !== state.msgSeq) return;
    state.messages = [];
    // 结构化错误态 + 重试按钮。用户不必再跑到工具栏去点"刷新"，
    // 也不必猜"是不是我点错了"——原因和出路都在原地。
    box.innerHTML = errorStateHtml('加载失败', errText(e), 'messages');
  }
}

async function loadFolders() {
  if (!state.currentId) return;
  const seq = ++state.folderSeq;
  const idAtStart = state.currentId;
  try {
    const d = await api('folders', { id: idAtStart });
    if (seq !== state.folderSeq) return;   // 已经切到别的账户了
    const common = ['INBOX', 'Junk', 'Sent', 'Drafts', 'Deleted', 'Archive'];
    const all = [...new Set([...common, ...d.folders])];
    $('folderSelect').innerHTML = all
      .map(f => `<option value="${esc(f)}">${esc(f)}</option>`).join('');
    $('folderSelect').value = state.currentMailbox;
  } catch { /* 文件夹列表失败不影响主流程 */ }
}

/* ============ 批量收码：结果板 ============
 * 安全约束：
 * - 结果按账户分组，组间顺序 = 服务端 results 顺序（= 输入 ids 顺序），
 *   组内顺序 = 后端给的 codes 顺序（uid 降序）。Date 头可被发件人伪造，
 *   前端绝不再按 date 排序；也绝不做跨账户混排。
 * - 1 秒轮询会不断带来新结果：已渲染的行只追加、永不重建/重排，
 *   复制回调把账户 id、uid、码值固定成闭包常量，不回读 DOM 索引或 data-*。
 */
function keyForResult(r) {
  const id = r.id != null ? String(r.id) : '';
  // 缺失 email 时也用本地账户表兜底，确保 results 和 errors 的同一账户归到一组
  const email = scanEmail(r).toLowerCase();
  const byId = id ? state.scanKeysById.get(id) : null;
  if (byId) {
    if (email) state.scanKeysByEmail.set(email, byId);
    return byId;
  }
  const byEmail = email ? state.scanKeysByEmail.get(email) : null;
  if (byEmail) {
    if (id) state.scanKeysById.set(id, byEmail);
    return byEmail;
  }
  const key = 'row-' + (++state.scanKeySeq);
  if (id) state.scanKeysById.set(id, key);
  if (email) state.scanKeysByEmail.set(email, key);
  return key;
}

function updateCodeBoardSub(job) {
  $('codeBoardSub').textContent =
    `已处理 ${Number(job.done) || 0}/${Number(job.total) || 0} · ${state.scanCodeCount} 个码 · ${state.scanFailures.size} 个失败`;
}

/** 页面启动时统一清零，避免任何上一次运行留下的定时器/任务状态 */
function resetScanState() {
  if (state.scanTimer !== null) clearInterval(state.scanTimer);
  state.scanTimer = null;
  state.scanJobId = null;
  state.scanPolling = false;
  state.scanCancelled = false;
  state.scanBusy = false;
  state.scanFailStreak = 0;
  state.selected = new Set();
  state.scanAutoCopyLocked = false;
  state.scanAutoCopyBackup = state.autoCopy;
  state.scanBoardDismissed = false;
  $('scanProgress').hidden = true;
  $('codeBoard').hidden = true;
  $('btnScanCancel').hidden = false;
  $('btnScanCancel').disabled = false;
  $('btnScanCancel').textContent = '取消';
  $('btnShowCodeBoard').hidden = true;
  $('btnBulkCodes').disabled = false;
  $('chkAutoCopy').checked = state.autoCopy;
  $('chkAutoCopy').disabled = false;
  $('scanProgressFill').style.width = '0%';
  $('scanProgressFill').classList.remove('indeterminate', 'finishing');
  resetCodeBoard();
}

/**
 * 关闭结果板并恢复单账户自动复制；"查看结果"按钮仍可再次打开。
 * 定时器不在这里停：任务按自己的生命周期继续。
 */
function closeCodeBoard() {
  $('codeBoard').hidden = true;
  $('chkAutoCopy').disabled = false;
  state.scanBoardDismissed = true;   // 轮询期间用户主动关过，就不再自动弹回来
  $('btnShowCodeBoard').hidden = false;
  if (state.scanAutoCopyLocked) {
    state.scanAutoCopyLocked = false;
    state.autoCopy = state.scanAutoCopyBackup;
    $('chkAutoCopy').checked = state.autoCopy;
  }
}

/**
 * 结果板打开期间强制关闭单账户自动复制：
 * 否则批量扫着顺手点开一封邮件，剪贴板会被静默覆写成另一封邮件的码。
 * 这只是结果板可见期间的临时覆盖，关闭结果板即恢复原值；
 * 单账户 btnCodes / autoCopy 的原有逻辑本身不改。
 */
function openCodeBoard() {
  state.scanBoardDismissed = false;
  if (!state.scanAutoCopyLocked) {
    state.scanAutoCopyLocked = true;
    state.scanAutoCopyBackup = state.autoCopy;
    state.autoCopy = false;
    $('chkAutoCopy').checked = false;
  }
  $('chkAutoCopy').disabled = true;
  $('codeBoard').hidden = false;
}

/**
 * 结果板可见期间它必须一直是锁着的。openCodeBoard 已经处理了正常路径，
 * 但 hidden 属性也可能被别处改成可见（或被将来的改动漏掉），
 * 这里在每个轮询节拍上做一次幂等的兜底：可见 → autoCopy 必须是关的。
 */
function syncAutoCopyLock() {
  const shown = $('codeBoard').hidden === false;
  if (!shown) return;
  if (!state.scanAutoCopyLocked) {
    state.scanAutoCopyLocked = true;
    state.scanAutoCopyBackup = state.autoCopy;
  }
  state.autoCopy = false;
  const chk = $('chkAutoCopy');
  if (chk.checked) chk.checked = false;
  if (!chk.disabled) chk.disabled = true;
}

/** 所有 title / aria-label 属性里的外部文本统一走这个入口 */
function escapeAttrForTitle(s) {
  // esc() 覆盖 & < > " ' 五个字符，可安全用于双引号属性
  return esc(s);
}

/** 结果里的邮箱缺失时用本地账户表补全，失败行不能显示一个空邮箱 */
function scanEmail(entry) {
  const raw = entry && entry.email != null ? String(entry.email) : '';
  if (raw) return raw;
  const id = entry && entry.id != null ? String(entry.id) : '';
  const acc = id ? state.accounts.find(a => String(a.id) === id) : null;
  return acc ? String(acc.email || '') : '（未知邮箱）';
}

function resetCodeBoard() {
  // 用户主动关过结果板就别因为换个任务又自动弹回来
  const wasDismissed = state.scanBoardDismissed === true;
  $('codeBoardList').innerHTML =
    '<div class="board-groups" id="boardGroups"></div>' +
    '<div class="board-failures" id="boardFailures" hidden>' +
      '<div class="board-failures-head">失败账户</div>' +
      '<div id="boardFailureList"></div>' +
    '</div>';
  // renderedAccounts / scanGroups / scanFailures 必须一起重置，
  // 否则旧 key 会阻止新组创建，或者旧的行被当成"已渲染"而不再追加新码。
  state.scanGroupsBox = $('boardGroups');
  state.scanFailuresBox = $('boardFailures');
  state.scanFailureList = $('boardFailureList');
  state.renderedAccounts = new Set();
  state.scanGroups = new Map();
  state.scanFailures = new Map();
  state.scanKeysByEmail = new Map();
  state.scanKeysById = new Map();
  state.scanKeySeq = 0;
  state.scanCodeCount = 0;
  state.scanBoardDismissed = wasDismissed;
  state.scanBoardJobId = null;   // 这块 DOM 属于哪个任务
  $('btnShowCodeBoard').hidden = true;
  $('codeBoardSub').textContent = '';
}

/**
 * 结果板的复制回调工厂。accountId / uid / email / code 全部在渲染时传进来，
 * 成为闭包常量；点击时绝不从 DOM 索引、dataset 或轮询后的结果数组回读。
 * 1 秒轮询会追加新行，已渲染的行永不重建、重排，按下→抬起不会错配账户。
 *
 * toast 必须回报是哪个账户的码：这一栏里可能同时有三个账户的 6 位码长得一样，
 * 只报码值等于没报，账户错配（用户以为复制的是 A，其实点了 B）当场看不出来。
 */
function boardCopyHandler(accountId, uid, email, code, btn) {
  const bound = { accountId, uid, email, code };
  return async ev => {
    ev.stopPropagation();
    const ok = await copyText(bound.code);
    // 邮箱过长时截断显示（前 12 字符 + …），但绝不整段省略掉账户身份
    const who = String(bound.email == null ? '' : bound.email);
    const short = who.length > 12 ? who.slice(0, 12) + '…' : who;
    if (ok) {
      toast(`已复制 ${short || '（未知账户）'} 的 ${bound.code}`);
      // 就地反馈：这一栏里可能同时有三个长得一样的码，用户必须确认
      // 点的是哪一行的按钮，而底部 toast 说不出"位置"
      flashCopied(btn);
    } else {
      toast(`复制失败（${short || '未知账户'}），请手动选择文本`, 'err');
    }
  };
}

function createScanGroup(key, email, placeholder) {
  const el = document.createElement('div');
  el.className = 'board-group';
  el.innerHTML =
    `<div class="board-group-head">` +
      `<span class="board-group-email">${esc(email)}</span>` +
      `<span class="board-group-count">0 个码</span>` +
    `</div>` +
    `<div class="board-code-list"><div class="board-no-code">${esc(placeholder)}</div></div>`;
  const group = {
    el, email,
    countEl: el.querySelector('.board-group-count'),
    list: el.querySelector('.board-code-list'),
    placeholderEl: el.querySelector('.board-no-code'),
    seen: new Set(),
    count: 0,
  };
  state.scanGroups.set(key, group);
  state.scanGroupsBox.appendChild(el);
  $('btnShowCodeBoard').hidden = false;
  if (!state.scanBoardDismissed) openCodeBoard();
  return group;
}

/** 按用户勾选的 ids 顺序预建组，保证组间顺序 = 输入 ids 顺序 */
function primeScanGroups(ids) {
  for (const id of ids) {
    const acc = state.accounts.find(a => String(a.id) === String(id));
    if (!acc) continue;
    const email = String(acc.email || '');
    const key = keyForResult({ id, email });
    if (!state.scanGroups.has(key)) createScanGroup(key, email, '等待扫描…');
  }
}

/**
 * 追加一个码行；账户身份与码值在渲染时冻结，点击时绝不从 DOM/索引回读。
 * 这里所有外部字段（code / from / senderDomain / subject）都过 esc()。
 * 八个必须转义的字段：email / code / subject / from / senderDomain / reason / error / current。
 */
function appendCodeRow(box, accountId, uid, email, c) {
  const code = String(c.code == null ? '' : c.code);
  const dom = senderDomain(c.from);
  const subject = String(c.subject == null ? '' : c.subject);
  const from = String(c.from == null ? '' : c.from);
  const row = document.createElement('div');
  row.className = 'board-code-row';
  row.innerHTML =
    `<span class="board-code-value">${esc(code)}</span>` +
    // 域名整列可读、末两级加粗；title/aria-label 里放原文与完整域名
    `<span class="board-code-domain" title="${escapeAttrForTitle(from || UNKNOWN_SENDER)}" aria-label="${escapeAttrForTitle(dom)}">${domainHtml(dom)}</span>` +
    `<span class="board-code-date">${esc(fmtCodeDate(c.date) || '（未知时间）')}</span>` +
    `<span class="board-code-from">发件人：${esc(from || UNKNOWN_SENDER)}</span>` +
    `<span class="board-code-subject" title="${escapeAttrForTitle(subject)}">${esc(subject)}</span>` +
    `<button type="button" class="board-code-copy">复制</button>`;
  const subjectEl = row.querySelector('.board-code-subject');
  subjectEl.hidden = true;
  const copyBtn = row.querySelector('.board-code-copy');
  // 复制回调闭包冻结 accountId / uid / email / code：轮询追加新行时
  // 已渲染的按钮永远不会指到别的账户或别的码。
  copyBtn.onclick = boardCopyHandler(
    String(accountId == null ? '' : accountId),
    String(uid == null ? '' : uid),
    email,
    code,
    copyBtn
  );
  box.appendChild(row);
}

/**
 * 首次见到某个账户时建组并登记进 renderedAccounts；
 * 之后每次轮询只往已有组里追加**该组内新增的码行**，绝不全量重建。
 *
 * 全量重建的代价不是性能：1 秒一次重绘，用户从"按下鼠标"到"抬起"
 * 跨过一次重绘，复制的就是另一行的码；滚动位置还会丢、行会闪。
 */
function renderScanResult(r) {
  if (!r) return;
  const key = keyForResult(r);
  const email = scanEmail(r);
  // error / reason 都是外部字符串；进 innerHTML 前必须 esc()
  const error = String(r.error == null ? '' : r.error);
  const reason = String(r.reason == null ? '' : r.reason);
  let group = state.scanGroups.get(key);
  const isNewAccount = !state.renderedAccounts.has(key);
  if (!group) {
    group = createScanGroup(key, email, '没有找到验证码');
  } else if (email && group.email !== email) {
    // 同一账户的邮箱不会变；这里只为异常数据保守更新标题（走 textContent，不拼 HTML）
    group.el.querySelector('.board-group-email').textContent = email;
    group.email = email;
  }
  // 已建过组的账户不再重复建组；新账户只追加，不触碰已有 DOM
  if (isNewAccount) state.renderedAccounts.add(key);

  // ok:false 的账户把原始原因也在组内单独列出来，不静默丢掉。
  // 轮询会重复给同一快照，只写一次，避免每 1 秒追加一行。
  // 优先显示 error（更具体），没有则 reason，都没有则"未知原因"。
  if (r.ok === false && !group.errorShown) {
    group.errorShown = true;
    const primary = error || reason || '未知原因';
    const detail = error && reason && error !== reason ? reason : '';
    const line = document.createElement('div');
    line.className = 'board-group-error';
    line.innerHTML =
      `<span class="board-group-error-reason">${esc(primary)}</span>` +
      (detail ? `<span class="board-group-error-detail">${esc(detail)}</span>` : '');
    if (group.placeholderEl) { group.placeholderEl.remove(); group.placeholderEl = null; }
    group.list.appendChild(line);
  }

  const codes = Array.isArray(r.codes) ? r.codes : [];
  // 按后端给的顺序渲染（uid 降序）。绝不按 date 排序：Date 头可由发件人
  // 伪造到 2099 年抢首位；也绝不用普通对象按数字 uid 分组（Object.keys 会升序重排）。
  for (const c of codes) {
    if (!c) continue;
    // uid 由 IMAP 服务端分配，是不可伪造的组内去重键；用 Set 保持插入顺序
    const uid = c.uid == null ? '' : String(c.uid);
    const seenKey = uid || ('i-' + group.seen.size);
    if (group.seen.has(seenKey)) continue;
    group.seen.add(seenKey);
    if (group.placeholderEl) { group.placeholderEl.remove(); group.placeholderEl = null; }
    appendCodeRow(group.list, r.id, uid, group.email, c);
    group.count++;
    state.scanCodeCount++;
  }
  group.countEl.textContent = `${group.count} 个码`;
}

/**
 * 失败行：job.errors[] 每项有 email / error / reason。
 * 渲染规则：优先 error（更具体），没有则 reason，都没有则"未知原因"。
 * 绝不能因为两个字段都空就把这一行丢掉——用户会以为这个账户成功了。
 */
function renderScanFailure(entry) {
  if (!entry) return;
  const key = keyForResult(entry);
  const rawReason = String(entry.reason == null ? '' : entry.reason).trim();
  const rawError = String(entry.error == null ? '' : entry.error).trim();
  const primary = rawError || rawReason || '未知原因';
  const extra = rawError && rawReason && rawError !== rawReason ? rawReason : '';

  if (state.scanFailures.has(key)) {
    const old = state.scanFailures.get(key);
    if (primary !== old.primary) {
      // 更新走 textContent，绝不把原因拼进 innerHTML
      old.reasonEl.textContent = primary;
      old.primary = primary;
    }
    if (extra && extra !== old.extra) {
      // 后来补到了更细的原因：只追加这一个文本节点，不重建已渲染的行
      if (!old.extraEl) {
        old.extraEl = document.createElement('span');
        old.extraEl.className = 'board-failure-error';
        old.reasonEl.parentNode.appendChild(old.extraEl);
      }
      old.extraEl.textContent = extra;
      old.extra = extra;
    }
    return;
  }
  const line = document.createElement('div');
  line.className = 'board-failure-row';
  // 邮箱、原因、原始 error 都是外部文本，进 innerHTML 前一律 esc()
  line.innerHTML =
    `<span class="board-failure-email">${esc(scanEmail(entry))}</span>` +
    `<span class="board-failure-sep">—</span>` +
    `<span class="board-failure-reason">${esc(primary)}</span>` +
    (extra ? `<span class="board-failure-error">${esc(extra)}</span>` : '');
  const reasonEl = line.querySelector('.board-failure-reason');
  const extraEl = line.querySelector('.board-failure-error');
  state.scanFailureList.appendChild(line);
  state.scanFailures.set(key, { reasonEl, primary, extraEl, extra });
  state.scanFailuresBox.hidden = false;
  $('btnShowCodeBoard').hidden = false;
}

/** 按服务端给的顺序消费一次快照：results 先，errors 后，绝不跨账户按时间排序 */
function mergeScanResults(job, jobId) {
  // 同一块结果板 DOM 只能承载一个 job 的结果。
  // 换任务（包括跟随 reused 任务）时重建容器，避免把两个任务的码
  // 混进同一组、同一行——那会让"已复制 A 的码"变成彻底的错配。
  if (jobId && state.scanBoardJobId !== jobId) {
    resetCodeBoard();
    state.scanBoardJobId = jobId;
  }
  const results = Array.isArray(job.results) ? job.results : [];
  for (const r of results) {
    renderScanResult(r);
    if (r && r.ok === false) {
      // 把 reason / error 原样带过去，由 renderScanFailure 决定优先级
      renderScanFailure({
        id: r.id, email: r.email,
        reason: r.reason, error: r.error,
      });
    }
  }
  const errors = Array.isArray(job.errors) ? job.errors : [];
  for (const e of errors) {
    if (!e) continue;
    renderScanFailure({
      id: e.id, email: e.email,
      reason: e.reason, error: e.error,
    });
  }
  updateCodeBoardSub(job);
}

/* ============ 批量收码：任务生命周期 ============ */
function stopScanPolling() {
  if (state.scanTimer !== null) {
    clearInterval(state.scanTimer);
    state.scanTimer = null;
  }
  state.scanJobId = null;
  state.scanCancelled = false;
  state.scanPolling = false;
  state.scanBusy = false;
  state.scanFailStreak = 0;
  $('btnScanCancel').disabled = false;
  $('btnScanCancel').textContent = '取消';
  $('btnBulkCodes').disabled = false;
}

/**
 * etaMs 在 done===0 时后端返回 null（没有样本算不出速度），
 * 也可能因为 done 极小、总耗时异常而变成 Infinity/负数。
 * 这些情况一律显示"计算中…"，绝不能把 null/NaN/Infinity 直接拼进界面。
 */
function fmtEta(etaMs) {
  if (etaMs == null) return '计算中…';
  const ms = Number(etaMs);
  if (!Number.isFinite(ms) || ms < 0) return '计算中…';
  const sec = Math.ceil(ms / 1000);
  if (!Number.isFinite(sec) || sec < 0) return '计算中…';
  if (sec === 0) return '即将完成';
  if (sec >= 3600) return '预计还需 1 小时以上';
  if (sec >= 60) return `预计还需 ${Math.floor(sec / 60)} 分 ${sec % 60} 秒`;
  return `预计还需 ${sec} 秒`;
}

function renderScanProgress(job) {
  const total = Math.max(0, Number(job.total) || 0);
  const done = Math.max(0, Number(job.done) || 0);
  const okn = Math.max(0, Number(job.ok) || 0);
  const failed = Math.max(0, Number(job.failed) || 0);
  // 固定文案 + 已格式化的数字，无外部文本
  const etaText = fmtEta(job.etaMs);
  const codes = Array.isArray(job.results)
    ? job.results.reduce((n, r) => n + (r && Array.isArray(r.codes) ? r.codes.length : 0), 0)
    : state.scanCodeCount;

  // 数字与固定文案，无外部文本
  $('scanProgressText').textContent =
    `已处理 ${done}/${total} · 成功 ${okn} · 失败 ${failed} · 找到 ${codes} 个码`;
  // current 是外部内容：进 innerHTML 前必须 esc()
  const current = String(job.current == null ? '' : job.current);
  const draining = job.draining === true;
  const tail = draining ? '正在收尾，请勿关闭…' : etaText;

  // 逐封进度：服务端上报 phase=connect|list|read|done。
  // 长任务里用户最想知道"现在在干什么"，只显示邮箱还不够——
  // 一个账号要读 8 封邮件，能看到 3/8 就知道没卡住。
  const phase = String(job.currentPhase || '');
  const cDone = Number(job.currentDone) || 0;
  const cTotal = Number(job.currentTotal) || 0;
  const cFound = Number(job.currentFound) || 0;
  let phaseText = '';
  if (phase === 'read' && cTotal > 0) {
    phaseText = `正在读取第 ${cDone}/${cTotal} 封` + (cFound > 0 ? ` · 已找到 ${cFound} 个码` : '');
  } else if (phase === 'list') {
    phaseText = '正在读取邮件列表';
  } else if (phase === 'connect') {
    phaseText = '正在连接 IMAP';
  }

  const subParts = [];
  if (current) subParts.push('当前：' + esc(current));
  if (phaseText) subParts.push(esc(phaseText));
  if (tail) subParts.push(esc(tail));
  $('scanProgressSub').innerHTML = subParts.join('&nbsp;&nbsp;&nbsp;&nbsp;');

  // 宽度只改 style，不拼进 HTML 模板。
  // total === 0 表示服务端还没算出总量：0% 的静止条看起来就是"卡死了"，
  // 换成来回扫动的 indeterminate 条，明确表达"在跑，但还估不出进度"。
  const fill = $('scanProgressFill');
  const indeterminate = total === 0;
  fill.classList.toggle('indeterminate', indeterminate);
  if (indeterminate) {
    fill.style.width = '';
  } else {
    const pct = Math.min(100, Math.max(0, Math.round(done / total * 100)));
    fill.style.width = pct + '%';
  }

  // 收尾态：done === total 但 draining 还没结束（后台还在写盘/刷新 token）。
  // 进度条停在 100% 会让人以为已经完事而关掉窗口，加一个极轻的呼吸表示还有活。
  const finishing = draining && total > 0 && done >= total;
  fill.classList.toggle('finishing', finishing);
}

/**
 * 任务结束后进度条必须静止：不确定态的扫动和收尾态的呼吸都是
 * "还在跑"的信号，任务真的停了还继续动就是在骗人。
 *
 * 只摘掉动画，不强行写 100%：任务可能是被取消的（done < total），
 * 把它画满会让用户以为全部扫完了。宽度保留最后一次 renderScanProgress
 * 写入的真实值；从未拿到过 total 的任务就停在空轨道上，如实表达"不知道"。
 */
function settleProgressFill() {
  const fill = $('scanProgressFill');
  if (!fill) return;
  fill.classList.remove('indeterminate', 'finishing');
  // indeterminate 期间清过 width，这里补回 0，避免留下一个没有宽度的
  // 不定宽元素（transform 动画已摘掉，空 width 会算成 0 宽，视觉上是空轨道）
  if (!fill.style.width) fill.style.width = '0%';
}

/**
 * 任务级 error 是硬时限/整体失败的文案，可能为空。不能只写 toast 一闪而过，
 * 必须留在进度区，让用户事后也能看到失败原因。
 */
function finishScan(job, label, jobError) {
  stopScanPolling();
  const jobId = job && job.id ? String(job.id) : null;
  mergeScanResults(job || {}, jobId);
  if (job) renderScanProgress(job);
  settleProgressFill();
  $('scanProgressText').textContent =
    (label ? label + '：' : '') + $('scanProgressText').textContent;
  const reason = String(jobError == null ? '' : jobError).trim();
  $('scanProgressSub').textContent = reason
    ? '任务已结束，结果保留在下方 · ' + reason
    : '任务已结束，结果保留在下方';
  if (reason) renderJobError(reason);
  $('btnScanCancel').hidden = true;
  $('btnShowCodeBoard').hidden = false;
  // 任务刚结束时自动展开结果；轮询期间若用户主动关闭过，则尊重他的选择
  if (!state.scanBoardDismissed) openCodeBoard();
}

/** 任务级错误单独列在结果板顶部；已渲染过就不重复追加 */
function renderJobError(reason) {
  const box = $('codeBoardList');
  let line = box.querySelector('.board-job-error');
  if (!line) {
    line = document.createElement('div');
    line.className = 'board-job-error';
    line.innerHTML =
      '<span class="board-job-error-label">任务提示</span>' +
      '<span class="board-job-error-text"></span>';
    box.insertBefore(line, box.firstChild);
  }
  line.querySelector('.board-job-error-text').textContent = reason;
  $('btnShowCodeBoard').hidden = false;
}

/**
 * 连续 3 次拿不到状态才走到这里（单次抖动在 pollScanStatus 里已忽略）。
 * 注意：停的只是前端轮询，后端任务多半还在跑；所以文案要说明
 * "再点一次收验证码会重新挂上同一个任务"（后端 reused:true 的幂等锁）。
 * 已增量写入的结果行一律保留，不清空。
 */
function scanFailed(err) {
  stopScanPolling();
  const msg = errText(err);
  settleProgressFill();
  $('scanProgress').hidden = false;
  $('btnScanCancel').hidden = true;
  $('btnShowCodeBoard').hidden = false;
  $('scanProgressText').textContent = '进度获取失败，已停止跟随';
  $('scanProgressSub').textContent =
    msg + ' · 后台任务可能仍在运行，稍后再点一次"收验证码"可重新跟随同一个任务';
  toast('批量收码失败：' + msg, 'err');
}

/**
 * 是否已经可以停止轮询。
 *
 * 关键：取消之后后端会把 job.state 继续保持在 'running'（draining=true），
 * 因为还有在途账号在写盘/写 token。此时若按 state !== 'running' 判断，
 * 前端会立刻显示"已结束"、用户关掉窗口，而后台还在写——可能毁账号。
 * 所以只有在 drained===true，或终态且 draining 为 false 时才算真的结束。
 */
function isScanSettled(job) {
  if (!job) return false;
  if (job.drained === true) return true;
  const st = String(job.state || '');
  const terminal = st === 'done' || st === 'failed' || st === 'cancelled';
  if (!terminal) return false;
  // 终态但仍标注正在收尾：继续轮询，等 drained
  return job.draining !== true;
}

/** 服务重启 / 任务过期：明确告诉用户失效原因，不要卡在"运行中"或无限重试 */
function scanJobLost(detail) {
  stopScanPolling();
  $('btnScanCancel').hidden = true;
  $('btnShowCodeBoard').hidden = false;
  $('scanProgressText').textContent = '任务已丢失（服务可能已重启），请重新扫描';
  $('scanProgressSub').textContent = detail || '已渲染的结果保留在下方';
  settleProgressFill();
  toast('任务已丢失（服务可能已重启），请重新扫描', 'err');
}

/**
 * 轮询一次状态。
 *
 * 网络抖动不能直接停轮询：服务在本机，抖动少见但页面隐藏/系统休眠
 * 恢复时第一个请求经常直接失败；如果一次失败就判定任务结束，
 * 用户会看到"已结束"的残缺结果，而后台其实还在跑。
 * 这里连续失败 3 次才停并报错，成功一次立即清零。
 */
async function pollScanStatus() {
  if (!state.scanJobId || state.scanPolling) return;
  const jobId = state.scanJobId;
  state.scanPolling = true;
  try {
    const d = await api('codes.scan.status', { jobId });
    if (state.scanJobId !== jobId) return;    // 已被清理或换了任务
    state.scanFailStreak = 0;                 // 成功一次就清零
    const job = d.job || {};
    renderScanProgress(job);
    mergeScanResults(job, jobId);
    // 结果板可见期间单账户自动复制必须是关的（见 syncAutoCopyLock 的说明）
    syncAutoCopyLock();
    if (isScanSettled(job)) {
      const st = String(job.state || '');
      const label = st === 'cancelled' ? '已取消'
        : st === 'failed' ? '任务失败' : '已完成';
      // 任务级 error（硬时限/整体失败）必须让用户看见
      const jobError = String(job.error == null ? '' : job.error);
      finishScan(job, label, jobError);
    }
  } catch (e) {
    if (state.scanJobId !== jobId) return;
    const status = e && e.status;
    // 404 / 410，或服务端明确回 ok:false（任务不存在或已过期）：
    // 服务重启过或任务已被回收，jobId 已失效。这不是抖动，
    // 无限重试只会让界面一直卡在"运行中"，要直接给出明确提示。
    if (status === 404 || status === 410 || (e && e.apiOkFalse)) {
      scanJobLost(e && e.message ? e.message : '');
      return;
    }
    state.scanFailStreak++;
    if (state.scanFailStreak >= 3) {
      scanFailed(e);
    } else {
      // 单次失败忽略，继续用同一个 jobId 轮询
      $('scanProgressSub').textContent =
        `网络不稳定，正在重试（${state.scanFailStreak}/3）…`;
    }
  } finally {
    if (state.scanJobId === jobId) state.scanPolling = false;
  }
}

/**
 * 启动批量收码。
 *
 * reused:true 表示后端已经有一个 running job（全局幂等锁），返回的是那个
 * 任务的 jobId。这种情况绝不能当成错误，也不能"重置进度"再从头显示：
 * 正确做法是直接用这个 jobId 挂上去轮询，进度条/结果板从服务端的快照
 * 自然长出来，用户看到的是那个任务真实的已完成量。
 */
async function startCodeScan() {
  if (state.scanBusy || state.scanJobId) { toast('已有批量收码任务在进行', 'warn'); return; }
  if (!state.selected.size) { toast('请先选择账户', 'warn'); return; }
  const ids = [...state.selected];
  state.scanBusy = true;

  const btn = $('btnBulkCodes');
  btn.disabled = true;
  $('btnScanCancel').hidden = false;
  $('btnScanCancel').disabled = false;
  $('btnScanCancel').textContent = '取消';
  $('btnShowCodeBoard').hidden = false;
  try {
    const d = await api('codes.scan.start', {
      ids,
      mailbox: 'INBOX',
      perAccount: 8,
      onlyUnread: false,
    });
    // 三种都可能是 reused：jobId 一定有，但不保证有 total（后端直接返回 running.total）
    const jobId = d && d.jobId;
    if (!jobId) throw new Error('服务端没有返回任务 ID');
    const reused = d.reused === true;

    // 只有"自己发起的全新任务"才在这里清空结果板。
    // 跟随已有 reused 任务时，由 mergeScanResults 判断这块 DOM 是不是
    // 同一个 jobId 的：是就原样保留（用户已经看到的行不能消失），
    // 不是就先重建容器再追加，绝不把两个任务的码混进同一组。
    if (!reused) {
      resetCodeBoard();
      state.scanBoardJobId = jobId;
      // 新任务按勾选顺序预建分组；跟随已有任务时组由服务端 results 顺序决定
      primeScanGroups(ids);
    }

    $('scanProgress').hidden = false;
    $('btnScanCancel').hidden = false;
    $('btnShowCodeBoard').hidden = false;
    // 新任务启动时先回到不确定态（服务端还没算出 total），
    // 第一个 poll 回来后会由 renderScanProgress 决定是继续扫动还是给真实百分比。
    $('scanProgressFill').style.width = '0%';
    $('scanProgressFill').classList.add('indeterminate');
    $('scanProgressFill').classList.remove('finishing');
    $('scanProgressText').textContent = reused ? '正在跟随已有任务…' : '准备中…';
    $('scanProgressSub').textContent = reused
      ? '后端已有批量收码任务在运行，本次将直接显示它的进度'
      : '';

    state.scanJobId = jobId;
    state.scanCancelled = false;
    state.scanPolling = false;
    state.scanFailStreak = 0;
    if (reused) {
      toast('已有任务在运行，正在跟随该任务的进度', 'warn');
      // 跟随时分组由服务端结果顺序建立，进度条也不能停在 0
      if (!state.scanBoardDismissed) openCodeBoard();
    }

    // 首个 poll 立即发，之后严格每 1000ms 一次。
    // 抖动的重试次数由 pollScanStatus 内部的失败计数控制，不在这里无限重试。
    await pollScanStatus();
    if (state.scanJobId === jobId && state.scanTimer === null) {
      state.scanTimer = setInterval(pollScanStatus, 1000);
    }
  } catch (e) {
    state.scanBusy = false;
    btn.disabled = false;
    $('btnScanCancel').disabled = false;
    $('btnScanCancel').textContent = '取消';
    toast('启动批量收码失败：' + errText(e), 'err');
  }
}

/**
 * 请求取消。
 * 取消在账号边界生效：后端会把 job.state 继续保持 'running'（draining=true），
 * 因为还有在途账号在写盘/写 token。所以这里绝不停轮询、也绝不显示"已结束"，
 * 要继续跟到 job.drained === true 为止，否则用户关掉窗口时后台还在写。
 */
async function cancelCodeScan() {
  if (!state.scanJobId || state.scanCancelled) return;
  const btn = $('btnScanCancel');
  btn.disabled = true;
  btn.textContent = '正在停止…';
  try {
    const d = await api('codes.scan.cancel', { jobId: state.scanJobId });
    state.scanCancelled = true;
    if (d && d.cancelled === false) {
      // 重复取消：后端已经记下了取消请求，等收尾完成即可
      $('scanProgressSub').textContent = '已在收尾中，等待后台完成…';
    } else {
      $('scanProgressSub').textContent = '已请求取消，等待后台收尾（在途账号写完后才停）…';
    }
    // 定时器继续跑；isScanSettled(job) 会在 drained 之后才判定结束。
    // 万一定时器不在了（例如上次请求失败停过），这里补一个，避免卡在"正在停止…"
    if (state.scanJobId && state.scanTimer === null) {
      state.scanTimer = setInterval(pollScanStatus, 1000);
    }
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '取消';
    toast('取消失败：' + e.message, 'err');
  }
}

/* ============ 通用确认弹窗 ============ */
/**
 * 只有一个确认弹窗 DOM，同时只允许一个 pending。
 * 若已有 await 中的确认（用户没关掉又触发了另一次），先把旧的按"取消"结算，
 * 否则旧的 Promise 永远悬着、它的调用方（例如删除流程）会卡死。
 * （pendingConfirm 在文件顶部的可变模块级状态里声明。）
 */
function settleConfirm(value) {
  const p = pendingConfirm;
  if (!p) return;
  pendingConfirm = null;
  p.resolve(value === true);
}

function askConfirm(opts) {
  const o = opts || {};
  // 覆盖旧 pending：先给旧调用方一个明确的 false，绝不静默悬空
  settleConfirm(false);

  $('confirmTitle').textContent = o.title == null ? '确认' : String(o.title);
  $('confirmMessage').textContent = o.message == null ? '' : String(o.message);
  const okBtn = $('confirmOk');
  okBtn.textContent = o.okText == null ? '确定' : String(o.okText);
  okBtn.classList.toggle('btn-danger', o.danger === true);

  return new Promise(resolve => {
    pendingConfirm = { resolve };
    openModal('modalConfirm');
    // 危险操作把焦点放在"取消"上，避免回车直接删掉账户
    const focusTarget = o.danger === true
      ? $('modalConfirm').querySelector('.modal-foot .btn:not(.btn-primary):not(.btn-danger)')
      : okBtn;
    if (focusTarget) focusTarget.focus({ preventScroll: true });
  });
}

/* ============ 账户行内联菜单 ============ */
/**
 * 同一时刻只允许一个菜单开着。菜单用 createElement 构建、贴在该行的右下方，
 * 不做 position:fixed 手算坐标（窗口缩放会错位）。列表容器有 overflow，
 * 底部空间不够时向上翻。滚动 / 窗口缩放 / 点外部 / Esc / 选中菜单项都会关闭。
 * （openMenu 在文件顶部的可变模块级状态里声明。）
 */
function closeAccountMenu(restoreFocus) {
  if (!openMenu) return;
  const m = openMenu;
  openMenu = null;
  if (m.root && m.root.parentNode) m.root.parentNode.removeChild(m.root);
  if (m.item) m.item.classList.remove('menu-open');
  document.removeEventListener('mousedown', m.onDocDown, true);
  document.removeEventListener('scroll', m.onScroll, true);
  window.removeEventListener('resize', m.onResize);
  if (m.root) m.root.removeEventListener('focusout', m.onFocusOut);
  // Esc / 选中菜单项后把焦点还给 ⋯，键盘用户不会掉到 <body> 上
  if (restoreFocus && m.anchor && m.anchor.isConnected) {
    try { m.anchor.focus({ preventScroll: true }); } catch { m.anchor.focus(); }
  }
}

/** 菜单项：真 <button>，Tab 可遍历、Enter/Space 天然可用 */
function makeMenuItem(label, onClick, extraClass) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'account-menu-item' + (extraClass ? ' ' + extraClass : '');
  b.setAttribute('role', 'menuitem');
  b.textContent = label;
  b.addEventListener('click', ev => {
    ev.stopPropagation();
    closeAccountMenu(true);
    onClick();
  });
  return b;
}

function openAccountMenu(anchorBtn, acc) {
  closeAccountMenu();
  if (!acc) return;
  const item = anchorBtn.closest('.account-item');
  if (!item) return;

  const root = document.createElement('div');
  root.className = 'account-menu-pop';
  root.setAttribute('role', 'menu');
  // 点菜单空白处（抬头）不应冒泡成"点击账户行"
  root.addEventListener('click', ev => ev.stopPropagation());

  // 邮箱只走 textContent：绝不拼进 HTML
  const head = document.createElement('div');
  head.className = 'account-menu-head';
  head.textContent = String(acc.email == null ? '' : acc.email);
  head.title = head.textContent;
  root.appendChild(head);

  root.appendChild(makeMenuItem('复制邮箱', () => { copyWithToast(acc.email, '邮箱地址'); }));
  root.appendChild(makeMenuItem('查看邮件', () => { selectAccount(acc.id); }));
  root.appendChild(makeMenuItem('端点诊断', () => { openDiagnose(acc); }));
  root.appendChild(makeMenuItem('删除账户', () => { removeAccount(acc); }, 'danger'));

  const onDocDown = ev => {
    if (!openMenu) return;
    if (openMenu.root.contains(ev.target)) return;
    if (openMenu.anchor && openMenu.anchor.contains(ev.target)) return;  // 交给点击处理做开关
    closeAccountMenu();
  };
  // 列表滚动（或任何滚动）就关掉：比跟随重算坐标简单可靠得多
  const onScroll = () => closeAccountMenu();
  const onResize = () => closeAccountMenu();
  // Tab 走后最后一项就离开了菜单：焦点跑到菜单外时自动收起
  const onFocusOut = ev => {
    if (!openMenu) return;
    if (ev.relatedTarget && openMenu.root.contains(ev.relatedTarget)) return;
    closeAccountMenu();
  };

  item.appendChild(root);
  item.classList.add('menu-open');

  // 底部空间不够就向上翻，避免被 .account-list 的 overflow 裁掉
  const list = $('accountList');
  if (list) {
    const itemRect = item.getBoundingClientRect();
    const listRect = list.getBoundingClientRect();
    const menuH = root.offsetHeight;
    const below = listRect.bottom - itemRect.bottom;
    const above = itemRect.top - listRect.top;
    if (below < menuH + 8 && above > below) root.classList.add('above');
  }

  openMenu = { id: String(acc.id), root, item, anchor: anchorBtn, onDocDown, onScroll, onResize, onFocusOut };
  document.addEventListener('mousedown', onDocDown, true);
  document.addEventListener('scroll', onScroll, true);
  window.addEventListener('resize', onResize);
  root.addEventListener('focusout', onFocusOut);

  const first = root.querySelector('.account-menu-item');
  // preventScroll：聚焦若触发滚动，会立刻命中 onScroll 把菜单关掉
  if (first) first.focus({ preventScroll: true });
}

/* ============ 端点诊断弹窗 ============ */
function diagEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text != null) el.textContent = String(text);
  return el;
}

/**
 * 诊断结果表格。端点 / label / aadsts / code / message / hint 全部来自服务端
 * （服务端常量 + 微软返回），一律 textContent 写入，绝不拼 HTML。
 * elapsedMs 是前端实测的整次请求耗时（服务端目前不返回逐条耗时，
 * 那一列就如实显示 —，绝不编数字）。
 */
function renderDiagnose(d, elapsedMs) {
  const body = $('diagBody');
  body.textContent = '';

  const tries = Array.isArray(d && d.tries) ? d.tries : [];

  const table = diagEl('table', 'diag-table');
  const thead = diagEl('thead');
  const htr = diagEl('tr');
  ['端点', '结果', '错误码', '耗时'].forEach(title => htr.appendChild(diagEl('th', null, title)));
  thead.appendChild(htr);
  table.appendChild(thead);

  const tbody = diagEl('tbody');
  for (const t of tries) {
    if (!t) continue;
    const endpoint = String(t.endpoint == null ? '' : t.endpoint);
    const label = String(t.label == null ? '' : t.label);
    const ok = t.ok === true;

    const tr = diagEl('tr', ok ? 'diag-ok' : 'diag-bad');
    tr.appendChild(diagEl('td', 'diag-endpoint',
      label ? endpoint + '（' + label + '）' : endpoint));
    tr.appendChild(diagEl('td', 'diag-result', ok ? '成功' : '失败'));

    // 错误码优先 aadsts，其次 oauth code；成功行留空
    const errCode = String(t.aadsts || t.code || '');
    tr.appendChild(diagEl('td', 'diag-code', ok ? '' : (errCode || '—')));

    // 服务端不返回逐条耗时：先看有没有自带字段，没有就如实显示 —
    // 注意 null / '' / undefined 都必须当成"没有"，Number(null) 会变成 0
    const ownMs = t.ms != null ? t.ms
      : t.elapsedMs != null ? t.elapsedMs
      : t.durationMs != null ? t.durationMs
      : t.timeMs != null ? t.timeMs
      : t.took != null ? t.took : null;
    let msNum = NaN;
    if (ownMs != null && ownMs !== '') msNum = Number(ownMs);
    else if (tries.length === 1 && Number.isFinite(elapsedMs)) msNum = elapsedMs;
    // 只有单条尝试时，前端实测的整次请求耗时就是这一条的耗时
    tr.appendChild(diagEl('td', 'diag-time',
      Number.isFinite(msNum) && msNum >= 0 ? Math.round(msNum) + ' ms' : '—'));
    tbody.appendChild(tr);

    const message = String(t.message == null ? '' : t.message);
    if (!ok && message) {
      const detailTr = diagEl('tr', 'diag-detail');
      const td = diagEl('td', 'diag-message', message);
      td.colSpan = 4;
      detailTr.appendChild(td);
      tbody.appendChild(detailTr);
    }
  }
  table.appendChild(tbody);
  body.appendChild(table);

  if (!tries.length) body.appendChild(diagEl('div', 'diag-empty', '服务端没有返回任何端点尝试结果'));

  const working = d && d.working ? String(d.working) : '';
  const workingLabel = d && d.workingLabel ? String(d.workingLabel) : '';
  body.appendChild(diagEl('div', 'diag-summary ' + (working ? 'ok' : 'bad'),
    working
      ? '可用端点：' + working + (workingLabel ? '（' + workingLabel + '）' : '')
      : '所有端点都失败'));

  const hint = d && d.hint ? String(d.hint) : '';
  if (hint) body.appendChild(diagEl('div', 'diag-hint', hint));
}

async function openDiagnose(acc) {
  if (!acc) return;
  // 竞态守卫：连开两个账户的诊断时，先发的响应可能后到
  const seq = ++state.diagSeq;

  $('diagEmail').textContent = String(acc.email == null ? '' : acc.email);
  $('diagErr').textContent = '';
  const body = $('diagBody');
  body.textContent = '';
  body.appendChild(diagEl('div', 'diag-loading', '诊断中…'));
  openModal('modalDiagnose');

  const t0 = (window.performance && performance.now) ? performance.now() : Date.now();
  try {
    const d = await api('account.diagnose', { id: acc.id });
    const elapsedMs = ((window.performance && performance.now) ? performance.now() : Date.now()) - t0;
    if (seq !== state.diagSeq) return;
    renderDiagnose(d, elapsedMs);
  } catch (e) {
    if (seq !== state.diagSeq) return;
    body.textContent = '';
    $('diagErr').textContent = '诊断失败：' + (e && e.message ? e.message : '未知错误');
  }
}

/* ============ 账户操作 ============ */
/**
 * 工具栏右侧的状态徽章：任何状态下都必须有文字。
 * 空字符串会让 .badge 变成一颗只有内边距的灰色胶囊，
 * 用户不知道那是"没状态"还是"界面坏了"。
 */
function applyCurrentStatus(acc) {
  const el = $('currentStatus');
  if (!el) return;
  if (!acc) {
    // 没有选中账户时整颗徽章不显示（靠 CSS 的 .badge:empty 收掉）
    el.className = 'badge';
    el.textContent = '';
    el.title = '';
    return;
  }
  const st = String(acc.status || '');
  if (st === 'ok') {
    el.className = 'badge ok';
    el.textContent = '可用';
  } else if (st === 'failed' || st === 'banned') {
    el.className = 'badge bad';
    el.textContent = st === 'banned' ? '封禁' : '异常';
  } else {
    // 从未检测 / 状态未知：用中性的"未检测"，不用红色吓用户
    el.className = 'badge warn';
    el.textContent = '未检测';
  }
  // statusMessage 是服务端给的原始原因，只放进 title，不塞进徽章
  el.title = acc.statusMessage ? String(acc.statusMessage) : '';
}

/** 选中账户：点行和菜单里的"查看邮件"走同一条路径，竞态守卫保持一致 */
async function selectAccount(nextId) {
  if (!nextId) return;
  if (nextId === state.currentId) return;   // 点自己不用重发两条连接
  // 历史页开着时点侧栏账户：用户想看的是这个账户的邮件。不先退出历史视图，
  // 邮件会加载到一块 hidden 的区域里，界面毫无反应，看起来像点击失效。
  if (state.history.open) hideHistoryView();

  state.currentId = nextId;
  state.currentMailbox = 'INBOX';

  // 切账户必须在任何 await 之前同步清干净，否则会残留上一个账户的内容。
  // 最危险的是验证码面板和 currentCode：留着的话用户点一下
  // 复制到的是**上一个账户**的验证码，而界面标题已经是新账户了。
  state.currentCode = null;
  state.messages = [];
  state.openUid = null;    // 切账户：列表会被整个换掉，旧的"当前打开"不再有效
  state.retryUid = null;
  state.msgSeq++;          // 让在途的 mail 请求全部作废
  state.folderSeq++;       // 让在途的 folder 请求全部作废
  state.openSeq++;         // 让在途的正文请求作废
  $('codePanel').classList.remove('show');
  $('codePanel').innerHTML = '';
  $('msgView').innerHTML = '<div class="placeholder">选择一封邮件查看内容</div>';
  $('msgList').innerHTML = '<div class="placeholder">加载中…</div>';

  const acc = state.accounts.find(a => a.id === state.currentId);
  $('currentEmail').textContent = acc ? acc.email : '';
  // 空徽章（className='badge ' + textContent=''）会渲染成一颗空灰胶囊，
  // 看起来像"加载失败留下的破图"。三态都给明确文案：
  //   可用 → ok；异常/封禁 → bad；从未检测 → warn（"未检测"）。
  applyCurrentStatus(acc);
  setActiveAccountRow(state.currentId);
  syncCopyEmailButton();
  renderPlatformEditor();

  // folders 和 messages 没有依赖关系，并行发，省一个来回
  await Promise.all([loadFolders(), loadMessages()]);

  // 读信成功会顺带把账号状态校正成"可用"（服务端 markAccountHealthy）。
  // 这里必须重新拉一次列表，否则侧栏那个红点/异常标记要等到下次刷新才变——
  // 用户看到的现象就是"邮件能读，但状态还显示异常"。
  // 只在本地状态不是 ok 时拉，正常账户不额外发请求。
  if (acc && acc.status !== 'ok') {
    await loadAccounts();
  }
}

async function removeAccount(acc) {
  if (!acc) return;
  const ok = await askConfirm({
    title: '删除账户',
    message: `确定要移除 ${acc.email} 吗？\n\n这只从本工具移除，不影响邮箱本身。`,
    okText: '删除',
    danger: true,
  });
  if (!ok) return;

  try {
    await api('account.remove', { ids: [acc.id] });

    if (state.currentId === acc.id) {
      // 删的是当前正在看的账户：把它留下的一切同步清干净，
      // 否则标题已经没了、下面还挂着上一个账户的正文和验证码。
      state.currentId = null;
      state.currentCode = null;
      state.messages = [];
      state.openUid = null;
      state.retryUid = null;
      state.msgSeq++;
      state.folderSeq++;
      state.openSeq++;
      $('codePanel').classList.remove('show');
      $('codePanel').innerHTML = '';
      renderMessages();
      $('msgView').innerHTML = '<div class="placeholder">选择一封邮件查看内容</div>';
      $('currentEmail').textContent = '选择一个账户';
      applyCurrentStatus(null);
      setActiveAccountRow(null);
      renderPlatformEditor();
    }

    state.selected.delete(acc.id);
    await loadAccounts();
    // 删掉的账户可能带走了某平台的最后一个标注：不刷新统计的话，
    // 筛选器会一直显示「GitHub (5)」，而库里根本没剩几条（F2-9）。
    loadPlatformStats();
    syncCopyEmailButton();
    toast('已删除');
  } catch (e) {
    toast(e && e.message ? e.message : '删除失败', 'err');
  }
}

/* ============ 复制当前邮箱 ============ */
/** 选中账户时启用，未选中时禁用；渲染/筛选/删除后都要同步 */
function syncCopyEmailButton() {
  const btn = $('btnCopyEmail');
  if (!btn) return;
  const acc = state.currentId
    ? state.accounts.find(a => a.id === state.currentId)
    : null;
  btn.disabled = !acc;
  btn.title = acc ? '复制邮箱地址：' + acc.email : '复制邮箱地址';
}

/** 由 uid 打开一封邮件（列表点击 / 详情里的重试共用同一条路径） */
async function openMessage(uid) {
  if (uid == null) return;
  uid = String(uid);

  // 竞态守卫：快速连点两封邮件时，先点的那封可能后到并把界面覆盖掉；
  // 更糟的是 state.currentCode 会被旧邮件覆盖，导致横幅显示错误的码
  // 并把它复制到剪贴板。所有写回都要先确认自己是最新那次点击。
  const seq = ++state.openSeq;
  const idAtStart = state.currentId;
  const mbAtStart = state.currentMailbox;

  // 当前打开的是哪一封：只改这两行 DOM，绝不整表重绘
  // （重绘会把滚动位置清零，100 封时用户滚到第 80 封点开就弹回顶部）。
  state.openUid = uid;
  state.retryUid = uid;
  const listBox = $('msgList');
  if (listBox) {
    const prevActive = listBox.querySelector('.msg-item.active');
    if (prevActive) prevActive.classList.remove('active');
    // uid 来自 IMAP，是服务端分配的数字串；仍然用属性选择器前做转义兜底
    const nextItem = listBox.querySelector(`[data-uid="${(window.CSS && CSS.escape) ? CSS.escape(uid) : uid}"]`);
    if (nextItem) nextItem.classList.add('active');
  }

  $('msgView').innerHTML = '<div class="placeholder">加载中…</div>';
  state.currentCode = null;
  // 正文通常也和列表一样快；超过 250ms 才用顶部对齐的骨架顶上
  const viewBox = $('msgView');
  const cancelSkeleton = showSkeletonLater(
    viewBox, skeletonDetailHtml(), () => seq !== state.openSeq
  );

  try {
    const d = await api('message', {
      id: idAtStart,
      mailbox: mbAtStart,
      uid,
    });
    cancelSkeleton();
    if (seq !== state.openSeq) return;

    // 先把正文渲染出来，不要等验证码请求——否则 message.code 慢 3 秒正文就白屏 3 秒
    renderMessage(d.message);

    // 标记已读只改这一行，不重绘整个列表（重绘会把滚动位置清零）
    const m = state.messages.find(x => String(x.uid) === uid);
    if (m) m.seen = true;
    const row = $('msgList').querySelector(`[data-uid="${uid}"]`);
    if (row) row.classList.remove('unread');

    // 再异步补验证码横幅
    let code = null;
    try {
      const c = await api('message.code', {
        id: idAtStart,
        mailbox: mbAtStart,
        uid,
      });
      code = c.code;
    } catch { /* 取不到验证码不影响正文显示 */ }

    // 验证码回来时可能已经切走了，这时绝不能写 currentCode 或复制
    if (seq !== state.openSeq) return;

    state.currentCode = code;
    renderMessage(d.message);   // 仅为了带上横幅重绘一次，此时正文已在本地

    if (code && state.autoCopy) {
      const ok = await copyText(code);
      if (seq !== state.openSeq) return;
      if (ok) toast('验证码已复制：' + code);
      else toast('识别到验证码 ' + code + '，自动复制失败', 'warn');
    }
  } catch (err) {
    cancelSkeleton();
    if (seq !== state.openSeq) return;
    viewBox.innerHTML = errorStateHtml('打开邮件失败', errText(err), 'detail');
    // 详情加载失败时把那封邮件的"当前打开"状态也撤掉：
    // 否则列表里标着"正在看这封"，右边却是一块错误提示。
    state.openUid = null;
    const a = listBox && listBox.querySelector('.msg-item.active');
    if (a) a.classList.remove('active');
  }
}

/* ============ 事件 ============ */
function bind() {
  initA11y();

  // 添加账户
  $('btnAdd').onclick = () => {
    ['fEmail', 'fClientId', 'fRefresh', 'fGroup', 'fNote', 'fTenant'].forEach(id => $(id).value = '');
    $('fEndpoint').value = 'auto';
    $('addErr').textContent = '';
    openModal('modalAdd');
  };

  $('btnSaveAccount').onclick = async () => {
    const err = $('addErr');
    err.textContent = '';
    const email = $('fEmail').value.trim();
    const clientId = $('fClientId').value.trim();
    const refreshToken = $('fRefresh').value.trim();
    if (!email || !clientId || !refreshToken) {
      err.textContent = '三项都是必填的';
      return;
    }
    try {
      await api('account.add', {
        email, clientId, refreshToken,
        group: $('fGroup').value.trim() || '默认',
        note: $('fNote').value.trim(),
        endpoint: $('fEndpoint').value,
        tenant: $('fTenant').value.trim(),
      });
      closeModal('modalAdd');
      await loadAccounts();
      // 新增账户会改变各平台的计数（默认没有任何平台，但"未标注 (N)"的 N 变了）
      loadPlatformStats();
      toast('账户已添加');
    } catch (e) { err.textContent = errText(e); }
  };

  // 批量导入
  $('btnImport').onclick = () => {
    $('iText').value = '';
    $('iGroup').value = '导入';
    $('importErr').textContent = '';
    openModal('modalImport');
  };

  $('btnDoImport').onclick = async () => {
    const err = $('importErr');
    err.textContent = '';
    const text = $('iText').value.trim();
    if (!text) { err.textContent = '请粘贴账户列表'; return; }
    try {
      const d = await api('account.import', { text, group: $('iGroup').value.trim() || '导入' });
      closeModal('modalImport');
      await loadAccounts();
      // 导入同样影响平台统计（新账户全都没有标注 → "未标注 (N)" 要涨）
      loadPlatformStats();
      let msg = `导入 ${d.addedCount} 个`;
      if (d.skippedCount) msg += `，跳过 ${d.skippedCount} 个重复`;
      if (d.invalidCount) msg += `，${d.invalidCount} 行格式有误`;
      toast(msg);
    } catch (e) { err.textContent = errText(e); }
  };

  // 全部检测：100 个账号、并发 5、单账号约 2 秒 → 40-80 秒。
  //
  // 不能一次 await 整批：那样服务端跑完才返回，前端 40-80 秒里只能显示
  // "检测中（5.6s / 100 个账号）"——用户不知道在检测谁、还有多久。
  // 改成前端分块调用（account.checkAll 本来就支持 ids），每块 5 个账号，
  // 块间更新"正在检测 xxx / 已完成 n/total"，信息密度立刻不一样。
  $('btnCheckAll').onclick = async () => {
    if (!state.accounts.length) { toast('没有账户可检测', 'warn'); return; }
    const btn = $('btnCheckAll');
    if (btn.disabled) return;                 // 连点不叠加

    const targets = state.accounts.map(a => ({ id: a.id, email: a.email }));
    const total = targets.length;
    const CHUNK = 5;                          // 与服务端原有并发度一致

    btn.disabled = true;
    btn.classList.add('busy');

    let done = 0;
    let okCount = 0;
    let failed = 0;
    const t0 = Date.now();

    const render = current => {
      const el = Date.now() - t0;
      const head = `${fmtSec(el)} · ${done}/${total}`;
      // 按钮宽度有限：只显示 @ 之前的部分（这批账号域名都一样，是冗余信息），
      // 过长再截断。完整邮箱在侧栏列表里始终可见。
      let who = '';
      if (current) {
        who = String(current).split('@')[0] || '';
        if (who.length > 14) who = who.slice(0, 13) + '…';
      }
      btn.textContent = who
        ? `检测 ${who}（${head}）`
        : `检测中（${head}）`;
    };
    render('');

    // 计时器保证两次分块之间数字也在动，不会"冻住"
    const tick = setInterval(() => render(state._checkCurrent || ''), 200);

    try {
      for (let i = 0; i < targets.length; i += CHUNK) {
        const chunk = targets.slice(i, i + CHUNK);
        // 让用户看到"正在检测谁"：取本块第一个
        state._checkCurrent = chunk[0] ? chunk[0].email : '';
        render(state._checkCurrent);

        let d;
        try {
          d = await api('account.checkAll', { ids: chunk.map(x => x.id) });
        } catch (e) {
          // 单块失败不中断整批：计入失败数，继续下一块
          failed += chunk.length;
          done += chunk.length;
          continue;
        }

        const results = (d && Array.isArray(d.results)) ? d.results : [];
        okCount += results.filter(r => r.ok).length;
        failed += results.filter(r => !r.ok).length;
        // 服务端可能跳过不存在的账号，用返回值兜底
        done += results.length || chunk.length;
        state._checkCurrent = '';
        render('');
      }

      await loadAccounts();
      if (failed === 0) {
        toast(`检测完成：${okCount}/${total} 可用`);
      } else {
        toast(`检测完成：${okCount} 可用，${failed} 个异常`, 'warn');
      }
    } catch (e) {
      toast(e.message, 'err');
    } finally {
      clearInterval(tick);
      state._checkCurrent = '';
      btn.classList.remove('busy');
      btn.disabled = false;
      btn.textContent = '全部检测';
    }
  };

  /* ---- 验证码历史 ---- */
  // 入口/返回：视图互斥，按钮的 aria-pressed 跟着切
  $('btnHistory').onclick = () => {
    if (state.history.open) hideHistoryView();
    else showHistoryView();
  };
  $('btnHistoryBack').onclick = hideHistoryView;

  // 搜索：与侧栏账户搜索同一套 250ms 防抖。历史是 HTTP 请求（要读盘解密），
  // 逐字符发请求会在输入 "outlook" 时连发 7 次、每次解密整个历史文件。
  // state 先记下值，保证防抖窗口内点到"清空筛选"等操作读到的是最新输入。
  $('histQ').addEventListener('input', e => {
    const v = e.target.value;
    state.history.filters.q = v;
    clearTimeout(histSearchTimer);
    histSearchTimer = setTimeout(applyHistFilters, 250);
  });

  $('histAccount').addEventListener('change', e => {
    state.history.filters.accountId = e.target.value;
    applyHistFilters();
  });
  $('histSince').addEventListener('change', e => {
    state.history.filters.sinceHours = e.target.value;
    applyHistFilters();
  });
  $('histOnlyUnused').addEventListener('change', e => {
    state.history.filters.onlyUnused = e.target.checked;
    applyHistFilters();
  });
  $('btnHistReset').addEventListener('click', resetHistFilters);
  $('btnHistRefresh').addEventListener('click', () => reloadHistory());

  // 全选本页：只影响当前这一页（≤200 条），不会去选服务端还没返回的记录
  $('histSelectAll').addEventListener('change', e => {
    const on = e.target.checked;
    state.history.selected.clear();
    if (on) state.history.items.forEach(it => state.history.selected.add(String(it.id || '')));
    renderHistory();
  });

  $('btnHistMarkUsed').addEventListener('click', () => markHistory([...state.history.selected], true));
  $('btnHistMarkUnused').addEventListener('click', () => markHistory([...state.history.selected], false));
  $('btnHistCopySel').addEventListener('click', copySelectedHistoryCodes);

  $('btnHistExportTxt').addEventListener('click', () => exportHistory('txt'));
  $('btnHistExportCsv').addEventListener('click', () => exportHistory('csv'));
  $('btnHistClear').addEventListener('click', openHistClear);
  $('btnHistClearOk').addEventListener('click', doHistClear);

  // 列表容器上的委托：只处理"整块重绘后依然要活着"的按钮（空态/错误态里的动作）。
  // 行内的复制/标记/勾选用 bindHistoryRows 逐行绑定闭包（见那里的注释）。
  $('historyList').addEventListener('click', e => {
    const retry = e.target.closest('[data-retry]');
    if (retry) {
      if (retry.dataset.retry === 'history') loadHistory();
      return;
    }
    const act = e.target.closest('[data-hist-action]');
    if (!act) return;
    const a = act.dataset.histAction;
    if (a === 'reset') resetHistFilters();
    else if (a === 'back') hideHistoryView();
    else if (a === 'refresh') loadHistory();
  });

  // 筛选
  //
  // 搜索要 debounce（F2-11）：renderAccounts 是**整表重绘**（100 行 × 每行的
  // chip 要算 4 个对比度派生色）。逐字符触发时每个键都重绘一次列表并重建
  // 两个下拉，输入"outlook"就是 7 次全量重绘、700 次行构造。
  // 150ms 是实测手感：比逐字符明显省，又快到用户感觉不到延迟。
  // groupFilter / platformFilter 是离散选择，没有这个问题，保持同步。
  let searchTimer = null;
  $('search').oninput = e => {
    const v = e.target.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      // 期间可能已经清空/换了输入：以最新值再取一次，不用闭包里那个
      state.filterText = $('search').value;
      renderAccounts();
    }, 150);
    // 先记下值，避免 150ms 内"全选当前筛选"用到旧的 filterText
    state.filterText = v;
  };
  $('groupFilter').onchange = e => { state.filterGroup = e.target.value; renderAccounts(); };
  $('platformFilter').onchange = e => { state.filterPlatform = e.target.value; renderAccounts(); };

  // 全选/取消全选：只作用于当前筛选结果，不影响筛选外的已选项
  $('chkSelectAll').onchange = e => {
    const ids = filteredAccountIds();
    if (e.target.checked) ids.forEach(id => state.selected.add(id));
    else ids.forEach(id => state.selected.delete(id));
    renderAccounts();
  };
  $('btnBulkClear').onclick = () => {
    state.selected.clear();
    renderAccounts();
  };
  $('btnBulkCodes').onclick = startCodeScan;
  $('btnBulkPlatforms').onclick = openBulkPlatformPicker;

  /* ---- 平台标注 ---- */
  $('btnExportPlatforms').onclick = exportPlatforms;

  // 详情面板：＋ 添加平台 → 打开选择器（单账户，预填现有平台）
  $('pfAdd').onclick = () => {
    const acc = currentAccount();
    if (!acc) { toast('请先选择账户', 'warn'); return; }
    openPlatformPicker({ bulk: false, ids: [acc.id], email: acc.email });
  };

  // 详情面板：chips 上的 × 直接移除
  $('pfChips').onclick = e => {
    const x = e.target.closest('[data-pf-remove]');
    if (!x) return;
    e.stopPropagation();
    removePlatformFromCurrent(x.dataset.pfRemove);
  };

  // 选择器：点内置平台 = 切换选中
  $('pfGrid').onclick = e => {
    const opt = e.target.closest('[data-pf-key]');
    if (!opt || !pfPicker) return;
    const key = opt.dataset.pfKey;
    if (pfPicker.sel.has(key)) pfPicker.sel.delete(key);
    else pfPicker.sel.set(key, pfName(key));
    renderPickerGrid();
  };

  // 选择器：已选 chip 上的 × = 取消这一项
  $('pfChosen').onclick = e => {
    const x = e.target.closest('[data-pf-unpick]');
    if (!x) return;
    pickerRemove(x.dataset.pfUnpick);
  };

  // 选择器：自定义平台（输入框回车或点「添加」都行）
  $('pfCustomAdd').onclick = () => {
    const inp = $('pfCustomInput');
    pickerAdd(inp.value);
    inp.value = '';
    inp.focus();
  };
  $('pfCustomInput').onkeydown = e => {
    if (e.key === 'Enter') { e.preventDefault(); $('pfCustomAdd').click(); }
  };

  // 选择器：模式 radio（批量才有）
  document.querySelectorAll('input[name="pfMode"]').forEach(el => {
    el.onchange = () => { if (pfPicker) pfPicker.mode = el.value; };
  });

  $('pfDone').onclick = submitPlatformPicker;

  // 账户列表事件委托
  $('accountList').onclick = async e => {
    const check = e.target.closest('.account-check');
    if (check) {
      // 点 checkbox / 其 label 不许连带打开账户
      e.stopPropagation();
      const item = check.closest('[data-id]');
      if (!item) return;
      const id = item.dataset.id;
      if (check.checked) state.selected.add(id);
      else state.selected.delete(id);
      updateSelectionUI();
      return;
    }
    const menuBtn = e.target.closest('[data-menu]');
    if (menuBtn) {
      e.stopPropagation();
      const id = menuBtn.dataset.menu;
      const acc = state.accounts.find(a => a.id === id);
      if (!acc) return;
      // 再点同一个 ⋯ 就是收起
      if (openMenu && openMenu.id === String(id) && openMenu.anchor === menuBtn) {
        closeAccountMenu();
        return;
      }
      openAccountMenu(menuBtn, acc);
      return;
    }

    const item = e.target.closest('[data-id]');
    if (!item) return;

    // 点菜单内部（抬头等）已经被 stopPropagation 挡掉，这里再兜一层
    if (openMenu && openMenu.root && openMenu.root.contains(e.target)) return;

    // 点账户行时先收起菜单，避免菜单跟着旧行留在屏幕上
    closeAccountMenu();
    await selectAccount(item.dataset.id);
  };

  // 复制当前邮箱地址（注册流程每天都在用的一步）
  $('btnCopyEmail').onclick = async () => {
    const acc = state.currentId
      ? state.accounts.find(a => a.id === state.currentId)
      : null;
    if (!acc) { toast('请先选择账户', 'warn'); return; }
    const btn = $('btnCopyEmail');
    const ok = await copyWithToast(acc.email, '邮箱地址');
    if (ok) flashCopied(btn);
  };

  // 刷新
  $('btnRefresh').onclick = async e => {
    if (!state.currentId) { toast('请先选择账户', 'warn'); return; }
    const btn = e.currentTarget;
    if (btn.disabled) return;                 // 连点不再叠加请求
    btn.disabled = true;
    btn.classList.add('busy');
    // 锁定宽度，避免"刷新"→"刷新中…"→"已刷新"之间工具栏跳动
    btn.textContent = '刷新中…';
    // 先算好「该恢复成什么」，异常路径也能落回同一个状态
    let nextText = '刷新';
    let keepMs = 0;
    try {
      // loadMessages 内部会 catch，永远不抛错。
      // 所以不能 await 完就无条件说"已刷新"——失败了必须如实报错。
      state.msgSeq++;                          // 让在途请求作废，确保拿到的是最新的
      const idAtStart = state.currentId;
      const d = await api('messages', {
        id: idAtStart,
        mailbox: state.currentMailbox,
        limit: 30,
      });
      if (state.currentId !== idAtStart) return;   // 期间切了账户，别写别人的列表
      state.messages = d.messages;
      // 不清 openUid：刷新后那封邮件若还在列表里，renderMessages 会把
      // .active 自动画回去，用户不会因为刷新而"丢失当前位置"。
      renderMessages();
      nextText = '已刷新 ✓';
      keepMs = 900;   // 让"已刷新 ✓"停留一拍，否则用户只看到按钮闪了一下

      // 刷新成功同样证明账号可用：本地状态不是 ok 就重拉一次列表，
      // 免得"能读信但侧栏还是红的"。
      const cur = state.accounts.find(a => a.id === idAtStart);
      if (cur && cur.status !== 'ok') await loadAccounts();
    } catch (err) {
      toast('刷新失败：' + errText(err), 'err');
    } finally {
      btn.classList.remove('busy');
      btn.disabled = false;
      clearTimeout(btn._refreshTimer);
      btn.textContent = nextText;
      btn._refreshTimer = setTimeout(() => { btn.textContent = '刷新'; }, keepMs);
    }
  };

  // 文件夹切换
  $('folderSelect').onchange = async e => {
    state.currentMailbox = e.target.value;
    // 换文件夹后详情必须清空，否则会残留上一个文件夹的正文和验证码横幅
    state.currentCode = null;
    state.openUid = null;   // 列表会被整个换掉，"当前打开"的标记也必须清掉
    state.retryUid = null;
    state.openSeq++;
    $('msgView').innerHTML = '<div class="placeholder">选择一封邮件查看内容</div>';
    await loadMessages();
  };

  // 邮件点击
  $('msgList').onclick = async e => {
    // 错误态里的"重试"按钮：走同一条委托，不必为每次重绘重新绑事件
    const retry = e.target.closest('[data-retry]');
    if (retry) {
      // messages = 重新拉列表；detail = 重开上一次没打开的那封
      if (retry.dataset.retry === 'messages') loadMessages();
      return;
    }

    const item = e.target.closest('[data-uid]');
    if (!item) return;
    await openMessage(item.dataset.uid);
  };

  // 详情面板里的"重试"：重开上一次失败的那封邮件
  $('msgView').onclick = e => {
    const retry = e.target.closest('[data-retry]');
    if (!retry) return;
    if (retry.dataset.retry === 'detail' && state.retryUid != null) {
      openMessage(state.retryUid);
    }
  };

  // 一键收取验证码
  $('btnCodes').onclick = async () => {
    if (!state.currentId) { toast('请先选择账户', 'warn'); return; }
    const btn = $('btnCodes');
    btn.disabled = true;
    // 服务端要跑 8-15 秒，全程只有"扫描中…"等于什么都没有。
    // 分阶段文案 + 实时秒数让用户确认它真的在动。
    btn.classList.add('busy');
    btn.textContent = '连接中…';
    const stopTicker = startTicker(btn, ms => {
      const phase = ms < 2000 ? '连接 IMAP'
        : ms < 8000 ? '读取邮件'
        : '解析验证码';
      return `正在${phase}（${fmtSec(ms)}）`;
    });
    try {
      const d = await api('codes', {
        id: state.currentId,
        mailbox: state.currentMailbox,
        scan: 15,
      });
      renderCodePanel(d.codes);
      if (!d.codes.length) toast('最近邮件里没找到验证码', 'warn');
    } catch (e) {
      toast(errText(e), 'err');
    } finally {
      // try/finally 保证计时器一定被清掉：请求抛错时若漏了 clearInterval，
      // 按钮会永远停在"正在解析验证码（41.2s）"
      stopTicker();
      btn.classList.remove('busy');
      btn.disabled = false;
      btn.textContent = '收验证码';
    }
  };

  // 自动复制开关。结果板打开期间 autoCopy 被强制关，开关暂时禁用，
  // 关闭结果板（closeCodeBoard）再恢复用户原本的选择。
  $('chkAutoCopy').onchange = e => {
    if (state.scanAutoCopyLocked) {
      e.target.checked = false;
      toast('批量结果板打开期间不自动复制', 'warn');
      return;
    }
    state.autoCopy = e.target.checked;
    toast(state.autoCopy ? '已开启自动复制' : '已关闭自动复制');
  };

  $('btnScanCancel').onclick = cancelCodeScan;
  $('btnShowCodeBoard').onclick = openCodeBoard;
  $('btnCloseCodeBoard').onclick = closeCodeBoard;

  // 写邮件
  $('btnCompose').onclick = () => {
    if (!state.currentId) { toast('请先选择账户', 'warn'); return; }
    ['cTo', 'cSubject', 'cBody'].forEach(id => $(id).value = '');
    $('composeErr').textContent = '';
    openModal('modalCompose');
  };

  $('btnSend').onclick = async () => {
    const err = $('composeErr');
    err.textContent = '';
    const to = $('cTo').value.trim();
    const subject = $('cSubject').value.trim();
    const text = $('cBody').value;
    if (!to) { err.textContent = '请填写收件人'; return; }
    if (!subject && !text) { err.textContent = '主题和正文不能都为空'; return; }

    const btn = $('btnSend');
    btn.disabled = true;
    btn.textContent = '发送中…';
    try {
      await api('send', { id: state.currentId, to, subject, text });
      closeModal('modalCompose');
      toast('邮件已发送');
    } catch (e) { err.textContent = errText(e); }
    finally { btn.disabled = false; btn.textContent = '发送'; }
  };

  // 确认弹窗的"确定"：先按 true 结算（settleConfirm 会清空 pending，
  // 接着 closeModal 里那次 settleConfirm(false) 就成了空操作）
  $('confirmOk').onclick = () => {
    settleConfirm(true);
    closeModal('modalConfirm');
  };

  // 弹窗关闭
  document.querySelectorAll('[data-close]').forEach(el => {
    el.onclick = () => closeModal(el.dataset.close);
  });
  document.querySelectorAll('.modal').forEach(m => {
    m.onclick = e => { if (e.target === m) closeModal(m.id); };
  });

  // Esc 关闭：菜单优先（同一时刻只会有一层），再关弹窗
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (openMenu) { closeAccountMenu(true); return; }
    document.querySelectorAll('.modal.show').forEach(m => closeModal(m.id));
  });
}

/* ============ 本机授权引导 ============ */

/**
 * handshake 现在需要本机授权（见 README「本机鉴权模型」）。
 * 拿不到 cookie 时服务端返回 401 + code=HANDSHAKE_REQUIRED，
 * 这里弹一个输入框让用户粘贴 ~/.maildesk/handshake 的内容。
 *
 * 为什么不做"自动读文件"：浏览器读不到本地文件系统，而且这正是要防的
 * ——能在后台自动读到秘密的东西，本机其他进程也能伪装。
 */
function askHandshakeCode(hintPath) {
  return new Promise(resolve => {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.id = 'modalHandshake';
    modal.innerHTML =
      '<div class="modal-box" style="width:520px">' +
        '<div class="modal-head"><h3>需要本机授权</h3></div>' +
        '<div class="modal-body">' +
          '<p class="hint">' +
            'MailDesk 会校验调用方是不是本机这台电脑上的你本人。' +
            '请打开下面这个文件，把里面的整行内容复制过来：' +
          '</p>' +
          '<p><code style="user-select:all">' +
            esc(hintPath || '~/.maildesk/handshake') + '</code></p>' +
          '<p class="hint">' +
            'Windows 上是 <code>C:\\Users\\你的用户名\\.maildesk\\handshake</code>，' +
            '用记事本打开即可，内容是一串 64 位十六进制。' +
          '</p>' +
          '<label for="hsCode">授权码</label>' +
          '<input type="text" id="hsCode" placeholder="粘贴授权码" ' +
            'autocomplete="off" spellcheck="false">' +
          '<div class="err" id="hsErr"></div>' +
        '</div>' +
        '<div class="modal-foot">' +
          '<button class="btn btn-primary" id="hsOk">授权</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(modal);
    const input = modal.querySelector('#hsCode');
    const errEl = modal.querySelector('#hsErr');
    const okBtn = modal.querySelector('#hsOk');
    input.focus();

    const submit = async () => {
      const code = input.value.trim();
      if (!code) { errEl.textContent = '请先粘贴授权码'; return; }
      okBtn.disabled = true;
      okBtn.textContent = '验证中…';
      try {
        const r = await fetch('/api?action=handshake.bootstrap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: code }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.token) {
          errEl.textContent = j.error || ('授权失败（HTTP ' + r.status + '）');
          okBtn.disabled = false;
          okBtn.textContent = '授权';
          input.select();
          return;
        }
        modal.remove();
        resolve(j.token);
      } catch (e) {
        errEl.textContent = '无法连接本地服务：' + e.message;
        okBtn.disabled = false;
        okBtn.textContent = '授权';
      }
    };

    okBtn.addEventListener('click', submit);
    input.addEventListener('keydown', ev => { if (ev.key === 'Enter') submit(); });
  });
}

/**
 * 拿会话 token。失败时区分"没授权"和"服务没起来"：
 * 前者要引导授权，后者要告诉用户去启动服务 —— 两者混成一句"无法连接"
 * 会让用户对着已启动的服务反复点重试。
 */
async function getToken() {
  for (let attempt = 0; attempt < 2; attempt++) {
    let r;
    try {
      r = await fetch('/api?action=handshake');
    } catch {
      throw new Error('无法连接本地服务：请确认 MailDesk 已启动');
    }
    if (r.ok) {
      const j = await r.json();
      if (j.token) return j.token;
    }
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && j.code === 'HANDSHAKE_REQUIRED') {
      if (attempt === 0) {
        // 引导成功后 cookie 已种好，再走一轮 handshake 取 token
        await askHandshakeCode(j.handshakeFile);
        continue;
      }
      throw new Error('授权已失效，请刷新页面重试');
    }
    throw new Error(j.error || ('握手失败（HTTP ' + r.status + '）'));
  }
  throw new Error('授权失败');
}

/* ============ 启动 ============ */
(async function init() {
  bind();
  resetScanState();
  try {
    state.token = await getToken();
  } catch (e) {
    toast(e.message, 'err');
    return;
  }
  try {
    await loadAccounts();
  } catch (e) {
    toast(e.message, 'err');
  }
  // 平台统计独立加载：它失败不影响账户列表，筛选器就只剩「全部平台」
  loadPlatformStats();
})();
