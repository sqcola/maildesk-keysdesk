'use strict';
/**
 * KeyDesk 服务端
 *
 * 单文件、switch(action) 分发，不引第三方依赖。
 *
 * 安全基线（与 MailDesk 同一套，但按本工具的威胁模型调整）：
 *  1. 只监听 127.0.0.1，端口固定 2151-2160
 *  2. 握手要出示本机秘密（文件在 DATA_DIR/handshake），之后才发一次性会话 token；
 *     除 handshake / handshake.bootstrap 外全部要求 Bearer
 *  3. Host 头校验，阻断 DNS rebinding
 *  4. CORS 只回 127.0.0.1/localhost 的本端口，绝不回 '*'
 *  5. 静态文件路径归一化 + 前缀校验，阻断路径穿越
 *  6. CSP script-src 'self'，不加载任何外部资源
 *  7. 未解锁时除白名单外一律 423，绝不把任何秘密送出去
 *
 * 与 MailDesk 的关键差异：这里管理的 TOTP secret 不可轮换。
 * 所以「未解锁」是一个硬状态：锁定态下连条目数量都不从解密数据推导。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { URL } = require('url');

const { KeyStore } = require('./lib/keystore');
// 单实例锁：双击两次 start.bat 时，第二个进程会因 EADDRINUSE 顺延端口照样起来，
// 两个实例写同一份 vault.enc 会互相覆盖。锁必须在改端口之前抢（见 start()）。
const instanceLock = require('./lib/instance-lock');
const { Store } = require('./lib/store');
const totp = require('./lib/totp');
const qr = require('./lib/qr');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.KEYDESK_DATA_DIR || path.join(ROOT, 'data');
const VAULT_PATH = path.join(DATA_DIR, 'vault.enc');
const SETTINGS_PATH = path.join(DATA_DIR, 'settings.json');

const DEFAULT_PORT = 2151;
const PORT_TRIES = 10;
const MAX_BODY = 1024 * 1024;   // 1MB：条目和恢复码文本远小于这个数

/* ---------------- 设置（非机密，可明文落盘） ---------------- */

function loadSettings() {
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
    const out = {};
    if (Number.isInteger(raw.idleTimeoutSec) && raw.idleTimeoutSec >= 0 && raw.idleTimeoutSec <= 86400) {
      out.idleTimeoutSec = raw.idleTimeoutSec;
    }
    return out;
  } catch {
    return {};
  }
}

function saveSettings(obj) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = SETTINGS_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, SETTINGS_PATH);
  } catch (e) {
    console.error('[settings] 写入失败：' + (e && e.message));
  }
}

const settings = loadSettings();

const keystore = new KeyStore(VAULT_PATH, {
  idleTimeoutSec: settings.idleTimeoutSec,
});
const store = new Store(keystore);

/* ---------------- 会话 token ---------------- */

const SESSION_TOKEN = crypto.randomBytes(32).toString('hex');
const SESSION_TOKEN_BUF = Buffer.from(SESSION_TOKEN, 'utf8');
const SESSION_TOKEN_BYTES = SESSION_TOKEN_BUF.length;

/* ---------------- 本机握手鉴权 ---------------- */

/**
 * 为什么 handshake 不能无条件发 token
 *
 * SESSION_TOKEN 只挡得住第三方网页（Host / CORS 对它们有效）。本机任意进程、
 * 本机其他 Windows 账户连 127.0.0.1:2151 是通的，一次 GET 就能换到 token，
 * 随后 entries.list、secrets.reveal（明文 TOTP）、entries.export、vault.settings
 * （把自动锁关掉）全部敞开 —— 这把"必须有主口令才能读到秘密"的边界直接绕过去了。
 *
 * 采用的方案与 MailDesk 一致：握手要出示一个只存在当前用户数据目录里的秘密。
 *  - 秘密放 DATA_DIR/handshake（0700 / NTFS ACL 收紧），和 vault.enc 同一层保护；
 *  - 浏览器读不到文件，所以给一个引导页：用户把文件内容粘进去，校验通过后
 *    下发 HttpOnly + SameSite=Strict 的 cookie（一年），此后 fetch 自动带上，
 *    app.js 的 api() 一行都不用改；
 *  - 脚本用 X-KeyDesk-Handshake 头，校验的是同一个秘密。
 *
 * 明确边界：与 KeyDesk 同用户运行的任意代码仍可读到本文件，从而拿到 token。
 * 这条路无法用应用层鉴权堵住，唯一防线是操作系统账户边界。
 */
const HANDSHAKE_FILE = path.join(DATA_DIR, 'handshake');
const HANDSHAKE_COOKIE = 'keydesk_hs';
// 一年。服务重启不失效（秘密持久化在文件里），换浏览器 / 清 cookie 才需要重来。
const HANDSHAKE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;
// 引导失败的冷却。秘密是 256 位随机，穷举不可能；这里只是让"有人在试"
// 在耗时和日志上显形。允许连错 3 次再冷却：正常用户第一次也常粘错
// （多带空格、只复制了一半），一错就冷却会让他看到"尝试过于频繁"而不知所以。
const BOOTSTRAP_COOLDOWN_MS = 750;
const BOOTSTRAP_FREE_TRIES = 3;
let bootstrapFails = 0;
let bootstrapBlockedUntil = 0;

/**
 * 读或创建本机握手秘密。
 *
 * 持久化而不是每次启动随机生成：cookie 要跨重启继续有效，否则每次开服务都得
 * 重新粘贴一次 —— 那等于把"两次输入主口令"的负担加到了每次启动上。
 * 文件损坏时重新生成，代价只是用户重做一次引导，不涉及 vault.enc。
 */
function loadOrCreateHandshakeSecret() {
  try {
    const s = fs.readFileSync(HANDSHAKE_FILE, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(s)) return s;
  } catch { /* 不存在或读不了：走生成分支 */ }

  const s = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  // 原子写：tmp + fsync + rename。半截文件会让下次启动认不出来而重新生成，
  // 虽然不致命，但没有理由留这个窗口（用户会莫名其妙被要求重新授权）。
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
 * Windows 上 chmod 基本无效（实际仍是继承来的 ACL），用 icacls 尽力收到
 * "只有当前用户"。两步顺序不能反：先 /grant:r 当前用户，成功了再去继承 ACE。
 * 反过来做的话，一旦第 2 步生效、第 1 步失败，文件就只剩 Owner 的
 * READ_CONTROL/WRITE_DAC，下次启动读不到秘密只能重新生成。
 * 失败一律吞掉：文件已在用户目录里，默认 ACL 通常本来就够。
 */
function tightenWindowsAcl(file) {
  if (process.platform !== 'win32') return;
  try {
    const user = os.userInfo().username;
    if (!user) return;
    const { execFileSync } = require('child_process');
    // execFileSync + 参数数组不经过 shell：用户名/路径含空格或特殊字符时不会被解释
    execFileSync('icacls', [file, '/grant:r', user + ':F'], { stdio: 'ignore', timeout: 5000 });
    execFileSync('icacls', [file, '/inheritance:r'], { stdio: 'ignore', timeout: 5000 });
  } catch { /* 尽力而为 */ }
}

const HANDSHAKE_SECRET = loadOrCreateHandshakeSecret();
// cookie 里放派生值而不是秘密本身：浏览器 cookie 库同用户可以读，
// 写秘密原文等于把秘密复制了一份到磁盘上另一个位置。
// 派生值仍只由秘密决定，比较 cookie 等价于校验秘密。
// cookie 名不要带 __Host- / __Secure- 前缀：回环是明文 HTTP，带 Secure 的
// cookie 会被浏览器静默丢弃，表现就是"授权成功但刷新后又要授权"。
const HANDSHAKE_COOKIE_VALUE = crypto.createHmac('sha256', Buffer.from(HANDSHAKE_SECRET, 'utf8'))
  .update('keydesk/handshake-cookie/v1')
  .digest('hex');

/** 常量时间字符串比较。长度不同直接 false —— timingSafeEqual 长度不等会抛异常 */
function safeEqualStr(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a), 'utf8');
  const bb = Buffer.from(String(b == null ? '' : b), 'utf8');
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** 从 Cookie 头里取 keydesk_hs 并校验。SameSite=Strict 保证第三方网页带不上它。 */
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
 * 命令行 / 脚本用的握手头。
 * 两种凭据都认：浏览器自动带 cookie，脚本直接读文件传头最自然。
 * 两者校验的是同一个秘密，区别只在传递方式。
 */
function hasHandshakeHeader(req) {
  const v = req.headers['x-keydesk-handshake'];
  if (!v) return false;
  return safeEqualStr(String(v).trim(), HANDSHAKE_SECRET);
}

/* ---------------- 通用工具 ---------------- */

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

const HTTP_BY_CODE = {
  LOCKED: 423,
  BAD_PASSPHRASE: 401,
  THROTTLED: 429,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INVALID: 400,
  INTERNAL: 500,
};

/** 把内部错误翻译成 {status, code, error}，绝不外泄内部细节 */
function classifyError(e) {
  const code = (e && e.code && HTTP_BY_CODE[e.code]) ? e.code : 'INTERNAL';
  let message;
  if (code === 'INTERNAL') {
    // 原始 message 只进本地日志（可能含文件路径等内部信息）
    console.error('[api] internal:', (e && e.stack) || e);
    message = '服务器内部错误，详见终端日志';
  } else {
    message = String((e && e.message) || '请求失败');
  }
  return { status: HTTP_BY_CODE[code], code, error: message };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;

    const failOnce = err => {
      if (done) return;
      done = true;
      reject(err);
      // 不要 destroy()：销毁 socket 会让调用方连 400 都发不出去，
      // 客户端只看到连接被重置（ECONNRESET），排查时极难定位。
      // 改为把剩余数据流读掉后丢弃，让响应能正常写回。
      req.removeAllListeners('data');
      req.on('data', () => { /* 丢弃 */ });
      req.resume();
    };

    req.on('data', c => {
      if (done) return;
      size += c.length;
      if (size > MAX_BODY) {
        failOnce(fail('INVALID', '请求体过大（上限 ' + Math.floor(MAX_BODY / 1024) + ' KB）'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(fail('INVALID', '请求体必须是 JSON 对象'));
        }
        resolve(parsed);
      } catch {
        reject(fail('INVALID', 'JSON 解析失败'));
      }
    });
    req.on('error', e => { if (!done) { done = true; reject(e); } });
  });
}

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function json(res, status, obj, allowedOrigin) {
  const body = JSON.stringify(obj);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...SECURITY_HEADERS,
  };
  if (allowedOrigin) {
    headers['Access-Control-Allow-Origin'] = allowedOrigin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    headers['Access-Control-Max-Age'] = '600';
    headers['Vary'] = 'Origin';
  }
  res.writeHead(status, headers);
  res.end(body);
}

/** 校验 confirm:true 这类显式确认，缺了就是 400 */
function requireConfirm(body, what) {
  if (body.confirm !== true) {
    throw fail('INVALID', what + ' 需要显式确认（confirm: true）');
  }
}

/** 校验一个字符串参数并返回 trim 后的值 */
function reqString(v, name, { min = 1, max = 4096, trim = false } = {}) {
  if (typeof v !== 'string') throw fail('INVALID', name + ' 必须是字符串');
  const s = trim ? v.trim() : v;
  if (s.length < min) throw fail('INVALID', name + ' 不能为空');
  if (s.length > max) throw fail('INVALID', name + ' 太长（最多 ' + max + ' 个字符）');
  return s;
}

/* ---------------- 静态文件 ---------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
};

function serveStatic(req, res, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    // 畸形百分号编码会让 decodeURIComponent 抛 URIError，
    // 冒泡出去就是 uncaughtException —— 整个凭据库直接不可用。
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Bad Request');
  }

  // 拒绝 NUL 字节：某些平台上的路径 API 会在 NUL 处截断，
  // 从而绕过下面的前缀检查。
  if (decoded.indexOf('\u0000') >= 0) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Bad Request');
  }

  const rel = decoded.replace(/^\/+/, '') || 'index.html';
  const base = path.resolve(PUBLIC_DIR);
  const target = path.resolve(base, rel);

  if (target !== base && !target.startsWith(base + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Forbidden');
  }

  let st;
  try { st = fs.statSync(target); } catch { st = null; }
  if (!st || !st.isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Not Found');
  }

  const ext = path.extname(target).toLowerCase();
  const body = fs.readFileSync(target);
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': body.length,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    // 本地文件重传成本可忽略；no-cache 让改动立刻生效、排查时不会误判
    'Cache-Control': 'no-cache, must-revalidate',
    // 页面里没有内联脚本、没有 onclick、没有内联样式。
    // script-src 'self' 是硬约束：只要这一条在，即使将来某处
    // 出现注入点，也无法把内联脚本变成可执行代码。
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self'; " +
      "img-src 'self' data:; connect-src 'self'; object-src 'none'; " +
      "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  });
  res.end(body);
}

/* ---------------- 业务：状态 ---------------- */

/** 锁定态也能安全回答的部分 */
function vaultStatus() {
  const initialized = keystore.exists();
  const locked = keystore.isLocked();
  let entryCount = 0;
  let updatedAt = null;

  if (initialized) {
    updatedAt = keystore.updatedAt();
  }
  if (initialized && !locked) {
    try { entryCount = store.stats().entryCount; }
    catch { entryCount = 0; }
  }

  return {
    ok: true,
    initialized,
    locked,
    entryCount,
    idleTimeoutSec: keystore.idleTimeoutSec(),
    updatedAt,
    vaultPath: VAULT_PATH,
  };
}

/* ---------------- 业务：每个 action ---------------- */

/**
 * 锁定态下允许的 action。
 * 除此之外一律 423 —— 这是本工具最重要的一条边界：
 * 只要没解锁，任何一条秘密都不许出进程。
 */
const ALLOWED_WHILE_LOCKED = new Set([
  'handshake',
  'handshake.bootstrap',
  'vault.status',
  'vault.setup',
  'vault.unlock',
  'vault.unlockRecovery',
]);

async function dispatch(action, body) {
  switch (action) {
    /* ============ 密钥库 ============ */

    case 'vault.status':
      return vaultStatus();

    case 'vault.setup': {
      const passphrase = reqString(body.passphrase, 'passphrase', { min: 1, max: 1024 });
      const r = keystore.setup(passphrase);
      // 恢复密钥只在这一次响应里出现，之后无法再取回
      return { ok: true, recoveryKey: r.recoveryKey, vaultPath: r.vaultPath };
    }

    case 'vault.unlock': {
      const passphrase = reqString(body.passphrase, 'passphrase', { min: 1, max: 1024 });
      const r = keystore.unlock(passphrase);
      return { ok: true, expiresAt: r.expiresAt };
    }

    case 'vault.unlockRecovery': {
      const recoveryKey = reqString(body.recoveryKey, 'recoveryKey', { min: 1, max: 128 });
      const r = keystore.unlockWithRecovery(recoveryKey);
      return { ok: true, expiresAt: r.expiresAt };
    }

    case 'vault.lock':
      keystore.lock();
      return { ok: true };

    case 'vault.changePassphrase': {
      // oldPassphrase 允许空串：用恢复密钥解锁的会话里用户根本没有旧口令
      // （他忘了口令，那正是他走恢复密钥的原因）。是否真的要求旧口令由
      // keystore 按会话来源判定——这里只负责把值原样传下去，不做存在性拦截。
      // 新口令仍然要求非空：强度校验在 keystore 的 checkPassphrase 里。
      const oldPassphrase = reqString(body.oldPassphrase, 'oldPassphrase', { min: 0, max: 1024 });
      const newPassphrase = reqString(body.newPassphrase, 'newPassphrase', { min: 1, max: 1024 });
      const r = keystore.changePassphrase(oldPassphrase, newPassphrase);
      // staleBackups 非空 = 旧口令派生的 KEK 还留在那些备份里，
      // 也就是说"旧口令已失效"这个承诺没有完全兑现。必须告诉前端，
      // 让用户知道要手动删（通常是因为杀毒/网盘占着句柄）。
      return { ok: true, staleBackups: (r && r.staleBackups) || [] };
    }

    case 'vault.regenerateRecovery': {
      const passphrase = reqString(body.passphrase, 'passphrase', { min: 1, max: 1024 });
      const r = keystore.regenerateRecovery(passphrase);
      return {
        ok: true,
        recoveryKey: r.recoveryKey,
        staleBackups: (r && r.staleBackups) || [],
      };
    }

    case 'vault.settings': {
      if (body.idleTimeoutSec === undefined) {
        return { ok: true, idleTimeoutSec: keystore.idleTimeoutSec() };
      }
      const n = keystore.setIdleTimeout(body.idleTimeoutSec);
      settings.idleTimeoutSec = n;
      saveSettings(settings);
      return { ok: true, idleTimeoutSec: n };
    }

    /* ============ 条目 ============ */

    case 'entries.list': {
      const q = body.q == null ? '' : String(body.q);
      const group = body.group == null ? '' : String(body.group);
      const includeArchived = body.includeArchived === true;
      return { ok: true, items: store.list({ q, group, includeArchived }) };
    }

    case 'entries.get': {
      const id = reqString(body.id, 'id', { min: 1, max: 64 });
      return { ok: true, entry: store.get(id) };
    }

    case 'entries.upsert': {
      if (!body.entry || typeof body.entry !== 'object') {
        throw fail('INVALID', '缺少 entry 参数');
      }
      const entry = store.upsert(body.entry);
      return { ok: true, entry };
    }

    case 'entries.remove': {
      if (!Array.isArray(body.ids)) throw fail('INVALID', 'ids 必须是数组');
      const removed = store.remove(body.ids);
      return { ok: true, removed };
    }

    case 'entries.archive': {
      if (!Array.isArray(body.ids)) throw fail('INVALID', 'ids 必须是数组');
      if (typeof body.archived !== 'boolean') throw fail('INVALID', 'archived 必须是布尔值');
      const updated = store.archive(body.ids, body.archived);
      return { ok: true, updated };
    }

    /* ============ 验证码 ============ */

    case 'otp.codes': {
      let ids;
      if (body.ids !== undefined) {
        if (!Array.isArray(body.ids)) throw fail('INVALID', 'ids 必须是数组');
        ids = body.ids;
      }
      return { ok: true, ...store.codes(ids) };
    }

    case 'otp.check': {
      // 两种形态：{input: "otpauth://..." 或 "JBSW..."} 或结构化字段
      let secret, algorithm, digits, period, issuer = '', account = '';

      if (body.input !== undefined && body.input !== null && body.input !== '') {
        const input = reqString(body.input, 'input', { min: 1, max: 4096 }).trim();
        if (/^otpauth:\/\//i.test(input)) {
          const p = totp.parseOtpauth(input);
          secret = p.secret;
          algorithm = p.algorithm;
          digits = p.digits;
          period = p.period;
          issuer = p.issuer;
          account = p.account;
        } else {
          secret = totp.normalizeSecret(input);
          algorithm = 'SHA1';
          digits = 6;
          period = 30;
        }
      } else {
        if (body.secret === undefined) throw fail('INVALID', '需要 input 或 secret');
        secret = totp.normalizeSecret(reqString(body.secret, 'secret', { min: 1, max: 256 }));
        algorithm = totp.normalizeAlgorithm(body.algorithm == null ? 'SHA1' : body.algorithm);
        digits = body.digits == null ? 6 : Number(body.digits);
        if (digits !== 6 && digits !== 8) throw fail('INVALID', 'digits 只能是 6 或 8');
        period = body.period == null ? 30 : Number(body.period);
        if (!Number.isInteger(period) || period < 10 || period > 120) {
          throw fail('INVALID', 'period 必须是 10..120 之间的整数');
        }
      }

      const secretBuf = totp.base32Decode(secret);
      const nowSec = Math.floor(Date.now() / 1000);
      const remaining = period - (nowSec % period);
      const code = totp.totp(secretBuf, nowSec, digits, period, algorithm);

      return {
        ok: true,
        normalized: { issuer, account, secret, algorithm, digits, period },
        preview: { code, remaining },
      };
    }

    case 'otp.verify': {
      const id = reqString(body.id, 'id', { min: 1, max: 64 });
      const code = reqString(body.code, 'code', { min: 1, max: 16 });
      const r = store.verify(id, code);
      return { ok: true, matched: r.matched, window: r.window };
    }

    /* ============ 恢复码 ============ */

    case 'recovery.reveal': {
      requireConfirm(body, '查看恢复码');
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const setId = reqString(body.setId, 'setId', { min: 1, max: 64 });
      return { ok: true, codes: store.revealRecovery(entryId, setId) };
    }

    case 'recovery.addSet': {
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const text = reqString(body.text, 'text', { min: 1, max: 65536 });
      const set = store.addSet(entryId, {
        label: body.label,
        createdAt: body.createdAt,
        trackUsage: body.trackUsage,
        text,
      });
      return { ok: true, set };
    }

    case 'recovery.setCurrent': {
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const setId = reqString(body.setId, 'setId', { min: 1, max: 64 });
      store.setCurrentSet(entryId, setId);
      return { ok: true };
    }

    case 'recovery.updateSet': {
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const setId = reqString(body.setId, 'setId', { min: 1, max: 64 });
      const set = store.updateSet(entryId, setId, {
        label: body.label,
        note: body.note,
        trackUsage: body.trackUsage,
      });
      return { ok: true, set };
    }

    case 'recovery.removeSet': {
      requireConfirm(body, '删除恢复码集合');
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const setId = reqString(body.setId, 'setId', { min: 1, max: 64 });
      const removed = store.removeSet(entryId, setId);
      return { ok: true, removed };
    }

    case 'recovery.markCodes': {
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      const setId = reqString(body.setId, 'setId', { min: 1, max: 64 });
      if (!Array.isArray(body.codeIds)) throw fail('INVALID', 'codeIds 必须是数组');
      if (typeof body.used !== 'boolean') throw fail('INVALID', 'used 必须是布尔值');
      const updated = store.markCodes(entryId, setId, body.codeIds, body.used);
      return { ok: true, updated };
    }

    /* ============ 秘密揭示 ============ */

    case 'secrets.reveal': {
      requireConfirm(body, '揭示秘密');
      const id = reqString(body.id, 'id', { min: 1, max: 64 });
      const field = reqString(body.field, 'field', { min: 1, max: 16 });
      const r = store.revealSecret(id, field);
      return { ok: true, value: r.value };
    }

    /* ============ 审计 ============ */

    // 审计视图只读、只看汇总字段（不含任何秘密值），但**仍然要求已解锁**：
    // "哪些账号没开 2FA"本身就是有价值的信息，锁定态下不该泄露。
    case 'audit.list':
      return { ok: true, ...store.auditList() };

    /* ============ 导出 / 二维码 / 备份 ============ */

    case 'entries.export': {
      requireConfirm(body, '导出');
      const r = store.exportOtpauth();
      return { ok: true, items: r.items, text: r.text };
    }

    /**
     * 加密备份包。
     *
     * 为什么不加 confirm:true：这个 action 的 body 里必须带 passphrase，
     * 已经是一个显式的、需要用户输入的动作，不是"点一下按钮就发生"的
     * 高危操作；再叠一层 confirm 只是多一个前端要拼的字段。
     * 真正的守卫是两条：必须已解锁（handleApi 里锁定态 → 423，
     * dispatch 只在过了那道门之后才会被调用），以及口令长度校验。
     */
    case 'export.encrypted': {
      const passphrase = reqString(body.passphrase, 'passphrase',
        { min: 1, max: 1024, trim: false });
      const r = store.exportEncrypted({ passphrase });
      // 只回路径和大小，绝不回任何密文内容 —— 导出包已经在磁盘上，
      // 再从 API 里传一遍只会多一份可能被日志记下的副本。
      return { ok: true, path: r.path, bytes: r.bytes };
    }

    case 'print.recovery': {
      const entryId = reqString(body.entryId, 'entryId', { min: 1, max: 64 });
      // 这里刻意**不**加 confirm:true，虽然返回的是一整组恢复码明文：
      // 打印是一个需要用户显式进入打印视图、再点"打印"的两步动作，
      // 而且 A2 的调用契约（规格 §2.4）只传 entryId。多要求一个字段
      // 会让前端静默 400，用户看到的是"打印没反应"——安检没加上，
      // 功能先坏了。
      return { ok: true, html: store.printRecovery(entryId) };
    }

    case 'qr.svg': {
      const text = reqString(body.text, 'text', { min: 1, max: 4096 });
      // 超长直接 400，不靠 QR 模块内部抛普通 Error 变成 500
      const byteLen = Buffer.byteLength(text, 'utf8');
      if (byteLen > qr.MAX_PAYLOAD_BYTES) {
        throw fail('INVALID', '二维码内容太长（' + byteLen + ' 字节，最多 ' +
          qr.MAX_PAYLOAD_BYTES + ' 字节）');
      }
      const svg = qr.toSvg(text, { scale: 6, margin: 3 });
      return { ok: true, svg };
    }

    case 'backup.info': {
      const stats = store.stats();
      let size = 0;
      try { size = fs.statSync(VAULT_PATH).size; } catch { size = 0; }
      return {
        ok: true,
        path: VAULT_PATH,
        size,
        updatedAt: stats.updatedAt,
        revision: stats.revision,
        entries: stats.entryCount,
        backups: keystore.backupInfo(),
      };
    }

    default:
      throw fail('NOT_FOUND', '未知的 action：' + String(action).slice(0, 64));
  }
}

/* ---------------- API 入口 ---------------- */

async function handleApi(req, res, url, allowedOrigin) {
  const action = url.searchParams.get('action') || '';

  if (!action) {
    return json(res, 400, { ok: false, error: '缺少 action 参数', code: 'INVALID' }, allowedOrigin);
  }

  // ---- 握手 ----
  // 不再无条件发 token。三条合法路径：
  //  1. 已经引导过（cookie 有效）—— 浏览器正常流程，app.js 的 api() 无需改动；
  //  2. 带 X-KeyDesk-Handshake: <本机秘密> —— 给脚本 / 命令行用；
  //  3. 刚用秘密完成引导，同一响应里直接下发 token。
  // 三条都拿不到秘密的，就是本机其他账户 / 沙箱进程 —— 正是要挡住的对象。
  if (action === 'handshake') {
    if (req.method !== 'GET' && req.method !== 'POST') {
      return json(res, 405, { ok: false, error: '方法不允许', code: 'INVALID' }, allowedOrigin);
    }
    if (hasHandshakeCookie(req) || hasHandshakeHeader(req)) {
      return json(res, 200, { ok: true, token: SESSION_TOKEN }, allowedOrigin);
    }
    return json(res, 401, {
      ok: false,
      code: 'HANDSHAKE_REQUIRED',
      error: '需要先完成本机授权：在浏览器打开本服务的首页，粘贴授权码',
      handshakeFile: HANDSHAKE_FILE,
    }, allowedOrigin);
  }

  // ---- 引导：用本机秘密换 cookie ----
  // 只接受同源请求（Sec-Fetch-Site: same-origin）。这条挡住的是"用户误开了
  // 恶意网页、那个网页跨站 POST 到本机"——浏览器会带 Sec-Fetch-Site: cross-site，
  // 而且跨站请求带自定义头必然触发预检，预检过不了。
  if (action === 'handshake.bootstrap') {
    // 冷却判断放在来源校验之前：进了冷却就一律 429，不受请求来源影响。
    // 连错 BOOTSTRAP_FREE_TRIES 次才开始冷却（见常量处的注释）。
    if (Date.now() < bootstrapBlockedUntil) {
      return json(res, 429, { ok: false, error: '尝试过于频繁，请稍后再试' }, allowedOrigin);
    }
    const site = String(req.headers['sec-fetch-site'] || '');
    // 兜底：个别老浏览器不发 Sec-Fetch-Site（Safari 16.4 之前），
    // 这时退回到"Origin 必须正好是本服务自己的源"。allowedOrigin 非空
    // 就意味着 handleRequest 已经校验过它是 127.0.0.1/localhost 的本端口。
    if (site !== 'same-origin' && !(site === '' && allowedOrigin)) {
      return json(res, 403, {
        ok: false,
        error: '只接受来自本服务页面的授权请求（Sec-Fetch-Site 校验失败）',
      }, allowedOrigin);
    }
    let b;
    try { b = await readBody(req); } catch { b = null; }
    const secret = String((b && (b.secret || b.code)) || '').trim();
    if (!safeEqualStr(secret, HANDSHAKE_SECRET)) {
      bootstrapFails++;
      if (bootstrapFails >= BOOTSTRAP_FREE_TRIES) {
        bootstrapBlockedUntil = Date.now() + BOOTSTRAP_COOLDOWN_MS;
      }
      console.error('[handshake] 引导失败：授权码不正确（来源 ' +
        (req.socket.remoteAddress || '?') + '）');
      return json(res, 401, {
        ok: false,
        error: '授权码不正确：请打开 ' + HANDSHAKE_FILE + ' 复制整行内容',
      }, allowedOrigin);
    }
    bootstrapFails = 0;
    // cookie 里放 HMAC 派生值而不是秘密本身；HttpOnly 让页面脚本拿不到它，
    // SameSite=Strict 让第三方页面带不上它。不加 Secure：回环是明文 HTTP，
    // 带 Secure 的 cookie 会被浏览器丢弃，用户就永远引导不成功。
    res.setHeader('Set-Cookie',
      HANDSHAKE_COOKIE + '=' + HANDSHAKE_COOKIE_VALUE
      + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + HANDSHAKE_COOKIE_MAX_AGE);
    return json(res, 200, { ok: true, token: SESSION_TOKEN }, allowedOrigin);
  }

  // ---- token 校验 ----
  const auth = String(req.headers['authorization'] || '');
  const provided = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  // timingSafeEqual 要求两侧字节数相同，用字符串长度比较容易在多字节输入上抛错
  const providedBuf = Buffer.from(provided, 'utf8');
  if (providedBuf.length !== SESSION_TOKEN_BYTES ||
      !crypto.timingSafeEqual(providedBuf, SESSION_TOKEN_BUF)) {
    return json(res, 401, { ok: false, error: '未授权：缺少或错误的访问令牌', code: 'BAD_PASSPHRASE' },
      allowedOrigin);
  }

  // ---- 锁定态硬门 ----
  // 先做自动锁定判定：闲置超时后即使进程还活着，也要立刻回到 423。
  //
  // 轮询类接口不算「用户活动」：前端每 5 秒调一次 otp.codes 刷验证码，
  // 若把它算作活动，空闲锁定永远不会触发（elapsed 永远 ~5 秒）。
  // 只读的状态查询同理。
  const PASSIVE_ACTIONS = new Set(['otp.codes', 'vault.status', 'backup.info']);
  if (keystore.maybeAutoLock(!PASSIVE_ACTIONS.has(action))) {
    return json(res, 423, { ok: false, error: '密钥库已自动锁定（空闲超时）', code: 'LOCKED' }, allowedOrigin);
  }
  if (keystore.isLocked() && !ALLOWED_WHILE_LOCKED.has(action)) {
    return json(res, 423, { ok: false, error: '密钥库已锁定，请先解锁', code: 'LOCKED' }, allowedOrigin);
  }

  // ---- 读 body ----
  let body = {};
  if (req.method === 'POST' || req.method === 'PUT') {
    try { body = await readBody(req); }
    catch (e) {
      const c = classifyError(e);
      return json(res, c.status, { ok: false, error: c.error, code: c.code }, allowedOrigin);
    }
  }

  try {
    const out = await dispatch(action, body);
    return json(res, 200, out, allowedOrigin);
  } catch (e) {
    const c = classifyError(e);
    return json(res, c.status, { ok: false, error: c.error, code: c.code }, allowedOrigin);
  }
}

/* ---------------- 握手引导页 ---------------- */

/**
 * 引导页 HTML。
 *
 * 为什么由 server.js 动态吐而不是放进 public/：
 *  - 这个页面必须知道自己的 CSP nonce，静态文件做不到；
 *  - 它是"未授权"状态的页面，不能出现在 public/ 里被当作普通静态资源
 *    随意取用（那会让 index.html 的语义变得含糊）。
 *
 * CSP 用 nonce 而不是 'unsafe-inline'：页面里只有一段内联脚本，
 * 用 nonce 既能跑，又保持 script-src 里没有 unsafe-inline
 * （security-test 断言了 index.html 与静态 CSP 都不含 unsafe-inline）。
 */
function bootstrapPage(nonce) {
  const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeyDesk · 本机授权</title>
<style nonce="${nonce}">
 body{font:14px/1.7 system-ui,"Segoe UI",sans-serif;background:#f5f6f8;color:#1f2430;margin:0;padding:48px 16px}
 .card{max-width:640px;margin:0 auto;background:#fff;border:1px solid #dde3ec;border-radius:10px;padding:24px 28px}
 h1{font-size:18px;margin:0 0 8px}
 p{margin:8px 0;color:#3c4455}
 code,textarea{font-family:ui-monospace,Consolas,monospace}
 code{background:#eef2f8;padding:1px 5px;border-radius:4px;font-size:13px;word-break:break-all}
 textarea{width:100%;box-sizing:border-box;height:64px;margin:10px 0;padding:8px;border:1px solid #c9d2e0;border-radius:6px;font-size:13px;resize:vertical}
 button{background:#2f6fed;color:#fff;border:0;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer}
 button[disabled]{opacity:.55;cursor:default}
 .err{color:#b42318;min-height:20px;margin-top:8px}
 .ok{color:#067647}
 .hint{font-size:12.5px;color:#667085}
</style></head><body><div class="card">
<h1>KeyDesk 需要一次本机授权</h1>
<p>这个工具存着你的 2FA 密钥和恢复码 —— 有了它们就能登录你所有开了两步验证的账号。
所以每次换浏览器访问前，要先证明"你本人坐在这台电脑前"。
授权码只存在你的用户目录里，本机其他账户读不到：</p>
<p><code>${escHtml(HANDSHAKE_FILE)}</code></p>
<p>用记事本打开它（或在终端里 <code>type "${escHtml(HANDSHAKE_FILE)}"</code>），
把整行 64 位字符粘贴到下面。每个浏览器只需做一次，之后会记住。</p>
<textarea id="code" spellcheck="false" autocomplete="off" placeholder="粘贴 64 位授权码"></textarea>
<button id="go">授权</button>
<div class="err" id="msg" role="alert"></div>
<p class="hint">脚本或命令行可以直接带请求头，不必走浏览器：
<code>curl -H "X-KeyDesk-Handshake: $(cat "${escHtml(HANDSHAKE_FILE)}")" "http://127.0.0.1:2151/api?action=handshake"</code></p>
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
    // X-KeyDesk-Bootstrap 是自定义头：跨站请求带它必然触发预检，
    // 而本服务的 CORS 白名单只放行自己这个端口，预检过不去。
    fetch('/api?action=handshake.bootstrap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KeyDesk-Bootstrap': '1' },
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
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; " +
      "img-src 'self' data:; connect-src 'self'; object-src 'none'; " +
      "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
  });
  res.end(body);
}

/* ---------------- 请求总入口 ---------------- */

let PORT = 0;

function handleRequest(req, res) {
  let url;
  try {
    url = new URL(req.url, 'http://127.0.0.1');
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Bad Request');
  }

  // Host 校验：DNS rebinding 下浏览器认为请求同源、不发预检，
  // 唯一能拦住的就是服务端自己核对 Host。
  const host = String(req.headers.host || '');
  const expectedHosts = PORT ? [`127.0.0.1:${PORT}`, `localhost:${PORT}`] : [];
  if (expectedHosts.length && !expectedHosts.includes(host)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    return res.end('Forbidden: invalid Host header');
  }

  // CORS：只接受本端口 127.0.0.1 / localhost。绝不回 '*'
  const origin = req.headers.origin;
  let allowedOrigin = null;
  if (origin) {
    try {
      const o = new URL(origin);
      const okHost = o.hostname === '127.0.0.1' || o.hostname === 'localhost';
      const okPort = o.port === String(PORT);
      allowedOrigin = (okHost && okPort) ? origin : null;
    } catch { allowedOrigin = null; }
  }

  if (req.method === 'OPTIONS') {
    const headers = { ...SECURITY_HEADERS, 'Content-Length': 0 };
    if (allowedOrigin) {
      headers['Access-Control-Allow-Origin'] = allowedOrigin;
      headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
      headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
      headers['Access-Control-Max-Age'] = '600';
      headers['Vary'] = 'Origin';
    }
    res.writeHead(204, headers);
    return res.end();
  }

  if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
    return handleApi(req, res, url, allowedOrigin)
      .catch(e => {
        console.error('[api] unhandled:', (e && e.stack) || e);
        if (!res.headersSent) {
          json(res, 500, { ok: false, error: '服务器内部错误，详见终端日志', code: 'INTERNAL' }, null);
        }
      });
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Method Not Allowed');
  }

  /* ---- 首页拦截（握手鉴权的浏览器侧）----
   * 没授权就不给首页：否则用户会看到一个"读不到密钥库状态、只弹一句错误"的
   * 界面，完全不知道需要先做什么。给出授权页，里面写着授权码文件和用法。
   * 已授权过的浏览器照常拿 index.html —— 原有使用流程一个字都不变。
   */
  if (url.pathname === '/' || url.pathname === '/index.html') {
    if (hasHandshakeCookie(req)) return serveStatic(req, res, url.pathname);
    return sendBootstrapPage(res);
  }

  return serveStatic(req, res, url.pathname);
}

const server = http.createServer((req, res) => {
  try {
    handleRequest(req, res);
  } catch (e) {
    // handleRequest 内部已有 try/catch，这里是最后一道：
    // 任何漏网的同步异常都不许把进程打死（打死 = 密钥库不可用）
    console.error('[request] uncaught:', (e && e.stack) || e);
    try {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Internal Server Error');
      }
    } catch { /* 连接已断开 */ }
  }
});

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
    const envPort = parseInt(process.env.KEYDESK_PORT, 10);
    const want = Number.isInteger(envPort) && envPort > 0 && envPort < 65536 ? envPort : DEFAULT_PORT;
    const tries = Number.isInteger(envPort) ? 1 : PORT_TRIES;

    (async () => {
      // 先占锁，再 listen。顺序不能反：这个锁存在的全部意义就是拦住
      // "端口被占 → 顺延到 2152 → 第二个实例照样跑起来"那条路。
      // 失败时直接把 INSTANCE_RUNNING 抛给调用方，由它打提示并退出。
      instanceLock.acquire(path.join(DATA_DIR, 'server.lock'));

      let bound = null;
      let lastErr = null;

      for (let i = 0; i < tries; i++) {
        const p = want + i;
        if (p > 65535) break;
        try {
          bound = await listenOn(p);
          break;
        } catch (e) {
          lastErr = e;
          if (e.code !== 'EADDRINUSE') throw e;
        }
      }

      if (!bound) {
        const msg = lastErr && lastErr.code === 'EADDRINUSE'
          ? `端口 ${want}${tries > 1 ? '~' + (want + tries - 1) : ''} 都被占用，` +
            '请关掉占用端口的程序，或用 KEYDESK_PORT 指定其它端口'
          : `无法启动服务：${(lastErr && lastErr.message) || '未知错误'}`;
        throw new Error(msg);
      }

      PORT = bound;
      const addr = `http://127.0.0.1:${PORT}`;

      // 启动横幅保持纯 ASCII：Windows cmd 默认 GBK 代码页，
      // start.bat 会先 chcp 65001，但用户也可能直接 node server.js。
      console.log('');
      console.log('  +------------------------------------------------+');
      console.log('  |            KeyDesk  -  2FA Vault               |');
      console.log('  +------------------------------------------------+');
      console.log('');
      console.log('  URL      : ' + addr);
      console.log('  Data dir : ' + DATA_DIR);
      console.log('  Auth file: ' + HANDSHAKE_FILE);
      console.log('  Vault    : ' + (keystore.exists() ? 'initialized' : 'not initialized'));
      if (bound !== want) console.log('  Note     : port ' + want + ' was busy, using ' + bound);
      console.log('');
      console.log('  Press Ctrl+C to stop.');
      console.log('');
      resolve(addr);
    })().catch(e => {
      // 走到这里说明抢到了锁但启动失败（端口全占、权限问题等）。
      // 必须把锁还回去：否则用户关掉占端口的程序后重开，会被自己上次
      // 失败尝试留下的锁挡住，看到"已经有一个 KeyDesk 在运行"。
      try { instanceLock.release(); } catch { /* 忽略 */ }
      reject(e);
    });
  });
}

if (require.main === module) {
  start().catch(e => {
    // 锁冲突时给一句人能看懂的话，而不是把整个异常栈丢给双击启动的用户。
    if (e && e.code === 'INSTANCE_RUNNING') {
      console.error(e.message);
    } else {
      console.error('启动失败：' + e.message);
    }
    process.exit(1);
  });

  // 退出前锁库：把内存里的 DEK 抹掉。虽然进程退出后内存也就没了，
  // 但显式清零能保证核心转储里不会留下密钥。
  // 顺手释放实例锁：放在 process.exit 之前，用户不用等 pid 回收就能重开。
  const shutdown = () => {
    try { keystore.lock(); } catch { /* 忽略 */ }
    try { instanceLock.release(); } catch { /* 忽略 */ }
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGHUP', shutdown);
  process.on('SIGBREAK', shutdown);

  process.on('uncaughtException', e => {
    try { console.error('[uncaughtException]', (e && e.stack) || e); } catch { /* 忽略 */ }
    try { keystore.lock(); } catch { /* 忽略 */ }
    try { instanceLock.release(); } catch { /* 忽略 */ }
    process.exit(1);
  });
  process.on('unhandledRejection', reason => {
    try { console.error('[unhandledRejection]', (reason && (reason.stack || reason.message)) || reason); }
    catch { /* 忽略 */ }
  });
}

module.exports = { start, SESSION_TOKEN, keystore, store };
