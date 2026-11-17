'use strict';
/**
 * KeyDesk 服务端
 *
 * 单文件、switch(action) 分发，不引第三方依赖。
 *
 * 安全基线（与 MailDesk 同一套，但按本工具的威胁模型调整）：
 *  1. 只监听 127.0.0.1，端口固定 2151-2160
 *  2. 启动生成一次性会话 token，除 handshake 外全部要求 Bearer
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
const { URL } = require('url');

const { KeyStore } = require('./lib/keystore');
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
  'vault.status',
  'vault.setup',
  'vault.unlock',
  'vault.unlockRecovery',
]);

async function dispatch(action, body) {
  switch (action) {
    /* ============ 会话 ============ */

    case 'handshake':
      return { ok: true, token: SESSION_TOKEN };

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
      const oldPassphrase = reqString(body.oldPassphrase, 'oldPassphrase', { min: 1, max: 1024 });
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

  // ---- 握手：唯一不需要 token 的接口 ----
  if (action === 'handshake') {
    if (req.method !== 'GET' && req.method !== 'POST') {
      return json(res, 405, { ok: false, error: '方法不允许', code: 'INVALID' }, allowedOrigin);
    }
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
      console.log('  Vault    : ' + (keystore.exists() ? 'initialized' : 'not initialized'));
      if (bound !== want) console.log('  Note     : port ' + want + ' was busy, using ' + bound);
      console.log('');
      console.log('  Press Ctrl+C to stop.');
      console.log('');
      resolve(addr);
    })().catch(reject);
  });
}

if (require.main === module) {
  start().catch(e => {
    console.error('启动失败：' + e.message);
    process.exit(1);
  });

  // 退出前锁库：把内存里的 DEK 抹掉。虽然进程退出后内存也就没了，
  // 但显式清零能保证核心转储里不会留下密钥。
  const shutdown = () => {
    try { keystore.lock(); } catch { /* 忽略 */ }
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGHUP', shutdown);
  process.on('SIGBREAK', shutdown);

  process.on('uncaughtException', e => {
    try { console.error('[uncaughtException]', (e && e.stack) || e); } catch { /* 忽略 */ }
    try { keystore.lock(); } catch { /* 忽略 */ }
    process.exit(1);
  });
  process.on('unhandledRejection', reason => {
    try { console.error('[unhandledRejection]', (reason && (reason.stack || reason.message)) || reason); }
    catch { /* 忽略 */ }
  });
}

module.exports = { start, SESSION_TOKEN, keystore, store };
