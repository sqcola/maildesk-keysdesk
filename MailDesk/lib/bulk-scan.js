'use strict';
/**
 * 批量收验证码：单账号扫描器
 *
 * 与旧的「列表 1 次 + 每封正文各 1 次连接」不同，这里一个账号只建
 * 一条 IMAP 连接：列表、N 封正文全在同一条连接上串行跑完。
 *
 * 不可动摇的两条：
 *  - token 必须走 mail.getAccessToken(account)：它负责 refresh_token 轮换
 *    落盘；自己拼 OAuth 请求会让旧令牌当场作废，等于销毁账号凭据
 *  - ImapClient 的 _current 是单槽位，不支持流水线，正文必须 for...of + await
 *
 * 安全约束（红队复核）：
 *  - 排序只认 IMAP 服务端分配的 UID（单调递增），不认发件人可伪造的 Date 头
 *  - subject/from 各截断 200 字符；每账号最多 20 条码
 *  - 结果里绝不出现账户对象、secrets 或任何 token
 */
const mail = require('./mail');
const { ImapClient, parseFetchResponse, decodeMimeWord } = require('./imap-client');
const { extractCode } = require('./code-extractor');

const DEFAULT_PER_ACCOUNT = 8;
const MAX_PER_ACCOUNT = 20;
const MAX_CODES = 20;
const MAX_FIELD = 200;
const DEFAULT_TIMEOUT_MS = 25000;
// 列表窗口：只为挑最近几封正文取列表，避免大邮箱一次拉全量 ENVELOPE
const LIST_WINDOW = 100;

// 服务端已知的内置文件夹名（快速放行）。
// select() 自身会拦控制字符并转义引号/反斜杠，这里再收一层：
// 已知名字直接通过；自定义文件夹只允许安全字符集，杜绝命令注入面。
const KNOWN_MAILBOXES = new Set([
  'INBOX', 'Junk', 'Junk Email', 'Spam', 'Sent', 'Sent Items',
  'Drafts', 'Deleted', 'Deleted Items', 'Trash', 'Archive', 'Outbox',
  '收件箱', '垃圾邮件', '已发送邮件', '草稿', '已删除邮件', '存档',
]);
// 自定义文件夹也只允许这份已知安全字符集：字母数字、层级斜杠、
// 常见分隔符与中文。引号/反斜杠/控制字符一律拒绝（select 会二次转义）。
const SAFE_MAILBOX_CHARS = /^[A-Za-z0-9 \/._\-一-鿿]+$/;

function isSafeMailbox(v) {
  if (typeof v !== 'string') return false;
  const name = v.trim();
  if (!name || name.length > 128) return false;
  // 与 ImapClient.select 同一套控制字符拦截（_command 也兜底拦 CR/LF）
  if (/[\x00-\x1f\x7f]/.test(name)) return false;
  // 已知内置文件夹快速放行；其余只允许安全字符集，select() 再做 quoted 转义
  if (KNOWN_MAILBOXES.has(name)) return true;
  return SAFE_MAILBOX_CHARS.test(name);
}

function clampInt(v, fallback, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

function clip(s, max = MAX_FIELD) {
  return String(s == null ? '' : s).slice(0, max);
}

function safeISO(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

function isUnseen(flags) {
  const list = Array.isArray(flags) ? flags : [];
  return !list.some(f => String(f).toLowerCase() === '\\seen');
}

/**
 * 从 UID FETCH 的响应里取出 BODY[] literal。
 * ImapClient 把 literal 原样并入 r.text；按 {n} 声明的字节数切，
 * 再兜一层去尾部 tagged response，避免把 ")\r\nA2 OK ..." 当正文。
 */
function extractLiteral(text) {
  const s = String(text || '');
  // ENVELOPE 里偶尔也会出现 literal（超长主题），不能见 {n} 就切。
  // 优先认 BODY[] 的 literal；找不到再退到全文最后一个 {n}。
  let m = /BODY(?:\[[^\]]*\])?\s*\{(\d+)\}\r?\n/i.exec(s);
  if (!m) {
    const all = [...s.matchAll(/\{(\d+)\}\r?\n/g)];
    m = all.length ? all[all.length - 1] : null;
  }
  if (!m) return '';
  const n = parseInt(m[1], 10);
  if (!Number.isFinite(n) || n < 0) return '';
  const start = m.index + m[0].length;

  let raw;
  try {
    raw = Buffer.from(s.slice(start), 'utf8').subarray(0, Math.min(n, 5 * 1024 * 1024)).toString('utf8');
  } catch {
    raw = s.slice(start, start + n);
  }
  return raw.replace(/\)\s*\r?\nA\d+\s+OK[\s\S]*$/, '').replace(/\r?\n\)\s*$/, '');
}

function envelopeFields(it, parsed) {
  const env = (it && it.envelope) || {};
  const from = (env.from && env.from[0]) || {};
  const headers = (parsed && parsed.headers) || {};
  return {
    subject: clip(decodeMimeWord(env.subject || '') || headers.subject || '(无主题)'),
    from: clip(from.address || headers.from || ''),
    date: safeISO(env.date),
  };
}

/** 返回不含任何凭据的中文错误对象 */
function failure(e, timedOut, timeoutMs) {
  const reason = mail.classifyError(e);
  let error;
  if (timedOut) {
    error = timeoutMs >= 1000
      ? `单账号扫描超时（${Math.round(timeoutMs / 1000)} 秒），已断开连接`
      : `单账号扫描超时（${timeoutMs} 毫秒），已断开连接`;
  } else if (reason && reason !== '未知错误') error = reason;
  else error = '账号扫描失败，请稍后重试';
  return {
    ok: false,
    codes: [],
    scanned: 0,
    unseenCount: 0,
    error,
    reason,
  };
}

/**
 * 扫描一个账号。
 *
 * opts: { mailbox='INBOX', perAccount=8, onlyUnread=false, timeoutMs=25000 }
 * 返回: { ok, codes, scanned, unseenCount, error?, reason? }
 *
 * opts.onProgress({ phase, done, total, found })
 *   逐封进度回调，用于让前端显示"正在读取第 3/8 封"而不是干等。
 *   phase: 'connect' | 'list' | 'read' | 'done'
 *   回调抛异常会被吞掉——进度上报失败不能影响扫描本身。
 *
 * 正常情况下不会抛异常；所有失败都收进返回对象。
 */
async function scanAccount(account, opts = {}) {
  const o = (opts && typeof opts === 'object') ? opts : {};
  const mailbox = typeof o.mailbox === 'string' && o.mailbox.trim() ? o.mailbox.trim() : 'INBOX';
  const perAccount = clampInt(o.perAccount, DEFAULT_PER_ACCOUNT, 1, MAX_PER_ACCOUNT);
  const onlyUnread = o.onlyUnread === true;
  const t = Number(o.timeoutMs);
  const timeoutMs = Number.isFinite(t) && t > 0 ? Math.min(t, 120000) : DEFAULT_TIMEOUT_MS;

  // 进度上报：任何异常都不允许影响扫描
  const report = (p) => {
    if (typeof o.onProgress !== 'function') return;
    try { o.onProgress(p); } catch { /* 忽略 */ }
  };

  if (!isSafeMailbox(mailbox)) {
    return {
      ok: false, codes: [], scanned: 0, unseenCount: 0,
      error: '邮箱名包含非法控制字符或格式不合法', reason: '未知错误',
    };
  }

  let client = null;
  let timedOut = false;
  let timer = null;
  const timeoutError = new Error('单账号扫描超时');
  timeoutError.code = 'BULK_SCAN_TIMEOUT';

  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      // 立刻断链：让挂住的 _command 尽快 reject，doScan 的 finally 得以执行；
      // 不在这里调 logout，避免和 finally 里的 logout 抢占 _current 单槽位。
      try { if (client) client.destroy(); } catch { /* 忽略 */ }
      reject(timeoutError);
    }, timeoutMs);
  });

  const doScan = (async () => {
    try {
      // 必须走这个函数：refresh_token 轮换 + 串行化 + 落盘都在里面
      const auth = await mail.getAccessToken(account);
      if (timedOut) throw timeoutError;

      const email = account && account.email ? String(account.email) : '';

      // 建连 + 认证，遇到微软的概率性拒绝就换新连接重试。
      // 实测这条错误在 100 个账号里会随机命中 1-3 个（串行也照样有），
      // 但在同一连接上反复 AUTHENTICATE 不一定管用——被拒的是这次 TCP 会话，
      // 所以必须重建连接。批量场景用 fast 序列，避免吃掉 25 秒预算。
      // 微软 IMAP 认证会随机拒绝部分账号。实测三套策略后确认：
      // 均匀 3 秒重试的命中率高于稀疏长间隔。这里给 4 次（约 12 秒），
      // 仍在单账号 25 秒预算内。
      const authDelays = [3000, 3000, 3000, 3000];
      let authErr = null;
      for (let attempt = 0; attempt <= authDelays.length; attempt++) {
        client = new ImapClient({
          host: mail.IMAP_HOST,
          port: 993,
          auth: { user: email, accessToken: auth.accessToken },
          timeout: 30000,
        });
        try {
          await client.connect();
          if (timedOut) throw timeoutError;
          await client.authenticateXoauth2();
          authErr = null;
          break;
        } catch (e) {
          authErr = e;
          try { client.destroy(); } catch { /* 忽略 */ }
          client = null;
          if (timedOut) throw timeoutError;
          const transient = /User is authenticated but not connected/i.test(String(e && e.message));
          if (!transient || attempt === authDelays.length) throw e;
          await new Promise(r => setTimeout(r, authDelays[attempt]));
          if (timedOut) throw timeoutError;
        }
      }
      if (authErr) throw authErr;
      if (timedOut) throw timeoutError;
      report({ phase: 'list', done: 0, total: 0, found: 0 });
      const mb = await client.select(mailbox);
      if (timedOut) throw timeoutError;

      const exists = (mb && Number(mb.exists)) || 0;
      if (exists === 0) {
        report({ phase: 'done', done: 0, total: 0, found: 0 });
        return { ok: true, codes: [], scanned: 0, unseenCount: 0 };
      }

      // 一次 FETCH 拿列表；ENVELOPE 只用于展示，不参与排序
      const start = Math.max(1, exists - LIST_WINDOW + 1);
      const listText = await client.fetch(`${start}:*`, 'UID FLAGS RFC822.SIZE ENVELOPE');
      if (timedOut) throw timeoutError;
      const items = parseFetchResponse(listText)
        .filter(it => Number.isInteger(it.uid) && it.uid > 0)
        // Date 头由发件人控制，UID 由 IMAP 服务端分配且单调递增：
        // 最近的邮件只看 UID，不能用伪造到 2099 年的 Date 把它顶到第一行
        .sort((a, b) => b.uid - a.uid);

      // unseenCount 回填过滤前的未读数
      const unseenCount = items.filter(it => isUnseen(it.flags)).length;
      const pool = onlyUnread ? items.filter(it => isUnseen(it.flags)) : items;
      const candidates = pool.slice(0, perAccount);
      const codes = [];

      // 逐封上报，让前端能显示"正在读取第 3/6 封"而不是干等
      report({ phase: 'read', done: 0, total: candidates.length, found: 0 });

      // _current 是单槽位：必须串行，绝不 Promise.all
      let readIdx = 0;
      for (const it of candidates) {
        if (timedOut) throw timeoutError;
        try {
          const r = await client.fetchBody({ uid: it.uid });
          if (timedOut) throw timeoutError;
          // 优先用协议层保留的原始字节：整段响应转成字符串后，多字节字符的
          // 字节边界就丢了，再按 `{n}` 声明的字节数切会落在字符中间，
          // 解码得到一堆 U+FFFD——中文验证码邮件的主题和正文会全部乱码。
          const raw = r.literalBuf ? r.literalBuf.toString('utf8') : extractLiteral(r.text);
          const parsed = mail.parseMime(raw);
          const meta = envelopeFields(it, parsed);
          const hit = extractCode([meta.subject, parsed.text, parsed.html].join('\n'));
          if (hit) {
            codes.push({
              uid: it.uid,
              code: clip(hit.code, 32),
              confidence: Number(hit.confidence) || 0,
              keyword: clip(hit.keyword),
              subject: meta.subject,
              from: meta.from,
              date: meta.date,
            });
          }
        } catch (err) {
          // 单封邮件解析/读取失败只跳过这一封；超时是整账号失败，必须冒泡
          if (timedOut || err === timeoutError) throw timeoutError;
        } finally {
          readIdx += 1;
          report({ phase: 'read', done: readIdx, total: candidates.length, found: codes.length });
        }
      }

      // 组内排序按 uid 降序；date 只用于展示
      codes.sort((a, b) => b.uid - a.uid);
      return {
        ok: true,
        codes: codes.slice(0, MAX_CODES),
        scanned: candidates.length,
        unseenCount,
      };
    } finally {
      // 超时、认证失败、每封邮件失败，都必须关掉这唯一一条连接
      if (client) {
        try { await client.logout(); } catch { /* 忽略 */ }
        try { client.destroy(); } catch { /* 忽略 */ }
      }
    }
  })();

  try {
    // Promise.race 已接管 doScan 的后续拒绝，不会泄漏 unhandledRejection；
    // 输掉 race 的那一边仍会执行自己的 finally 关掉唯一一条连接。
    return await Promise.race([doScan, timeout]);
  } catch (e) {
    // 只返回脱敏后的中文原因，绝不把底层 message（可能含路径/令牌片段）给前端
    return failure(e, timedOut, timeoutMs);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = { scanAccount, isSafeMailbox, KNOWN_MAILBOXES, MAX_CODES, MAX_FIELD, DEFAULT_TIMEOUT_MS };
