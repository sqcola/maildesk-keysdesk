'use strict';
/**
 * 验证码提取引擎
 *
 * 设计原则：
 *  - 只在本地正则匹配，不做任何外发
 *  - 支持中英文常见验证码邮件模板
 *  - 区分「验证码」和「订单号/金额/时间」等干扰数字
 */

// 常见的验证码关键词（中英）
const CODE_KEYWORDS = [
  '验证码', '校验码', '确认码', '动态码', '激活码', '安全码', '登录码',
  'verification code', 'verify code', 'confirmation code', 'security code',
  'login code', 'one-time code', 'otp', 'passcode', 'access code',
  'your code', 'auth code', 'authentication code', 'pin code',
];

// 需要排除的干扰模式（这些数字不是验证码）
const NOISE_PATTERNS = [
  /\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b/g,        // 日期 2026-11-03
  /\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b/g,      // 日期 11/03/2026
  /\b\d{1,2}:\d{2}(:\d{2})?\b/g,              // 时间 14:30:00
  /\b(19|20)\d{2}\b/g,                        // 年份
  /\b\d{1,3}(,\d{3})+(\.\d+)?\b/g,            // 千分位金额 1,234,567
  /\b¥\s*\d+(\.\d+)?/g,                       // 人民币
  /\$\s*\d+(\.\d+)?/g,                        // 美元
  /\b\d+(\.\d+)?\s*(元|美元|USD|CNY|RMB)\b/gi,
  /\b(订单|order|invoice|发票|单号)\s*[:：]?\s*[A-Z0-9]{6,}/gi,
  /\b[A-Z]{2,}\d{6,}\b/g,                     // 订单号 ABC123456
  /\b\d{11,}\b/g,                             // 手机号/长数字
  /\b\d{1,5}\s*(px|em|rem|%)\b/gi,            // CSS 尺寸
  /https?:\/\/\S+/g,                          // URL
  /\b[0-9a-f]{16,}\b/gi,                      // 哈希/ID
];

// 验证码候选：4-8 位数字，或 4-8 位字母数字混合
// 分隔符部分要能容忍「code is:」「验证码为：」「code=」等多种写法，
// 所以拆成"可选连接词 + 可选标点"两段，而不是二选一。
const SEP = String.raw`\s*(?:是|为|is|=)?\s*[:：=]?\s*`;
const KW = String.raw`(?:验证码|校验码|确认码|动态码|激活码|安全码|登录码|code|otp|pin|passcode)`;

const CANDIDATE_PATTERNS = [
  // 「验证码是 123456」「code: 123456」「验证码为123456」
  new RegExp(KW + SEP + String.raw`([0-9]{4,8})\b`, 'gi'),
  // 字母数字混合（如 Steam Guard 的 K7X9P2、Discord 的 aB3dE9）
  new RegExp(KW + SEP + String.raw`([A-Z0-9]{4,8})\b`, 'gi'),
  // 「123456 是你的验证码」
  /\b([0-9]{4,8})\s*(?:是|为)?\s*(?:你的|您的)?\s*(?:验证码|校验码|确认码|动态码|code|otp)/gi,
  // 「输入 123456」
  /(?:输入|enter|type)\s+(?:the\s+)?(?:code\s+)?([0-9]{4,8})\b/gi,
  // 被空格/连字符分隔的数字组：「592 104」「592-104」「592 104 3」
  // 只在附近有验证码关键词时才采用，避免误伤
  new RegExp(KW + SEP + String.raw`([0-9]{2,4}[-\s][0-9]{2,4}(?:[-\s][0-9]{2,4})?)\b`, 'gi'),
  // 邮件正文里独立成行/独立分隔的 4-8 位数字（常见于纯验证码邮件）
  /(?:^|\s)([0-9]{6})(?:\s|$)/gm,
  /(?:^|\s)([0-9]{4})(?:\s|$)/gm,
];

// 输入上限：超过此长度直接截断。
// 验证码邮件正文通常几 KB，200KB 足够；不设限的话
// 一封超长邮件能把事件循环卡住（见 normalizeText 的说明）。
const MAX_INPUT = 200 * 1024;

/**
 * 清洗文本：去掉 HTML 标签、多余空白
 *
 * 注意：这里刻意不用 /<[^>]+>/g 这类正则。
 * 该正则在遇到大量 '<' 且没有 '>' 时，每个 '<' 都要向后扫到结尾，
 * 整体是 O(n²)。实测 80k 个 '<' 卡 13 秒，足以冻住整个服务。
 * 下面用一次线性扫描代替。
 */
function stripTags(s) {
  let out = '';
  let i = 0;
  const n = s.length;
  while (i < n) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { out += s.slice(i); break; }
    out += s.slice(i, lt);
    const gt = s.indexOf('>', lt + 1);
    if (gt < 0) {
      // 没有闭合的 '>'：丢弃剩下部分，避免无限回溯
      break;
    }
    out += ' ';
    i = gt + 1;
  }
  return out;
}

/** 线性去掉 <script>/<style> 块（不用回溯正则） */
function stripScriptStyle(s) {
  let out = '';
  let i = 0;
  const lower = s.toLowerCase();
  while (i < s.length) {
    const sc = lower.indexOf('<script', i);
    const st = lower.indexOf('<style', i);
    let next = -1;
    let tag = '';
    if (sc >= 0 && (st < 0 || sc < st)) { next = sc; tag = '</script'; }
    else if (st >= 0) { next = st; tag = '</style'; }

    if (next < 0) { out += s.slice(i); break; }
    out += s.slice(i, next);
    const close = lower.indexOf(tag, next);
    if (close < 0) break; // 未闭合，丢弃剩余
    const end = lower.indexOf('>', close);
    if (end < 0) break;
    out += ' ';
    i = end + 1;
  }
  return out;
}

function normalizeText(s) {
  if (!s) return '';
  let t = String(s);
  if (t.length > MAX_INPUT) t = t.slice(0, MAX_INPUT);

  t = stripScriptStyle(t);
  t = stripTags(t);
  t = t
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"');
  // 空白折叠：用单次扫描，避免 /\s+/g 在大输入上的开销
  return t.replace(/[ \t\r\n\f\v]+/g, ' ').trim();
}

/**
 * 从文本中提取验证码
 * @param {string} rawText 邮件主题 + 正文
 * @returns {{code:string, confidence:number, keyword:string}|null}
 */
function extractCode(rawText) {
  let text = normalizeText(rawText);
  if (!text) return null;

  // 记录原文用于判断是否来自关键词上下文
  const original = text;

  // 去掉干扰项
  for (const re of NOISE_PATTERNS) {
    text = text.replace(re, ' ');
  }
  text = text.replace(/\s+/g, ' ');

  const found = [];

  for (let i = 0; i < CANDIDATE_PATTERNS.length; i++) {
    const re = CANDIDATE_PATTERNS[i];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const code = m[1];
      if (!code) continue;

      // 排除明显不是验证码的
      if (!isPlausible(code)) continue;

      // 置信度：越靠前的模式越可信
      let confidence = 100 - i * 12;

      // 上下文有强关键词，加分
      const start = Math.max(0, m.index - 40);
      const ctx = text.slice(start, m.index + m[0].length + 40).toLowerCase();
      const hitKeyword = CODE_KEYWORDS.find(k => ctx.includes(k));
      if (hitKeyword) confidence += 25;

      found.push({ code, confidence, keyword: hitKeyword || '' });
    }
  }

  if (!found.length) return null;

  // 去重并取最高分；同分取最长（6 位比 4 位更像验证码）
  const best = new Map();
  for (const f of found) {
    const prev = best.get(f.code);
    if (!prev || f.confidence > prev.confidence ||
        (f.confidence === prev.confidence && f.code.length > prev.code.length)) {
      best.set(f.code, f);
    }
  }

  const sorted = [...best.values()].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return b.code.length - a.code.length;
  });

  return sorted[0] || null;
}

/**
 * 判断一个字符串像不像验证码
 */
function isPlausible(code) {
  if (!code) return false;

  // 带分隔符的验证码（592 104 / 592-104）→ 去掉分隔符后校验
  let c = code;
  if (/[\s-]/.test(c)) {
    c = c.replace(/[\s-]/g, '');
    if (!/^\d{4,9}$/.test(c)) return false;
    return !/^(\d)\1+$/.test(c);
  }

  if (c.length < 4 || c.length > 8) return false;

  // 全相同字符（0000、111111、AAAA）通常是占位符
  if (/^(.)\1+$/.test(c)) return false;

  // 看起来像年份（仅纯数字时判断）
  if (/^\d{4}$/.test(c)) {
    const n = parseInt(c, 10);
    if (n >= 1900 && n <= 2100) return false;
  }

  // 字母数字混合码：至少要有一个字母和一个数字，且不能是纯单词
  if (/[A-Za-z]/.test(c)) {
    if (!/\d/.test(c)) return false;          // 纯字母不是验证码
    if (c.length < 4) return false;
    // 常见英文单词误判过滤：全小写且长度>5 的多半是单词
    if (/^[a-z]{6,}$/.test(c)) return false;
  }

  return true;
}

/**
 * 从多封邮件中批量提取（按时间倒序，取最新的）
 * @param {Array<{subject:string, text?:string, html?:string, date:string, from:string}>} messages
 * @returns {Array<{code:string, confidence:number, subject:string, from:string, date:string}>}
 */
function extractFromMessages(messages) {
  const out = [];
  for (const m of messages) {
    const combined = [m.subject || '', m.text || '', m.html || ''].join('\n');
    const r = extractCode(combined);
    if (r) {
      out.push({
        code: r.code,
        confidence: r.confidence,
        keyword: r.keyword,
        subject: m.subject || '',
        from: m.from || '',
        date: m.date || '',
      });
    }
  }
  return out;
}

module.exports = { extractCode, extractFromMessages, normalizeText, isPlausible, CODE_KEYWORDS };
