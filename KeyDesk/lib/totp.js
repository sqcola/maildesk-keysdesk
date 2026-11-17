'use strict';
/**
 * TOTP / HOTP 核心（RFC 4226 + RFC 6238）
 *
 * 本文件只做纯计算，不碰磁盘、不碰网络、不持有任何状态。
 * 之所以把算法单独放在一个模块里，是因为它是整个工具里唯一
 * 「算错就登不上账号」的部分，必须能脱离服务端单独跑测试
 * （selftest.js 直接 require 这个文件，把 RFC 6238 的 18 个
 * 官方向量逐条比对）。
 */

const crypto = require('crypto');

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** 支持的 HMAC 算法 → node 的算法名 */
const ALGOS = {
  SHA1: 'sha1',
  SHA256: 'sha256',
  SHA512: 'sha512',
};

/** 把用户/URI 里的算法写法统一成 SHA1/SHA256/SHA512 */
function normalizeAlgorithm(algo) {
  const s = String(algo == null ? '' : algo).trim().toUpperCase().replace(/[-_]/g, '');
  if (s === '' || s === 'SHA1') return 'SHA1';
  if (s === 'SHA256') return 'SHA256';
  if (s === 'SHA512') return 'SHA512';
  throw new Error('不支持的算法：' + algo + '（只支持 SHA1 / SHA256 / SHA512）');
}

/**
 * HOTP：RFC 4226 的动态截断。
 *
 * @param {Buffer} secretBuf HMAC 密钥（原始字节，不是 Base32）
 * @param {number|bigint} counter 8 字节大端计数器
 * @param {number} digits 6 或 8
 * @param {string} algo 'SHA1'|'SHA256'|'SHA512'
 * @returns {string} 定长数字串
 */
function hotp(secretBuf, counter, digits, algo) {
  if (!Buffer.isBuffer(secretBuf) || secretBuf.length === 0) {
    throw new Error('HOTP 需要非空的密钥 Buffer');
  }
  const d = digits == null ? 6 : Number(digits);
  // 上界 8：RFC 4226 §5.3 要求至少 6 位，7/8 可选；RFC 6238 附录 A 的
  // DIGITS_POWER 只到 10^8。9/10 位是无效语义——31 位整数最大 2147483647，
  // 10^10 > 2^31，取模恒等于原值，所谓"10 位码"只是把 31 位整数补前导零。
  if (!Number.isInteger(d) || d < 6 || d > 8) throw new Error('位数必须是 6..8 之间的整数');
  const algorithm = ALGOS[normalizeAlgorithm(algo)];
  if (!algorithm) throw new Error('不支持的算法');

  const c = typeof counter === 'bigint' ? counter : BigInt(Math.trunc(Number(counter)));
  if (c < 0n) throw new Error('计数器不能为负');

  // 计数器 8 字节大端。writeBigUInt64BE 超过 2^64-1 会抛 RangeError，
  // 这里先挡一下，避免把内部异常原样吐给上层。
  if (c > 0xffffffffffffffffn) throw new Error('计数器超出 64 位范围');
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(c);

  const h = crypto.createHmac(algorithm, secretBuf).update(buf).digest();

  // RFC 4226 §5.3 动态截断：低 4 位决定偏移，取 4 字节，最高位清零
  const offset = h[h.length - 1] & 0x0f;
  const bin = ((h[offset] & 0x7f) << 24) |
              ((h[offset + 1] & 0xff) << 16) |
              ((h[offset + 2] & 0xff) << 8) |
              (h[offset + 3] & 0xff);

  // 用 10 的幂取模。注意 Math.pow(10, 8) 仍在安全整数内，
  // 但为了不出浮点意外，这里用整数表。
  const POW10 = [1, 10, 100, 1000, 10000, 100000, 1000000,
                 10000000, 100000000, 1000000000, 10000000000];
  return String(bin % POW10[d]).padStart(d, '0');
}

/**
 * TOTP：RFC 6238。counter = floor(timeSec / period)。
 *
 * @param {Buffer} secretBuf
 * @param {number} timeSec Unix 秒（可以带小数，会被截断）
 * @param {number} digits
 * @param {number} period 默认 30
 * @param {string} algo
 */
function totp(secretBuf, timeSec, digits, period, algo) {
  const p = period == null ? 30 : Number(period);
  if (!Number.isFinite(p) || p <= 0) throw new Error('周期必须是正数秒');
  const t = Number(timeSec);
  if (!Number.isFinite(t)) throw new Error('时间戳无效');
  const counter = Math.floor(t / p);
  return hotp(secretBuf, counter, digits, algo);
}

/**
 * Base32 解码（RFC 4648，无校验位）。
 *
 * 容忍程度按真实世界的 otpauth URI 来定：
 *  - 小写字母
 *  - 空格、制表符、换行（Google Authenticator 导出时常带换行）
 *  - 连字符 '-'（有些服务商把密钥按 4 位分组展示）
 *  - '=' 填充（有无都行，尾部残缺位直接丢弃）
 */
function base32Decode(str) {
  if (typeof str !== 'string') throw new Error('Base32 密钥必须是字符串');
  const cleaned = str
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/=+$/g, '');

  if (!cleaned) throw new Error('Base32 密钥为空');
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    const bad = cleaned.replace(/[A-Z2-7]/g, '').charAt(0);
    throw new Error('Base32 密钥包含非法字符：' + bad);
  }

  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    value = (value << 5) | B32_ALPHABET.indexOf(cleaned[i]);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // 尾部剩余不足 8 位的部分按 RFC 4648 丢弃
  if (out.length === 0) throw new Error('Base32 密钥太短，解码后为空');
  return Buffer.from(out);
}

/** Base32 编码（用于生成恢复密钥）。不带 '=' 填充。 */
function base32Encode(buf) {
  if (!Buffer.isBuffer(buf)) throw new Error('base32Encode 需要 Buffer');
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

/**
 * 归一化并校验裸 Base32 密钥。
 * 数据库里存的一律是这种形式（大写、无空格、无填充），
 * 这样比对和导出的结果才是稳定的。
 */
function normalizeSecret(str, opts) {
  // strictLength 默认 true（新建/编辑输入时严格）；
  // 读盘校验必须传 false，否则老库里已有的非规范长度密钥会被隔离。
  const strictLength = !(opts && opts.strictLength === false);
  const s = String(str == null ? '' : str)
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/=+$/g, '');
  // 下限取 16 个 Base32 字符 = 10 字节，对齐 Google Authenticator 的
  // MIN_KEY_BYTES 硬门槛（google-authenticator-android 的 PasscodeGenerator）。
  // 更短的密钥（如 8 字符 = 5 字节）HMAC 依然能算出"看起来正常"的码，
  // 但熵只有 40 bit，且部分验证器会直接拒绝——不报错不等于没错。
  // 上限 128 字符 = 80 字节，与 libpam 的 100 字节上限同一量级。
  if (!/^[A-Z2-7]{16,128}$/.test(s)) {
    if (!s) throw new Error('密钥不能为空');
    if (s.length < 16) throw new Error('密钥太短（至少 16 个 Base32 字符，即 10 字节）');
    if (s.length > 128) throw new Error('密钥太长（最多 128 个 Base32 字符）');
    throw new Error('密钥只能包含 A-Z 和 2-7（Base32）');
  }
  // Base32 的长度不是连续的：n 字节编码后固定 ceil(n*8/5) 个字符，
  // 所以合法的字符数只有 2,4,5,7,8,10,12,13,15,16,18,20,21,23,24,26,28,29,31,32,...
  // 取非法长度（如 17、19）时末尾会多出不足 8 位的残余位，解码时被丢弃，
  // 结果是两个不同的字符串解出同一个字节序列：
  //   "JBSWY3DPEHPK3PXP"   (16 字符) → 10 字节
  //   "JBSWY3DPEHPK3PXPA"  (17 字符) → 同样 10 字节，完全相同
  // 这会掩盖用户输入时多打一个字符的错误。Google 自己的 Base32String 源码
  // 注释里也承认了这个歧义（"string of sixteen 7s and seventeen 7s both
  // decode to the same byte array"）。
  //
  // 注意不能简单要求 length % 8 === 0：20 字符（mod 8 = 4）是合法长度，
  // 现实中大量密钥就是这个长度。
  //
  // ⚠ 这个检查**只用于新建/编辑输入**，不能用于读盘校验。
  // 老库里可能已有 17/19/22 这类长度的 secret（前一版本接受的），它们
  // 完全能正常算码。如果在读取路径上拒绝，normalizeEntry 会把条目扔进
  // 隔离区 → 用户看到"我的条目消失了"，而 UI 又不显示隔离区。
  // 所以调用方必须传 strict:false 走读盘路径（见 normalizeEntry）。
  const bytes = Math.floor(s.length * 5 / 8);
  if (strictLength && bytes > 0 && Math.ceil(bytes * 8 / 5) !== s.length) {
    throw new Error('密钥长度不合法（' + s.length + ' 个 Base32 字符）。' +
      '合法长度应为 16/18/20/21/23/24/26/28... 这类，当前长度会让解码结果与其他密钥重复');
  }
  return s;
}

/** 判断字符串是否是本模块认可的合法密钥（不抛异常版本） */
function isValidSecret(str) {
  try { normalizeSecret(str); return true; } catch { return false; }
}

/** 从 label（"GitHub:alice@x.com"）里拆 issuer / account */
function splitLabel(label) {
  const raw = String(label == null ? '' : label);
  const i = raw.indexOf(':');
  if (i < 0) return { issuer: '', account: raw.trim() };
  return {
    issuer: raw.slice(0, i).trim(),
    account: raw.slice(i + 1).trim(),
  };
}

/**
 * 解析 otpauth:// URI。
 *
 * 返回 {issuer, account, secret, algorithm, digits, period}，
 * 全部字段都是「可直接入库」的规范形式。
 * 任何一处不合法都抛带人话的错误——前端把这句话直接显示给用户。
 *
 * 明确拒绝 otpauth://hotp/：计数器模式和本工具「每隔 30 秒换一次码」
 * 的模型不兼容，静默接受只会让人以为能用、实际登不上。
 */
function parseOtpauth(uri) {
  const raw = String(uri == null ? '' : uri).trim();
  if (!raw) throw new Error('otpauth URI 不能为空');
  if (!/^otpauth:\/\//i.test(raw)) throw new Error('不是 otpauth:// 开头的 URI');

  const afterScheme = raw.slice('otpauth://'.length);
  const slash = afterScheme.indexOf('/');
  if (slash < 0) throw new Error('otpauth URI 缺少类型段（应为 otpauth://totp/...）');

  const kind = afterScheme.slice(0, slash).toLowerCase();
  const rest = afterScheme.slice(slash + 1);

  if (kind === 'hotp') {
    throw new Error('不支持 otpauth://hotp/（计数器模式）。本工具只管理基于时间的 TOTP');
  }
  if (kind !== 'totp') {
    throw new Error('不支持的 otpauth 类型：' + kind + '（只支持 totp）');
  }

  const q = rest.indexOf('?');
  // fragment（'#' 之后）不属于 query，按 RFC 3986 必须剥掉。
  // 不剥会让 "issuer=X#frag" 被当成 issuer 值，或让 secret 里混进垃圾。
  const hash = q < 0 ? rest.indexOf('#') : -1;
  const afterHash = q >= 0 ? rest.slice(q + 1).indexOf('#') : -1;
  let labelRaw, queryRaw;
  if (q < 0) {
    labelRaw = hash < 0 ? rest : rest.slice(0, hash);
    queryRaw = '';
  } else {
    labelRaw = rest.slice(0, q);
    queryRaw = afterHash < 0 ? rest.slice(q + 1) : rest.slice(q + 1, q + 1 + afterHash);
  }

  // label 是百分号编码的，'/' 也可能被编码成 %2F 藏在里面，
  // 所以先整体解码再按第一个 ':' 拆。
  let label;
  try { label = decodeURIComponent(labelRaw); }
  catch { throw new Error('otpauth URI 的 label 百分号编码非法'); }

  // 手动解析 query：URLSearchParams 会把 '+' 解码成空格，
  // 而 Base32 密钥里偶尔出现被误写成 '+' 的情况，这里保持保守解析。
  const params = {};
  for (const part of queryRaw.split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    const k = eq < 0 ? part : part.slice(0, eq);
    const v = eq < 0 ? '' : part.slice(eq + 1);
    let dk, dv;
    try { dk = decodeURIComponent(k).toLowerCase(); } catch { continue; }
    try { dv = decodeURIComponent(v); } catch { continue; }
    if (!Object.prototype.hasOwnProperty.call(params, dk)) params[dk] = dv;
  }

  // ---- secret ----
  if (!params.secret) throw new Error('otpauth URI 缺少 secret 参数');
  let secret;
  try { secret = normalizeSecret(params.secret); }
  catch (e) { throw new Error('otpauth URI 里的 secret 不合法：' + e.message); }

  // ---- 不支持的厂商扩展参数：明确拒绝，不静默忽略 ----
  //
  // encoder=steam 是最常见的例子：Steam Guard 用的是 5 位字母码，算法
  // 与标准 TOTP 完全不同。静默接受会让用户看到一个"看起来正常、实际永远
  // 登不上"的条目——这和文件开头拒绝 hotp 的理由是同一个。
  if (params.encoder && params.encoder.toLowerCase() !== 'totp') {
    throw new Error('不支持 encoder=' + params.encoder + ' 的条目（如 Steam Guard）。' +
      '这类验证码不是标准 TOTP，本工具算出来的码登不上');
  }

  // ---- label 与 issuer ----
  const fromLabel = splitLabel(label);
  const issuerParam = (params.issuer || '').trim();

  // 无 issuer 参数且 label 含多个冒号 → 本身就有歧义（Aegis #1701）。
  // 静默按第一个冒号切会给错结果，用户不会察觉。这里明确报错。
  if (!issuerParam) {
    const colonCount = (label.match(/:/g) || []).length;
    if (colonCount > 1) {
      throw new Error('otpauth URI 的 label 含多个冒号且没有 issuer 参数，无法确定哪个是分隔符。' +
        '请手动分成 issuer 和 account 两栏填写');
    }
  }

  // label 里冒号左边是 issuer，右边是 account。但 issuer 本身可能含冒号
  // （"A:B" 这种），splitLabel 只切第一个 —— 那样 "A:B:c" 会被拆成
  // issuer="A" / account="B:c"，和构建端不一致。
  // 用 issuer 参数来消歧：如果参数给了 issuer，且 label 以 "issuer:" 开头，
  // 就按 issuer 的长度切，剩下的全部是 account。
  let issuer;
  let account;
  if (issuerParam && (label === issuerParam || label.startsWith(issuerParam + ':'))) {
    issuer = issuerParam;
    account = label === issuerParam ? '' : label.slice(issuerParam.length + 1);
  } else if (issuerParam && !fromLabel.issuer) {
    // label 里没有冒号（只是一个账号），issuer 只从参数来
    issuer = issuerParam;
    account = fromLabel.account;
  } else {
    issuer = fromLabel.issuer;
    account = fromLabel.account;
  }

  if (params.issuer && fromLabel.issuer && issuerParam !== fromLabel.issuer &&
      !label.startsWith(issuerParam + ':')) {
    throw new Error('otpauth URI 的 issuer 参数与 label 前缀不一致（' +
      issuerParam + ' vs ' + fromLabel.issuer + '）');
  }

  // ---- algorithm / digits / period ----
  let algorithm = 'SHA1';
  if (params.algorithm) {
    try { algorithm = normalizeAlgorithm(params.algorithm); }
    catch (e) { throw new Error('otpauth URI 的 algorithm 不合法：' + e.message); }
  }

  let digits = 6;
  if (params.digits != null && params.digits !== '') {
    const n = Number(params.digits);
    if (!Number.isInteger(n) || (n !== 6 && n !== 8)) {
      throw new Error('otpauth URI 的 digits 只支持 6 或 8，实际：' + params.digits);
    }
    digits = n;
  }

  let period = 30;
  if (params.period != null && params.period !== '') {
    const n = Number(params.period);
    if (!Number.isInteger(n) || n < 10 || n > 120) {
      throw new Error('otpauth URI 的 period 必须是 10..120 之间的整数，实际：' + params.period);
    }
    period = n;
  }

  return {
    issuer: issuer.trim(),
    account: account.trim(),
    secret,
    algorithm,
    digits,
    period,
  };
}

/**
 * 从结构化字段生成 otpauth URI（导出用）。
 *
 * 与 parseOtpauth 互为逆运算：export 出来的 URI 再 parse 回来，
 * 六个字段必须完全一致——selftest 里有这条往返断言。
 */
function buildOtpauth(entry) {
  const e = entry || {};
  const issuer = String(e.issuer == null ? '' : e.issuer).trim();
  const account = String(e.account == null ? '' : e.account).trim();
  const secret = normalizeSecret(e.secret);
  const algorithm = normalizeAlgorithm(e.algorithm || 'SHA1');
  const digits = e.digits == null ? 6 : Number(e.digits);
  const period = e.period == null ? 30 : Number(e.period);

  if (!Number.isInteger(digits) || (digits !== 6 && digits !== 8)) {
    throw new Error('导出失败：digits 必须是 6 或 8');
  }
  if (!Number.isInteger(period) || period < 10 || period > 120) {
    throw new Error('导出失败：period 必须是 10..120');
  }

  // label 里绝不能出现冒号（无论是 issuer 段还是 account 段），
  // 否则导入方无法判断哪个是分隔符（Aegis #1701）。
  // issuer 有冒号时不写前缀；account 有冒号时把冒号替换成全角冒号，
  // 保证 label 里一个半角冒号都没有。完整值仍通过参数/条目本身保存。
  const issuerHasColon = issuer.includes(':');
  const safeAccount = account.replace(/:/g, '：');
  const label = (issuer && !issuerHasColon)
    ? encodeURIComponent(issuer) + ':' + encodeURIComponent(safeAccount)
    : encodeURIComponent(safeAccount);

  const params = [];
  if (issuer) params.push('issuer=' + encodeURIComponent(issuer));
  params.push('secret=' + encodeURIComponent(secret));
  if (algorithm !== 'SHA1') params.push('algorithm=' + algorithm);
  if (digits !== 6) params.push('digits=' + String(digits));
  if (period !== 30) params.push('period=' + String(period));

  return 'otpauth://totp/' + label + '?' + params.join('&');
}

module.exports = {
  hotp,
  totp,
  base32Decode,
  base32Encode,
  normalizeSecret,
  isValidSecret,
  normalizeAlgorithm,
  parseOtpauth,
  buildOtpauth,
  splitLabel,
  ALGOS,
};
