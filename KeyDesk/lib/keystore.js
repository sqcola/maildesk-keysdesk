'use strict';
/**
 * 密钥库：K1b 双槽方案
 *
 *   DEK          = randomBytes(32)                 数据真密钥，只在进程内存里存在
 *   KEK_pass     = scrypt(passphrase, saltPass)    用口令包裹 DEK
 *   KEK_recovery = scrypt(recoveryKey, saltRecovery) 用恢复密钥包裹 DEK
 *   data         = AES-256-GCM(DEK, payload, AAD="keydesk/1|"+saltPass+"|"+saltRecovery)
 *
 * 为什么是「包裹 DEK」而不是「口令和恢复密钥各加密一份数据」：
 *  - 改口令 / 换恢复密钥时只需要重新包裹 32 字节的 DEK，数据本身
 *    虽然也要重加密（因为 AAD 里含盐），但只有一份明文来源，不会
 *    出现两份数据逐渐不一致。
 *  - 恢复密钥和口令在回到 DEK 的路上是对称的，任意一个都能解开，
 *    但都不直接当数据密钥用。
 *
 * 内存中的 DEK 绝不写盘、不进日志、不进任何 API 响应。lock() 会先
 * buf.fill(0) 再置空，避免它残留在 Buffer 池里被其它分配复用。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// 只借用 pidState：判断数据目录里遗留的 tmp 文件是否属于一个**确定已消失**
// 的进程，才敢删。两个模块对"pid 是否还活着"必须用同一套判断，否则会出现
// 「锁认为它死了、清理认为它活着」这种自相矛盾的状态。
const { pidState } = require('./instance-lock');

const FORMAT = 'keydesk/1';

// 已验证：N=32768,r=8,p=1,maxmem=64MB 实测约 241ms
const KDF = { algo: 'scrypt', N: 32768, r: 8, p: 1 };

// 参数合法性范围。只用于校验磁盘上声明的参数是否「像话」，
// 不是用来挑参数的。下限 1024 挡住明显被降级的文件
// （把 N 改成 1 的人一定不是好人）；上限挡住会让进程内存炸掉的值。
// 真正的创建路径永远写 KDF 里的常量。
//
// nMax 从 2^20 收到 2^18：scrypt 的内存需求 ≈ 128 * N * r，N=2^20、r=8
// 时单次派生就要 1 GiB（下面 maxmem 再留 2 倍余量 = 2 GiB），而这个值
// 是**从磁盘文件里读出来的**——一个被改坏或恶意构造的 vault.enc 只要把
// N 写成 2^20，用户点一次"解锁"就能把进程撑到 OOM，锁屏界面看上去像是
// 卡死。2^18 = 256 MiB（r=8 时），已经是 OWASP 首推值 2^17 的两倍，
// 留给未来提高成本的余量足够，同时把"一次文件声明能换走多少内存"
// 钉在可控范围内。
const KDF_LIMITS = { nMin: 1024, nMax: 1 << 18, rMin: 1, rMax: 32, pMin: 1, pMax: 4 };

// maxmem 的硬上限。maxmem 按参数推导（不能硬编码，见 _derive），但推导
// 本身会放大：128 * r * N * 2 在 KDF_LIMITS 允许的极端组合（N=2^18, r=32）
// 下是 2 GiB。上限钳制保证"文件里声明的参数"最多只能要到这么多内存，
// 超出的组合会在 scrypt 里直接抛 ERR_CRYPTO_INVALID_SCRYPT_PARAMS，
// 由 unlock 判别后报 INTERNAL（参数超出本机能力），而不是真的去分配。
const MAX_SCRYPT_MEM = 512 * 1024 * 1024;
const KEYLEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const DEK_LEN = 32;
const WRAP_CT_LEN = DEK_LEN + TAG_LEN;   // 48 = 32 字节 DEK + 16 字节 GCM tag

const BACKUP_COUNT = 3;
const THROTTLE_AFTER = 5;
// 第 5 次失败后 5s，第 6 次 15s，第 7 次 60s，第 8 次起 300s
const THROTTLE_DELAYS_MS = [5000, 15000, 60000, 300000];

const DEFAULT_IDLE_SEC = 900;
const MIN_PASSPHRASE = 8;
const MAX_PASSPHRASE = 1024;

/* ---------------- 小工具 ---------------- */

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

const b64 = buf => Buffer.from(buf).toString('base64');
const unb64 = s => Buffer.from(String(s == null ? '' : s), 'base64');

// vaultPath 可能来自用户配置（KEYDESK_DATA_DIR），文件名里出现正则元字符时
// 直接拼进 RegExp 会匹配到别的文件——清扫遗留 tmp 的规则必须只命中自己的。
const escapeRe = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function nowMs() { return Date.now(); }

/**
 * 恢复槽指纹：iv + ct + 绑定的 salt 的 SHA-256。
 *
 * 用途是「检出恢复槽有没有被改坏」，不是保密。存明文摘要没有信息泄露——
 * 它只覆盖本来就明文存在文件里的字段，不涉及 DEK 或恢复密钥。
 */
function _recoveryFingerprint(meta) {
  const w = (meta && meta.wraps && meta.wraps.recovery) || {};
  const salt = (meta && meta.kdf && meta.kdf.saltRecovery) || '';
  return crypto.createHash('sha256')
    .update(String(w.iv || '') + '|' + String(w.ct || '') + '|' + String(salt))
    .digest('hex');
}

/** 恢复密钥用的 Base32 字母表（与 totp.js 保持同一套，避免两处不一致） */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** 16 字节 → 26 个 Base32 字符（RFC 4648，无填充，末字符只承载 4 位） */
function base32Encode26(buf) {
  let bits = 0, value = 0, out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 0x1f];
  return out;
}

/** 把 26 个字符按 4 位一组加上 '-'：ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ */
function formatRecoveryKey(chars) {
  const groups = [];
  for (let i = 0; i < chars.length; i += 4) groups.push(chars.slice(i, i + 4));
  return groups.join('-');
}

/** 生成一把新的恢复密钥 */
function generateRecoveryKey() {
  return formatRecoveryKey(base32Encode26(crypto.randomBytes(16)));
}

/**
 * 归一化用户输入的恢复密钥：大写、去掉 '-' 和空白。
 * 长度必须是 26，且全部落在 Base32 字母表内。
 * 这些校验只拦"手滑输错"，不承担保密责任——输成另一把合法密钥
 * 会在解包 DEK 时被 GCM tag 拦下。
 */
function normalizeRecoveryKey(input) {
  const s = String(input == null ? '' : input)
    .toUpperCase()
    .replace(/[\s-]/g, '');
  if (!s) throw fail('INVALID', '恢复密钥不能为空');
  if (s.length !== 26) {
    throw fail('INVALID', '恢复密钥应为 26 个字符（不含连字符），当前 ' + s.length + ' 个');
  }
  if (!/^[A-Z2-7]+$/.test(s)) {
    throw fail('INVALID', '恢复密钥包含非法字符（只能是 A-Z 和 2-7）');
  }
  // 末字符自检：base32Encode26 把 128 位编成 26 个字符，前 25 个字符吃掉
  // 125 位，最后 3 位经 (value << 2) & 0x1f 输出——低 2 位恒为 0，所以
  // 末字符的 5 位索引只能是 0/4/8/../28，即 'AEIMQUY4' 这 8 种。
  // 换句话说，末位抄错的恢复密钥里有 7/8 会在派生前就被这里挡住，
  // 用户看到的是"末位不正确"而不是绕一大圈之后的"恢复密钥不正确"
  // （后者会计入失败限速，5 次之后就变成"请 300 秒后再试"）。
  //
  // 注意这里是 8 种不是 7 种：研究报告写的 'AEMIQUY' 漏了 '4'，
  // 照抄会拒绝 1/8 的合法密钥。20000 次 generateRecoveryKey() 实测
  // 分布为 4/A/E/I/M/Q/U/Y 各约 2500 次，确认无误。
  if ('4AEIMQUY'.indexOf(s[25]) === -1) {
    throw fail('INVALID', '恢复密钥末位不正确，请检查最后一位是否抄错');
  }
  return s;
}

/**
 * 弱口令拦截。
 *
 * 为什么这件事比"调高 scrypt 参数"重要得多：按实测 260ms/次（N=2^15, 单核），
 * `password123` 在 64 核机器上 4 秒就能试出来；即使把参数提到 OWASP 首推的
 * N=2^17，也只是 16 秒。而口令从"字典里"换成"4 词 Diceware"，成本从秒级
 * 变成 10^15 年级。**KDF 参数只能放大口令的熵，不能创造熵。**
 *
 * 做法跟 NIST SP 800-63B-4 §3.1.1.2 一致：用 blocklist + 模式规则，
 * 不做"必须含大小写数字符号"的组合规则（NIST 明确 SHALL NOT 强加组合规则，
 * 那种规则只会把用户逼成 `Password1!` 这种既难记又好猜的东西）。
 *
 * 这里的规则是"拒绝最蠢的"，不是"评估强度"。它拦不住 `Tr0ub4dor&3`，
 * 但那类口令的熵本来就远高于字典词，不拦也不会是短板。
 */
const WEAK_PATTERNS = [
  { re: /^\d+$/, why: '全是数字。这类口令在字典里排最前面，几秒就能试出来' },
  // 纯字母**且短**才算弱：`correcthorsebatterystaple` 是纯字母，但它是 25 个
  // 字符的 Diceware 串，熵远高于任何字典攻击能覆盖的范围。按长度而不是
  // 按字符类别判断，才符合"熵来自长度而不是复杂度"这个事实。
  { re: /^[a-z]{1,11}$/i, why: '全是字母且不超过 11 位，猜起来很快' },
  { re: /^(.)\1+$/, why: '整串都是同一个字符' },
  { re: /^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|wer|ert|rty|asd|sdf|dfg|zxc|xcv)/i,
    why: '以键盘顺序开头，这是破解字典的头几页' },
  // 默认口令名单只做**整串**匹配（在下面的 TOP_WEAK 里），这里只拦
  // "默认口令 + 一点点后缀"这种经典套路，且要求整串就是那个词加纯数字尾。
  // 不用 `^test` 前缀匹配：`test passphrase 123` 有 20 个字符、带空格和数字，
  // 熵并不低，只因为以 test 开头就拒绝，是把用户往更短更好猜的方向逼。
  { re: /^(password|passwd|qwerty|letmein|welcome|admin|root|monkey|dragon|iloveyou|master|sunshine|princess|football|baseball|superman|trustno1|abc123|test|guest|login)[\d!@#$%^&*._-]{0,4}$/i,
    why: '这是一个众所周知的默认口令加了一点点后缀' },
];

// 报告实测：单靠模式规则已覆盖 Pwdb top-1000 的 90.2%。再补几个高频词，
// 覆盖面到 91.9%，而体积只多不到 2KB —— 再大的字典按 NIST 的说法已无收益
// （blocklist 的作用是防"最蠢的选择"，不是穷举所有弱口令）。
const TOP_WEAK = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234',
  'passw0rd', 'p@ssw0rd', 'p@ssword', 'pass', 'passwd',
  '123456', '1234567', '12345678', '123456789', '1234567890',
  'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn',
  'abc123', 'abcd1234', 'a1b2c3', '111111', '000000', '121212', '654321',
  'iloveyou', 'admin', 'admin123', 'root', 'toor', 'test', 'test123',
  'letmein', 'welcome', 'welcome1', 'monkey', 'dragon', 'master',
  'sunshine', 'princess', 'football', 'baseball', 'superman',
  'trustno1', 'shadow', 'michael', 'jennifer', 'computer', 'internet',
  'changeme', 'secret', 'default', 'guest', 'user', 'login',
  'bitcoin', 'ethereum', 'wallet', 'crypto',
]);

function checkPassphrase(p) {
  if (typeof p !== 'string') throw fail('INVALID', '口令必须是字符串');
  if (p.length < MIN_PASSPHRASE) {
    throw fail('INVALID', '口令至少 ' + MIN_PASSPHRASE + ' 个字符（建议一句好记的长句）');
  }
  if (p.length > MAX_PASSPHRASE) {
    throw fail('INVALID', '口令太长（最多 ' + MAX_PASSPHRASE + ' 个字符）');
  }
  const lower = p.toLowerCase();
  if (TOP_WEAK.has(lower)) {
    throw fail('INVALID',
      '这个口令在公开的泄露口令表里，几秒钟就能被猜到。换一句只有你知道的话' +
      '（比如"楼下那家面馆周三不开门"这类），越长越好记越好');
  }
  for (const { re, why } of WEAK_PATTERNS) {
    if (re.test(p)) throw fail('INVALID', '口令强度不足：' + why + '。换一句长一点、不常见的话');
  }
  return p;
}

/* ---------------- 文件结构校验 ---------------- */

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * 校验并规范化磁盘上的 vault.enc 结构。
 * 任何一处不对劲都当成"文件损坏"报出来，而不是带着半截对象往下走——
 * 带着坏结构继续解密的后果是把 DEK 解成垃圾或直接崩在某个 undefined 上。
 */
function parseVaultFile(text) {
  let raw;
  try { raw = JSON.parse(text); }
  catch { throw fail('INTERNAL', 'vault.enc 不是合法 JSON，文件可能损坏'); }

  if (!isPlainObject(raw)) throw fail('INTERNAL', 'vault.enc 顶层结构不正确');
  if (raw.format !== FORMAT) {
    throw fail('INTERNAL', 'vault.enc 的 format 不是 ' + FORMAT + '（实际 ' + String(raw.format) + '）');
  }

  const kdf = raw.kdf;
  if (!isPlainObject(kdf)) throw fail('INTERNAL', 'vault.enc 缺少 kdf 段');
  if (kdf.algo !== 'scrypt') throw fail('INTERNAL', '不支持的 KDF 算法：' + String(kdf.algo));
  // 参数由文件自带（这样将来调整成本参数时，老库仍然能打开）。
  // 只校验是否在合理范围内：N 必须是 2 的幂，r/p 在 1..32 / 1..4。
  for (const k of ['N', 'r', 'p']) {
    if (!Number.isInteger(kdf[k])) throw fail('INTERNAL', 'vault.enc 的 kdf.' + k + ' 不是整数');
  }
  const isPow2 = n => n > 0 && (n & (n - 1)) === 0;
  if (!isPow2(kdf.N) || kdf.N < KDF_LIMITS.nMin || kdf.N > KDF_LIMITS.nMax) {
    throw fail('INTERNAL', 'vault.enc 的 scrypt N 不合法（' + kdf.N + '）');
  }
  if (kdf.r < KDF_LIMITS.rMin || kdf.r > KDF_LIMITS.rMax) {
    throw fail('INTERNAL', 'vault.enc 的 scrypt r 不合法（' + kdf.r + '）');
  }
  if (kdf.p < KDF_LIMITS.pMin || kdf.p > KDF_LIMITS.pMax) {
    throw fail('INTERNAL', 'vault.enc 的 scrypt p 不合法（' + kdf.p + '）');
  }
  for (const k of ['saltPass', 'saltRecovery']) {
    if (typeof kdf[k] !== 'string') throw fail('INTERNAL', 'vault.enc 缺少 ' + k);
    const buf = unb64(kdf[k]);
    if (buf.length !== SALT_LEN) throw fail('INTERNAL', k + ' 长度不是 16 字节');
  }

  const wraps = raw.wraps;
  if (!isPlainObject(wraps)) throw fail('INTERNAL', 'vault.enc 缺少 wraps 段');
  for (const slot of ['pass', 'recovery']) {
    const w = wraps[slot];
    if (!isPlainObject(w)) throw fail('INTERNAL', 'vault.enc 缺少 wraps.' + slot);
    if (typeof w.iv !== 'string' || typeof w.ct !== 'string') {
      throw fail('INTERNAL', 'wraps.' + slot + ' 结构不正确');
    }
    if (unb64(w.iv).length !== IV_LEN) throw fail('INTERNAL', 'wraps.' + slot + '.iv 长度不是 12 字节');
    if (unb64(w.ct).length !== WRAP_CT_LEN) {
      throw fail('INTERNAL', 'wraps.' + slot + '.ct 长度不是 ' + WRAP_CT_LEN + ' 字节');
    }
  }

  const data = raw.data;
  if (!isPlainObject(data)) throw fail('INTERNAL', 'vault.enc 缺少 data 段');
  if (typeof data.iv !== 'string' || typeof data.ct !== 'string') {
    throw fail('INTERNAL', 'data 结构不正确');
  }
  if (unb64(data.iv).length !== IV_LEN) throw fail('INTERNAL', 'data.iv 长度不是 12 字节');
  if (unb64(data.ct).length < TAG_LEN) throw fail('INTERNAL', 'data.ct 太短');

  return raw;
}

/* ---------------- GCM 封装 ---------------- */

function aesGcmEncrypt(key, plaintextBuf, aad) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const enc = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: b64(iv), ct: b64(Buffer.concat([enc, tag])) };
}

function aesGcmDecrypt(key, ivB64, ctB64, aad, onFail) {
  const iv = unb64(ivB64);
  const buf = unb64(ctB64);
  if (iv.length !== IV_LEN) throw fail('INTERNAL', 'GCM IV 长度不正确');
  if (buf.length < TAG_LEN) throw fail('INTERNAL', 'GCM 密文太短');
  const ct = buf.subarray(0, buf.length - TAG_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // tag 校验失败：密钥不对，或者密文被改过。两种情况对外都是"解不开"。
    throw (onFail || fail('INTERNAL', '解密失败：密钥不正确或文件被篡改'));
  }
}

/* ---------------- KeyStore ---------------- */

class KeyStore {
  /**
   * @param {string} vaultPath vault.enc 的完整路径
   * @param {{idleTimeoutSec?:number}} opts
   */
  constructor(vaultPath, opts) {
    const o = opts || {};
    this.vaultPath = vaultPath;
    this.dir = path.dirname(vaultPath);

    // 创建新库时写进文件的 KDF 参数。默认永远是上面那组已实测的常量；
    // 测试传入更小的 N 来把上百次 scrypt 压到能跑完。
    // 读取已有库时一律用文件里声明的参数（见 meta.kdf），
    // 所以调小这个值不会让老库打不开。
    this._kdfParams = o.kdf
      ? { algo: 'scrypt', N: o.kdf.N, r: o.kdf.r, p: o.kdf.p }
      : { ...KDF };

    this._dek = null;            // Buffer(32) 或 null
    // 当前 DEK 是用哪个槽解开的：'pass' | 'recovery' | null。
    // 这个状态只影响一件事：改口令时要不要校验旧口令。恢复解锁的会话里
    // 用户**根本没有旧口令**（他的口令已经忘了，那正是他走恢复密钥的原因），
    // 要求"验证旧口令"等于永远不让他设新口令——人被锁在门外、拿恢复密钥
    // 进来、却只能一直用恢复密钥，这是设计漏洞，不是安全特性。
    this._unlockedVia = null;
    this._meta = null;           // 最近一次从磁盘读到的结构（不含明文）

    // 清理上次异常退出留下的中间文件。
    //
    // .rollback 是改口令前的完整快照；因为它裹的是**同一把 DEK**（改口令
    // 不换 DEK，为了保住恢复槽），残留一份 = 旧口令 + 它就能解开当前库，
    // 前向安全完全失效。正常路径 _discardSnapshot 会删，但崩溃/断电/进程被
    // 杀就留下了，而且跨重启一直在。
    try { fs.unlinkSync(this.vaultPath + '.rollback'); } catch { /* 不存在是常态 */ }
    // .bak.stage 是 _atomicWrite 里"上一代主文件"的中转副本，同样含完整
    // 密文与数据库结构，崩溃残留没有保留价值（它要么已被并入 bak.1，
    // 要么这次写入压根没成功），一并清掉。
    try { fs.unlinkSync(this.vaultPath + '.bak.stage'); } catch { /* 同上 */ }
    try { fs.unlinkSync(this.vaultPath + '.bak.1.tmp'); } catch { /* 同上 */ }
    // 带 pid 的 tmp / stage：只删**持有者确定已消失**的那些。
    // 不能按固定名无脑删：两个实例同时跑时，另一个实例的 tmp 正是它
    // 下一次 rename 的源文件，删掉它等于让那一次保存凭空失败。
    this._cleanupStaleTmpFiles();
    this._idleTimeoutSec = Number.isInteger(o.idleTimeoutSec) && o.idleTimeoutSec >= 0
      ? o.idleTimeoutSec
      : DEFAULT_IDLE_SEC;
    this._lastActivity = 0;

    // 失败限速（内存态：重启即清零。攻击者若能重启进程，说明已经能执行本地代码了）
    this._failures = 0;
    this._lockUntil = 0;

    try { fs.mkdirSync(this.dir, { recursive: true }); } catch { /* 已存在 */ }
  }

  /* ---- 状态 ---- */

  exists() {
    try { return fs.existsSync(this.vaultPath) && fs.statSync(this.vaultPath).isFile(); }
    catch { return false; }
  }

  isLocked() { return this._dek === null; }

  idleTimeoutSec() { return this._idleTimeoutSec; }

  setIdleTimeout(sec) {
    // 注意 null：Number(null) === 0，会被当成"永不锁定"静默接受。
    // 那是一个安全设置被悄悄改成最宽松值的典型路径，必须显式拒绝。
    // 空字符串同理（Number('') === 0），布尔也拒。
    if (sec === null || sec === undefined || typeof sec === 'boolean') {
      throw fail('INVALID', '空闲锁定时间必须是 0..86400 之间的整数（0 表示永不自动锁定）');
    }
    let n;
    if (typeof sec === 'number') n = sec;
    else if (typeof sec === 'string' && /^\d+$/.test(sec.trim())) n = Number(sec.trim());
    else {
      throw fail('INVALID', '空闲锁定时间必须是 0..86400 之间的整数（0 表示永不自动锁定）');
    }
    if (!Number.isInteger(n) || n < 0 || n > 86400) {
      throw fail('INVALID', '空闲锁定时间必须是 0..86400 之间的整数（0 表示永不自动锁定）');
    }
    this._idleTimeoutSec = n;
    this._touch();
    return n;
  }

  /** 最近一次成功写入/解锁的时间（ISO），未初始化时为 null */
  updatedAt() {
    try {
      const meta = this._readMetaSafe();
      return meta && typeof meta.updatedAt === 'string' ? meta.updatedAt : null;
    } catch { return null; }
  }

  /** 还剩多少秒自动锁定；0 表示不自动锁 */
  secondsUntilLock() {
    if (this._dek === null) return 0;
    if (this._idleTimeoutSec === 0) return -1;
    const elapsed = Math.floor((nowMs() - this._lastActivity) / 1000);
    return Math.max(0, this._idleTimeoutSec - elapsed);
  }

  expiresAt() {
    const s = this.secondsUntilLock();
    if (s <= 0) return null;          // 0 = 已过期；-1 = 永不
    return new Date(nowMs() + s * 1000).toISOString();
  }

  _touch() { this._lastActivity = nowMs(); }

  /**
   * 每次已解锁状态下的 API 调用都应调用一次。
   * 返回 true 表示这次调用触发了自动锁定（调用方应回 423）。
   */
  /**
   * 空闲自动锁定判定。
   *
   * @param {boolean} userActive 这次调用是否代表「用户真的在操作」。
   *
   * 必须区分用户操作和后台轮询：前端每 5 秒轮询一次 otp.codes 刷新验证码，
   * 如果轮询也算活动，那 elapsed 永远是 ~5 秒，900 秒的阈值永远达不到 ——
   * 「15 分钟空闲自动锁」这个安全承诺就是假的，用户离开工位后库一直开着。
   * 只有真正改变状态的操作（新建/编辑/删除/揭示/解锁）才重置计时器。
   */
  maybeAutoLock(userActive = true) {
    if (this._dek === null) return false;
    if (this._idleTimeoutSec === 0) { if (userActive) this._touch(); return false; }
    const elapsed = (nowMs() - this._lastActivity) / 1000;
    if (elapsed >= this._idleTimeoutSec) {
      this.lock();
      return true;
    }
    if (userActive) this._touch();
    return false;
  }

  /* ---- 限速 ---- */

  _checkThrottle() {
    const now = nowMs();
    if (this._lockUntil > now) {
      const wait = Math.ceil((this._lockUntil - now) / 1000);
      throw fail('THROTTLED', '连续输错次数过多，请 ' + wait + ' 秒后再试');
    }
  }

  _recordFailure() {
    this._failures += 1;
    if (this._failures >= THROTTLE_AFTER) {
      const idx = Math.min(this._failures - THROTTLE_AFTER, THROTTLE_DELAYS_MS.length - 1);
      this._lockUntil = nowMs() + THROTTLE_DELAYS_MS[idx];
    }
  }

  _resetFailures() {
    this._failures = 0;
    this._lockUntil = 0;
  }

  /** 仅供测试/诊断：当前限速状态（不含任何密钥材料） */
  throttleState() {
    return {
      failures: this._failures,
      lockedForMs: Math.max(0, this._lockUntil - nowMs()),
    };
  }

  /* ---- 读盘 ---- */

  _readMetaSafe() {
    if (!this.exists()) return null;
    const text = fs.readFileSync(this.vaultPath, 'utf8');
    return parseVaultFile(text);
  }

  _readMeta() {
    if (!this.exists()) throw fail('NOT_FOUND', '尚未创建密钥库');
    return this._readMetaSafe();
  }

  /* ---- KDF ---- */

  _derive(secretString, saltB64, kdfParams) {
    const salt = unb64(saltB64);
    if (salt.length !== SALT_LEN) throw fail('INTERNAL', 'KDF 盐长度不正确');
    const k = kdfParams || KDF;
    // maxmem 必须由参数推导，不能硬编码。
    // scrypt 的内存需求 ≈ 128 * N * r，再留 2 倍余量给内部开销。
    // 硬编码 64MB 会让"合法且在 KDF_LIMITS 范围内"的参数（如 N=65536）
    // 直接抛 ERR_CRYPTO_INVALID_SCRYPT_PARAMS，而 unlock 的 catch 会把它
    // 误报成"口令不正确"——用户既打不开又不知道原因，还会计入限速。
    // 未来调高成本参数时，老库会因此永久锁死。
    //
    // 但推导出来的值必须再钳一次上限：推导的输入 k.N / k.r 来自磁盘文件，
    // KDF_LIMITS 允许的组合（N=2^18, r=32）能推算出 2 GiB，等于把
    // "文件里写个数就能让进程分配 2 GiB"重新打开。MAX_SCRYPT_MEM 挡住
    // 这一类；超过的组合由 scrypt 抛参数错误，交给调用方判别成 INTERNAL。
    const maxmem = Math.min(MAX_SCRYPT_MEM, Math.max(64 * 1024 * 1024, 128 * k.r * k.N * 2));
    // 口令 Buffer 必须用完清零。Buffer.from(string, 'utf8') 走的是
    // Node 的 Buffer 分配池（小于 4KB 的 Buffer 从 8KB 的共享池切一块），
    // fill(0) 之外的释放只是把控制权还给池子，池里的**字节不会被擦掉**，
    // 直到被后来的分配覆盖。也就是说 scrypt 返回后，明文口令会以
    // "已释放内存"的形态在进程堆里停留任意长时间，核心转储、页面交换、
    // 甚至下一次无关的 Buffer 分配都可能把它带出来。口令是唯一能解开
    // DEK 的材料，不能这样留在池里。用 try/finally 保证 scryptSync 抛错
    // （参数非法、内存不足）时也照样清零。
    const pwBuf = Buffer.from(secretString, 'utf8');
    try {
      // scryptSync 是同步的（约 240ms）。这里必须同步：调用方在同一个
      // 请求处理链里紧接着就要用 key 解包 DEK，异步化只会增加暴露窗口。
      return crypto.scryptSync(pwBuf, salt, KEYLEN, {
        N: k.N, r: k.r, p: k.p,
        maxmem,
      });
    } finally {
      pwBuf.fill(0);
    }
  }

  _dataAad(meta) {
    // AAD 里的格式串必须跟**这份文件**的 format 走，不能写死常量。
    // 老文件的 data 段是用 'keydesk/1' 做 AAD 加密的：将来 FORMAT 升到
    // 'keydesk/2' 之后，如果这里仍然用常量，打开老库就会算出 'keydesk/2|...'
    // 的 AAD，GCM tag 校验必然失败——表现为"数据段解不开/文件被篡改"，
    // 而实际上数据完好。meta.format 由 parseVaultFile 校验过（当前只接受
    // 'keydesk/1'），|| FORMAT 是给手工构造 / 未来迁移中的 meta 兜底。
    // 注意：字段顺序和分隔符不能动，动了所有现有库都解不开。
    return (meta.format || FORMAT) + '|' + meta.kdf.saltPass + '|' + meta.kdf.saltRecovery;
  }

  _wrapAad(slot, saltB64) {
    // AAD 把密文钉死在「哪个槽 + 哪份盐」上：把 recovery 槽的密文
    // 搬到 pass 槽（或换一份盐）都会当场校验失败。
    return FORMAT + '|wrap|' + slot + '|' + saltB64;
  }

  /* ---- 原子写 + 备份轮转 ---- */

  /**
   * 备份轮转：bak(3) ← bak(2) ← bak(1) ← srcPath（上一代主文件的内容）。
   *
   * 轮转的输入必须是**调用方持有的上一代副本**，不能在这里读 this.vaultPath：
   * 见 _atomicWrite，轮转已经挪到 rename 成功之后，那时主文件里是新一代，
   * 直接读它会让 bak.1 保存一份和主文件相同的副本，备份链形同虚设。
   */
  _rotateBackups(srcPath) {
    const p = this.vaultPath;
    const bak = n => p + '.bak.' + n;
    // 没有上一代（首次创建，或主文件被人手工删了）就完全不动备份链。
    // 这时候推进只会把旧备份凭空挤掉一代，而没有任何新内容补上。
    if (!srcPath) return;
    try {
      // 从最老的一代往前推：3 ← 2，2 ← 1
      for (let n = BACKUP_COUNT; n >= 2; n--) {
        if (fs.existsSync(bak(n - 1))) {
          try { fs.copyFileSync(bak(n - 1), bak(n)); } catch { /* 备份失败不阻断主流程 */ }
        }
      }
      // bak.1 的写入要「先落盘再改名」而不是直接 copyFileSync 到目标名。
      // copyFileSync 不是原子的：它先把目标截断成 0 字节再灌内容，此刻断电
      // 就留下一个空/半截的 bak.1。而 bak.1 是"五分钟前还能用的那份库"，
      // 恰恰是用户误操作后唯一能回退的东西。先复制到 .bak.1.tmp、fsync
      // 确保字节真的在盘上、再 rename 覆盖——目录项替换才是原子的，
      // 断电后要么是完整的旧 bak.1，要么是完整的新 bak.1。
      // （bak(2)/bak(3) 仍是直接 copyFileSync：它们的源本身是完整的旧备份，
      //  最坏情况只损失更老的一代，代价可以接受。）
      const stage = bak(1) + '.tmp';
      try {
        fs.copyFileSync(srcPath, stage);
        const fd = fs.openSync(stage, 'r+');
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        fs.renameSync(stage, bak(1));
      } catch {
        try { fs.unlinkSync(stage); } catch { /* 忽略 */ }
      }
    } catch {
      // 备份轮转是尽力而为：磁盘满或权限问题时不能让"保存"本身失败，
      // 否则用户改一笔就丢一笔。主写入后面还有自检兜底。
    }
  }

  /**
   * 清掉残留的 tmp / stage 文件（崩在 rename 之前的残骸）。
   *
   * 带 pid 的临时名解决了并发撕裂，代价是崩溃残留不再像固定名那样
   * "下一次写入顺手覆盖掉"，会一直堆在数据目录里（每个含完整密文）。
   * 所以构造时和改口令后各扫一遍，但只删**确定死掉**的 pid 的：
   *   · pid 还活着 → 可能是另一个实例在写，绝不能动；
   *   · pid 判断不了（EPERM 之外的异常）→ 同样不动，留给以后；
   *   · 名字里没有合法 pid（旧版本留下的固定名 .tmp）→ 也删，
   *     那是老代码的残骸，当前代码不会再用这个名字。
   *
   * 调用点都在"本模块没有并发写入"的位置（构造函数、改口令落盘之后），
   * 且写入是同步的：正常退出路径不会留下自己的残骸；留下的必然是死 pid 的。
   *
   * @param {boolean} includeOwn 连**本进程**的残骸一起删。只在"确定本次
   *   写入已经失败、不会再有 rename 用到那个文件"时传 true（例如 setup 的
   *   失败回滚）——别的时候删自己的 tmp 会把一次正在进行的保存弄失败。
   */
  _cleanupStaleTmpFiles(includeOwn = false) {
    const base = path.basename(this.vaultPath);
    let names;
    try { names = fs.readdirSync(this.dir); } catch { return; }
    const oldFixed = new Set([base + '.tmp']);
    const pidRe = new RegExp('^' + escapeRe(base) + '\\.(?:tmp|bak\\.stage)-(\\d+)-\\d+$');
    for (const name of names) {
      const full = path.join(this.dir, name);
      if (oldFixed.has(name)) {
        try { fs.unlinkSync(full); } catch { /* 忽略 */ }
        continue;
      }
      const m = pidRe.exec(name);
      if (!m) continue;
      const pid = Number(m[1]);
      // 本进程的残骸默认保留：另一个"保存"可能正拿着这个 tmp 准备 rename。
      if (pid === process.pid && !includeOwn) continue;
      if (pid !== process.pid && pidState(pid) !== 'dead') continue;
      try { fs.unlinkSync(full); } catch { /* 忽略 */ }
    }
  }

  _atomicWrite(text) {
    // tmp 名必须每进程唯一。
    //
    // 原来写死成 vault.enc.tmp：双击两次 start.bat 时，第二个实例因 EADDRINUSE
    // 顺延到 2152 照样启动，两个进程于是共用同一个 tmp 文件。实测两种后果：
    //   1. 整库不可读：A 的 fsync 与 B 的 write 交错，主文件被污染成非 JSON，
    //      下次读取直接报"文件结构损坏"，全部条目一起打不开；
    //   2. 写盘过程互相踩：一方 rename 走了另一方正在写的文件，后者拿到 ENOENT。
    // pid + 时间戳让并发写入各用各的 tmp，rename 是原子的，最后落盘的那份
    // 是完整的 JSON —— 语义退化成"后写者赢"，而不是"互相撕碎"。
    // 同一进程内多次写入是同步的，前一次 rename 完成后才会走到下一次 open，
    // 所以时间戳相同也不会重叠。
    const tmp = this.vaultPath + '.tmp-' + process.pid + '-' + Date.now();
    // 上一代内容的中转副本。轮转被挪到 rename 成功之后（理由见下），
    // 而 rename 一执行完 tmp 就变成了主文件、老内容无处可取，
    // 所以在 rename 之前先把当前主文件抓一份到这里。
    // 同样带上 pid + 时间戳：固定名会让两个实例同时轮转备份链，
    // 一个进程可能把另一个刚拷好的 stage 当成自己的上一代推进 bak.1。
    const stage = this.vaultPath + '.bak.stage-' + process.pid + '-' + Date.now();

    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      // 用 writeFileSync 而不是 writeSync：POSIX 的 write() 允许部分写入，
      // writeSync 的返回值正是"实际写进去多少字节"。几百 KB 的普通文件在
      // 实测中总是一次写完，但"通常没问题"不该是数据完整性的依据 ——
      // 少写一个字节 = 整份 vault.enc 解不开。writeFileSync 内部会循环到写完。
      fs.writeFileSync(fd, text, 'utf8');
      fs.fsyncSync(fd);          // 先落盘再改名，断电也不会留下半截文件
    } catch (e) {
      // 写/fsync 失败（磁盘满、I/O 错误）：关掉 fd 并删掉半成品。
      // 不删的话，这份**不完整**的密文会一直躺在数据目录里；
      // 而"没有半成品"正是原子写相对直接覆盖写唯一多出来的保证。
      try { fs.closeSync(fd); } catch { /* 忽略 */ }
      try { fs.unlinkSync(tmp); } catch { /* 忽略 */ }
      throw e;
    }
    try {
      fs.closeSync(fd);
    } catch { /* 已关闭或关闭失败都不影响 rename */ }

    let staged = false;
    try {
      if (fs.existsSync(this.vaultPath)) {
        fs.copyFileSync(this.vaultPath, stage);
        staged = true;
      }
    } catch { staged = false; /* 抓不到上一代就少一代备份，不阻断本次写入 */ }

    try {
      fs.renameSync(tmp, this.vaultPath);
    } catch (e) {
      // rename 失败（Windows 上杀毒软件、Everything、OneDrive/坚果云等
      // 持有句柄时会 EPERM）：此时备份链必须原封不动。老实现是先轮转
      // 再 rename，rename 一失败 bak.1/bak.2 已经被推进一格，bak.1 与
      // bak.2 内容相同、真正的"上上代"被挤掉——用户以为有三代备份，
      // 实际只剩两代且其中一代是废的。
      //
      // .tmp 也要在这里删掉：它已经写满了**新一代**的完整内容，留着既没有
      // 用处（下次 _atomicWrite 会整份重写），又是一份多出来的密文副本躺在
      // 数据目录里。下次进程启动时构造函数虽然也会清，但用户很可能在同一个
      // 进程里接着重试保存，那段时间里它就是无人管理的残留。
      try { fs.unlinkSync(tmp); } catch { /* 忽略 */ }
      try { fs.unlinkSync(stage); } catch { /* 忽略 */ }
      throw e;
    }

    // 目录 fsync：文件 fsync 只保证**文件内容**落盘，rename 改的是目录项，
    // 目录项还在页缓存里就断电的话，ext4 上可能出现主文件和 tmp 同时消失
    // （旧名字已删、新名字没写下去）——这是能把整个库弄丢的最坏情况，
    // 而内容明明已经 fsync 过了。Windows 上 openSync(dir,'r') 会 EPERM，
    // 那里的 NTFS 日志语义不依赖这个调用，所以放 catch 忽略。
    try {
      const dfd = fs.openSync(this.dir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* Windows EPERM，忽略 */ }

    try { fs.chmodSync(this.vaultPath, 0o600); } catch { /* Windows 上语义有限 */ }

    // 到这里新一代已经稳稳落盘，再推进备份链。顺序反过来就会在 rename
    // 失败时污染备份，见上面的注释。
    this._rotateBackups(staged ? stage : null);
    try { fs.unlinkSync(stage); } catch { /* 忽略 */ }
  }

  /**
   * 写入前的安全网：把当前 vault.enc 原样留一份到 escape hatch 路径，
   * 供 _verifyWritten 失败时回滚。
   *
   * 为什么不能直接依赖 .bak.1：_rotateBackups 只在 rename **成功之后**
   * 才推进（失败时必须原样保留，见 _atomicWrite），所以"写坏了"这条
   * 路径上 bak 链根本没动；而且用户/清理工具可能早已把 .bak.N 删掉。
   * 这里要的是一份"这次操作专用的、退出即删"的快照。
   */
  _snapshotForRollback() {
    try {
      if (!fs.existsSync(this.vaultPath)) return null;
      const snap = this.vaultPath + '.rollback';
      fs.copyFileSync(this.vaultPath, snap);
      return snap;
    } catch {
      return null;   // 快照失败不阻断，但要如实记录在返回值里
    }
  }

  _rollback(snap) {
    if (!snap) return false;
    try {
      fs.copyFileSync(snap, this.vaultPath);
      // 回滚后内存里的 meta 也要跟着回来，否则下一次读会看到新参数
      this._meta = null;
      return true;
    } catch {
      return false;
    } finally {
      try { fs.unlinkSync(snap); } catch { /* 忽略 */ }
    }
  }

  _discardSnapshot(snap) {
    if (!snap) return;
    try { fs.unlinkSync(snap); } catch { /* 忽略 */ }
  }


  /** 写入后读回并完整解密一遍，确认这份文件将来真的能打开 */
  _verifyWritten(expectedPayloadText, secretString, slot) {
    const meta = this._readMeta();
    const kek = this._derive(secretString, slot === 'pass' ? meta.kdf.saltPass : meta.kdf.saltRecovery, meta.kdf);
    const dek = aesGcmDecrypt(
      kek,
      meta.wraps[slot].iv,
      meta.wraps[slot].ct,
      this._wrapAad(slot, slot === 'pass' ? meta.kdf.saltPass : meta.kdf.saltRecovery),
      fail('INTERNAL', '落盘自检失败：' + slot + ' 槽解不开 DEK')
    );
    let plain;
    try {
      plain = aesGcmDecrypt(
        dek,
        meta.data.iv,
        meta.data.ct,
        this._dataAad(meta),
        fail('INTERNAL', '落盘自检失败：数据段解不开')
      ).toString('utf8');
    } finally {
      dek.fill(0);
    }
    if (expectedPayloadText != null && plain !== expectedPayloadText) {
      throw fail('INTERNAL', '落盘自检失败：读回的明文与写入不一致');
    }
    return true;
  }

  /* ---- 生命周期 ---- */

  /**
   * 首次创建密钥库。
   * @returns {{recoveryKey:string, vaultPath:string}}
   */
  setup(passphrase) {
    checkPassphrase(passphrase);
    if (this.exists()) throw fail('CONFLICT', '密钥库已存在，不能重复初始化');

    const recoveryKey = generateRecoveryKey();
    const recoveryNorm = normalizeRecoveryKey(recoveryKey);

    const dek = crypto.randomBytes(DEK_LEN);
    const saltPass = b64(crypto.randomBytes(SALT_LEN));
    const saltRecovery = b64(crypto.randomBytes(SALT_LEN));

    const kekPass = this._derive(passphrase, saltPass, this._kdfParams);
    const kekRecovery = this._derive(recoveryNorm, saltRecovery, this._kdfParams);

    const payloadText = JSON.stringify({
      version: 1, revision: 0, updatedAt: new Date().toISOString(), entries: [],
    });

    const meta = {
      format: FORMAT,
      kdf: { algo: 'scrypt', N: this._kdfParams.N, r: this._kdfParams.r,
             p: this._kdfParams.p, saltPass, saltRecovery },
      wraps: {
        pass: aesGcmEncrypt(kekPass, dek, this._wrapAad('pass', saltPass)),
        recovery: aesGcmEncrypt(kekRecovery, dek, this._wrapAad('recovery', saltRecovery)),
      },
      data: null,
      updatedAt: new Date().toISOString(),
    };
    kekPass.fill(0);
    kekRecovery.fill(0);

    meta.data = aesGcmEncrypt(dek, Buffer.from(payloadText, 'utf8'), this._dataAad(meta));
    // 记录恢复槽指纹，供以后改口令时检出"恢复槽被改坏"
    meta.recoveryCheck = _recoveryFingerprint(meta);

    try {
      this._atomicWrite(JSON.stringify(meta, null, 2));
      // 两个槽都要自检：恢复密钥是灾难恢复的唯一后路，
      // 它写坏了要等到真正需要时才被发现，那时已经晚了。
      this._verifyWritten(payloadText, passphrase, 'pass');
      this._verifyWritten(payloadText, recoveryNorm, 'recovery');
    } catch (e) {
      dek.fill(0);
      // 自检失败必须清掉刚写下的半个库。
      // 不清的后果是死锁：用户看到"创建失败"，再点一次却被告知"密钥库已存在"，
      // 而恢复密钥从来没显示过——他既不知道口令能不能用，也没有逃生门。
      // 这正是"建立唯一逃生门"的那一刻，绝不能留下半成品。
      try { fs.unlinkSync(this.vaultPath); } catch { /* 忽略 */ }
      // 本次写入自己的 tmp 名带 pid + 时间戳，这里不知道是哪一个；
      // setup 失败时本进程不会再有并发写，includeOwn 是安全的。
      this._cleanupStaleTmpFiles(true);
      for (let n = 1; n <= BACKUP_COUNT; n++) {
        try { fs.unlinkSync(this.vaultPath + '.bak.' + n); } catch { /* 忽略 */ }
      }
      this._meta = null;
      throw e instanceof Error && e.code ? e : fail('INTERNAL', '初始化失败：' + (e && e.message));
    }

    this._dek = dek;
    // 刚用用户输入的口令建库，等价于"口令槽解开"的会话
    this._unlockedVia = 'pass';
    this._meta = meta;
    this._resetFailures();
    this._touch();

    return { recoveryKey, vaultPath: this.vaultPath };
  }

  unlock(passphrase) {
    this._checkThrottle();
    if (!this.exists()) throw fail('NOT_FOUND', '尚未创建密钥库');
    if (typeof passphrase !== 'string' || !passphrase) {
      throw fail('BAD_PASSPHRASE', '口令不能为空');
    }

    const meta = this._readMeta();
    let dek;
    try {
      const kek = this._derive(passphrase, meta.kdf.saltPass, meta.kdf);
      try {
        dek = aesGcmDecrypt(kek, meta.wraps.pass.iv, meta.wraps.pass.ct,
          this._wrapAad('pass', meta.kdf.saltPass), null);
      } finally {
        kek.fill(0);
      }
    } catch (e) {
      // KDF 参数超出本机能力时不能报"口令不正确"——那会让用户以为记错了口令，
      // 而且会计入失败限速，越试越锁。这种情况数据没坏，是参数不自洽。
      if (e && /ERR_CRYPTO_INVALID_SCRYPT_PARAMS|memory limit|Invalid scrypt/i.test(
        String(e.code || '') + ' ' + String(e.message || ''))) {
        throw fail('INTERNAL',
          '密钥库的 KDF 参数超出本机计算能力（可能被篡改或来自更高配置的机器）');
      }
      this._recordFailure();
      throw fail('BAD_PASSPHRASE', '口令不正确');
    }

    // 解出来的 DEK 还要能解开数据，才算真的对——wraps 对了但 data
    // 被换过（或用了别的 vault 的 data 段）也要在这里拦住。
    try {
      aesGcmDecrypt(dek, meta.data.iv, meta.data.ct, this._dataAad(meta), null);
    } catch {
      dek.fill(0);
      this._recordFailure();
      throw fail('INTERNAL', '密钥库数据段校验失败，文件可能被篡改');
    }

    this._setDek(dek, meta, 'pass');
    return { expiresAt: this.expiresAt() };
  }

  unlockWithRecovery(recoveryKeyInput) {
    this._checkThrottle();
    if (!this.exists()) throw fail('NOT_FOUND', '尚未创建密钥库');

    const recoveryNorm = normalizeRecoveryKey(recoveryKeyInput); // 格式错直接 INVALID
    const meta = this._readMeta();
    let dek;
    try {
      const kek = this._derive(recoveryNorm, meta.kdf.saltRecovery, meta.kdf);
      try {
        dek = aesGcmDecrypt(kek, meta.wraps.recovery.iv, meta.wraps.recovery.ct,
          this._wrapAad('recovery', meta.kdf.saltRecovery), null);
      } finally {
        kek.fill(0);
      }
    } catch (e) {
      // 与 unlock 同样的判别：KDF 参数超出本机能力（文件被篡改、或来自配置
      // 更高的机器）时，恢复密钥本身是对的，不能报"恢复密钥不正确"。
      // 误报的代价比 unlock 那边更大：恢复密钥是**唯一的逃生门**，报"不正确"
      // 会让用户在唯一一条生路上反复重打 26 个字符，每次都计入失败限速，
      // 5 次后变成"请 300 秒后再试"，而他手上的密钥其实一点问题都没有。
      if (e && /ERR_CRYPTO_INVALID_SCRYPT_PARAMS|memory limit|Invalid scrypt/i.test(
        String(e.code || '') + ' ' + String(e.message || ''))) {
        throw fail('INTERNAL',
          '密钥库的 KDF 参数超出本机计算能力（可能被篡改或来自更高配置的机器）');
      }
      // 注意 normalizeRecoveryKey 抛的 INVALID 不经过这里（它在 try 外），
      // 所以"末位抄错"这类格式问题仍然报 INVALID，不会被记成失败尝试。
      this._recordFailure();
      throw fail('BAD_PASSPHRASE', '恢复密钥不正确');
    }

    try {
      aesGcmDecrypt(dek, meta.data.iv, meta.data.ct, this._dataAad(meta), null);
    } catch {
      dek.fill(0);
      this._recordFailure();
      throw fail('INTERNAL', '密钥库数据段校验失败，文件可能被篡改');
    }

    this._setDek(dek, meta, 'recovery');
    return { expiresAt: this.expiresAt() };
  }

  /**
   * @param {'pass'|'recovery'} via 这个 DEK 是通过哪个槽解开的。
   *   决定改口令时是否要求旧口令（见 changePassphrase 的注释）。
   *   新建库（setup）走的是口令路径：此刻口令就是用户刚设的那个。
   */
  _setDek(dek, meta, via) {
    if (this._dek) this._dek.fill(0);
    this._dek = dek;
    // 兜底成 'pass'：调用方漏传时退回"要求旧口令"这条更严格的路径，
    // 宁可让恢复会话的用户多碰一次要求，也不能悄悄放开口令校验。
    this._unlockedVia = via === 'recovery' ? 'recovery' : 'pass';
    this._meta = meta;
    this._resetFailures();
    this._touch();
  }

  /** 清空内存里的 DEK。重复调用是安全的。 */
  lock() {
    if (this._dek) {
      this._dek.fill(0);
      this._dek = null;
    }
    this._unlockedVia = null;
    this._meta = null;
    this._lastActivity = 0;
    return true;
  }

  /* ---- 数据读写 ---- */

  /**
   * 解密并返回 payload 对象。未解锁时抛 LOCKED。
   * 每次调用都从磁盘重读：这样多开进程/外部恢复了备份时，
   * 内存里不会拿着过期快照继续覆盖。
   *
   * @param {{touch?: boolean}} opts
   *   touch=false 表示这次读**不算用户活动**（后台轮询走这条路）。
   *   必须支持，否则空闲锁定形同虚设：前端每 5 秒调一次 otp.codes
   *   刷验证码，每次都会 load()，如果 load() 无条件刷新 _lastActivity，
   *   空闲计时器永远到不了阈值——"15 分钟自动锁"就成了假承诺。
   */
  load(opts) {
    if (this._dek === null) throw fail('LOCKED', '密钥库已锁定');
    const touch = !(opts && opts.touch === false);
    if (touch) this._touch();

    const meta = this._readMeta();
    const plain = aesGcmDecrypt(
      this._dek, meta.data.iv, meta.data.ct, this._dataAad(meta),
      fail('INTERNAL', '数据解密失败，vault.enc 可能已损坏')
    );
    this._meta = meta;

    let obj;
    try { obj = JSON.parse(plain.toString('utf8')); }
    catch { throw fail('INTERNAL', '解密后的数据不是合法 JSON'); }
    if (!isPlainObject(obj)) throw fail('INTERNAL', '解密后的数据顶层结构不正确');
    return obj;
  }

  /** 加密并原子写入 payload。未解锁时抛 LOCKED。 */
  save(payload) {
    if (this._dek === null) throw fail('LOCKED', '密钥库已锁定');
    this._touch();

    const meta = this._readMeta();
    const text = JSON.stringify(payload);
    meta.data = aesGcmEncrypt(this._dek, Buffer.from(text, 'utf8'), this._dataAad(meta));
    meta.updatedAt = new Date().toISOString();
    this._atomicWrite(JSON.stringify(meta, null, 2));
    this._meta = meta;
    return true;
  }

  /**
   * 改口令：验证旧口令 → 重新包裹 DEK → 用新 AAD 重加密数据。
   *
   * 恢复解锁的会话（_unlockedVia === 'recovery'）跳过第 1 步，原因：
   * 用户正是因为**忘了口令**才用恢复密钥进来的——他没有旧口令可验。
   * 会话身份已经由恢复密钥证明了（256 位随机、且解开了整份数据），
   * 再要求旧口令等于让这个人永远停不了用恢复密钥。
   *
   * 安全边界没有被放松：
   *   · 锁定态在方法最开头就抛 LOCKED —— 没解锁的库根本走不到这里；
   *   · 新口令照样过 checkPassphrase（跳过旧口令不等于允许弱口令）；
   *   · 恢复槽照样由 _verifyCurrentRecoverySlot 校验完整性，改完仍然能用；
   *   · 改完 _unlockedVia 置回 'pass'：此时口令槽已经装的是新口令，
   *     后续再改就必须验新口令了。
   */
  changePassphrase(oldPassphrase, newPassphrase) {
    if (!this.exists()) throw fail('NOT_FOUND', '尚未创建密钥库');
    // 这一条必须排在"是否恢复会话"判断之前，也排在新口令强度校验之前：
    // 锁定的库不能被改口令，哪怕调用方声称自己是恢复会话、哪怕新口令本身合法。
    // 先校验强度再判锁定的话，锁定态下会先回 INVALID，语义上像是"库可以改、
    // 只是口令不合规"，容易把人引到错误的方向。
    if (this._dek === null) throw fail('LOCKED', '密钥库已锁定');
    this._checkThrottle();
    checkPassphrase(newPassphrase);

    const meta = this._readMeta();
    const viaRecovery = this._unlockedVia === 'recovery';

    // 1) 验证旧口令（用 wraps.pass，不依赖内存里的解锁状态）。
    //    恢复会话跳过——见方法头的注释。
    if (!viaRecovery) {
      try {
        const kekOld = this._derive(String(oldPassphrase == null ? '' : oldPassphrase), meta.kdf.saltPass, meta.kdf);
        try {
          const dek = aesGcmDecrypt(kekOld, meta.wraps.pass.iv, meta.wraps.pass.ct,
            this._wrapAad('pass', meta.kdf.saltPass), null);
          dek.fill(0);
        } finally {
          kekOld.fill(0);
        }
      } catch {
        this._recordFailure();
        throw fail('BAD_PASSPHRASE', '原口令不正确');
      }
    }

    // 2) 先解出现有明文，才能用新 AAD 重加密
    const plain = aesGcmDecrypt(
      this._dek, meta.data.iv, meta.data.ct, this._dataAad(meta),
      fail('INTERNAL', '数据解密失败，vault.enc 可能已损坏')
    ).toString('utf8');

    // 3) 新盐 + 新 KEK 重新包裹同一个 DEK；恢复槽保持不变
    //
    // KDF 参数必须用文件里声明的 meta.kdf，不能用 this._kdfParams（那是进程
    // 编译期默认值，只该用于 setup 新建库）。用错会导致：老库（N 与当前默认
    // 不同）改口令后写进去的 wraps 用新参数包、文件头却仍是旧参数，
    // 自检解不开 → 口令彻底失效。这个坑会在"将来调整 KDF 成本"时爆发。
    //
    // 为什么不换 DEK：恢复槽里的 ct 是用 KEK_recovery 包的 DEK，换 DEK 就
    // 必须用恢复密钥重算 KEK_recovery——但改口令时用户只给了口令，没有恢复
    // 密钥。硬换会把恢复通道改坏（用户以为自己还有逃生门，实际打不开了）。
    //
    // 前向安全改由下一步「清除旧备份」保证：旧 .bak 里包裹的是旧 KEK，
    // 而备份轮转不再保留这些文件，攻击者拿不到它们。
    const saltPass = b64(crypto.randomBytes(SALT_LEN));
    const kekNew = this._derive(newPassphrase, saltPass, meta.kdf);
    meta.kdf.saltPass = saltPass;
    meta.wraps.pass = aesGcmEncrypt(kekNew, this._dek, this._wrapAad('pass', saltPass));
    kekNew.fill(0);

    meta.data = aesGcmEncrypt(this._dek, Buffer.from(plain, 'utf8'), this._dataAad(meta));
    meta.updatedAt = new Date().toISOString();

    // 4) 落盘 + 自检，失败则回滚
    const snap = this._snapshotForRollback();
    try {
      this._atomicWrite(JSON.stringify(meta, null, 2));
      this._verifyWritten(plain, newPassphrase, 'pass');
      // 恢复通道必须仍然可用——它是最后的逃生门，改了口令把它弄坏是灾难
      this._verifyCurrentRecoverySlot(meta);
    } catch (e) {
      const restored = this._rollback(snap);
      // 把底层原因带出来：如果是"恢复槽已损坏"，用户需要知道是这个问题，
      // 而不是笼统的"修改口令失败"——后者会让他反复重试同一个动作。
      const reason = (e && e.message && !/^修改口令失败/.test(e.message)) ? e.message : '';
      throw fail('INTERNAL',
        '修改口令失败' + (reason ? '：' + reason : '') +
        (restored ? '。已回滚到修改前的状态（旧口令仍可用）'
                  : '。且回滚失败——请用恢复密钥解锁'));
    }
    this._discardSnapshot(snap);

    // 5) 清除旧备份：它们包裹的是旧口令派生的 KEK。
    //    留着等于"旧口令仍能通过 bak 解开当前数据"，改口令就没有前向安全性。
    //    这一步在落盘成功之后做——先保证新口令可用，再删退路。
    //    删不掉的文件必须让调用方看得见（见 _purgeBackups 的注释）：
    //    Windows 上被杀毒/网盘占用是真实会发生的，静默吞掉就意味着
    //    "界面说改好了，其实旧口令还能开"。
    const staleBackups = this._purgeBackups();

    this._meta = meta;
    // 口令槽已经是新口令了，从这里开始这次会话就是"口令解开"的：
    // 再次改口令必须验这个新口令，不能一直沿用恢复会话的豁免。
    this._unlockedVia = 'pass';
    this._resetFailures();
    this._touch();
    return { ok: true, staleBackups };
  }

  /**
   * 校验恢复槽自上次写入以来没有被改坏。
   *
   * 为什么不能"真正解密校验"：恢复槽里包的是 DEK，密钥是 KEK_recovery，
   * 而它由恢复密钥派生——改口令的流程里用户只给了口令，拿不到恢复密钥。
   * 所以没法在这里试解。
   *
   * 但可以校验**完整性**：setup / regenerateRecovery 时（那时恢复密钥在手里，
   * 刚写过一次、必成功）记下 wraps.recovery 的指纹。之后每次改口令都比对
   * 当前恢复槽是否仍是那一份。这能挡住"恢复槽被磁盘损坏/手工改坏"的场景——
   * 那正是用户以为还有逃生门、实际已经没有的最坏情况。
   *
   * 早先这里只查字段非空，纯属安慰剂：把 ct 换成 48 字节垃圾照样"通过"。
   */
  _verifyCurrentRecoverySlot(meta) {
    if (!meta || !meta.wraps || !meta.wraps.recovery) {
      throw fail('INTERNAL', '恢复槽缺失');
    }
    const { iv, ct } = meta.wraps.recovery;
    if (!iv || !ct) throw fail('INTERNAL', '恢复槽结构不完整');
    if (!meta.recoveryCheck) {
      // 老版本建的库没有这个字段：无法校验，但不该阻止改口令。
      // 这里不抛错，只是没法提供保证。
      return;
    }
    const now = _recoveryFingerprint(meta);
    if (now !== meta.recoveryCheck) {
      throw fail('INTERNAL',
        '恢复槽内容与上次写入时不一致，可能已损坏。继续改口令会让你以为还有恢复密钥、' +
        '实际已经用不了。请先用当前口令登录后重新生成恢复密钥');
    }
  }

  /**
   * 删除全部 .bak.N 备份。
   *
   * 为什么必须删：备份轮转保留的是历史 vault.enc，里面包裹 DEK 用的是
   * **当时的** KEK（由当时的旧口令派生）。改口令后如果不删，攻击者拿到
   * 任意一个旧 .bak + 旧口令 → 解出 DEK → 而这个 DEK 就是当前数据用的
   * 那把（因为换口令不换 DEK）→ 改口令形同虚设。
   *
   * 代价是失去"误操作后回退到上一版"的能力。这个取舍是明确的：
   * 对一个存 TOTP secret 的库，"改口令后旧口令必须失效"比"能回滚到
   * 五分钟前"重要得多。真要回退，用用户自己做的 vault.enc 离线备份。
   */
  /**
   * 删除全部备份代与中间副本。
   *
   * 改口令 / 重生成恢复密钥之后必须调用：.bak.N 裹的是**旧 KEK + 同一个 DEK**
   * （改口令不换 DEK，是为了保住恢复槽），留着它们等于"旧口令仍然能打开当前库"，
   * 那次改口令就是纯装饰。
   *
   * 返回删不掉的文件名列表，而不是静默吞掉。这一点很重要：Windows 上杀毒软件、
   * Everything、网盘同步客户端都可能持有 .bak 的句柄，unlink 会 EPERM。此时
   * 用户界面上写着"已改口令"，而实际上旧口令仍然有效——这是**安全承诺与事实
   * 不符**，必须让调用方能把它报出来，不能假装成功。
   */
  _purgeBackups() {
    const p = this.vaultPath;
    const failed = [];
    const rm = (f) => {
      try { fs.unlinkSync(f); }
      catch (e) {
        // ENOENT 说明本来就没有，是正常情况（首次创建、或已被清理过）
        if (e && e.code === 'ENOENT') return;
        failed.push(path.basename(f));
      }
    };
    for (let n = 1; n <= BACKUP_COUNT; n++) rm(p + '.bak.' + n);
    // .bak.stage 里是「这次写入之前」那一代主文件的完整副本，也就是
    // **旧口令 / 旧恢复密钥包裹的 DEK**。正常路径 _atomicWrite 会把它删掉，
    // 但如果轮转过程中进程被杀，它就会留下来——那是一个绕过本次清除的
    // 旧 KEK 副本，前向安全的漏洞和留着旧 .bak 一模一样，必须一并清。
    rm(p + '.bak.stage');
    rm(p + '.bak.1.tmp');
    // 带 pid 的 stage / tmp 是同一类东西（上一代主文件的完整密文副本）。
    // 只清"持有者确定已死"的：另一个实例正在写的 stage 是它下一次 rename
    // 的源文件，清掉它等于让那个实例的一次保存失败。
    this._cleanupStaleTmpFiles();
    return failed;
  }

  /** 重新生成恢复密钥（需要当前口令确认身份） */
  regenerateRecovery(passphrase) {
    this._checkThrottle();
    if (!this.exists()) throw fail('NOT_FOUND', '尚未创建密钥库');
    if (this._dek === null) throw fail('LOCKED', '密钥库已锁定');

    const meta = this._readMeta();

    // 验证口令
    try {
      const kek = this._derive(String(passphrase == null ? '' : passphrase), meta.kdf.saltPass, meta.kdf);
      try {
        const dek = aesGcmDecrypt(kek, meta.wraps.pass.iv, meta.wraps.pass.ct,
          this._wrapAad('pass', meta.kdf.saltPass), null);
        dek.fill(0);
      } finally {
        kek.fill(0);
      }
    } catch {
      this._recordFailure();
      throw fail('BAD_PASSPHRASE', '口令不正确');
    }

    const plain = aesGcmDecrypt(
      this._dek, meta.data.iv, meta.data.ct, this._dataAad(meta),
      fail('INTERNAL', '数据解密失败，vault.enc 可能已损坏')
    ).toString('utf8');

    const recoveryKey = generateRecoveryKey();
    const recoveryNorm = normalizeRecoveryKey(recoveryKey);
    const saltRecovery = b64(crypto.randomBytes(SALT_LEN));
    // 同 changePassphrase：必须用文件里声明的 KDF 参数，不能用进程默认值
    const kekRec = this._derive(recoveryNorm, saltRecovery, meta.kdf);

    meta.kdf.saltRecovery = saltRecovery;
    meta.wraps.recovery = aesGcmEncrypt(kekRec, this._dek, this._wrapAad('recovery', saltRecovery));
    kekRec.fill(0);

    meta.data = aesGcmEncrypt(this._dek, Buffer.from(plain, 'utf8'), this._dataAad(meta));
    meta.updatedAt = new Date().toISOString();
    // 恢复槽刚重写过，指纹要跟着更新，否则下次改口令会被误判成"槽被改坏"
    meta.recoveryCheck = _recoveryFingerprint(meta);

    // 落盘 + 自检，失败回滚。这里尤其重要：新恢复密钥已经在内存里生成了，
    // 如果写坏了而旧槽又被覆盖，用户会同时失去旧恢复密钥（文件里已变）和
    // 新恢复密钥（异常导致没返回）——恢复通道彻底死亡。
    const snap = this._snapshotForRollback();
    try {
      this._atomicWrite(JSON.stringify(meta, null, 2));
      this._verifyWritten(plain, recoveryNorm, 'recovery');
      // 口令槽必须仍然可用
      this._verifyWritten(plain, passphrase, 'pass');
    } catch (e) {
      const restored = this._rollback(snap);
      throw fail('INTERNAL',
        '更换恢复密钥失败' + (restored ? '，已回滚（旧恢复密钥仍可用）'
                                      : '，且回滚失败——请立即用当前口令解锁并检查'));
    }
    this._discardSnapshot(snap);

    // 旧备份里包裹的是旧恢复密钥/旧口令派生的 KEK，留着重开当前数据
    const staleBackups = this._purgeBackups();

    this._meta = meta;
    this._resetFailures();
    this._touch();
    return { recoveryKey, staleBackups };
  }

  /** 给 backup.info 用：上一代备份的路径与时间 */
  backupInfo() {
    const out = [];
    for (let n = 1; n <= BACKUP_COUNT; n++) {
      const p = this.vaultPath + '.bak.' + n;
      let st = null;
      try { st = fs.statSync(p); } catch { /* 不存在 */ }
      if (st) out.push({ n, path: p, size: st.size, mtime: st.mtime.toISOString() });
    }
    return out;
  }
}

module.exports = {
  KeyStore,
  generateRecoveryKey,
  normalizeRecoveryKey,
  parseVaultFile,
  // 暴露给测试和别处复用（导出包也用同一把尺子量口令）
  checkPassphrase,
  // 暴露给测试用，避免测试里再抄一份参数
  KDF,
  FORMAT,
  DEFAULT_IDLE_SEC,
  MIN_PASSPHRASE,
  THROTTLE_AFTER,
  THROTTLE_DELAYS_MS,
  WRAP_CT_LEN,
};
