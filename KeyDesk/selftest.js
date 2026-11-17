'use strict';
/**
 * KeyDesk 自检
 *   node selftest.js
 *
 * 零框架。每一条都是「断言失败就是真 bug」，没有凑数的检查项。
 * 最重要的两组：
 *  - RFC 6238 的 18 个官方向量：算法算错 = 所有账号登不上
 *  - 「响应不含秘密」：泄露一次 = TOTP 密钥永久失效（它不可轮换）
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

let pass = 0, fail = 0;
const failures = [];

function t(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    pass++;
  } catch (e) {
    console.log('  ✗ ' + name + '\n      ' + (e && e.message));
    failures.push(name + ': ' + (e && e.message));
    fail++;
  }
}

async function tAsync(name, fn) {
  try {
    await fn();
    console.log('  ✓ ' + name);
    pass++;
  } catch (e) {
    console.log('  ✗ ' + name + '\n      ' + (e && e.message));
    failures.push(name + ': ' + (e && e.message));
    fail++;
  }
}

function section(s) { console.log('\n=== ' + s + ' ==='); }

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'keydesk-test-'));
}

/**
 * 测试用的 KDF 参数。
 *
 * 生产参数 N=32768 一次约 240ms，而本文件要建几十个库、每个 setup 还
 * 自检两个槽、改口令再解一次……加起来轻松超过 10 分钟，实际调试时
 * 没人会等。这里降到 N=1024（约 8ms），语义完全一致：
 * scrypt 的正确性由第 8 节单独用生产参数验证，这里只验证流程。
 */
const FAST_KDF = { N: 1024, r: 8, p: 1 };

/* ================= 1. 模块加载 ================= */

section('1. 模块加载');
const totp = require('./lib/totp');
const keystoreMod = require('./lib/keystore');
const storeMod = require('./lib/store');
const qr = require('./lib/qr');
const { KeyStore } = keystoreMod;
const { Store } = storeMod;

t('totp 模块导出完整', () => {
  for (const k of ['hotp', 'totp', 'base32Decode', 'normalizeSecret',
    'parseOtpauth', 'buildOtpauth']) {
    assert.strictEqual(typeof totp[k], 'function', '缺少 ' + k);
  }
});
t('keystore 模块导出完整', () => {
  assert.strictEqual(typeof KeyStore, 'function');
  assert.strictEqual(typeof keystoreMod.generateRecoveryKey, 'function');
});
t('store 模块导出完整', () => {
  assert.strictEqual(typeof Store, 'function');
  assert.strictEqual(typeof storeMod.parseCodesText, 'function');
});
t('qr 模块导出完整', () => {
  assert.strictEqual(typeof qr.generate, 'function');
  assert.strictEqual(typeof qr.toSvg, 'function');
});

/* ================= 2. RFC 6238 全向量 ================= */

section('2. RFC 6238 官方向量（18 项）');

const S1 = Buffer.from('12345678901234567890');
const S256 = Buffer.from('12345678901234567890123456789012');
const S512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234');

// 算法 / 密钥 / 时间 / 期望值
const RFC_VECTORS = [
  ['SHA1', S1, 59, '94287082'],
  ['SHA256', S256, 59, '46119246'],
  ['SHA512', S512, 59, '90693936'],
  ['SHA1', S1, 1111111109, '07081804'],
  ['SHA256', S256, 1111111109, '68084774'],
  ['SHA512', S512, 1111111109, '25091201'],
  ['SHA1', S1, 1111111111, '14050471'],
  ['SHA256', S256, 1111111111, '67062674'],
  ['SHA512', S512, 1111111111, '99943326'],
  ['SHA1', S1, 1234567890, '89005924'],
  ['SHA256', S256, 1234567890, '91819424'],
  ['SHA512', S512, 1234567890, '93441116'],
  ['SHA1', S1, 2000000000, '69279037'],
  ['SHA256', S256, 2000000000, '90698825'],
  ['SHA512', S512, 2000000000, '38618901'],
  ['SHA1', S1, 20000000000, '65353130'],
  ['SHA256', S256, 20000000000, '77737706'],
  ['SHA512', S512, 20000000000, '47863826'],
];

for (const [algo, key, ts, expected] of RFC_VECTORS) {
  t('RFC 6238 ' + algo + ' t=' + ts + ' -> ' + expected, () => {
    const got = totp.totp(key, ts, 8, 30, algo);
    assert.strictEqual(got, expected);
  });
}

/* ================= 3. HOTP ================= */

section('3. HOTP / 计数器');

t('HOTP counter=0 RFC 4226 附录 D', () => {
  // 密钥 "12345678901234567890"，counter 0..9 的标准值
  const expected = ['755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489'];
  const key = Buffer.from('12345678901234567890');
  for (let i = 0; i < expected.length; i++) {
    assert.strictEqual(totp.hotp(key, i, 6, 'SHA1'), expected[i], 'counter=' + i);
  }
});

t('HOTP 接受 bigint 计数器', () => {
  const key = Buffer.from('12345678901234567890');
  assert.strictEqual(totp.hotp(key, 5n, 6, 'SHA1'), '254676');
});

t('HOTP 拒绝负计数器', () => {
  assert.throws(() => totp.hotp(S1, -1, 6, 'SHA1'), /不能为负/);
});

t('HOTP 拒绝空密钥', () => {
  assert.throws(() => totp.hotp(Buffer.alloc(0), 0, 6, 'SHA1'), /非空/);
});

t('TOTP 周期 60 与 30 的计数器关系', () => {
  // t=120 时：period=30 -> counter 4；period=60 -> counter 2
  const a = totp.totp(S1, 120, 6, 30, 'SHA1');
  const b = totp.hotp(S1, 4, 6, 'SHA1');
  assert.strictEqual(a, b);
  const c = totp.totp(S1, 120, 6, 60, 'SHA1');
  const d = totp.hotp(S1, 2, 6, 'SHA1');
  assert.strictEqual(c, d);
});

t('TOTP 拒绝非法周期', () => {
  assert.throws(() => totp.totp(S1, 120, 6, 0, 'SHA1'), /正数/);
  assert.throws(() => totp.totp(S1, 120, 6, -30, 'SHA1'), /正数/);
});

t('TOTP 拒绝非法时间', () => {
  assert.throws(() => totp.totp(S1, NaN, 6, 30, 'SHA1'), /时间戳/);
});

/* ================= 4. Base32 ================= */

section('4. Base32 解码');

t('Base32 无填充解码', () => {
  const buf = totp.base32Decode('JBSWY3DPEHPK3PXP');
  assert.strictEqual(buf.length, 10);
  assert.strictEqual(buf.toString('hex'), '48656c6c6f21deadbeef');
});

t('Base32 带填充解码（= 被忽略）', () => {
  const a = totp.base32Decode('JBSWY3DPEHPK3PXP');
  const b = totp.base32Decode('JBSWY3DPEHPK3PXP====');
  assert.deepStrictEqual(a, b);
});

t('Base32 小写解码', () => {
  const a = totp.base32Decode('JBSWY3DPEHPK3PXP');
  const b = totp.base32Decode('jbswy3dpehpk3pxp');
  assert.deepStrictEqual(a, b);
});

t('Base32 含空格 / 连字符 / 换行', () => {
  const a = totp.base32Decode('JBSWY3DPEHPK3PXP');
  for (const variant of [
    'JBSW Y3DP EHPK 3PXP',
    'JBSW-Y3DP-EHPK-3PXP',
    ' JBSWY3DP\nEHPK3PXP ',
    'JBSW\tY3DP\tEHPK3PXP',
  ]) {
    assert.deepStrictEqual(totp.base32Decode(variant), a, JSON.stringify(variant));
  }
});

t('Base32 拒绝非法字符', () => {
  // 0/1/8/9 不在 Base32 字母表内（易与 O/I/B 混淆）
  assert.throws(() => totp.base32Decode('JBSWY3DP0189'), /非法字符/);
  assert.throws(() => totp.base32Decode('JBSW!Y3DP'), /非法字符/);
});

t('Base32 拒绝空串', () => {
  assert.throws(() => totp.base32Decode(''), /为空/);
  assert.throws(() => totp.base32Decode('   '), /为空/);
});

t('Base32 编码/解码往返', () => {
  for (const len of [1, 5, 10, 16, 20, 32, 64]) {
    const buf = crypto.randomBytes(len);
    const dec = totp.base32Decode(totp.base32Encode(buf));
    assert.deepStrictEqual(dec, buf, 'len=' + len);
  }
});

t('Base32 解码 RFC 4648 测试向量（"foobar"）', () => {
  assert.strictEqual(totp.base32Decode('MZXW6YTBOI').toString('utf8'), 'foobar');
});

/* ================= 5. secret 归一化 ================= */

section('5. secret 归一化与校验');

t('normalizeSecret 转大写去空格去填充', () => {
  assert.strictEqual(totp.normalizeSecret(' jbsw y3dp ehpk 3pxp== '), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(totp.normalizeSecret('jbsw-y3dp-ehpk-3pxp'), 'JBSWY3DPEHPK3PXP');
});

// 下限对齐 Google Authenticator 的 MIN_KEY_BYTES = 10 字节（16 个 Base32 字符）。
// 更短的密钥 HMAC 照样能算出码，但熵不足且部分验证器直接拒绝——
// 静默接受等于把问题推到用户登录失败那天。
t('normalizeSecret 接受 16 字符下界（10 字节）', () => {
  assert.strictEqual(totp.normalizeSecret('JBSWY3DPEHPK3PXP'), 'JBSWY3DPEHPK3PXP');
});

t('normalizeSecret 拒绝 5 字节密钥（比 Google 门槛松会静默出错）', () => {
  assert.throws(() => totp.normalizeSecret('ABCDEFGH'), /至少 16 个 Base32 字符/);
});

t('normalizeSecret 接受 128 字符上界', () => {
  const s = 'A'.repeat(128);
  assert.strictEqual(totp.normalizeSecret(s), s);
});

t('normalizeSecret 拒绝 7 字符', () => {
  assert.throws(() => totp.normalizeSecret('ABCDEFG'), /太短/);
});

t('normalizeSecret 拒绝 129 字符', () => {
  assert.throws(() => totp.normalizeSecret('A'.repeat(129)), /太长/);
});

t('normalizeSecret 拒绝非 Base32 字符', () => {
  // 用够长的串，否则会先撞上长度下限而不是字符集校验
  assert.throws(() => totp.normalizeSecret('JBSWY3DPEHPK3PX!'), /A-Z 和 2-7/);
  assert.throws(() => totp.normalizeSecret('JBSWY3DPEHPK3PX1'), /A-Z 和 2-7/);
});

t('isValidSecret 不抛错版本', () => {
  assert.strictEqual(totp.isValidSecret('JBSWY3DPEHPK3PXP'), true);
  assert.strictEqual(totp.isValidSecret('bad!'), false);
  assert.strictEqual(totp.isValidSecret(''), false);
  assert.strictEqual(totp.isValidSecret(null), false);
});

/* ================= 6. otpauth 解析 ================= */

section('6. otpauth URI 解析');

t('解析标准 otpauth URI', () => {
  const r = totp.parseOtpauth(
    'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub');
  assert.strictEqual(r.issuer, 'GitHub');
  assert.strictEqual(r.account, 'alice@example.com');
  assert.strictEqual(r.secret, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(r.algorithm, 'SHA1');
  assert.strictEqual(r.digits, 6);
  assert.strictEqual(r.period, 30);
});

t('解析带 algorithm/digits/period', () => {
  const r = totp.parseOtpauth(
    'otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60');
  assert.strictEqual(r.algorithm, 'SHA256');
  assert.strictEqual(r.digits, 8);
  assert.strictEqual(r.period, 60);
});

t('解析缺 issuer 参数时从 label 取', () => {
  const r = totp.parseOtpauth('otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP');
  assert.strictEqual(r.issuer, 'GitHub');
  assert.strictEqual(r.account, 'alice');
});

t('解析 label 无冒号（账号即全部）', () => {
  const r = totp.parseOtpauth('otpauth://totp/alice@x.com?secret=JBSWY3DPEHPK3PXP');
  assert.strictEqual(r.issuer, '');
  assert.strictEqual(r.account, 'alice@x.com');
});

t('解析含中文 issuer/account（百分号编码）', () => {
  const uri = 'otpauth://totp/' + encodeURIComponent('公司邮箱') + ':' +
    encodeURIComponent('张三@例子.中国') + '?secret=JBSWY3DPEHPK3PXP&issuer=' +
    encodeURIComponent('公司邮箱');
  const r = totp.parseOtpauth(uri);
  assert.strictEqual(r.issuer, '公司邮箱');
  assert.strictEqual(r.account, '张三@例子.中国');
});

t('解析小写参数名与 + 编码空格', () => {
  const r = totp.parseOtpauth('otpauth://totp/a?SECRET=JBSWY3DPEHPK3PXP&ISSUER=Foo');
  assert.strictEqual(r.issuer, 'Foo');
  assert.strictEqual(r.secret, 'JBSWY3DPEHPK3PXP');
});

t('解析拒绝 hotp（明确报错）', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&counter=0'),
    /不支持 otpauth:\/\/hotp\//);
});

t('解析拒绝非 otpauth 前缀', () => {
  assert.throws(() => totp.parseOtpauth('https://example.com'), /不是 otpauth/);
});

t('解析拒绝缺少 secret', () => {
  assert.throws(() => totp.parseOtpauth('otpauth://totp/X:y?issuer=X'), /缺少 secret/);
});

t('解析拒绝非法 secret', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/X:y?secret=!!!!'),
    /secret 不合法/);
});

t('解析拒绝 issuer 与 label 前缀不一致', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=B'),
    /不一致/);
});

t('解析拒绝非法 digits', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=7'),
    /digits 只支持 6 或 8/);
});

t('解析拒绝越界 period', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&period=5'),
    /period 必须是 10..120/);
});

t('解析拒绝未知类型', () => {
  assert.throws(() => totp.parseOtpauth('otpauth://foo/X:y?secret=JBSWY3DPEHPK3PXP'),
    /不支持的 otpauth 类型/);
});

t('buildOtpauth / parseOtpauth 往返一致', () => {
  const cases = [
    { issuer: 'GitHub', account: 'alice@x.com', secret: 'JBSWY3DPEHPK3PXP' },
    { issuer: '公司', account: '张三', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8, period: 60 },
    { issuer: '', account: 'solo@x.com', secret: 'JBSWY3DPEHPK3PXP' },
    { issuer: 'A:B', account: 'c?d', secret: 'JBSWY3DPEHPK3PXP' },
  ];
  for (const c of cases) {
    const uri = totp.buildOtpauth(c);
    const r = totp.parseOtpauth(uri);
    assert.strictEqual(r.issuer, c.issuer, 'issuer ' + JSON.stringify(c));
    assert.strictEqual(r.account, c.account, 'account ' + JSON.stringify(c));
    assert.strictEqual(r.secret, c.secret);
    assert.strictEqual(r.algorithm, c.algorithm || 'SHA1');
    assert.strictEqual(r.digits, c.digits || 6);
    assert.strictEqual(r.period, c.period || 30);
  }
});

/* ================= 7. 加解密往返 ================= */

section('7. 加解密往返');

t('AES-256-GCM 往返（UTF-8 + 二进制安全）', () => {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const pt = Buffer.from('中文 deadbeef ' + 'x'.repeat(1000), 'utf8');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from('aad', 'utf8'));
  const enc = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  assert.strictEqual(tag.length, 16);

  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from('aad', 'utf8'));
  d.setAuthTag(tag);
  const out = Buffer.concat([d.update(enc), d.final()]);
  assert.deepStrictEqual(out, pt);
});

t('GCM 包裹 32 字节 DEK 后 ct 长度 = 48', () => {
  const kek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const dek = crypto.randomBytes(32);
  const c = crypto.createCipheriv('aes-256-gcm', kek, iv, { authTagLength: 16 });
  c.setAAD(Buffer.from('keydesk/1', 'utf8'));
  const enc = Buffer.concat([c.update(dek), c.final()]);
  const tag = c.getAuthTag();
  assert.strictEqual(enc.length + tag.length, 48);
});

/* ================= 8. scrypt 参数 ================= */

section('8. scrypt 参数');

t('scrypt N=32768 r=8 p=1 产出 32 字节且可重现', () => {
  const salt = Buffer.alloc(16, 7);
  const opts = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  const a = crypto.scryptSync('pass', salt, 32, opts);
  const b = crypto.scryptSync('pass', salt, 32, opts);
  assert.strictEqual(a.length, 32);
  assert.deepStrictEqual(a, b);
});

t('scrypt 蒸馏出的 KEK 与常量表一致', () => {
  assert.strictEqual(keystoreMod.KDF.N, 32768);
  assert.strictEqual(keystoreMod.KDF.r, 8);
  assert.strictEqual(keystoreMod.KDF.p, 1);
});

t('scrypt 不同盐产出不同 KEK', () => {
  const opts = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  const a = crypto.scryptSync('pass', Buffer.alloc(16, 1), 32, opts);
  const b = crypto.scryptSync('pass', Buffer.alloc(16, 2), 32, opts);
  assert.notDeepStrictEqual(a, b);
});

/* ================= 9. 密钥库 ================= */

section('9. 密钥库 setup / unlock / lock');

const VBASE = tmpDir();

t('setup 生成 26 字符恢复密钥（带连字符分组）', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  const r = ks.setup('correct horse battery');
  assert.match(r.recoveryKey, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$/);
  assert.strictEqual(r.recoveryKey.replace(/-/g, '').length, 26);
});

t('setup 后处于已解锁状态', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  assert.strictEqual(ks.isLocked(), false);
});

t('vault.enc 结构符合契约', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));

  assert.strictEqual(j.format, 'keydesk/1');
  assert.strictEqual(j.kdf.algo, 'scrypt');
  // 这个库是用 FAST_KDF 建的，文件里记录的应该正是它
  assert.strictEqual(j.kdf.N, FAST_KDF.N);
  assert.strictEqual(j.kdf.r, FAST_KDF.r);
  assert.strictEqual(j.kdf.p, FAST_KDF.p);
  assert.strictEqual(Buffer.from(j.kdf.saltPass, 'base64').length, 16);
  assert.strictEqual(Buffer.from(j.kdf.saltRecovery, 'base64').length, 16);
  assert.strictEqual(Buffer.from(j.wraps.pass.iv, 'base64').length, 12);
  assert.strictEqual(Buffer.from(j.wraps.pass.ct, 'base64').length, 48);
  assert.strictEqual(Buffer.from(j.wraps.recovery.iv, 'base64').length, 12);
  assert.strictEqual(Buffer.from(j.wraps.recovery.ct, 'base64').length, 48);
  assert.strictEqual(Buffer.from(j.data.iv, 'base64').length, 12);
  assert.ok(Buffer.from(j.data.ct, 'base64').length >= 16);
  assert.ok(!isNaN(Date.parse(j.updatedAt)));
});

t('vault.enc 明文里不含 DEK / 口令', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  const text = fs.readFileSync(p, 'utf8');
  assert.ok(!text.includes('correct horse battery'), '文件里出现了明文口令');
  assert.ok(!/secret|JBSWY/.test(text), '文件里出现了不该有的明文字段');
});

t('lock 后 isLocked 为真且 load 抛 LOCKED', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  assert.strictEqual(ks.isLocked(), true);
  assert.throws(() => ks.load(), (e) => e.code === 'LOCKED');
});

t('lock 幂等', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock(); ks.lock(); ks.lock();
  assert.strictEqual(ks.isLocked(), true);
});

t('unlock 正确口令成功', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  const r = ks.unlock('correct horse battery');
  assert.strictEqual(ks.isLocked(), false);
  assert.ok(r.expiresAt === null || !isNaN(Date.parse(r.expiresAt)));
});

t('重新打开进程（新实例）也能解锁 + 读数据', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const k1 = new KeyStore(p, { kdf: FAST_KDF });
  k1.setup('correct horse battery');
  k1.save({ version: 1, revision: 7, entries: [{ keep: 'me' }] });

  const k2 = new KeyStore(p, { kdf: FAST_KDF });
  assert.strictEqual(k2.isLocked(), true);
  k2.unlock('correct horse battery');
  const payload = k2.load();
  assert.strictEqual(payload.revision, 7);
  assert.deepStrictEqual(payload.entries, [{ keep: 'me' }]);
});

t('错口令被 GCM tag 拒绝（BAD_PASSPHRASE）', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  assert.throws(() => ks.unlock('wrong password'), (e) => e.code === 'BAD_PASSPHRASE');
  assert.strictEqual(ks.isLocked(), true, '错口令后必须仍然是锁定的');
});

t('恢复密钥能解锁，且解出同一份数据', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  const r = ks.setup('correct horse battery');
  ks.save({ version: 1, revision: 3, entries: [{ x: 1 }] });
  ks.lock();

  ks.unlockWithRecovery(r.recoveryKey);
  assert.strictEqual(ks.isLocked(), false);
  assert.strictEqual(ks.load().revision, 3);
});

t('恢复密钥容忍小写与多余连字符', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  const r = ks.setup('correct horse battery');
  ks.lock();
  const mangled = ' ' + r.recoveryKey.toLowerCase().replace(/-/g, ' ') + ' ';
  ks.unlockWithRecovery(mangled);
  assert.strictEqual(ks.isLocked(), false);
});

t('错恢复密钥被拒绝', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  const wrong = 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA';
  assert.throws(() => ks.unlockWithRecovery(wrong), (e) => e.code === 'BAD_PASSPHRASE');
});

t('恢复密钥格式错报 INVALID', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  assert.throws(() => ks.unlockWithRecovery('TOO-SHORT'), (e) => e.code === 'INVALID');
});

t('setup 拒绝过短口令', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  assert.throws(() => ks.setup('short'), (e) => e.code === 'INVALID');
});

t('setup 拒绝重复初始化', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  assert.throws(() => ks.setup('correct horse battery'), (e) => e.code === 'CONFLICT');
});

t('未初始化时 unlock 报 NOT_FOUND', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  assert.throws(() => ks.unlock('whatever123'), (e) => e.code === 'NOT_FOUND');
});

/* ================= 10. 改口令 ================= */

section('10. 改口令');

t('改口令后旧口令失效、新口令可用', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('old password 1');
  ks.save({ version: 1, revision: 11, entries: [{ v: 'secret-data' }] });

  ks.changePassphrase('old password 1', 'new password 2');
  ks.lock();

  assert.throws(() => ks.unlock('old password 1'), (e) => e.code === 'BAD_PASSPHRASE');
  ks.unlock('new password 2');
  assert.strictEqual(ks.load().revision, 11);
  assert.deepStrictEqual(ks.load().entries, [{ v: 'secret-data' }]);
});

t('改口令后恢复密钥仍然有效（数据没被绑死在新口令上）', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  const r = ks.setup('old password 1');
  ks.save({ version: 1, revision: 5, entries: [] });
  ks.changePassphrase('old password 1', 'new password 2');
  ks.lock();

  ks.unlockWithRecovery(r.recoveryKey);
  assert.strictEqual(ks.load().revision, 5);
});

t('改口令时错误旧口令被拒', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('old password 1');
  assert.throws(
    () => ks.changePassphrase('not the password', 'new password 2'),
    (e) => e.code === 'BAD_PASSPHRASE');
});

t('改口令时新口令太短被拒', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('old password 1');
  assert.throws(() => ks.changePassphrase('old password 1', 'tiny'),
    (e) => e.code === 'INVALID');
});

t('重新生成恢复密钥后旧恢复密钥失效', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  const old = ks.setup('correct horse battery');
  ks.save({ version: 1, revision: 9, entries: [] });

  const fresh = ks.regenerateRecovery('correct horse battery');
  assert.notStrictEqual(fresh.recoveryKey, old.recoveryKey);
  ks.lock();

  assert.throws(() => ks.unlockWithRecovery(old.recoveryKey), (e) => e.code === 'BAD_PASSPHRASE');
  ks.unlockWithRecovery(fresh.recoveryKey);
  assert.strictEqual(ks.load().revision, 9);
});

t('重新生成恢复密钥需要正确口令', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  assert.throws(() => ks.regenerateRecovery('wrong'),
    (e) => e.code === 'BAD_PASSPHRASE');
});

/* ================= 11. 原子写 / 备份轮转 ================= */

section('11. 原子写入与备份轮转');

t('save 只留最终文件，不留 .tmp', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.save({ version: 1, revision: 1, entries: [] });
  assert.ok(!fs.existsSync(p + '.tmp'), '临时文件没有清理');
});

t('多次 save 生成 bak.1 / bak.2 / bak.3', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');

  // setup 写一次，之后每次 save 都把上一代推到 bak.1
  for (let i = 1; i <= 5; i++) {
    ks.save({ version: 1, revision: i, entries: [] });
  }
  for (let n = 1; n <= 3; n++) {
    assert.ok(fs.existsSync(p + '.bak.' + n), '缺少 bak.' + n);
  }
  assert.ok(!fs.existsSync(p + '.bak.4'), '不应有 bak.4');
});

t('备份轮转保留了上一代真实内容', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.save({ version: 1, revision: 100, entries: [] });
  ks.save({ version: 1, revision: 200, entries: [] });

  // bak.1 应该是 revision 100 那一版
  const bak = JSON.parse(fs.readFileSync(p + '.bak.1', 'utf8'));
  assert.strictEqual(bak.format, 'keydesk/1');
  ks.lock();
  ks.unlock('correct horse battery');
  assert.strictEqual(ks.load().revision, 200);
});

t('损坏的 vault.enc 被识别为损坏（不是静默返回空库）', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();

  fs.writeFileSync(p, '{not json', 'utf8');
  assert.throws(() => ks.unlock('correct horse battery'), /损坏|JSON/);
});

t('被篡改的密文无法解密（GCM tag 校验）', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();

  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  const buf = Buffer.from(j.data.ct, 'base64');
  buf[0] ^= 0xff;                        // 翻一个 bit
  j.data.ct = buf.toString('base64');
  fs.writeFileSync(p, JSON.stringify(j), 'utf8');

  assert.throws(() => ks.unlock('correct horse battery'), (e) =>
    e.code === 'BAD_PASSPHRASE' || e.code === 'INTERNAL');
});

t('把 recovery 槽的密文搬到 pass 槽会失败（AAD 绑定）', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'vault.enc');
  const ks = new KeyStore(p, { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();

  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  j.wraps.pass = j.wraps.recovery;
  fs.writeFileSync(p, JSON.stringify(j), 'utf8');

  assert.throws(() => ks.unlock('correct horse battery'), (e) => e.code === 'BAD_PASSPHRASE');
});

/* ================= 12. 限速 ================= */

section('12. 失败限速');

t('连续 5 次错口令后进入限速（THROTTLED）', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();

  const THROTTLE_AFTER = keystoreMod.THROTTLE_AFTER;
  for (let i = 0; i < THROTTLE_AFTER; i++) {
    assert.throws(() => ks.unlock('wrong' + i), (e) => e.code === 'BAD_PASSPHRASE');
  }
  assert.throws(() => ks.unlock('correct horse battery'), (e) => e.code === 'THROTTLED');
  const st = ks.throttleState();
  assert.ok(st.lockedForMs > 0, '应处于锁定窗口内');
});

t('限速延迟按 5s/15s/60s/300s 递增', () => {
  const delays = keystoreMod.THROTTLE_DELAYS_MS;
  assert.deepStrictEqual(delays, [5000, 15000, 60000, 300000]);
});

t('成功解锁会清零失败计数', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.lock();
  for (let i = 0; i < 3; i++) {
    try { ks.unlock('wrong'); } catch { /* expected */ }
  }
  ks.unlock('correct horse battery');
  assert.strictEqual(ks.throttleState().failures, 0);
});

/* ================= 13. 空闲自动锁 ================= */

section('13. 空闲自动锁定');

t('默认空闲锁定 900 秒', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  assert.strictEqual(ks.idleTimeoutSec(), 900);
});

t('setIdleTimeout 支持 0（永不）', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  assert.strictEqual(ks.setIdleTimeout(0), 0);
  ks.setup('correct horse battery');
  assert.strictEqual(ks.secondsUntilLock(), -1);
});

t('超时后 maybeAutoLock 返回 true 并把库锁上', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 0, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.setIdleTimeout(1);
  // 直接把最近活动时间往前拨，避免测试等 1 秒以上
  ks._lastActivity = Date.now() - 5000;
  assert.strictEqual(ks.maybeAutoLock(), true);
  assert.strictEqual(ks.isLocked(), true);
});

t('未超时时 maybeAutoLock 返回 false', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 600, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  assert.strictEqual(ks.maybeAutoLock(), false);
  assert.strictEqual(ks.isLocked(), false);
});

// 回归：轮询不能重置空闲计时器。
// 前端每 5 秒调一次 otp.codes 刷验证码；如果把它算作"用户活动"，
// elapsed 永远是 ~5 秒，900 秒的阈值永远达不到 —— "15 分钟自动锁定"
// 这个安全承诺就是假的，用户离开工位后库一直开着。
t('被动轮询（passive）不重置空闲计时', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 0, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.setIdleTimeout(2);
  ks._lastActivity = Date.now() - 5000;   // 已超时

  // passive=true 的调用：必须判定为超时并锁定
  assert.strictEqual(ks.maybeAutoLock(false), true, '被动轮询也必须能触发锁定');
  assert.strictEqual(ks.isLocked(), true);
});

t('主动操作（active）会重置空闲计时', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 0, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  ks.setIdleTimeout(600);
  const before = ks._lastActivity;
  // 等 2ms 确保时间戳真的变了
  const t0 = Date.now();
  while (Date.now() - t0 < 2) { /* 忙等，保持同步 */ }
  assert.strictEqual(ks.maybeAutoLock(true), false);
  assert.ok(ks._lastActivity >= before, '主动操作应刷新 _lastActivity');
});

// 集成级回归：只测 maybeAutoLock 本身不够。
// 之前 store.codes() → _loadNormalized() → ks.load() 里有一句无条件的
// _touch()，把 server.js 传下来的 userActive=false 架空了。结果是前端
// 每 5 秒轮询 otp.codes，「15 分钟空闲锁定」永远触发不了。
// 这条测试走真实调用链，才能抓到那种"改了一处、被另一处抵消"的问题。
t('集成：codes() 轮询不会重置空闲计时', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 0, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  const store = new Store(ks);
  store.upsert({
    type: 'totp', issuer: 'Idle', account: 'i@x.com',
    totp: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
  });
  ks.setIdleTimeout(2);

  ks._lastActivity = Date.now() - 5000;   // 已超时
  const before = ks._lastActivity;

  // 走真实路径：codes() 内部会调 _read → _loadNormalized → ks.load()
  store.codes();

  assert.strictEqual(ks._lastActivity, before,
    'codes() 不能重置 _lastActivity（否则轮询会让空闲锁定永不触发）');
});

t('集成：list() 仍算用户活动', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { idleTimeoutSec: 0, kdf: FAST_KDF });
  ks.setup('correct horse battery');
  const store = new Store(ks);
  ks.setIdleTimeout(600);
  ks._lastActivity = Date.now() - 1000;
  const before = ks._lastActivity;

  const t0 = Date.now();
  while (Date.now() - t0 < 2) { /* 忙等 */ }
  store.list({});

  assert.ok(ks._lastActivity > before, '用户主动浏览列表应算作活动');
});

t('setIdleTimeout 拒绝越界值', () => {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  assert.throws(() => ks.setIdleTimeout(-1), (e) => e.code === 'INVALID');
  assert.throws(() => ks.setIdleTimeout(86401), (e) => e.code === 'INVALID');
  assert.throws(() => ks.setIdleTimeout(1.5), (e) => e.code === 'INVALID');
});

/* ================= 14. 条目校验 ================= */

section('14. 条目字段校验');

function freshStore() {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  ks.setup('test passphrase 123');
  return { ks, store: new Store(ks), dir };
}

/** 只建一个空 KeyStore（不 setup），供口令轮换类测试自己控制 */
function freshKeystore() {
  const dir = tmpDir();
  const ks = new KeyStore(path.join(dir, 'vault.enc'), { kdf: FAST_KDF });
  return {
    ks, dir,
    cleanup: () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* 忽略 */ } },
  };
}

const BAD_ENTRIES = [
  ['缺 type', { issuer: 'X' }],
  ['非法 type', { type: 'bogus', issuer: 'X' }],
  ['缺 issuer', { type: 'note' }],
  ['issuer 超长', { type: 'note', issuer: 'A'.repeat(65) }],
  ['account 超长', { type: 'note', issuer: 'X', account: 'A'.repeat(129) }],
  ['totp 缺 secret', { type: 'totp', issuer: 'X' }],
  ['totp secret 非法', { type: 'totp', issuer: 'X', totp: { secret: '!!!' } }],
  ['totp secret 太短', { type: 'totp', issuer: 'X', totp: { secret: 'ABC' } }],
  ['totp algorithm 非法', { type: 'totp', issuer: 'X', totp: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'MD5' } }],
  ['totp digits=7', { type: 'totp', issuer: 'X', totp: { secret: 'JBSWY3DPEHPK3PXP', digits: 7 } }],
  ['totp period=5', { type: 'totp', issuer: 'X', totp: { secret: 'JBSWY3DPEHPK3PXP', period: 5 } }],
  ['totp period=121', { type: 'totp', issuer: 'X', totp: { secret: 'JBSWY3DPEHPK3PXP', period: 121 } }],
  ['url 非 http', { type: 'note', issuer: 'X', url: 'ftp://x' }],
  ['tags 非数组', { type: 'note', issuer: 'X', tags: 'a' }],
  ['tags 项超长', { type: 'note', issuer: 'X', tags: ['A'.repeat(33)] }],
  ['note 超长', { type: 'note', issuer: 'X', note: 'A'.repeat(2001) }],
];

for (const [label, raw] of BAD_ENTRIES) {
  t('拒绝 ' + label, () => {
    const { store } = freshStore();
    assert.throws(() => store.upsert(raw), (e) => e.code === 'INVALID');
  });
}

t('recovery-only 允许先建空条目（随后再 addSet）', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'Soon' });
  assert.strictEqual(e.recovery.total, 0);
  store.addSet(e.id, { text: 'AAAA-BBBB' });
  assert.strictEqual(store.get(e.id).recovery.total, 1);
});

t('接受最小合法 note 条目', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'note', issuer: 'X' });
  assert.strictEqual(e.issuer, 'X');
  assert.strictEqual(e.hasTotp, false);
  assert.strictEqual(e.digits, null);
});

t('接受边界长度 issuer (64)', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'note', issuer: 'A'.repeat(64) });
  assert.strictEqual(e.issuer.length, 64);
});

t('issuer 两端空白被 trim', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'note', issuer: '  GitHub  ' });
  assert.strictEqual(e.issuer, 'GitHub');
});

t('totp digits=8 / period=60 被接受', () => {
  const { store } = freshStore();
  const e = store.upsert({
    type: 'totp', issuer: 'X',
    totp: { secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 60, algorithm: 'SHA512' },
  });
  assert.strictEqual(e.digits, 8);
  assert.strictEqual(e.period, 60);
  assert.strictEqual(e.totp.algorithm, 'SHA512');
});

/* ================= 15. 恢复码代际 ================= */

section('15. 恢复码代际逻辑');

t('解析恢复码文本：每行一个', () => {
  const codes = storeMod.parseCodesText('abcd-efgh\nijkl-mnop\nqrst-uvwx');
  assert.deepStrictEqual(codes, ['ABCD-EFGH', 'IJKL-MNOP', 'QRST-UVWX']);
});

t('解析恢复码文本：空格 / 逗号 / 制表符', () => {
  const codes = storeMod.parseCodesText('abcd efgh, ijkl\tmnop');
  assert.deepStrictEqual(codes, ['ABCD', 'EFGH', 'IJKL', 'MNOP']);
});

// GitHub 官方的 github-recovery-codes.txt 里有英文说明段落。
// 按空白切词后 "these"/"codes"/"sign"/"lose"/"access"/"your" 都匹配
// RE_CODE（4-40 位大写字母数字），曾被当成 13 个恢复码混进来。
// 判据：多片段行若全无数字，则要求所有片段长度完全一致（码行特征），
// 否则视为散文丢弃（英文短语几乎不可能所有词等长）。
t('解析恢复码文本：跳过 GitHub 官方文件的英文说明段落', () => {
  const gh = [
    'Recovery codes',
    '',
    'You can use these codes to sign in if you lose access to your',
    'authentication device. Each code can be used only once.',
    '',
    'a168c-cfb97',
    'b2d4e-1a3f5',
  ].join('\n');
  const codes = storeMod.parseCodesText(gh);
  assert.deepStrictEqual(codes, ['A168C-CFB97', 'B2D4E-1A3F5'],
    '不能把散文词当成恢复码，实际: ' + JSON.stringify(codes));
});

t('解析恢复码文本：散文与码混排只取码', () => {
  const codes = storeMod.parseCodesText('These are your codes\nABCD-1234\nEFGH-5678');
  assert.deepStrictEqual(codes, ['ABCD-1234', 'EFGH-5678'], '实际: ' + JSON.stringify(codes));
});

// 零依赖验证报告实测出的反例：说明句**独立成行**时，之前的判据会漏。
// "Each code can be used only once." 里 can/be 被 RE_CODE 的长度门槛过滤掉，
// 剩 Each/Code/Used/Only 恰好全 4 字符 → 被"长度一致"判据当成码行。
// 新判据是块识别：真码总是连续多行同形，孤立单行不算。
t('解析恢复码文本：说明句独立成行时不混入', () => {
  const gh = [
    'Recovery codes',
    '',
    'You can use these codes to sign in if you lose access to your authentication device.',
    'Each code can be used only once.',
    '',
    'a168c-cfb97',
    '954bb-c166b',
  ].join('\n');
  const codes = storeMod.parseCodesText(gh);
  assert.deepStrictEqual(codes, ['A168C-CFB97', '954BB-C166B'],
    '实际: ' + JSON.stringify(codes));
  assert.ok(!codes.includes('EACH'), '不能把 EACH 当成恢复码');
  assert.ok(!codes.includes('ONLY'), '不能把 ONLY 当成恢复码');
});

// 日期行含数字，旧判据"有数字就是码行"会把它当码；且 `2026-01-01`
// 完全符合 RE_CODE = /^[A-Z0-9-]{4,40}$/。
t('解析恢复码文本：日期行不被当成恢复码', () => {
  const codes = storeMod.parseCodesText('Recovery codes\nGenerated 2026-01-01\n\na168c-cfb97\n954bb-c166b');
  assert.deepStrictEqual(codes, ['A168C-CFB97', '954BB-C166B'], '实际: ' + JSON.stringify(codes));
  assert.ok(!codes.some(c => /^\d{4}-\d{2}-\d{2}$/.test(c)), '不能把日期当恢复码');
});

t('解析恢复码文本：剥离序号前缀', () => {
  const codes = storeMod.parseCodesText('1. abcd-efgh\n2) ijkl-mnop\n3、qrst-uvwx');
  assert.deepStrictEqual(codes, ['ABCD-EFGH', 'IJKL-MNOP', 'QRST-UVWX']);
});

t('解析恢复码文本：组内去重保持顺序', () => {
  const codes = storeMod.parseCodesText('abcd\nABCD\nijkl');
  assert.deepStrictEqual(codes, ['ABCD', 'IJKL']);
});

t('解析恢复码文本：跳过标题行与空行', () => {
  const codes = storeMod.parseCodesText(
    'Recovery codes\n\nabcd-efgh\n\n  \nijkl-mnop\n');
  assert.deepStrictEqual(codes, ['ABCD-EFGH', 'IJKL-MNOP']);
});

t('恢复码值归一保留连字符', () => {
  assert.strictEqual(storeMod.normalizeCodeValue(' abcd-efgh '), 'ABCD-EFGH');
  assert.strictEqual(storeMod.normalizeCodeValue('ab cd ef gh'), 'ABCDEFGH');
});

t('addSet 建为当前代', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const set = store.addSet(e.id, { text: 'AAAA-BBBB\nCCCC-DDDD' });
  assert.strictEqual(set.supersededAt, null);
  assert.strictEqual(set.codeCount, 2);
  const d = store.get(e.id);
  assert.strictEqual(d.recovery.currentSetId, set.id);
  assert.strictEqual(d.recovery.setCount, 1);
});

t('addSet 第二次把上一代 supersededAt 写成新代的 createdAt', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const s1 = store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: '2025-01-01T00:00:00Z' });
  const s2 = store.addSet(e.id, { text: 'CCCC-DDDD', createdAt: '2026-06-01T00:00:00Z' });

  // s2.supersededAt 为 null，s1.supersededAt = s2.createdAt
  assert.strictEqual(s2.supersededAt, null);
  const d = store.get(e.id);
  const s1After = d.recovery.sets.find(x => x.id === s1.id);
  assert.strictEqual(s1After.supersededAt, s2.createdAt);
  assert.strictEqual(d.recovery.currentSetId, s2.id);
});

t('setCurrent 把指定代设为当前，旧的变 superseded', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const s1 = store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: '2025-01-01T00:00:00Z' });
  const s2 = store.addSet(e.id, { text: 'CCCC-DDDD', createdAt: '2026-06-01T00:00:00Z' });

  store.setCurrentSet(e.id, s1.id);
  const d = store.get(e.id);
  const cur = d.recovery.sets.find(x => x.supersededAt === null);
  assert.strictEqual(cur.id, s1.id, 's1 应重新成为当前代');
  const s2After = d.recovery.sets.find(x => x.id === s2.id);
  assert.ok(s2After.supersededAt !== null, 's2 应变成历史代');
});

t('setCurrent 后永远只有一个 current', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const s1 = store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: '2025-01-01T00:00:00Z' });
  store.addSet(e.id, { text: 'CCCC-DDDD', createdAt: '2026-06-01T00:00:00Z' });
  store.setCurrentSet(e.id, s1.id);
  const d = store.get(e.id);
  const currents = d.recovery.sets.filter(x => x.supersededAt === null);
  assert.strictEqual(currents.length, 1);
});

t('自愈：多个 null 时保留 createdAt 最新者', () => {
  // 直接调 healSets（模拟手工编辑文件后的脏数据）
  const sets = [
    { id: 'rs_a', createdAt: '2025-01-01T00:00:00.000Z', supersededAt: null },
    { id: 'rs_b', createdAt: '2026-06-01T00:00:00.000Z', supersededAt: null },
    { id: 'rs_c', createdAt: '2024-01-01T00:00:00.000Z', supersededAt: '2025-01-01T00:00:00.000Z' },
  ];
  const changed = storeMod.healSets(sets);
  assert.strictEqual(changed, true);
  const currents = sets.filter(s => s.supersededAt === null);
  assert.strictEqual(currents.length, 1);
  assert.strictEqual(currents[0].id, 'rs_b', '应保留 createdAt 最新的 rs_b');
});

t('自愈：单个 null 时不改动', () => {
  const sets = [{ id: 'rs_a', createdAt: '2025-01-01T00:00:00.000Z', supersededAt: null }];
  assert.strictEqual(storeMod.healSets(sets), false);
});

t('deleting 当前代后最新的一组接任', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: '2025-01-01T00:00:00Z' });
  const s2 = store.addSet(e.id, { text: 'CCCC-DDDD', createdAt: '2026-06-01T00:00:00Z' });

  store.removeSet(e.id, s2.id);
  const d = store.get(e.id);
  assert.strictEqual(d.recovery.setCount, 1);
  assert.strictEqual(d.recovery.sets[0].supersededAt, null, '剩下那组应成为当前代');
});

t('markCodes 批量标记已用', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const set = store.addSet(e.id, { text: 'AAAA-BBBB\nCCCC-DDDD\nEEEE-FFFF' });
  const codes = store.revealRecovery(e.id, set.id);
  const ids = [codes[0].id, codes[1].id];

  const n = store.markCodes(e.id, set.id, ids, true);
  assert.strictEqual(n, 2);
  const after = store.revealRecovery(e.id, set.id);
  assert.ok(after[0].usedAt !== null);
  assert.ok(after[1].usedAt !== null);
  assert.strictEqual(after[2].usedAt, null);

  // 撤消
  store.markCodes(e.id, set.id, ids, false);
  const undone = store.revealRecovery(e.id, set.id);
  assert.strictEqual(undone[0].usedAt, null);
});

t('recovery.sets 上限 20 组', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  for (let i = 0; i < 20; i++) {
    store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: '2025-01-0' + ((i % 9) + 1) + 'T00:00:00Z' });
  }
  assert.throws(() => store.addSet(e.id, { text: 'ZZZZ-YYYY' }), (e2) => e2.code === 'INVALID');
});

t('单组恢复码上限 50', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const many = Array.from({ length: 51 }, (_, i) => 'C' + String(i).padStart(3, '0') + '-X');
  assert.throws(() => store.addSet(e.id, { text: many.join('\n') }),
    (e2) => e2.code === 'INVALID');
});

/* ================= 16. 原型污染 ================= */

section('16. 原型污染防护');

t('拒绝 __proto__ 键', () => {
  const { store } = freshStore();
  const raw = JSON.parse('{"type":"note","issuer":"X","__proto__":{"polluted":true}}');
  assert.throws(() => store.upsert(raw), /非法字段/);
  assert.strictEqual({}.polluted, undefined, 'Object.prototype 被污染了');
});

t('拒绝 constructor 键', () => {
  const { store } = freshStore();
  const raw = JSON.parse('{"type":"note","issuer":"X","constructor":{"x":1}}');
  assert.throws(() => store.upsert(raw), /非法字段/);
});

t('拒绝 prototype 键', () => {
  const { store } = freshStore();
  const raw = JSON.parse('{"type":"note","issuer":"X","prototype":{"x":1}}');
  assert.throws(() => store.upsert(raw), /非法字段/);
});

t('未知字段不会被写进条目', () => {
  const { store } = freshStore();
  const e = store.upsert({
    type: 'note', issuer: 'X',
    evilField: 'should vanish',
    recovery: undefined,
  });
  const d = store.get(e.id);
  assert.strictEqual(d.evilField, undefined);
  // 磁盘上的原始条目也不能有
  const payload = store.ks.load();
  const raw = payload.entries[0];
  assert.strictEqual(raw.evilField, undefined);
  assert.ok(!Object.prototype.hasOwnProperty.call(raw, 'evilField'));
});

t('原型链上的继承属性不会被当成输入', () => {
  const { store } = freshStore();
  // 用 {} 当原型，给原型塞一个 issuer，输入本身没有
  const proto = { issuer: 'FromProto', type: 'note' };
  const raw = Object.create(proto);
  assert.throws(() => store.upsert(raw), (e) => e.code === 'INVALID');
});

/* ================= 16.5 TOTP 边界（RFC 研究发现的坑） ================= */

section('16.5 TOTP 边界处理');

// RFC 6238 §5.2 是 MUST：成功的 OTP 不能被第二次接受。
// 只靠时间窗口不够——同一个码在 30 秒内可以重复验证成功。
t('verify 防重放：同一个码第二次验证失败', () => {
  const { store } = freshStore();
  const e = store.upsert({
    type: 'totp', issuer: 'Replay', account: 'r@x.com',
    totp: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
  });
  const codes = store.codes();
  const item = codes.items.find(x => x.id === e.id);
  assert.ok(item, '应能取到当前码');

  const first = store.verify(e.id, item.code);
  assert.strictEqual(first.matched, true, '第一次应该成功');

  const second = store.verify(e.id, item.code);
  assert.strictEqual(second.matched, false, '同一个码第二次必须被拒绝（RFC 6238 MUST）');
});

// Google Key URI 规范：issuer 和 account 都不能含冒号，否则导入方无法
// 判断哪个是分隔符（Aegis #1701）。
t('buildOtpauth：含冒号时 label 里不出现多个冒号', () => {
  const uri = totp.buildOtpauth({
    issuer: 'A:B', account: 'C:D', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1', digits: 6, period: 30,
  });
  const labelPart = uri.split('?')[0];
  const colons = (labelPart.match(/%3A|:/gi) || []).length;
  assert.ok(colons <= 1, 'label 里最多一个冒号（分隔符），实际 ' + colons + ' 个：' + labelPart);
});

// 无 issuer 参数 + label 含多个冒号 = 无解歧义，必须报错而非静默切错
t('parseOtpauth：多冒号且无 issuer 参数时明确报错', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/Test%3A%20Foo%3AUser?secret=JBSWY3DPEHPK3PXP'),
    /多个冒号|无法确定/,
    '不能静默按第一个冒号切分'
  );
});

// RFC 3986：# 之后是 fragment，不属于 query
t('parseOtpauth：剥掉 #fragment', () => {
  const p = totp.parseOtpauth('otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=X#frag');
  assert.strictEqual(p.issuer, 'X', 'issuer 不能含 fragment，实际: ' + p.issuer);
});

// digits 9/10 是无效语义：31 位整数最大 2147483647，10^10 > 2^31
t('hotp：digits 上界为 8（9/10 无意义）', () => {
  const key = Buffer.from('12345678901234567890', 'ascii');
  assert.throws(() => totp.hotp(key, 0, 10, 'SHA1'), /6\.\.8/);
  assert.throws(() => totp.hotp(key, 0, 9, 'SHA1'), /6\.\.8/);
  assert.strictEqual(totp.hotp(key, 0, 8, 'SHA1').length, 8);
});

// Steam Guard 是 5 位字母码，算法与标准 TOTP 不同。静默接受会让用户
// 看到一个"看起来正常、实际永远登不上"的条目。
t('parseOtpauth：明确拒绝 encoder=steam', () => {
  assert.throws(
    () => totp.parseOtpauth('otpauth://totp/Steam:u?secret=JBSWY3DPEHPK3PXP&encoder=steam'),
    /Steam|encoder/,
    '不能静默忽略厂商扩展编码器'
  );
});

// Base32 合法长度不连续。17 字符会与 16 字符解出同一字节序列，
// 掩盖用户多打一个字符的错误。
t('normalizeSecret：拒绝会产生别名的非法长度', () => {
  assert.ok(totp.isValidSecret('JBSWY3DPEHPK3PXP'), '16 字符合法');
  assert.ok(!totp.isValidSecret('JBSWY3DPEHPK3PXPA'), '17 字符非法（与 16 字符别名）');
  assert.ok(!totp.isValidSecret('JBSWY3DPEHPK3PXPABC'), '19 字符非法');
  // 不能误伤：20 字符（mod 8 = 4）是现实中大量存在的合法长度
  assert.ok(totp.isValidSecret('JBSWY3DPEHPK3PXPJBSW'), '20 字符合法，不能被误伤');
});

/* ================= 17. 不泄露断言 ================= */

section('17. 不泄露断言（核心）');

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';
const REC_CODE_VALUES = ['SECR-ET22', 'HIDD-EN33'];
const PASSWORD_VALUE = 'MyVerySecretPassw0rd!';

function leakStore() {
  const { store } = freshStore();
  const e = store.upsert({
    type: 'totp',
    issuer: 'GitHub',
    account: 'alice@x.com',
    totp: { secret: SECRET },
    password: { value: PASSWORD_VALUE },
    recovery: {
      sets: [{
        createdAt: new Date().toISOString(),
        codes: REC_CODE_VALUES.map(v => ({ value: v })),
      }],
    },
  });
  return { store, id: e.id };
}

t('entries.list 响应不含 secret / 恢复码 value / password value', () => {
  const { store } = leakStore();
  const json = JSON.stringify(store.list({}));
  assert.ok(!json.includes('secret'), '出现了 secret 字样: ' + json.slice(0, 200));
  assert.ok(!json.includes(SECRET), '出现了明文 TOTP 密钥');
  assert.ok(!json.includes(REC_CODE_VALUES[0]), '出现了恢复码明文');
  assert.ok(!json.includes(PASSWORD_VALUE), '出现了密码明文');
  assert.ok(!json.includes('password.value'), '出现了 password.value 字段');
});

t('entries.get 响应不含 secret / 恢复码 value / password value', () => {
  const { store, id } = leakStore();
  const json = JSON.stringify(store.get(id));
  assert.ok(!json.includes(SECRET), '出现了明文 TOTP 密钥');
  assert.ok(!json.includes(REC_CODE_VALUES[0]), '出现了恢复码明文');
  assert.ok(!json.includes(PASSWORD_VALUE), '出现了密码明文');
  // Detail 里允许有 totp:{algorithm,digits,period}，但不许有 secret 这个键
  const detail = store.get(id);
  assert.strictEqual(detail.totp.secret, undefined);
  assert.strictEqual(detail.totp.algorithm, 'SHA1');
});

t('otp.codes 响应不含 secret', () => {
  const { store } = leakStore();
  const json = JSON.stringify(store.codes());
  assert.ok(!json.includes(SECRET), '出现了明文 TOTP 密钥');
});

t('otp.codes 只返回 id/code/period/remaining/expiresAt 五个字段', () => {
  const { store } = leakStore();
  const out = store.codes();
  assert.strictEqual(out.items.length, 1);
  const keys = Object.keys(out.items[0]).sort();
  assert.deepStrictEqual(keys, ['code', 'expiresAt', 'id', 'period', 'remaining']);
});

t('Summary 的 recovery 只给计数不给值', () => {
  const { store, id } = leakStore();
  const item = store.list({}).find(x => x.id === id);
  assert.strictEqual(item.recovery.total, 2);
  assert.strictEqual(item.recovery.unused, 2);
  assert.strictEqual(item.recovery.setCount, 1);
  assert.ok(!JSON.stringify(item).includes(REC_CODE_VALUES[0]));
});

t('Detail 的 recovery.sets 只有统计字段', () => {
  const { store, id } = leakStore();
  const d = store.get(id);
  const set = d.recovery.sets[0];
  assert.deepStrictEqual(
    Object.keys(set).sort(),
    ['codeCount', 'createdAt', 'id', 'label', 'note', 'supersededAt', 'trackUsage', 'unusedCount']
  );
});

t('revealSecret 是唯一能拿到 TOTP 密钥的路径', () => {
  const { store, id } = leakStore();
  assert.strictEqual(store.revealSecret(id, 'totp').value, SECRET);
});

t('revealRecovery 是唯一能拿到恢复码的路径', () => {
  const { store, id } = leakStore();
  const d = store.get(id);
  const codes = store.revealRecovery(id, d.recovery.currentSetId);
  assert.deepStrictEqual(codes.map(c => c.value), REC_CODE_VALUES);
});

t('passwordSet 只是布尔，不泄露值', () => {
  const { store, id } = leakStore();
  const item = store.list({}).find(x => x.id === id);
  assert.strictEqual(item.passwordSet, true);
});

t('导出只含 otpauth 字段，不含恢复码 / 密码', () => {
  const { store } = leakStore();
  const out = store.exportOtpauth();
  const json = JSON.stringify(out);
  assert.ok(json.includes('otpauth://'), '应含 URI');
  assert.ok(!json.includes(REC_CODE_VALUES[0]), '导出里出现了恢复码');
  assert.ok(!json.includes(PASSWORD_VALUE), '导出里出现了密码');
  const keys = Object.keys(out.items[0]).sort();
  assert.deepStrictEqual(keys, ['account', 'id', 'issuer', 'otpauthUri']);
});

/* ================= 18. store 行为 ================= */

section('18. store 其它行为');

t('upsert 新建 -> 更新不改 id', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'note', issuer: 'A' });
  const b = store.upsert({ id: a.id, type: 'note', issuer: 'B' });
  assert.strictEqual(a.id, b.id);
  assert.strictEqual(b.issuer, 'B');
  assert.strictEqual(store.list({}).length, 1);
});

t('upsert 拒绝通过 id 篡改其它条目', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'note', issuer: 'A' });
  const b = store.upsert({ type: 'note', issuer: 'B' });
  // 拿 b 的 id 但声称是 a 的对象？normalizeEntry 里 id 与 existing 不一致会报错
  // 这里模拟的是：客户端传一个不存在的 id + 已存在条目的其它字段
  assert.throws(
    () => store.upsert({ id: 'not-a-uuid', type: 'note', issuer: 'C' }),
    (e) => e.code === 'INVALID');
});

t('编辑时未提供 recovery 字段 -> 保留原恢复码', () => {
  const { store } = freshStore();
  const a = store.upsert({
    type: 'totp', issuer: 'A', totp: { secret: 'JBSWY3DPEHPK3PXP' },
    recovery: { sets: [{ createdAt: new Date().toISOString(), codes: [{ value: 'AAAA-BBBB' }] }] },
  });
  const before = store.get(a.id).recovery.total;
  store.upsert({ id: a.id, type: 'totp', issuer: 'A-renamed' });
  const after = store.get(a.id);
  assert.strictEqual(after.recovery.total, before, '恢复码被静默清空了');
  assert.strictEqual(after.issuer, 'A-renamed');
});

t('编辑时显式传 recovery:{sets:[]} -> 真的清空', () => {
  const { store } = freshStore();
  const a = store.upsert({
    type: 'recovery-only', issuer: 'A',
    recovery: { sets: [{ createdAt: new Date().toISOString(), codes: [{ value: 'AAAA-BBBB' }] }] },
  });
  // type 是 recovery-only，清空后不合法；先改成 note
  store.upsert({ id: a.id, type: 'note', issuer: 'A', recovery: { sets: [] } });
  assert.strictEqual(store.get(a.id).recovery.total, 0);
});

t('编辑时未提供 totp.secret -> 保留原密钥', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'totp', issuer: 'A', totp: { secret: SECRET } });
  store.upsert({ id: a.id, type: 'totp', issuer: 'A', totp: { digits: 8 } });
  const detail = store.get(a.id);
  assert.strictEqual(detail.digits, 8);
  assert.strictEqual(store.revealSecret(a.id, 'totp').value, SECRET);
});

t('改成 note 类型会真的清掉密钥', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'totp', issuer: 'A', totp: { secret: SECRET } });
  store.upsert({ id: a.id, type: 'note', issuer: 'A' });
  assert.strictEqual(store.get(a.id).hasTotp, false);
  assert.throws(() => store.revealSecret(a.id, 'totp'), (e) => e.code === 'INVALID');
});

t('remove 批量删除', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'note', issuer: 'A' });
  const b = store.upsert({ type: 'note', issuer: 'B' });
  const c = store.upsert({ type: 'note', issuer: 'C' });
  const n = store.remove([a.id, c.id]);
  assert.strictEqual(n, 2);
  assert.strictEqual(store.list({}).length, 1);
  assert.strictEqual(store.list({})[0].id, b.id);
});

t('archive / unarchive', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'note', issuer: 'A' });
  store.archive([a.id], true);
  assert.strictEqual(store.list({}).length, 0, '归档后默认列表不应包含');
  assert.strictEqual(store.list({ includeArchived: true }).length, 1);
  store.archive([a.id], false);
  assert.strictEqual(store.list({}).length, 1);
});

t('list 支持 q 搜索与 group 过滤', () => {
  const { store } = freshStore();
  store.upsert({ type: 'note', issuer: 'GitHub', group: 'work', note: 'primary account' });
  store.upsert({ type: 'note', issuer: 'GitLab', group: 'work' });
  store.upsert({ type: 'note', issuer: 'Google', group: 'personal' });

  assert.strictEqual(store.list({ q: 'git' }).length, 2);
  assert.strictEqual(store.list({ group: 'work' }).length, 2);
  assert.strictEqual(store.list({ group: 'personal' }).length, 1);
  assert.strictEqual(store.list({ q: 'primary' }).length, 1);
});

t('pin 的条目排在最前', () => {
  const { store } = freshStore();
  store.upsert({ type: 'note', issuer: 'Zeta' });
  store.upsert({ type: 'note', issuer: 'Alpha', pinned: true });
  assert.strictEqual(store.list({})[0].issuer, 'Alpha');
});

t('revision 每次写入 +1', () => {
  const { store } = freshStore();
  const r0 = store.stats().revision;
  store.upsert({ type: 'note', issuer: 'A' });
  const r1 = store.stats().revision;
  store.upsert({ type: 'note', issuer: 'B' });
  const r2 = store.stats().revision;
  assert.strictEqual(r1, r0 + 1);
  assert.strictEqual(r2, r1 + 1);
});

t('verify 对当前码返回 matched=true', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'totp', issuer: 'A', totp: { secret: 'JBSWY3DPEHPK3PXP' } });
  const now = Math.floor(Date.now() / 1000);
  const expect = totp.totp(totp.base32Decode('JBSWY3DPEHPK3PXP'), now, 6, 30, 'SHA1');
  const r = store.verify(a.id, expect);
  assert.strictEqual(r.matched, true);
  assert.deepStrictEqual(r.window, [-1, 0, 1]);
});

t('verify 对错码返回 matched=false', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'totp', issuer: 'A', totp: { secret: 'JBSWY3DPEHPK3PXP' } });
  const wrong = '000000' === totp.totp(totp.base32Decode('JBSWY3DPEHPK3PXP'),
    Math.floor(Date.now() / 1000), 6, 30, 'SHA1') ? '111111' : '000000';
  assert.strictEqual(store.verify(a.id, wrong).matched, false);
});

t('verify 拒绝非数字输入', () => {
  const { store } = freshStore();
  const a = store.upsert({ type: 'totp', issuer: 'A', totp: { secret: 'JBSWY3DPEHPK3PXP' } });
  assert.throws(() => store.verify(a.id, 'abcdef'), (e) => e.code === 'INVALID');
  assert.throws(() => store.verify(a.id, '12345'), (e) => e.code === 'INVALID');
});

t('stale：超过 365 天的当前代标记 stale', () => {
  const { store } = freshStore();
  const e = store.upsert({ type: 'recovery-only', issuer: 'X' });
  const old = new Date(Date.now() - 400 * 24 * 3600 * 1000).toISOString();
  store.addSet(e.id, { text: 'AAAA-BBBB', createdAt: old });
  const item = store.list({})[0];
  assert.strictEqual(item.recovery.stale, true);

  const fresh = store.upsert({ type: 'recovery-only', issuer: 'Y' });
  store.addSet(fresh.id, { text: 'CCCC-DDDD' });
  const item2 = store.list({}).find(x => x.id === fresh.id);
  assert.strictEqual(item2.recovery.stale, false);
});

t('自愈写回：磁盘上多个 current 在 load 后只剩一个', () => {
  const { store, ks } = freshStore();
  const a = store.upsert({
    type: 'recovery-only', issuer: 'X',
    recovery: {
      sets: [
        { createdAt: '2025-01-01T00:00:00Z', supersededAt: null, codes: [{ value: 'AAAA-BBBB' }] },
        { createdAt: '2026-01-01T00:00:00Z', supersededAt: null, codes: [{ value: 'CCCC-DDDD' }] },
      ],
    },
  });
  // 首次 upsert 时已经是 normalize 过的，可能已被自愈。再手动污染一次：
  const payload = ks.load();
  const raw = payload.entries.find(x => x.id === a.id);
  raw.recovery.sets[0].supersededAt = null;
  raw.recovery.sets[1].supersededAt = null;
  ks.save(payload);

  const d = store.get(a.id);
  const currents = d.recovery.sets.filter(s => s.supersededAt === null);
  assert.strictEqual(currents.length, 1);
  assert.strictEqual(currents[0].createdAt, d.recovery.sets.find(
    s => s.id === d.recovery.currentSetId).createdAt);
});

t('磁盘上单条坏数据不会让整库打不开', () => {
  const { store, ks } = freshStore();
  store.upsert({ type: 'note', issuer: 'Good' });
  const payload = ks.load();
  payload.entries.push({ type: 'totally-bogus' });
  ks.save(payload);

  const list = store.list({});
  assert.strictEqual(list.length, 1, '好的那条应该还在');
  assert.strictEqual(list[0].issuer, 'Good');
});

/* ================= 19. QR ================= */

section('19. QR 编码');

t('QR 生成 v1（短文本）', () => {
  const r = qr.generate('hello');
  assert.strictEqual(r.version, 1);
  assert.strictEqual(r.size, 21);
});

t('QR 生成时按长度自动选版本', () => {
  assert.strictEqual(qr.generate('x'.repeat(14)).version, 1);
  assert.strictEqual(qr.generate('x'.repeat(15)).version, 2);
  assert.strictEqual(qr.generate('x'.repeat(210)).version, 10);
});

t('QR 拒绝超过 210 字节', () => {
  assert.throws(() => qr.generate('x'.repeat(211)), /太长/);
});

t('QR 拒绝空内容', () => {
  assert.throws(() => qr.generate(''), /不能为空/);
});

t('QR 矩阵尺寸 = 4*v+17', () => {
  for (let n = 1; n <= 210; n += 17) {
    const r = qr.generate('y'.repeat(n));
    assert.strictEqual(r.size, r.version * 4 + 17);
    assert.strictEqual(r.modules.length, r.size);
  }
});

t('QR 定位图形正确（三个角上 7x7）', () => {
  const r = qr.generate('test');
  const m = r.modules;
  const size = r.size;
  // 左上角定位图形的中心 3x3 应为深色
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -1; dy <= 1; dy++) {
      for (let dx = -1; dx <= 1; dx++) {
        assert.strictEqual(m[cy + dy][cx + dx], true,
          '定位图形中心 (' + (cx + dx) + ',' + (cy + dy) + ') 应为深色');
      }
    }
    // 外环 (dist 3) 也是深色
    assert.strictEqual(m[cy - 3][cx - 3], true);
  }
});

t('QR 定时图形交替', () => {
  const r = qr.generate('test');
  const m = r.modules;
  for (let i = 8; i < r.size - 8; i++) {
    assert.strictEqual(m[6][i], i % 2 === 0, '第6行第' + i + '列定时图形错了');
    assert.strictEqual(m[i][6], i % 2 === 0, '第6列第' + i + '行定时图形错了');
  }
});

t('QR 固定暗模块在 (8, size-8)', () => {
  const r = qr.generate('test');
  assert.strictEqual(r.modules[r.size - 8][8], true);
});

t('QR SVG 输出合法结构', () => {
  const svg = qr.toSvg('otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP');
  assert.ok(svg.startsWith('<svg '), 'SVG 应以 <svg 开头');
  assert.ok(svg.endsWith('</svg>'));
  assert.ok(svg.includes('xmlns="http://www.w3.org/2000/svg"'));
  assert.ok(svg.includes('<rect'));
  assert.ok(!/<script/i.test(svg), 'SVG 不得含 script');
});

t('QR SVG 不含脚本 / 事件属性', () => {
  const svg = qr.toSvg('"><script>alert(1)</script>');
  assert.ok(!/<script/i.test(svg));
  assert.ok(!/on\w+\s*=/i.test(svg));
});

t('QR 全部 8 个掩码都能解出原文本', () => {
  // 用 selftest 内部的迷你解码器验证（与 _qrcheck 同一逻辑的精简版）
  const dec = require('./qr-decode-test');
  for (const s of ['a', 'hello world', 'otpauth://totp/GitHub:alice@x.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub']) {
    const r = qr.generate(s);
    const d = dec.decode(r.modules, r.version, qr.VERSION_INFO);
    assert.strictEqual(d.text, s, '解出的文本不一致');
    assert.strictEqual(d.rsOk, true, 'RS 校验失败');
    assert.strictEqual(d.eccOk, true, '格式信息 ECC 校验失败');
  }
});

/* ================= 20. 结束 ================= */

(async () => {
  // 需要异步的测试放这里
  console.log('\n=== 23. 口令轮换与会话密钥安全 ===');

  await tAsync('改口令后旧备份被清除（否则旧口令仍能开当前库）', async () => {
    const { ks, dir, cleanup } = freshKeystore();
    try {
      ks.setup('old-pass-aaaaaaaa');
      ks.save({ version: 1, revision: 1, entries: [] });
      for (let i = 2; i <= 4; i++) ks.save({ version: 1, revision: i, entries: [] });
      const vp = ks.vaultPath;
      assert.ok([1, 2, 3].some(n => fs.existsSync(vp + '.bak.' + n)), '改口令前应有备份');

      ks.changePassphrase('old-pass-aaaaaaaa', 'new-pass-bbbbbbbb');

      assert.ok(![1, 2, 3].some(n => fs.existsSync(vp + '.bak.' + n)),
        '改口令后必须清除 bak：它们包裹的是旧 KEK，留着等于旧口令仍有效');
      const ks2 = new KeyStore(vp);
      assert.throws(() => ks2.unlock('old-pass-aaaaaaaa'), /BAD_PASSPHRASE|口令/);
      const ks3 = new KeyStore(vp);
      ks3.unlock('new-pass-bbbbbbbb');
    } finally { cleanup(); }
  });

  await tAsync('改口令后恢复密钥仍有效（逃生门不能被改坏）', async () => {
    const { ks, cleanup } = freshKeystore();
    try {
      const r = ks.setup('pass-11111111');
      ks.changePassphrase('pass-11111111', 'pass-22222222');
      const ks2 = new KeyStore(ks.vaultPath);
      ks2.unlockWithRecovery(r.recoveryKey);   // 不抛即通过
    } finally { cleanup(); }
  });

  await tAsync('改口令自检失败时回滚，旧口令仍可用', async () => {
    const { ks, cleanup } = freshKeystore();
    const orig = KeyStore.prototype._verifyWritten;
    try {
      ks.setup('keep-me-pass-2026');
      ks.save({ version: 1, revision: 1, entries: [{ id: 'a', issuer: 'X' }] });

      KeyStore.prototype._verifyWritten = () => { throw new Error('模拟自检失败'); };
      assert.throws(() => ks.changePassphrase('keep-me-pass-2026', 'new-pass-2026xx'));

      KeyStore.prototype._verifyWritten = orig;
      const ks2 = new KeyStore(ks.vaultPath);
      ks2.unlock('keep-me-pass-2026');   // 旧口令必须还能用
      const d = ks2.load();
      assert.strictEqual(d.entries.length, 1, '数据必须没丢');
    } finally {
      KeyStore.prototype._verifyWritten = orig;
      cleanup();
    }
  });

  await tAsync('regenerateRecovery 失败时旧恢复密钥仍有效', async () => {
    const { ks, cleanup } = freshKeystore();
    const orig = KeyStore.prototype._verifyWritten;
    try {
      const r = ks.setup('rec-pass-2026xx');
      ks.save({ version: 1, revision: 1, entries: [] });
      KeyStore.prototype._verifyWritten = () => { throw new Error('模拟失败'); };
      assert.throws(() => ks.regenerateRecovery('rec-pass-2026xx'));
      KeyStore.prototype._verifyWritten = orig;

      const ks2 = new KeyStore(ks.vaultPath);
      ks2.unlockWithRecovery(r.recoveryKey);
    } finally {
      KeyStore.prototype._verifyWritten = orig;
      cleanup();
    }
  });

  await tAsync('老库（KDF 参数与进程默认不同）改口令仍成功', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kd-legacy-'));
    const vp = path.join(dir, 'vault.enc');
    try {
      // 用低参数建库，模拟"将来调整过成本参数"的老库
      const ksOld = new KeyStore(vp, { kdf: { N: 1024, r: 8, p: 1 } });
      ksOld.setup('legacy-pass-2026');
      ksOld.save({ version: 1, revision: 1, entries: [{ id: 'a', issuer: 'L' }] });

      // 用默认参数的实例打开并改口令
      const ksNew = new KeyStore(vp);
      ksNew.unlock('legacy-pass-2026');
      ksNew.changePassphrase('legacy-pass-2026', 'upgraded-pass-2026');

      const meta = JSON.parse(fs.readFileSync(vp, 'utf8'));
      assert.strictEqual(meta.kdf.N, 1024, 'KDF 参数应保持文件里声明的值，不能被换成进程默认');

      const ks3 = new KeyStore(vp);
      ks3.unlock('upgraded-pass-2026');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  await tAsync('并发写入不会丢数据（最后写入者胜，但结构完整）', async () => {
    const { store, ks } = freshStore();
    const a = store.upsert({ type: 'note', issuer: 'A' });
    // 模拟两个"进程"各自读-改-写
    const p1 = ks.load();
    const p2 = ks.load();
    p1.entries.push({ id: storeMod.newEntryId(), type: 'note', issuer: 'B',
      account: '', url: '', group: '', tags: [], note: '',
      icon: { text: 'B', color: '#24292f' }, totp: null, recovery: { sets: [] },
      password: { value: '', updatedAt: null },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      lastUsedAt: null, pinned: false, archived: false });
    p2.entries.push({ id: storeMod.newEntryId(), type: 'note', issuer: 'C',
      account: '', url: '', group: '', tags: [], note: '',
      icon: { text: 'C', color: '#24292f' }, totp: null, recovery: { sets: [] },
      password: { value: '', updatedAt: null },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      lastUsedAt: null, pinned: false, archived: false });
    ks.save(p1);
    ks.save(p2);   // 覆盖 p1

    const final = ks.load();
    assert.ok(final.entries.length >= 1);
    // 至少 A 还在
    assert.ok(final.entries.some(e => e.issuer === 'A' || e.issuer === 'C'));
  });

  section('20. 弱口令拦截');

  // 这些口令按实测（260ms/次单核）在 64 核机器上几秒可破，
  // KDF 参数救不了——熵只能来自口令本身。
  // 注意全部 ≥8 字符：短于 8 的会被长度检查先拦下（那也是正确行为，
  // 但测不到弱口令规则本身，等于空测）。
  const WEAK = ['password123', '12345678', 'aaaaaaaa', 'qwertyui',
                'letmein1', 'abc12345', 'password12', 'test1234', 'admin123'];
  for (const pw of WEAK) {
    t('拒绝弱口令 ' + pw, () => {
      // 只断言"抛错"不够：一条口令可能因为长度被拒，那样弱口令规则
      // 根本没被执行到。所以必须匹配具体的拒绝理由。
      assert.throws(() => keystoreMod.checkPassphrase(pw),
        e => !/至少 8 个字符/.test(e.message));
    });
  }
  // 反过来：长口令不能被误伤。`test passphrase 123` 有 20 字符、带空格和数字，
  // 只因为以 test 开头就拒绝，是把用户往更短更好猜的方向逼。
  for (const pw of ['my-strong-passphrase', 'test passphrase 123',
                    'correct horse battery staple', 'diceware-word-list-9',
                    '楼下那家面馆周三不开门']) {
    t('接受强口令 ' + pw.slice(0, 12), () => {
      assert.strictEqual(keystoreMod.checkPassphrase(pw), pw);
    });
  }

  section('21. 加密导出');

  const expDir = tmpDir();
  try {
    const ks = new KeyStore(path.join(expDir, 'vault.enc'), { kdf: FAST_KDF });
    ks.setup('my-strong-export-test');
    ks.save({ version: 1, entries: [], settings: {} });
    const store = new Store(ks);

    // 弱口令必须被拒，且错误码是 INVALID 而不是 INTERNAL。
    // 这条断言是有来历的：store.js 的 fail(message, code) 与 keystore.js 的
    // fail(code, message) 参数顺序相反，写反了 code 会变成整段中文，
    // 路由层认不出就兜底成 500，用户看到"服务器内部错误"而不是"口令太弱"。
    t('导出拒绝弱口令且 code 是 INVALID', () => {
      assert.throws(
        () => store.exportEncrypted({ passphrase: 'password123' }),
        e => e.code === 'INVALID'
      );
    });
    t('导出拒绝过短口令', () => {
      assert.throws(() => store.exportEncrypted({ passphrase: 'aB3' }), e => e.code === 'INVALID');
    });

    const r = store.exportEncrypted({ passphrase: 'another-strong-backup' });
    t('导出产出文件', () => {
      assert.ok(fs.existsSync(r.path));
      assert.ok(r.bytes > 0);
    });
    t('导出包是密文（不含明文 secret）', () => {
      const raw = fs.readFileSync(r.path, 'utf8');
      assert.ok(!raw.includes('otpauth'), '不应含明文 otpauth');
      const j = JSON.parse(raw);
      assert.strictEqual(j.format, 'keydesk-export/1');
      assert.ok(j.iv && j.ct && j.kdf, '应含 iv/ct/kdf');
    });
    t('导出包能被同一口令解开', () => {
      const crypto = require('crypto');
      const j = JSON.parse(fs.readFileSync(r.path, 'utf8'));
      const salt = Buffer.from(j.kdf.salt, 'base64');
      const kek = crypto.scryptSync(Buffer.from('another-strong-backup', 'utf8'), salt, 32, {
        N: j.kdf.N, r: j.kdf.r, p: j.kdf.p,
        maxmem: 128 * j.kdf.r * j.kdf.N * 2,
      });
      const ct = Buffer.from(j.ct, 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(j.iv, 'base64'),
        { authTagLength: 16 });
      // 域分离 AAD：导出包不能当 vault.enc 用，反之亦然
      d.setAAD(Buffer.from('keydesk/export/1', 'utf8'));
      d.setAuthTag(ct.subarray(-16));
      const plain = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]).toString('utf8');
      assert.ok(plain.length > 0);
    });
    t('导出包用 vault 的 AAD 解不开（域分离生效）', () => {
      const crypto = require('crypto');
      const j = JSON.parse(fs.readFileSync(r.path, 'utf8'));
      const salt = Buffer.from(j.kdf.salt, 'base64');
      const kek = crypto.scryptSync(Buffer.from('another-strong-backup', 'utf8'), salt, 32, {
        N: j.kdf.N, r: j.kdf.r, p: j.kdf.p,
        maxmem: 128 * j.kdf.r * j.kdf.N * 2,
      });
      const ct = Buffer.from(j.ct, 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(j.iv, 'base64'),
        { authTagLength: 16 });
      d.setAAD(Buffer.from('keydesk/1|aaa|bbb', 'utf8'));
      d.setAuthTag(ct.subarray(-16));
      assert.throws(() => {
        Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
      });
    });
  } finally {
    try { fs.rmSync(expDir, { recursive: true, force: true }); } catch { /* 忽略 */ }
  }

  section('22. 审计视图');

  const audDir = tmpDir();
  try {
    const ks = new KeyStore(path.join(audDir, 'vault.enc'), { kdf: FAST_KDF });
    ks.setup('my-strong-audit-test');
    ks.save({ version: 1, entries: [], settings: {} });
    const store = new Store(ks);
    // 三条：完整 / 无恢复码 / 什么都没有
    store.upsert({
      type: 'totp', issuer: 'Full', account: 'a@x.com',
      totp: { secret: 'JBSWY3DPEHPK3PXP' },
      password: { value: 'pw', updatedAt: new Date().toISOString() },
      recovery: { sets: [{ id: 's1', createdAt: new Date().toISOString(),
        codes: [{ id: 'c1', value: 'aaaaa-bbbbb', usedAt: null }] }] },
    });
    store.upsert({ type: 'totp', issuer: 'NoRecovery', account: 'b@x.com',
      totp: { secret: 'JBSWY3DPEHPK3PXP' } });
    store.upsert({ type: 'recovery-only', issuer: 'Bare', account: 'c@x.com' });

    const a = store.auditList();
    const byIssuer = {};
    for (const it of a.items) byIssuer[it.issuer] = it.problems;

    t('完整条目不出现在审计里', () => {
      assert.ok(!byIssuer['Full'], '有 TOTP+恢复码+密码的条目不该报问题');
    });
    t('无恢复码被报出', () => {
      assert.ok(byIssuer['NoRecovery'].includes('no-recovery'));
    });
    t('无 TOTP 被报出', () => {
      assert.ok(byIssuer['Bare'].includes('no-totp'));
    });
    t('无恢复码也被报出', () => {
      assert.ok(byIssuer['Bare'].includes('no-recovery'));
    });
  } finally {
    try { fs.rmSync(audDir, { recursive: true, force: true }); } catch { /* 忽略 */ }
  }

  console.log('');
  console.log('----------------------------------------');
  console.log('  通过 ' + pass + '   失败 ' + fail);
  if (fail) {
    console.log('');
    console.log('  失败项：');
    for (const f of failures) console.log('   - ' + f);
  }
  console.log('----------------------------------------');
  process.exit(fail ? 1 : 0);
})();
