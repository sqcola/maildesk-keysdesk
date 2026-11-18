#!/usr/bin/env node
'use strict';
/**
 * check-key-test.js —— tools/check-key.js 的回归测试
 *
 * 运行： node tools/check-key-test.js      （在 MailDesk/ 下）
 *
 * 为什么这个文件存在：check-key.js 是用户"到底该留哪一份密钥"的唯一判据。
 * 它一旦误报"打不开"，用户的下一步动作是删密钥 —— 数据永久丢失。
 * 历史上就出过一次：解密时漏了 setAAD，导致 v2 库上**正确的密钥也被判成认证失败**，
 * 工具的结论与真实读取路径完全相反。下面的用例就是在守这条。
 */
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const { Vault } = require('../lib/vault');
const ck = require('./check-key');

let pass = 0, fail = 0;
function t(name, fn) {
  // 同步 harness 遇到 async 回调时断言失败会变成 unhandled rejection，
  // 这里照样打 ✓ —— 与 selftest.js 同一个坑，直接拒绝更安全。
  if (fn && fn.constructor && fn.constructor.name === 'AsyncFunction') {
    console.log('  ✗ ' + name + '\n      async 回调不被本 harness 支持，请改成同步');
    fail++;
    return;
  }
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;

/**
 * 手工按落盘格式加密一条 secrets。
 *
 * 这里的 AAD 前缀是**字面量** 'maildesk/2|'，故意不用 check-key.js 导出的
 * accountAad()：用被测函数去构造测试数据，等于自己证自己，
 * 前缀一旦被改成错的值，两边一起变，测试照样绿。
 */
function seal(keyBuf, obj, aad) {
  const iv = crypto.randomBytes(IV_LEN);
  const c = crypto.createCipheriv(ALGO, keyBuf, iv);
  if (aad !== undefined) c.setAAD(Buffer.from('maildesk/2|' + aad, 'utf8'));
  const enc = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj), 'utf8')), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}

let n = 0;
/** 造一对临时目录：dataDir（密文）+ keyDir（密钥），并返回清理函数 */
function tmpPair() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ck-test-' + (n++) + '-'));
  const dataDir = path.join(root, 'data');
  const keyDir = path.join(root, 'keys');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(keyDir, { recursive: true });
  return { root, dataDir, keyDir, store: path.join(dataDir, 'accounts.enc') };
}
const cleanup = ctx => { try { fs.rmSync(ctx.root, { recursive: true, force: true }); } catch { /* 忽略 */ } };

/** 用真实 Vault 造一个 v2 库，返回密钥 Buffer */
function makeV2(ctx, accounts) {
  const v = new Vault(ctx.dataDir, ctx.keyDir);
  v.save(accounts);
  return { vault: v, key: fs.readFileSync(path.join(ctx.keyDir, 'vault.key')) };
}

const readStore = p => JSON.parse(fs.readFileSync(p, 'utf8'));
const writeStore = (p, obj) => fs.writeFileSync(p, JSON.stringify(obj, null, 2));

// ---------------------------------------------------------------------------
console.log('\n=== 1. v2 库（这条是本文件存在的理由）===');

t('v2 库 + 正确密钥 → ok === true（漏 setAAD 时这条会红）', () => {
  const ctx = tmpPair();
  try {
    const { key } = makeV2(ctx, [
      { id: 'a1', email: 'a@x.com', secrets: { refreshToken: 'RT-1' } },
      { id: 'a2', email: 'b@x.com', secrets: { refreshToken: 'RT-2' } },
    ]);
    assert.strictEqual(readStore(ctx.store).version, 2, '用例前提：Vault 应写成 v2');

    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '正确密钥必须判定为可解，实际：' + r.reason);
    assert.strictEqual(r.count, 2, '应解出 2 个账户');
    assert.strictEqual(r.verdict, 'ok');
    assert.deepStrictEqual(r.corrupted, []);
  } finally { cleanup(ctx); }
});

t('v2 库 + 错误密钥 → ok === false，且明确指出认证失败', () => {
  const ctx = tmpPair();
  try {
    makeV2(ctx, [
      { id: 'a1', email: 'a@x.com', secrets: { refreshToken: 'RT-1' } },
      { id: 'a2', email: 'b@x.com', secrets: { refreshToken: 'RT-2' } },
    ]);
    const r = ck.tryDecrypt(crypto.randomBytes(32), ctx.store);
    assert.strictEqual(r.ok, false, '错误密钥必须判为解不开');
    assert.strictEqual(r.verdict, 'auth-failed', '全部认证失败应归类为"钥匙不对"');
    assert.ok(/认证失败/.test(r.reason), 'reason 应含"认证失败"，实际：' + r.reason);
    assert.strictEqual(r.count, 0);
  } finally { cleanup(ctx); }
});

t('v2 条目缺 AAD 会失败：把 AAD 绑定做反（改 id）必须认证失败', () => {
  // 反向验证：确认 v2 确实靠 AAD 绑定 id，本工具也真的在用它。
  // 如果 tryDecrypt 根本没设 AAD，这条会"解开了"，从而暴露回归。
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [{ id: 'a1', v: 2, blob: seal(key, { refreshToken: 'RT' }, 'WRONG-ID') }],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, false, 'AAD 与 id 不匹配时必须解不开');
    assert.strictEqual(r.verdict, 'auth-failed');
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('\n=== 2. v1 库没有被改坏 ===');

t('v1 库（无文件 version、条目无 v）+ 正确密钥 → ok === true', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      // 刻意不写 version，也不写条目 v：这是最老的一批库
      accounts: [
        { id: 'old1', email: 'o1@x.com', blob: seal(key, { refreshToken: 'RT-O1' }) },
        { id: 'old2', email: 'o2@x.com', blob: seal(key, { refreshToken: 'RT-O2' }) },
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, 'v1 库必须仍能解，实际：' + r.reason);
    assert.strictEqual(r.count, 2);
    assert.strictEqual(r.verdict, 'ok');
  } finally { cleanup(ctx); }
});

t('v1 库（version:1）+ 正确密钥 → ok === true', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 1,
      accounts: [{ id: 'v1a', blob: seal(key, { refreshToken: 'RT' }) }],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '实际：' + r.reason);
    assert.strictEqual(r.count, 1);
  } finally { cleanup(ctx); }
});

t('v1 库 + 错误密钥 → ok === false', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 1,
      accounts: [{ id: 'v1a', blob: seal(key, { refreshToken: 'RT' }) }],
    });
    const r = ck.tryDecrypt(crypto.randomBytes(32), ctx.store);
    assert.strictEqual(r.ok, false, 'v1 上错密钥也必须判死');
    assert.ok(/认证失败/.test(r.reason), '实际：' + r.reason);
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('\n=== 3. 混装库与版本判定 ===');

t('混装库：一条 v1 + 一条 v2，都能解开', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { id: 'mix1', v: 1, blob: seal(key, { refreshToken: 'RT-MIX1' }) },
        { id: 'mix2', v: 2, blob: seal(key, { refreshToken: 'RT-MIX2' }, 'mix2') },
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '混装库应整体可解，实际：' + r.reason);
    assert.strictEqual(r.count, 2, '两条都应解出');
    assert.deepStrictEqual(r.corrupted, []);
  } finally { cleanup(ctx); }
});

t('文件声明 v2 但条目没有 v → 按 v2 解（与 vault.js 的 entryVersion 一致）', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [{ id: 'nov', blob: seal(key, { refreshToken: 'RT' }, 'nov') }],   // 无 v
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '应走 v2 分支（带 AAD），实际：' + r.reason);
    assert.strictEqual(r.count, 1);
  } finally { cleanup(ctx); }
});

t('声明与密文不一致时仍能解开（两版都试，与 vault.js 一致）', () => {
  // 场景：文件被手工改成 version:1、条目 v 被抹掉，但密文其实是 v2。
  // vault.js 的 all() 会先按 v1 解（失败）再按 v2 解（成功）；
  // check-key.js 若不"两版都试"，就会把一个完好的库判成打不开。
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 1,   // 说谎的文件级版本
      accounts: [{ id: 'liar', blob: seal(key, { refreshToken: 'RT' }, 'liar') }],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '两版都试应能救回来，实际：' + r.reason);
    assert.strictEqual(r.count, 1);
  } finally { cleanup(ctx); }
});

t('超长 id（>512）走 sha256 分支，与 vault.js 算出的 AAD 一致', () => {
  // 真实 id 是 36 字符 UUID，但 accounts.enc 可被外部改动。
  // 这条用**真实 Vault** 写的库来对拍：Vault 那边走的是真身 accountAad，
  // 本工具走的是复刻版，两边算出不同的 AAD 这里就会红。
  const ctx = tmpPair();
  try {
    const longId = 'x'.repeat(600);
    const { key } = makeV2(ctx, [{ id: longId, email: 'l@x.com', secrets: { refreshToken: 'RT-LONG' } }]);
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '超长 id 的 AAD 应一致，实际：' + r.reason);
    assert.strictEqual(r.count, 1);
  } finally { cleanup(ctx); }
});

t('id 为 null/undefined 时 AAD 退化成前缀（与 vault.js 一致）', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { v: 2, blob: seal(key, { refreshToken: 'RT-N1' }, '') },            // id 缺失
        { id: null, v: 2, blob: seal(key, { refreshToken: 'RT-N2' }, '') },  // id 为 null
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '空 id 应按 "maildesk/2|" 解，实际：' + r.reason);
    assert.strictEqual(r.count, 2);
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('\n=== 4. 复刻函数本身的契约（对拍 vault.js 的规则）===');

// 解密用例其实测不出 entryVersion 是否精确：因为"两版都试"的设计会让版本判错
// 也照样解出来（这正是 vault.js 想要的健壮性）。但规则本身仍需锁住 ——
// 它是复刻件，一旦哪天有人"顺手简化"，下一个改动就会以极难排查的方式出问题。
t('entryVersion：条目自己的 v 优先，取值 1/2 都认', () => {
  assert.strictEqual(ck.entryVersion({ v: 1 }, 2), 1, '条目 v=1 必须胜过文件级 2');
  assert.strictEqual(ck.entryVersion({ v: 2 }, 1), 2, '条目 v=2 必须胜过文件级 1');
  assert.strictEqual(ck.entryVersion({ v: '2' }, 1), 2, '字符串形式也要认');
});

t('entryVersion：条目无 v 时退回文件级 version，只有 2 当 v2', () => {
  assert.strictEqual(ck.entryVersion({}, 2), 2);
  assert.strictEqual(ck.entryVersion({}, 1), 1);
  assert.strictEqual(ck.entryVersion({}, undefined), 1, '缺失按 v1（最宽松的那版）');
  assert.strictEqual(ck.entryVersion({}, 99), 1, '未知版本按 v1，不能按 v2 猜');
  assert.strictEqual(ck.entryVersion(null, 2), 2, '条目为 null 也不能抛');
  assert.strictEqual(ck.entryVersion({ v: 3 }, 2), 2, '非法 v 退回文件级');
});

t('accountAad：前缀、"sha256:" 分支、空 id 退化', () => {
  assert.strictEqual(ck.accountAad('acc1'), 'maildesk/2|acc1');
  assert.strictEqual(ck.accountAad(null), 'maildesk/2|');
  assert.strictEqual(ck.accountAad(undefined), 'maildesk/2|');
  assert.strictEqual(ck.accountAad(''), 'maildesk/2|');
  assert.strictEqual(ck.accountAad(123), 'maildesk/2|123', '非字符串要转成字符串');
  assert.strictEqual(ck.accountAad('a'.repeat(512)), 'maildesk/2|' + 'a'.repeat(512), '512 是边界内');
  const long = 'b'.repeat(513);
  const got = ck.accountAad(long);
  assert.strictEqual(got,
    'maildesk/2|sha256:' + crypto.createHash('sha256').update(long, 'utf8').digest('hex'),
    '超过 512 必须走 sha256，且与 vault.js 同一算法');
});

// ---------------------------------------------------------------------------
console.log('\n=== 5. 部分损坏的诊断（钥匙对、数据坏）===');

t('部分条目损坏 → ok === true，且列出的坏条目数正确', () => {
  const ctx = tmpPair();
  try {
    const { key } = makeV2(ctx, [
      { id: 'c1', email: 'c1@x.com', secrets: { refreshToken: 'RT-1' } },
      { id: 'c2', email: 'c2@x.com', secrets: { refreshToken: 'RT-2' } },
      { id: 'c3', email: 'c3@x.com', secrets: { refreshToken: 'RT-3' } },
    ]);
    // 翻转第 2 条密文的最后一个字节（位翻转 / 磁盘坏块的最小模型）
    const raw = readStore(ctx.store);
    const t2 = raw.accounts.find(a => a.id === 'c2');
    const b2 = Buffer.from(t2.blob, 'base64');
    b2[b2.length - 1] ^= 0xff;
    t2.blob = b2.toString('base64');
    writeStore(ctx.store, raw);

    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '有一条能解开就说明密钥是对的，实际：' + r.reason);
    assert.strictEqual(r.count, 2, '应解出 2 条');
    assert.strictEqual(r.corrupted.length, 1, '应报告 1 条坏数据');
    assert.strictEqual(r.corrupted[0].id, 'c2');
    assert.ok(/认证失败/.test(r.corrupted[0].reason), '实际：' + r.corrupted[0].reason);
    assert.strictEqual(r.verdict, 'partial');
    // 输出里必须带着坏条目数量，用户才分得清"换钥匙"和"修数据"
    assert.ok(/1 条解不开/.test(r.reason), '实际：' + r.reason);
  } finally { cleanup(ctx); }
});

t('单条密文长度异常不影响其余条目（不再一票否决整库）', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { id: 'ok1', v: 2, blob: seal(key, { refreshToken: 'RT' }, 'ok1') },
        { id: 'short', v: 2, blob: Buffer.alloc(5).toString('base64') },   // 连 iv+tag 都放不下
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '长度异常只是坏数据，不是钥匙不对');
    assert.strictEqual(r.count, 1);
    assert.strictEqual(r.corrupted.length, 1);
    assert.strictEqual(r.corrupted[0].id, 'short');
    assert.ok(/长度异常/.test(r.corrupted[0].reason), '实际：' + r.corrupted[0].reason);
  } finally { cleanup(ctx); }
});

t('全部条目损坏但密钥正确 → 归类为"库损坏"而不是"钥匙不对"', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { id: 'b1', v: 2, blob: Buffer.alloc(3).toString('base64') },
        { id: 'b2', v: 2, blob: Buffer.alloc(4).toString('base64') },
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, false);
    // 没有任何一条是"认证失败"（都是长度异常），所以不能武断地说"你拿错钥匙了"
    assert.strictEqual(r.verdict, 'corrupted', '不应把数据损坏误报成密钥不符');
    assert.ok(/损坏|解不开/.test(r.reason), '实际：' + r.reason);
  } finally { cleanup(ctx); }
});

t('能解开但内容不是合法 JSON → 判坏条目，且诊断里不得泄露明文', () => {
  // 回归：JSON.parse 抛出的 message 会带上明文片段（Node 18+ 是
  // 'Unexpected token ... in JSON at position ...'，新版会引用原文），
  // 那段明文就是 refresh_token。诊断信息绝不能把它带进终端或日志。
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    const SECRET = 'RT-SHOULD-NEVER-LEAK-1234567890';
    // 手工加密一段**不是 JSON** 的内容，但 AAD 正确（能通过认证）
    const iv = crypto.randomBytes(IV_LEN);
    const c = crypto.createCipheriv(ALGO, key, iv);
    c.setAAD(Buffer.from('maildesk/2|badjson', 'utf8'));
    const enc = Buffer.concat([c.update(Buffer.from('not-json ' + SECRET, 'utf8')), c.final()]);
    const blob = Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { id: 'good', v: 2, blob: seal(key, { refreshToken: 'RT-GOOD' }, 'good') },
        { id: 'badjson', v: 2, blob },
      ],
    });

    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '有一条能解就说明密钥正确，实际：' + r.reason);
    assert.strictEqual(r.corrupted.length, 1);
    assert.strictEqual(r.corrupted[0].id, 'badjson');
    assert.ok(!JSON.stringify(r).includes(SECRET),
      '诊断信息里出现了明文令牌：' + JSON.stringify(r));
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('\n=== 6. 原有边界行为保持不变 ===');

t('空库 → ok === true，count 0，并说明证明不了什么', () => {
  const ctx = tmpPair();
  try {
    writeStore(ctx.store, { version: 2, accounts: [] });
    const r = ck.tryDecrypt(crypto.randomBytes(32), ctx.store);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.count, 0);
    assert.strictEqual(r.verdict, 'empty');
    assert.ok(/无法验证/.test(r.reason), '实际：' + r.reason);
  } finally { cleanup(ctx); }
});

t('缺 blob 的条目计为可解（没有密文可验）', () => {
  const ctx = tmpPair();
  try {
    const key = crypto.randomBytes(32);
    writeStore(ctx.store, {
      version: 2,
      accounts: [
        { id: 'noblob', v: 2, email: 'n@x.com' },   // 没有 secrets
        { id: 'hasblob', v: 2, blob: seal(key, { refreshToken: 'RT' }, 'hasblob') },
      ],
    });
    const r = ck.tryDecrypt(key, ctx.store);
    assert.strictEqual(r.ok, true, '实际：' + r.reason);
    assert.strictEqual(r.count, 2, '缺 blob 的条目应计入可解');
    assert.deepStrictEqual(r.corrupted, []);
  } finally { cleanup(ctx); }
});

t('accounts.enc 不存在 → ok === false', () => {
  const ctx = tmpPair();
  try {
    const r = ck.tryDecrypt(crypto.randomBytes(32), path.join(ctx.dataDir, 'nope.enc'));
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.verdict, 'no-store');
    assert.ok(/不存在/.test(r.reason));
  } finally { cleanup(ctx); }
});

t('密钥长度不对 → ok === false，且说明长度', () => {
  const ctx = tmpPair();
  try {
    writeStore(ctx.store, { version: 2, accounts: [] });
    for (const bad of [Buffer.alloc(16), Buffer.alloc(0), null]) {
      const r = ck.tryDecrypt(bad, ctx.store);
      assert.strictEqual(r.ok, false);
      assert.ok(/长度/.test(r.reason), JSON.stringify(bad) + ' → ' + r.reason);
    }
  } finally { cleanup(ctx); }
});

t('accounts.enc 不是合法 JSON → ok === false，不抛异常', () => {
  const ctx = tmpPair();
  try {
    fs.writeFileSync(ctx.store, '{ 这不是 json');
    const r = ck.tryDecrypt(crypto.randomBytes(32), ctx.store);
    assert.strictEqual(r.ok, false);
    assert.ok(/无法解析/.test(r.reason), '实际：' + r.reason);
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('\n=== 7. --purge-legacy 在 v2 库上必须能走通 ===');

const TOOL = path.join(__dirname, 'check-key.js');

t('v2 库 + 正确密钥 + --purge-legacy --yes → 真的删掉 LEGACY_KEY，退出码 0', () => {
  const ctx = tmpPair();
  try {
    // 用真实 Vault 造 v2 库（密钥落在 keyDir）
    makeV2(ctx, [{ id: 'p1', email: 'p@x.com', secrets: { refreshToken: 'RT-P' } }]);
    const key = fs.readFileSync(path.join(ctx.keyDir, 'vault.key'));
    // 再在数据目录放一份**内容相同**的旧密钥：这就是"迁移只差最后一步删除"
    fs.writeFileSync(path.join(ctx.dataDir, 'vault.key'), key);

    const r = spawnSync(process.execPath, [TOOL, '--purge-legacy', '--yes'], {
      env: { ...process.env, MAILDESK_DATA_DIR: ctx.dataDir, MAILDESK_KEY_DIR: ctx.keyDir },
      encoding: 'utf8', timeout: 60000,
    });
    assert.strictEqual(r.status, 0, '应退出 0，实际 ' + r.status + '\n' + r.stdout + r.stderr);
    assert.ok(/能解密 accounts.enc/.test(r.stdout),
      '必须先判定 primary 可解（漏 setAAD 时这里永远是"解不开"）：\n' + r.stdout);
    assert.ok(/已删除旧密钥/.test(r.stdout), '应真的执行删除：\n' + r.stdout);
    assert.ok(!fs.existsSync(path.join(ctx.dataDir, 'vault.key')), 'LEGACY_KEY 应已被删除');
    assert.ok(fs.existsSync(path.join(ctx.keyDir, 'vault.key')), 'primary 密钥必须保留');
    // 删密钥不能碰密文：数据还得能读
    assert.strictEqual(new Vault(ctx.dataDir, ctx.keyDir).all().length, 1, 'accounts.enc 不得被改动');
  } finally { cleanup(ctx); }
});

t('v2 库 + 错误 primary + --purge-legacy --yes → 拒绝删除，退出码 1（保护方向仍是安全的）', () => {
  const ctx = tmpPair();
  try {
    makeV2(ctx, [{ id: 'p1', email: 'p@x.com', secrets: { refreshToken: 'RT-P' } }]);
    // 把 primary 换成一把错的钥匙，旧位置留一把「像是另一批数据的钥匙」
    fs.writeFileSync(path.join(ctx.keyDir, 'vault.key'), crypto.randomBytes(32));
    fs.writeFileSync(path.join(ctx.dataDir, 'vault.key'), crypto.randomBytes(32));

    const r = spawnSync(process.execPath, [TOOL, '--purge-legacy', '--yes'], {
      env: { ...process.env, MAILDESK_DATA_DIR: ctx.dataDir, MAILDESK_KEY_DIR: ctx.keyDir },
      encoding: 'utf8', timeout: 60000,
    });
    assert.strictEqual(r.status, 1, '错误的 primary 必须拒绝删除，实际 ' + r.status + '\n' + r.stdout);
    assert.ok(/\[拒绝\].*解不开/.test(r.stdout), '应给出拒绝理由：\n' + r.stdout);
    assert.ok(fs.existsSync(path.join(ctx.dataDir, 'vault.key')), '绝不能动旧密钥');
  } finally { cleanup(ctx); }
});

t('v2 库体检：CLI 退出码 0，输出解出的账户数', () => {
  const ctx = tmpPair();
  try {
    makeV2(ctx, [
      { id: 'e1', email: 'e1@x.com', secrets: { refreshToken: 'RT-1' } },
      { id: 'e2', email: 'e2@x.com', secrets: { refreshToken: 'RT-2' } },
    ]);
    const r = spawnSync(process.execPath, [TOOL], {
      env: { ...process.env, MAILDESK_DATA_DIR: ctx.dataDir, MAILDESK_KEY_DIR: ctx.keyDir },
      encoding: 'utf8', timeout: 60000,
    });
    assert.strictEqual(r.status, 0, 'v2 库上正确密钥必须退出 0，实际 ' + r.status + '\n' + r.stdout);
    assert.ok(/解出 2 个账户/.test(r.stdout), '应报告解出的账户数：\n' + r.stdout);
    assert.ok(/至少有一份密钥能解开/.test(r.stdout), '结论行应判为可用：\n' + r.stdout);
  } finally { cleanup(ctx); }
});

t('v2 库 + 错误密钥体检：退出码 1，且提示"这把密钥不是本库的"（不是数据损坏）', () => {
  const ctx = tmpPair();
  try {
    makeV2(ctx, [{ id: 'e1', email: 'e1@x.com', secrets: { refreshToken: 'RT-1' } }]);
    // 库已用 keyDir 里的密钥写好，现在把 keyDir 的密钥换掉（模拟"拿错了钥匙"）
    fs.writeFileSync(path.join(ctx.keyDir, 'vault.key'), crypto.randomBytes(32));
    const r = spawnSync(process.execPath, [TOOL], {
      env: { ...process.env, MAILDESK_DATA_DIR: ctx.dataDir, MAILDESK_KEY_DIR: ctx.keyDir },
      encoding: 'utf8', timeout: 60000,
    });
    assert.strictEqual(r.status, 1, '错误密钥应退出 1，实际 ' + r.status + '\n' + r.stdout);
    assert.ok(/认证失败/.test(r.stdout), '应指出认证失败：\n' + r.stdout);
    assert.ok(/不是本库的/.test(r.stdout), '应明确是"钥匙不对"：\n' + r.stdout);
  } finally { cleanup(ctx); }
});

// ---------------------------------------------------------------------------
console.log('');
console.log('----------------------------------------');
console.log('  通过 ' + pass + '   失败 ' + fail);
console.log('----------------------------------------');
process.exit(fail ? 1 : 0);
