'use strict';
/**
 * 自检脚本：不联网，只验证核心模块能被正确加载和执行
 * 运行： node selftest.js
 */
const assert = require('assert');

let pass = 0, fail = 0, skipped = 0;
function t(name, fn) {
  // 同步 harness 收到 async 回调时，fn() 返回的是一个 Promise——
  // 里面的断言失败会变成 unhandled rejection，而这里照样打 ✓。
  // 实测：注入一条 t('x', async () => { assert.strictEqual(1, 2) })
  // 输出是「✓ x」+「通过 147 失败 0」。直接拒绝，强制改用 tAsync。
  if (fn && fn.constructor && fn.constructor.name === 'AsyncFunction') {
    console.log('  ✗ ' + name + '\n      async 回调必须用 tAsync，否则断言失败会被静默吞掉');
    fail++;
    return;
  }
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}
async function tAsync(name, fn) {
  try { await fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

/**
 * 显式跳过的用例。
 *
 * 为什么需要它：ACL 断言只能在 Windows + NTFS 上做，CI 里多半取不到。
 * 如果这类用例什么都不打印就返回，输出里的 "✓" 会让人以为 ACL 真的被验证过；
 * 如果不加区分地算进 fail，非 Windows 机器上永远是红的。两种都不行，
 * 所以单独计数并**打印原因**。它不计入 fail，因此不会让退出码变红。
 */
function tSkip(name, reason) {
  console.log('  ⊘ ' + name + '\n      （跳过：' + reason + '）');
  skipped++;
}

console.log('\n=== 1. 模块加载 ===');
const imap = require('./lib/imap-client');
const mail = require('./lib/mail');
const smtp = require('./lib/smtp');
const { Vault } = require('./lib/vault');
t('imap-client 加载', () => assert.ok(imap.ImapClient));
t('mail 加载', () => assert.ok(mail.listMessages && mail.checkAccount));
t('smtp 加载', () => assert.ok(smtp.sendMail && smtp.buildMessage));
t('vault 加载', () => assert.ok(Vault));

console.log('\n=== 2. ENVELOPE 解析 ===');
t('解析标准 ENVELOPE', () => {
  const text = `* 1 FETCH (UID 42 FLAGS (\\Seen) RFC822.SIZE 1024 ENVELOPE ("Mon, 2 Nov 2026 10:00:00 +0800" "Test Subject" (("Zhang" NIL "zhang" "example.com")) (("Zhang" NIL "zhang" "example.com")) (("Zhang" NIL "zhang" "example.com")) (("Li" NIL "li" "example.com")) NIL NIL NIL "<abc@example.com>"))`;
  const r = imap.parseFetchResponse(text);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].uid, 42);
  assert.strictEqual(r[0].size, 1024);
  assert.strictEqual(r[0].envelope.subject, 'Test Subject');
  assert.strictEqual(r[0].envelope.from[0].address, 'zhang@example.com');
  assert.strictEqual(r[0].envelope.to[0].address, 'li@example.com');
  assert.ok(r[0].flags.includes('\\Seen'));
});

t('解析多封', () => {
  const text = [
    '* 1 FETCH (UID 10 FLAGS () ENVELOPE (NIL "A" NIL NIL NIL NIL NIL NIL NIL NIL))',
    '* 2 FETCH (UID 11 FLAGS () ENVELOPE (NIL "B" NIL NIL NIL NIL NIL NIL NIL NIL))',
  ].join('\r\n');
  const r = imap.parseFetchResponse(text);
  assert.strictEqual(r.length, 2);
  assert.strictEqual(r[1].envelope.subject, 'B');
});

t('MIME 字解码（UTF-8 B）', () => {
  const enc = Buffer.from('测试主题', 'utf8').toString('base64');
  assert.strictEqual(imap.decodeMimeWord(`=?UTF-8?B?${enc}?=`), '测试主题');
});

t('MIME 字解码（GBK B）', () => {
  // GBK "测试" = B2E2 CAD4
  const enc = Buffer.from([0xb2, 0xe2, 0xca, 0xd4]).toString('base64');
  assert.strictEqual(imap.decodeMimeWord(`=?GBK?B?${enc}?=`), '测试');
});

t('NIL 处理', () => {
  const text = `* 1 FETCH (UID 5 FLAGS () ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL))`;
  const r = imap.parseFetchResponse(text);
  assert.strictEqual(r[0].envelope.subject, null);
  assert.deepStrictEqual(r[0].envelope.from, []);
});

// 回归：fetchBody 之前签名是 (seq, uid)，mail.js 传 (uid, true)，
// 布尔被当成 UID 拼进命令 → "UID FETCH true (...)" → 服务端 BAD。
// 单封邮件永远打不开，列表却正常，是这个 bug 的典型表现。
tAsync('fetchBody 拒绝非数字 uid', async () => {
  // 不走构造函数（它会尝试建连接），直接拿原型方法验证参数校验。
  // 这个校验必须在拼命令之前触发，否则 true 会变成 "UID FETCH true (...)"。
  const fake = { _command: () => Promise.resolve({ text: '' }) };
  for (const bad of [true, 'abc', 0, -1, null, undefined, 1.5]) {
    await assert.rejects(
      () => imap.ImapClient.prototype.fetchBody.call(fake, { uid: bad }),
      /正整数 uid/,
      'uid=' + JSON.stringify(bad) + ' 应被拒绝'
    );
  }
});

tAsync('fetchBody 用 UID FETCH 且拼入正确数字', async () => {
  let sent = '';
  const fake = { _command: cmd => { sent = cmd; return Promise.resolve({ text: '' }); } };
  await imap.ImapClient.prototype.fetchBody.call(fake, { uid: '28' });
  assert.ok(/^UID FETCH 28 \(/.test(sent), '实际命令: ' + sent);
  assert.ok(!/true|undefined|NaN/.test(sent), '命令里出现非数字: ' + sent);
});

console.log('\n=== 3. MIME 邮件解析 ===');
t('纯文本邮件', () => {
  const raw = 'Subject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World';
  const p = mail.parseMime(raw);
  assert.strictEqual(p.text.trim(), 'Hello World');
});
t('base64 正文', () => {
  const body = Buffer.from('中文内容', 'utf8').toString('base64');
  const raw = 'Subject: T\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' + body;
  const p = mail.parseMime(raw);
  assert.strictEqual(p.text.trim(), '中文内容');
});
t('multipart/alternative', () => {
  const raw = [
    'Subject: Multi',
    'Content-Type: multipart/alternative; boundary="BOUND"',
    '',
    '--BOUND',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'plain part',
    '--BOUND',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<b>html part</b>',
    '--BOUND--',
  ].join('\r\n');
  const p = mail.parseMime(raw);
  assert.ok(p.text.includes('plain part'), 'text 分支');
  assert.ok(p.html.includes('html part'), 'html 分支');
});
t('quoted-printable', () => {
  const raw = 'Subject: Q\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=E4=BD=A0=E5=A5=BD';
  const p = mail.parseMime(raw);
  assert.strictEqual(p.text.trim(), '你好');
});

// 回归：8bit 传输编码的中文正文曾经全部乱码。
// 原因是解码分支用 Buffer.from(bodyRaw, 'binary')——latin1 会把每个
// UTF-8 多字节字符硬截成一个字节，中文变成替换字符和控制字符。
// 真实邮件（微软安全通知、绝大多数客户端发出的邮件）大量使用 8bit，
// 这个 bug 影响面是所有中文邮件正文。
t('8bit 编码的中文正文不乱码', () => {
  const raw = [
    'Subject: T',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    '以下安全信息已从 Microsoft 帐户中删除',
  ].join('\r\n');
  const p = mail.parseMime(raw);
  assert.ok(/[一-龥]/.test(p.text), '应含中文，实际: ' + JSON.stringify(p.text));
  assert.ok(!p.text.includes('�'), '不应含替换字符 U+FFFD');
  assert.ok(p.text.includes('以下安全信息'), '正文内容应正确，实际: ' + JSON.stringify(p.text));
});

t('无 Content-Transfer-Encoding 头时中文不乱码', () => {
  const raw = [
    'Subject: T',
    'Content-Type: text/plain; charset=utf-8',
    '',
    '中文正文测试',
  ].join('\r\n');
  const p = mail.parseMime(raw);
  assert.ok(/[一-龥]/.test(p.text), '应含中文，实际: ' + JSON.stringify(p.text));
  assert.ok(!p.text.includes('�'), '不应含替换字符');
});

t('multipart 里的 8bit 中文分段不乱码', () => {
  const raw = [
    'Subject: Multi',
    'Content-Type: multipart/alternative; boundary="B"',
    '',
    '--B',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    '纯文本中文',
    '--B',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    '<p>HTML 中文</p>',
    '--B--',
  ].join('\r\n');
  const p = mail.parseMime(raw);
  assert.ok(p.text.includes('纯文本中文'), 'text 分支: ' + JSON.stringify(p.text));
  assert.ok(p.html.includes('HTML 中文'), 'html 分支: ' + JSON.stringify(p.html));
});

// 回归：literal 提取（extractLiteral）曾经用 indexOf('{') + indexOf('}') 定位，
// 切点落在声明中间；而且按字符数切而非字节数切，多字节字符会被截断。
// 现在协议层直接保留原始 Buffer（literalBuf），必须确保这条路径存在且正确。
t('imap-client 为 literal 保留原始字节', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, 'lib', 'imap-client.js'), 'utf8');
  assert.ok(/literalBuf/.test(src), '应保留 literal 的原始 Buffer');
  assert.ok(/literalBuf:\s*null/.test(src) || /literalBuf\s*=\s*null/.test(src),
    '_current 初始化应带 literalBuf 字段');
});

t('mail.js 优先使用 literalBuf 而不是按字符切', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, 'lib', 'mail.js'), 'utf8');
  assert.ok(/r\.literalBuf/.test(src), 'getMessage 应优先用 literalBuf');
  assert.ok(/Buffer\.from\(bodyRaw,\s*'utf8'\)/.test(src),
    '8bit/无编码分支必须按 utf8 转 Buffer');
  assert.ok(!/Buffer\.from\(bodyRaw,\s*'binary'\)/.test(src),
    '不得再用 binary(latin1) 转 Buffer，那会把中文截断');
});

// 回归：微软偶尔对完全正常的账号返回
// "A1 NO User is authenticated but not connected."
// 实测 100 个账号里 3 个报这个错，其中 2 个隔几秒重试就通过。
// 不重试会把好账号误判成坏账号，所以这条必须重试。
t('IMAP 认证重试逻辑已实现', () => {
  assert.ok(typeof mail.authenticateWithRetry === 'function', '应导出 authenticateWithRetry');
  const src = require('fs').readFileSync(require('path').join(__dirname, 'lib', 'mail.js'), 'utf8');
  assert.ok(/User is authenticated but not connected/.test(src), '应识别这条微软错误');
  assert.ok(/AUTH_RETRY_DELAYS/.test(src), '应有重试间隔');
  // 关键：重试必须重建连接。实测同一连接上反复 AUTHENTICATE 不一定管用，
  // 被拒的是这次 TCP 会话状态。
  assert.ok(/async function connectAndAuth/.test(src), '应有重建连接的重试封装');
  // new ImapClient 必须在 connectAndAuth 的 for 循环体内——每轮重试新建一条连接
  const fnBody = src.slice(src.indexOf('async function connectAndAuth'),
                           src.indexOf('async function withImap'));
  const loopStart = fnBody.indexOf('for (');
  const clientNew = fnBody.indexOf('new ImapClient(');
  assert.ok(loopStart > -1 && clientNew > loopStart,
    'new ImapClient 必须在重试循环内，否则重试复用的是同一条连接');
  // withImap 和 checkAccount 都必须走 connectAndAuth
  const uses = (src.match(/connectAndAuth\(/g) || []).length;
  assert.ok(uses >= 3, 'connectAndAuth 应有定义 + 至少 2 处调用，实际 ' + uses + ' 次');
  // bulk-scan 也要重连重试
  const bs = require('fs').readFileSync(require('path').join(__dirname, 'lib', 'bulk-scan.js'), 'utf8');
  assert.ok(/User is authenticated but not connected/.test(bs), 'bulk-scan 也应识别这条错误并重试');
});

t('该错误有明确的中文归类', () => {
  const e = new Error('IMAP 命令失败：A1 NO User is authenticated but not connected.');
  const s = mail.classifyError(e);
  assert.ok(s.includes('IMAP'), '归类应提到 IMAP，实际: ' + s);
  assert.ok(s.includes('重试') || s.includes('关闭'), '应提示可重试或 IMAP 被关闭，实际: ' + s);
});

console.log('\n=== 4. 邮件构造（发送）===');
t('纯文本邮件', () => {
  const m = smtp.buildMessage({
    from: 'a@b.com', to: ['c@d.com'], subject: 'Hi', text: 'Body',
  });
  assert.ok(m.includes('From: <a@b.com>') || m.includes('From: a@b.com'));
  assert.ok(m.includes('To: c@d.com'));
  assert.ok(m.includes('Content-Type: text/plain'));
});
t('中文主题用 RFC2047 编码', () => {
  const m = smtp.buildMessage({
    from: 'a@b.com', to: ['c@d.com'], subject: '中文主题', text: 'x',
  });
  assert.ok(/Subject: =\?UTF-8\?B\?/.test(m), '应编码');
});
t('纯 ASCII 主题不编码', () => {
  const m = smtp.buildMessage({
    from: 'a@b.com', to: ['c@d.com'], subject: 'Plain Subject', text: 'x',
  });
  assert.ok(m.includes('Subject: Plain Subject'));
});
t('text+html 双版本', () => {
  const m = smtp.buildMessage({
    from: 'a@b.com', to: ['c@d.com'], subject: 'S', text: 'T', html: '<p>H</p>',
  });
  assert.ok(m.includes('multipart/alternative'));
});

console.log('\n=== 5. 加密存储 ===');
const os = require('os');
const path = require('path');
const fs = require('fs');

t('写入→读取往返', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-'));
  const v = new Vault(dir);
  v.save([{
    id: 'x1', email: 'test@outlook.com',
    secrets: { clientId: 'cid-123', refreshToken: 'rt-secret-abc', endpoint: 'consumers' },
  }]);
  const back = v.all();
  assert.strictEqual(back.length, 1);
  assert.strictEqual(back[0].email, 'test@outlook.com');
  assert.strictEqual(back[0].secrets.refreshToken, 'rt-secret-abc');
  fs.rmSync(dir, { recursive: true, force: true });
});

t('磁盘上不出现明文凭据', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-'));
  const v = new Vault(dir);
  v.save([{
    id: 'x1', email: 'test@outlook.com',
    secrets: { clientId: 'cid-SECRET', refreshToken: 'rt-TOPSECRET' },
  }]);
  const onDisk = fs.readFileSync(path.join(dir, 'accounts.enc'), 'utf8');
  assert.ok(!onDisk.includes('rt-TOPSECRET'), 'refresh_token 不应以明文出现');
  assert.ok(!onDisk.includes('cid-SECRET'), 'client_id 不应以明文出现');
  // 邮箱是**故意**明文存的（它是元数据，导出清单时需要它，且不是凭据）。
  // 原来这里写成 `!onDisk.includes(...) || true`——恒真，永远不可能失败，
  // 读起来却像"测过了邮箱不明文"。改成正向断言，把设计意图说清楚。
  assert.ok(onDisk.includes('test@outlook.com'),
    '邮箱地址应明文留存（元数据，不是凭据；导出清单依赖它）');
  fs.rmSync(dir, { recursive: true, force: true });
});

t('删除账户', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-'));
  const v = new Vault(dir);
  v.save([{ id: 'a', email: 'a@x.com', secrets: { refreshToken: 'r' } }]);
  v.remove('a');
  assert.strictEqual(v.all().length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

console.log('\n=== 6. 错误归类 ===');
t('invalid_grant', () => {
  const e = new Error('invalid_grant'); e.oauthError = 'invalid_grant';
  assert.ok(mail.classifyError(e).includes('失效'));
});
t('service abuse', () => {
  const e = new Error('User account is found to be in service abuse mode');
  e.oauthError = 'invalid_grant';
  assert.ok(mail.classifyError(e).includes('封禁'));
});
t('未知错误有兜底', () => {
  assert.strictEqual(mail.classifyError(new Error('random')), '未知错误');
});

console.log('\n=== 7. 路径穿越防护（静态文件）===');
t('server.js 含路径校验', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  assert.ok(src.includes('startsWith(base + path.sep)'), '应有前缀校验');
  assert.ok(src.includes("'127.0.0.1'"), '应只绑定回环地址');
  assert.ok(src.includes('timingSafeEqual'), 'token 比较应用常量时间');
  assert.ok(!/rejectUnauthorized:\s*false/.test(src), '不应关闭证书校验');
});
t('前端使用转义函数', () => {
  const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  assert.ok(src.includes('function esc('), '应有 esc 函数');
  assert.ok(src.includes('sandbox'), '邮件 HTML 应进 sandbox iframe');
});
t('lib 中无 rejectUnauthorized:false', () => {
  for (const f of ['imap-client.js', 'mail.js', 'smtp.js']) {
    const src = fs.readFileSync(path.join(__dirname, 'lib', f), 'utf8');
    assert.ok(!/rejectUnauthorized:\s*false/.test(src), f + ' 不应关闭证书校验');
  }
});

// 回归：IMAP 命令注入必须在协议层统一拦截。
// 之前只有 select() 自己转义，其余调用点（fetch 的 seqSet/items、将来新增的 SEARCH）
// 全靠调用方自觉，漏一个就能注入 `...\r\nA9 DELETE "INBOX"`。
tAsync('_command 拒绝含 CR/LF 的命令', async () => {
  const c = new imap.ImapClient({ host: 'x', port: 1, auth: {}, timeout: 1 });
  c.socket = { destroyed: false, write: () => { throw new Error('不应该写出去'); } };
  for (const bad of ['SEARCH SUBJECT "x"\r\nA9 DELETE "INBOX"', 'FETCH 1\nX', 'A\rB', 'A\nB']) {
    await assert.rejects(() => c._command(bad), /换行符/, '应拒绝: ' + JSON.stringify(bad));
  }
});

tAsync('_command 放行正常命令', async () => {
  const c = new imap.ImapClient({ host: 'x', port: 1, auth: {}, timeout: 1 });
  let written = '';
  c.socket = { destroyed: false, write: s => { written += s; } };
  const p = c._command('SELECT "INBOX"');
  assert.ok(written.startsWith('A1 SELECT "INBOX"\r\n'), '实际写出: ' + JSON.stringify(written));
  c.pending.get('A1').resolve({ text: '' });
  await p;
});

// 回归：批量删除必须是 O(N) 一次落盘，不能逐条删。
// 逐条 vault.remove 每次全库解密+加密落盘，删 100 个能卡死几十秒。
t('account.remove 使用 removeMany 一次性落盘', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  const start = src.indexOf("case 'account.remove'");
  const end = src.indexOf("case 'account.check'");
  assert.ok(start > 0 && end > start, '应能定位 account.remove 分支');
  const block = src.slice(start, end);
  assert.ok(/vault\.removeMany\s*\(/.test(block), '应调用 vault.removeMany');
  assert.ok(!/forEach\([^)]*=>\s*vault\.remove\s*\(/.test(block), '不应逐条调用 vault.remove');
});

console.log('\n=== 8. 验证码提取 ===');
const { extractCode } = require('./lib/code-extractor');

const codeCases = [
  ['中文标准', '【某某】您的验证码是 483920，5分钟内有效', '483920'],
  ['英文', 'Your verification code is 748291.', '748291'],
  ['GitHub', '[GitHub] Your one-time code: 392817', '392817'],
  ['Steam混合码', 'Steam Guard\nYour Steam Guard code is: K7X9P2', 'K7X9P2'],
  ['正文独立数字', '登录验证\n\n576243\n\n此验证码 10 分钟内有效', '576243'],
  ['带空格', '验证码：592 104', '592 104'],
  ['干扰日期', '订单日期 2026-11-03，验证码是 883421', '883421'],
  ['干扰金额', '本次消费 ¥1,299.00，验证码 665544', '665544'],
  ['干扰时间', '发送时间 14:30:25，您的验证码为 771239', '771239'],
  ['干扰长数字', '订单号 20261103123456，验证码 990011', '990011'],
  ['占位符', '您的验证码是 000000', null],
  ['年份陷阱', 'Copyright 2026 All rights reserved. 验证码 445566', '445566'],
  ['无验证码', '这是一封普通的营销邮件。', null],
  ['HTML', '<div><p>您的验证码</p><h1>817263</h1></div>', '817263'],
  ['输入提示', 'Please enter 663311 in the app.', '663311'],
  ['纯字母不误判', 'Your security code policy is important.', null],
];

for (const [name, input, expect] of codeCases) {
  t('验证码/' + name, () => {
    const r = extractCode(input);
    const got = r ? r.code : null;
    assert.strictEqual(got, expect);
  });
}

console.log('\n=== 9. 剪贴板与前端 ===');
t('前端有 copyText 实现', () => {
  const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  assert.ok(src.includes('function copyText'), '应有 copyText');
  assert.ok(src.includes('navigator.clipboard'), '应优先用 Clipboard API');
  assert.ok(src.includes('execCommand'), '应有兜底');
});
t('前端有自动复制开关', () => {
  const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  assert.ok(src.includes('autoCopy'), '应有 autoCopy 状态');
});
t('验证码渲染前已转义', () => {
  const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  const m = src.match(/code-row-value">\$\{([^}]+)\}/);
  assert.ok(m && m[1].includes('esc('), '验证码插入 HTML 前必须 esc()');
});

console.log('\n=== 10. 端点自动探测 ===');
const mailMod = require('./lib/mail');

t('导出了 refreshAccessTokenAuto', () => {
  assert.strictEqual(typeof mailMod.refreshAccessTokenAuto, 'function');
});
t('候选端点包含 4 种', () => {
  const keys = mailMod.ENDPOINT_CANDIDATES.map(e => e.key);
  assert.deepStrictEqual(keys, ['consumers', 'common', 'organizations', 'live']);
});
t('normalizeEndpoint 处理非法值', () => {
  const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  assert.ok(src.includes('function normalizeEndpoint'), '应有该函数');
  assert.ok(src.includes("'auto'"), '应支持 auto');
});
t('AADSTS7000012 有专门归类', () => {
  const e = new Error('AADSTS7000012: The grant was obtained for a different tenant.');
  e.aadsts = 'AADSTS7000012';
  const r = mailMod.classifyError(e);
  assert.ok(r.includes('租户') && r.includes('tenant'), '应提示填 tenant ID：' + r);
});
t('AADSTS40016 有专门归类', () => {
  const e = new Error('AADSTS40016');
  e.aadsts = 'AADSTS40016';
  assert.ok(mailMod.classifyError(e).includes('组织端点'));
});
t('致命错误不重试其他端点', () => {
  const src = fs.readFileSync(path.join(__dirname, 'lib', 'mail.js'), 'utf8');
  assert.ok(/AADSTS70000/.test(src) && /break;/.test(src), '应有短路逻辑');
});
t('支持自定义 tenant', () => {
  const src = fs.readFileSync(path.join(__dirname, 'lib', 'mail.js'), 'utf8');
  assert.ok(/encodeURIComponent\(tenant\)/.test(src), 'tenant 应被 URL 编码');
});

console.log('\n=== 11. refresh_token 轮换持久化 ===');

/** 造一个假账户（不联网、不碰真实账户库） */
function fakeAccount(extra = {}) {
  return {
    id: 'acc-' + Math.random().toString(36).slice(2, 10),
    email: 't@outlook.com',
    secrets: {
      clientId: 'cid-test',
      refreshToken: 'RT-OLD-0000',
      password: 'pw-should-survive',
      endpoint: 'consumers',
      tenant: '',
      migrated4: true,
      refreshTokenRotated: false,
      ...(extra.secrets || {}),
    },
    ...extra,
  };
}

/** 假的兑换实现：记录调用次数，返回新的 refresh_token */
function fakeExchange(state) {
  return async () => {
    state.calls++;
    const n = state.calls;
    return {
      accessToken: 'AT-' + n,
      expiresIn: 3600,
      refreshToken: 'RT-NEW-' + n,
      scope: 'scope',
      endpointUsed: 'consumers',
    };
  };
}

(async function asyncTests() {
  // --- 轮换会被写回 ---
  await tAsync('刷新返回新 refresh_token 时会写回账户库', async () => {
    const acc = fakeAccount();
    const state = { calls: 0 };
    const writes = [];
    const r = await mailMod.getAccessToken(acc, {
      _exchange: fakeExchange(state),
      persistRefreshToken: async (a, newToken, prevToken) => { writes.push({ newToken, prevToken }); },
    });
    assert.strictEqual(state.calls, 1, '应只兑换一次');
    assert.strictEqual(writes.length, 1, '应写回一次');
    assert.strictEqual(writes[0].newToken, 'RT-NEW-1', '写回的应是新令牌');
    assert.strictEqual(writes[0].prevToken, 'RT-OLD-0000', '应把旧令牌一并交出去');
    assert.strictEqual(r.newRefreshToken, 'RT-NEW-1');
    assert.strictEqual(r.refreshTokenRotated, true);
    assert.strictEqual(acc.secrets.refreshToken, 'RT-NEW-1', '内存对象也应同步');
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('持久化发生在返回之前', async () => {
    const acc = fakeAccount();
    const order = [];
    const r = await mailMod.getAccessToken(acc, {
      _exchange: async () => {
        order.push('exchange');
        return { accessToken: 'AT', expiresIn: 3600, refreshToken: 'RT-NEW-X', endpointUsed: 'consumers' };
      },
      persistRefreshToken: async () => { order.push('persist'); },
    });
    order.push('returned');
    assert.deepStrictEqual(order, ['exchange', 'persist', 'returned'],
      '顺序应为 兑换 → 落盘 → 返回，实际：' + order.join(' → '));
    assert.ok(r.accessToken);
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('服务端没返回新令牌时不重复写盘', async () => {
    const acc = fakeAccount();
    const state = { calls: 0 };
    const writes = [];
    await mailMod.getAccessToken(acc, {
      _exchange: async () => {
        state.calls++;
        return { accessToken: 'AT-1', expiresIn: 3600, refreshToken: null, endpointUsed: 'consumers' };
      },
      persistRefreshToken: async () => { writes.push(1); },
    });
    assert.strictEqual(writes.length, 0, '没轮换就不该写盘');
    mailMod.clearTokenCache(acc.id);
  });

  // --- 并发串行化 ---
  await tAsync('同一账户两次并发调用只兑换一次', async () => {
    const acc = fakeAccount();
    const state = { calls: 0 };
    const writes = [];
    const opts = () => ({
      // 故意加点延迟，逼出真实的并发窗口
      _exchange: async (args) => {
        state.calls++;
        await new Promise(r => setTimeout(r, 40));
        return {
          accessToken: 'AT-C', expiresIn: 3600,
          refreshToken: 'RT-CONCURRENT-NEW', endpointUsed: 'consumers', sawToken: args.refreshToken,
        };
      },
      persistRefreshToken: async (a, n) => { writes.push(n); },
    });
    const [r1, r2] = await Promise.all([
      mailMod.getAccessToken(acc, opts()),
      mailMod.getAccessToken(acc, opts()),
    ]);
    assert.strictEqual(state.calls, 1, '应只有一次网络兑换，实际 ' + state.calls);
    assert.strictEqual(writes.length, 1, '应只写回一次');
    assert.strictEqual(writes[0], 'RT-CONCURRENT-NEW', '写回的必须是最新令牌');
    assert.strictEqual(r1.accessToken, r2.accessToken, '两次应拿到同一个 access_token');
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('并发时第二次走缓存而不是再兑换', async () => {
    const acc = fakeAccount();
    let calls = 0;
    const exchange = async () => {
      calls++;
      await new Promise(r => setTimeout(r, 30));
      return { accessToken: 'AT-Z', expiresIn: 3600, refreshToken: 'RT-Z', endpointUsed: 'consumers' };
    };
    const persist = async () => {};
    const results = await Promise.all(
      Array.from({ length: 5 }, () => mailMod.getAccessToken(acc, { _exchange: exchange, persistRefreshToken: persist }))
    );
    assert.strictEqual(calls, 1, '5 个并发只应有 1 次兑换，实际 ' + calls);
    assert.ok(results.every(r => r.accessToken === 'AT-Z'), '都应拿到同一 token');
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('不同账户互不阻塞', async () => {
    const a1 = fakeAccount();
    const a2 = fakeAccount();
    let calls = 0;
    const exchange = async () => {
      calls++;
      await new Promise(r => setTimeout(r, 25));
      return { accessToken: 'AT-' + calls, expiresIn: 3600, refreshToken: 'RT-' + calls, endpointUsed: 'consumers' };
    };
    const persist = async () => {};
    await Promise.all([
      mailMod.getAccessToken(a1, { _exchange: exchange, persistRefreshToken: persist }),
      mailMod.getAccessToken(a2, { _exchange: exchange, persistRefreshToken: persist }),
    ]);
    assert.strictEqual(calls, 2, '两个不同账户应各自兑换一次');
    mailMod.clearTokenCache(a1.id);
    mailMod.clearTokenCache(a2.id);
  });

  // --- 写盘失败必须冒泡 ---
  await tAsync('写盘失败时错误不被吞掉', async () => {
    const acc = fakeAccount();
    let caught = null;
    try {
      await mailMod.getAccessToken(acc, {
        _exchange: async () => ({
          accessToken: 'AT-F', expiresIn: 3600,
          refreshToken: 'RT-LOST', endpointUsed: 'consumers',
        }),
        persistRefreshToken: async () => { throw new Error('磁盘只读'); },
      });
    } catch (e) { caught = e; }
    assert.ok(caught, '必须抛出异常，不能静默成功');
    assert.strictEqual(caught.code, 'REFRESH_TOKEN_PERSIST_FAILED', '应有明确错误码');
    assert.ok(/RT-LOST/.test(caught.message) === false, '错误信息不得包含令牌明文');
    assert.ok(/轮换/.test(caught.message), '应说明令牌已被轮换：' + caught.message);
    assert.ok(/磁盘只读/.test(caught.message), '应带上底层原因');
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('写盘失败后不缓存 access_token', async () => {
    const acc = fakeAccount();
    let calls = 0;
    const exchange = async () => {
      calls++;
      return { accessToken: 'AT-R', expiresIn: 3600, refreshToken: 'RT-R-' + calls, endpointUsed: 'consumers' };
    };
    await assert.rejects(
      mailMod.getAccessToken(acc, {
        _exchange: exchange,
        persistRefreshToken: async () => { throw new Error('写失败'); },
      })
    );
    // 第二次必须真的重试兑换，而不是命中缓存假装成功
    await assert.rejects(
      mailMod.getAccessToken(acc, {
        _exchange: exchange,
        persistRefreshToken: async () => { throw new Error('写失败'); },
      })
    );
    assert.strictEqual(calls, 2, '失败不应被缓存掩盖，应重新尝试兑换');
    mailMod.clearTokenCache(acc.id);
  });

  await tAsync('没有持久化回调时拒绝刷新', async () => {
    const acc = fakeAccount();
    let exchanged = false;
    let caught = null;
    try {
      await mailMod.getAccessToken(acc, {
        _exchange: async () => { exchanged = true; throw new Error('不该走到这里'); },
        persistRefreshToken: null,
      });
    } catch (e) { caught = e; }
    // 注意：全局持久化器可能已被 server 注入，这里只验证"缺失时不会静默销毁凭据"
    if (caught) {
      assert.strictEqual(caught.code, 'REFRESH_TOKEN_NO_PERSISTER');
      assert.strictEqual(exchanged, false, '没有持久化能力就不应发起兑换');
    }
    mailMod.clearTokenCache(acc.id);
  });

  // --- 与真实 Vault 的集成（临时目录）---
  await tAsync('Vault 写回只动 refresh_token，其余字段原样保留', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{
        id: 'r1', email: 'r@outlook.com', status: 'ok',
        secrets: {
          clientId: 'CID-KEEP', refreshToken: 'RT-OLD', password: 'PW-KEEP',
          endpoint: 'consumers', tenant: '', migrated4: true, refreshTokenRotated: false,
        },
      }]);
      const r = v.updateRefreshToken('r1', 'RT-NEW', 'RT-OLD');
      assert.strictEqual(r.applied, true);
      const back = v.find('r1');
      assert.strictEqual(back.secrets.refreshToken, 'RT-NEW', '应写入新令牌');
      assert.strictEqual(back.secrets.clientId, 'CID-KEEP', 'clientId 不能被破坏');
      assert.strictEqual(back.secrets.password, 'PW-KEEP', 'password 不能被破坏');
      assert.strictEqual(back.secrets.migrated4, true, 'migrated4 标记不能被破坏');
      assert.strictEqual(back.secrets.refreshTokenRotated, true, '应打上轮换标记');
      assert.strictEqual(back.status, 'ok', 'status 不能被破坏');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('Vault 里已是新值时幂等', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 'i1', email: 'i@x.com', secrets: { refreshToken: 'RT-SAME', clientId: 'c' } }]);
      const r = v.updateRefreshToken('i1', 'RT-SAME', 'RT-ANYTHING');
      assert.strictEqual(r.applied, true);
      assert.strictEqual(r.reason, 'already-current');
      assert.strictEqual(v.find('i1').secrets.refreshToken, 'RT-SAME');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('Vault 里有更新的令牌时不回退覆盖', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 's1', email: 's@x.com', secrets: { refreshToken: 'RT-NEWEST', clientId: 'c' } }]);
      // 拿着过期快照（以为库里是 RT-OLD）想写 RT-MINE
      const r = v.updateRefreshToken('s1', 'RT-MINE', 'RT-OLD');
      assert.strictEqual(r.applied, false, '不应覆盖更新的值');
      assert.strictEqual(r.reason, 'vault-has-different-token');
      assert.strictEqual(r.currentToken, 'RT-NEWEST', '应把库里的现值交还');
      assert.strictEqual(v.find('s1').secrets.refreshToken, 'RT-NEWEST', '库里的值不能被回退');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('账户已删除时不复活', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 'keep', email: 'k@x.com', secrets: { refreshToken: 'RT' } }]);
      const r = v.updateRefreshToken('gone', 'RT-NEW', 'RT-OLD');
      assert.strictEqual(r.skipped, true);
      assert.strictEqual(r.reason, 'account-not-found');
      assert.strictEqual(v.all().length, 1, '不应凭空多出账户');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('updateMeta 不会碰 secrets', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 'm1', email: 'm@x.com', secrets: { refreshToken: 'RT-ROTATED', clientId: 'c', migrated4: true } }]);
      v.updateMeta('m1', { status: 'ok', statusMessage: 'fine', lastCheckedAt: 'now' });
      const b = v.find('m1');
      assert.strictEqual(b.secrets.refreshToken, 'RT-ROTATED', 'secrets 必须原样保留');
      assert.strictEqual(b.secrets.migrated4, true);
      assert.strictEqual(b.status, 'ok');
      assert.strictEqual(b.statusMessage, 'fine');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('updateMeta 拒绝写 secrets 字段', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-rot-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 'm2', email: 'm2@x.com', secrets: { refreshToken: 'RT-SAFE' } }]);
      v.updateMeta('m2', { secrets: { refreshToken: 'RT-EVIL' }, status: 'ok' });
      const b = v.find('m2');
      assert.strictEqual(b.secrets.refreshToken, 'RT-SAFE', 'secrets 不允许经 updateMeta 写入');
      assert.strictEqual(b.status, 'ok', '其他字段仍应更新');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('端到端：getAccessToken + 真实 Vault 落盘', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-e2e-'));
    try {
      const v = new Vault(dir);
      v.save([{
        id: 'e1', email: 'e1@outlook.com',
        secrets: {
          clientId: 'CID-E', refreshToken: 'RT-OLD-E', password: 'PW-E',
          endpoint: 'consumers', migrated4: true, refreshTokenRotated: false,
        },
      }]);
      const acc = v.find('e1');
      const persist = async (a, newTok, prevTok) => {
        const r = v.updateRefreshToken(a.id, newTok, prevTok);
        if (!r.applied) throw new Error('写回失败：' + r.reason);
        return r;
      };
      await mailMod.getAccessToken(acc, {
        _exchange: async () => ({
          accessToken: 'AT-E', expiresIn: 3600,
          refreshToken: 'RT-NEW-E', endpointUsed: 'consumers',
        }),
        persistRefreshToken: persist,
      });
      const disk = v.find('e1');
      assert.strictEqual(disk.secrets.refreshToken, 'RT-NEW-E', '真实落盘应持有新令牌');
      assert.strictEqual(disk.secrets.clientId, 'CID-E', 'clientId 保留');
      assert.strictEqual(disk.secrets.password, 'PW-E', 'password 保留');
      assert.strictEqual(disk.secrets.migrated4, true, 'migrated4 保留');
      assert.strictEqual(disk.secrets.refreshTokenRotated, true, '应打上轮换标记');
      // 落盘文件里不应出现明文令牌
      const onDisk = fs.readFileSync(path.join(dir, 'accounts.enc'), 'utf8');
      assert.ok(!onDisk.includes('RT-NEW-E'), '新令牌不得以明文落盘');
      mailMod.clearTokenCache('e1');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await tAsync('clearTokenCache 后重新读账户会用新令牌', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-e2e-'));
    try {
      const v = new Vault(dir);
      v.save([{ id: 'c1', email: 'c1@x.com', secrets: { clientId: 'c', refreshToken: 'RT-1' } }]);
      const seen = [];
      const persist = async (a, n, p) => { v.updateRefreshToken(a.id, n, p); };
      const exchange = async (args) => {
        seen.push(args.refreshToken);
        return { accessToken: 'AT', expiresIn: 3600, refreshToken: 'RT-2', endpointUsed: 'consumers' };
      };
      await mailMod.getAccessToken(v.find('c1'), { _exchange: exchange, persistRefreshToken: persist });
      mailMod.clearTokenCache('c1');
      const acc2 = v.find('c1'); // 从磁盘重新读，模拟新进程/新请求
      await mailMod.getAccessToken(acc2, { _exchange: exchange, persistRefreshToken: persist });
      assert.deepStrictEqual(seen, ['RT-1', 'RT-2'], '第二次应使用落盘后的新令牌，实际：' + seen.join(','));
      mailMod.clearTokenCache('c1');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // --- 静态检查：调用方不得绕过持久化 ---
  t('server.js 注入了持久化回调', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(src.includes('setRefreshTokenPersister'), '应注入持久化回调');
    assert.ok(src.includes('updateRefreshToken'), '应走 Vault.updateRefreshToken');
  });
  t('server.js 不再直接调用 refreshAccessToken', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(!/mail\.refreshAccessToken\s*\(/.test(src),
      '直接调用会绕过轮换持久化，必须走 refreshAccountToken');
  });
  t('检查类接口不再整条 upsert（会用旧 secrets 覆盖轮换令牌）', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(src.includes('updateMeta'), '应只回写元数据');
    assert.ok(!/vault\.upsert\(acc\)/.test(src.slice(src.indexOf("case 'account.check'"))),
      'account.check 不得再整条 upsert');
  });

  // --- 真实 server.js 接线（最后跑：会安装全局持久化回调）---
  await tAsync('server.js 注入的回调能把轮换令牌写进真实 Vault', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-srv-'));
    const prevDir = process.env.MAILDESK_DATA_DIR;
    // 必须先设环境变量再 require：server.js 在模块加载时就构造了 Vault
    process.env.MAILDESK_DATA_DIR = dir;
    const srvPath = require.resolve('./server');
    delete require.cache[srvPath];
    try {
      require('./server'); // 安装 mail.setRefreshTokenPersister

      // 用 server.js 的那个 Vault 实例建一条账户
      const { Vault } = require('./lib/vault');
      const v = new Vault(dir);
      v.save([{
        id: 'srv1', email: 'srv1@outlook.com',
        secrets: {
          clientId: 'CID-SRV', refreshToken: 'RT-OLD-SRV', password: 'PW-SRV',
          endpoint: 'consumers', migrated4: true, refreshTokenRotated: false,
        },
      }]);

      // 不传 persistRefreshToken → 走 server.js 注入的全局回调
      const acc = v.find('srv1');
      await mailMod.getAccessToken(acc, {
        _exchange: async () => ({
          accessToken: 'AT-SRV', expiresIn: 3600,
          refreshToken: 'RT-NEW-SRV', endpointUsed: 'consumers',
        }),
      });

      const disk = v.find('srv1');
      assert.strictEqual(disk.secrets.refreshToken, 'RT-NEW-SRV', '全局回调应已落盘新令牌');
      assert.strictEqual(disk.secrets.clientId, 'CID-SRV', 'clientId 保留');
      assert.strictEqual(disk.secrets.password, 'PW-SRV', 'password 保留');
      assert.strictEqual(disk.secrets.migrated4, true, 'migrated4 保留');
      assert.strictEqual(disk.secrets.refreshTokenRotated, true, '应打上轮换标记');
      mailMod.clearTokenCache('srv1');
    } finally {
      mailMod.setRefreshTokenPersister(null); // 撤掉全局回调，避免影响后续
      delete require.cache[srvPath];
      if (prevDir === undefined) delete process.env.MAILDESK_DATA_DIR;
      else process.env.MAILDESK_DATA_DIR = prevDir;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  console.log('\n=== 12. 批量收码 job 管理器 ===');
  const jobs = require('./lib/jobs');

  t('jobs 模块加载', () => {
    assert.ok(jobs.createJob && jobs.getJob && jobs.runPool);
    assert.ok(jobs.beginTransaction && jobs.endTransaction && jobs.drainTransactions);
  });

  t('jobId 白名单拒绝危险输入', () => {
    for (const bad of ['__proto__', '../../../etc', 'x', '', null, 123, 'a'.repeat(200)]) {
      assert.strictEqual(jobs.isSafeId(bad), false, '应拒绝 ' + JSON.stringify(bad));
    }
  });

  t('createJob 初始状态正确', () => {
    const j = jobs.createJob('selftest-type', 7);
    assert.strictEqual(j.state, 'running');
    assert.strictEqual(j.total, 7);
    assert.strictEqual(j.done, 0);
    assert.deepStrictEqual(j.results, []);
    assert.deepStrictEqual(j.errors, []);
    j.state = 'done';
    jobs.finishJob(j);
  });

  // 回归：硬限曾经写死 15 分钟，而正常流程下 300 账号 / 25 秒超时 / 并发 3
  // 的队列最坏就要 42 分钟 —— 选满账号必然被截断，而且是「正常流程」被截断。
  // 这里直接测推导函数，不去等真定时器：断言的是"最坏情况也在硬限之内"。
  const SCAN_N = 300, SCAN_TIMEOUT = 25000, SCAN_LANES = 3;
  t('硬限推导：300 账号的大任务最坏耗时也在硬限之内', () => {
    const worst = Math.ceil(SCAN_N / SCAN_LANES) * SCAN_TIMEOUT;   // 42 分钟
    const limit = jobs.runningHardLimitMs(SCAN_N, SCAN_TIMEOUT, SCAN_LANES);
    assert.ok(limit > worst,
      '硬限 ' + jobs.hardLimitText(limit) + ' 必须大于最坏耗时 ' + jobs.hardLimitText(worst));
    // 且必须留出余量（建连、令牌写盘都在 25 秒之外），不能刚好等于
    assert.ok(limit - worst >= jobs.HARD_LIMIT_MARGIN_MIN_MS,
      '余量只有 ' + (limit - worst) + 'ms，不足以覆盖收尾开销');
  });

  t('硬限推导：小任务有下限，不会被算成几分钟就杀', () => {
    // 1 个账号 25 秒：纯按规模算只有 31 分钟以下，但必须有下限兜住
    const one = jobs.runningHardLimitMs(1, 25000, 3);
    assert.strictEqual(one, jobs.RUNNING_HARD_LIMIT_MIN_MS,
      '单账号任务应落到下限，实际 ' + one);
    // 0 个账号（空库点了批量）也不许算出 0 或负数
    assert.strictEqual(jobs.runningHardLimitMs(0, 25000, 3), jobs.RUNNING_HARD_LIMIT_MIN_MS);
  });

  t('硬限推导：被恶意构造的超大 total 不会撑成无限期占用', () => {
    // 单例锁唯一的兜底释放路径就是硬限，所以必须有上限
    const huge = jobs.runningHardLimitMs(1e9, 25000, 1);
    assert.strictEqual(huge, jobs.RUNNING_HARD_LIMIT_MAX_MS,
      '超大任务应钳到上限，实际 ' + huge);
    // 非法参数不能算出 NaN / Infinity（那样 setTimeout 会立刻触发或永不触发）
    for (const bad of [NaN, -1, null, undefined, 'x', Infinity]) {
      const v = jobs.runningHardLimitMs(300, bad, bad);
      assert.ok(Number.isFinite(v) && v >= jobs.RUNNING_HARD_LIMIT_MIN_MS && v <= jobs.RUNNING_HARD_LIMIT_MAX_MS,
        '参数 ' + String(bad) + ' 算出了 ' + v);
    }
  });

  t('硬限记在 job 上，且随 total 收缩不变（不会因跳过已删账户而提前杀）', () => {
    const j = jobs.createJob('limit-selftest', 300, { perAccountMs: 25000, concurrency: 3 });
    const limit = jobs.jobHardLimitMs(j);
    assert.ok(limit > Math.ceil(300 / 3) * 25000, '300 账号的 job 硬限应大于最坏耗时');
    // 扫到一半有账户被删：total 会缩小，但硬限不能跟着变小
    j.total = 10;
    assert.strictEqual(jobs.jobHardLimitMs(j), limit, '硬限不应随 total 收缩而改变');
    j.state = 'done';
    jobs.finishJob(j);
  });

  t('expireRunning 的文案用这个 job 自己的硬限，不再写死 15 分钟', () => {
    const j = jobs.createJob('limit-text', 300, { perAccountMs: 25000, concurrency: 3 });
    jobs.expireRunning(j);
    const expected = jobs.hardLimitText(jobs.runningHardLimitMs(300, 25000, 3));
    assert.ok(j.error.includes(expected), '文案里的分钟数应为 ' + expected + '，实际：' + j.error);
    assert.ok(!/15 分钟/.test(j.error), '不应再出现写死的 15 分钟：' + j.error);
    j.state = 'failed';
    jobs.finishJob(j);
  });

  t('幂等锁：running 时 findRunning 能拿到', () => {
    const j = jobs.createJob('lock-selftest', 3);
    const found = jobs.findRunning('lock-selftest');
    assert.ok(found && found.id === j.id, '应返回同一个 job');
    assert.strictEqual(jobs.findRunning('other-type'), null, '不同类型互不影响');
    j.state = 'done';
    jobs.finishJob(j);
    assert.strictEqual(jobs.findRunning('lock-selftest'), null, '收尾后应释放');
  });

  await tAsync('runPool 保持结果顺序且失败不中断', async () => {
    const seen = [];
    const r = await jobs.runPool([1, 2, 3, 4], 2, async x => {
      seen.push(x);
      if (x === 2) throw new Error('模拟失败');
      return { ok: true, x };
    });
    assert.strictEqual(r.length, 4);
    assert.strictEqual(r[0].x, 1);
    assert.strictEqual(r[1].ok, false, '抛错的应被收成 ok:false');
    assert.strictEqual(r[2].x, 3, '顺序必须与输入一致');
    assert.strictEqual(r[3].x, 4);
    assert.strictEqual(seen.length, 4, '单个失败不应中断整批');
  });

  await tAsync('runPool 可取消，已在飞行的自然结束', async () => {
    let cancelled = false;
    const started = [];
    const r = await jobs.runPool([1, 2, 3, 4, 5, 6], 2, async x => {
      started.push(x);
      return { ok: true, x };
    }, {
      isCancelled: () => cancelled,
      onItem: res => { if (res.x === 2) cancelled = true; },
    });
    assert.ok(started.length < 6, '取消后不应再取新任务，实际取了 ' + started.length);
    assert.strictEqual(r.length, 6, '结果数组长度仍等于输入长度');
  });

  t('在途事务计数：begin/end 成对', () => {
    const before = jobs.pendingTransactions();
    const e1 = jobs.beginTransaction();
    const e2 = jobs.beginTransaction();
    assert.strictEqual(jobs.pendingTransactions(), before + 2);
    e1(); e2();
    assert.strictEqual(jobs.pendingTransactions(), before);
  });

  await tAsync('drainTransactions 无在途时立即返回', async () => {
    const t0 = Date.now();
    const ok = await jobs.drainTransactions(1000);
    assert.strictEqual(ok, true);
    assert.ok(Date.now() - t0 < 300, '耗时 ' + (Date.now() - t0) + 'ms，应立即返回');
  });

  await tAsync('drainTransactions 有在途时会等待', async () => {
    const end = jobs.beginTransaction();
    setTimeout(() => end(), 180);
    const t0 = Date.now();
    const ok = await jobs.drainTransactions(3000);
    const waited = Date.now() - t0;
    assert.strictEqual(ok, true, '应在超时前等到');
    assert.ok(waited >= 120, '应真的等待了，实际 ' + waited + 'ms');
  });

  t('服务端接入了退出协调', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(src.includes('drainTransactions'), '退出前应等待在途事务');
    assert.ok(/SIGBREAK/.test(src), 'Windows 关闭控制台发 SIGBREAK，必须接管');
    assert.ok(/uncaughtException/.test(src), '必须接管未捕获异常，否则后台刷新中途崩溃会丢令牌');
    assert.ok(/unhandledRejection/.test(src), '必须接管未处理拒绝');
  });

  t('bulk-scan 不绕过 getAccessToken（否则毁账号）', () => {
    const src = fs.readFileSync(path.join(__dirname, 'lib', 'bulk-scan.js'), 'utf8');
    assert.ok(/getAccessToken/.test(src), '必须走 mail.getAccessToken');
    assert.ok(!/login\.microsoftonline/.test(src), '不得自己拼 OAuth 端点');
    assert.ok(!/https\.request/.test(src), '不得自己发 HTTP 请求换 token');
  });

  t('批量收码的三个 action 已注册', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    for (const a of ['codes.scan.start', 'codes.scan.status', 'codes.scan.cancel']) {
      assert.ok(src.includes(`case '${a}'`), '缺少 ' + a);
    }
    assert.ok(src.indexOf("case 'codes.scan.start'") > src.indexOf("case 'account.diagnose'"),
      '新 case 必须在 account.diagnose 之后');
  });

  // 回归：读信成功后必须把账号状态校正成"可用"。
  // 之前只有 account.check/checkAll 会写状态，读信路径不写。结果是
  // 全部检测时被微软瞬时拒绝、标成异常的账号，用户点开后邮件明明能读，
  // 侧栏却一直显示异常，只能再跑一次全部检测才能纠正。
  t('读信路径会校正账号状态', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(/function markAccountHealthy/.test(src), '应有状态校正辅助函数');
    // 三个读信入口都要调用
    for (const action of ['folders', 'messages', 'message']) {
      const i = src.indexOf(`case '${action}'`);
      assert.ok(i > 0, '缺少 case ' + action);
      // 取该 case 到下个 case 之间的片段
      const next = src.indexOf('case \'', i + 10);
      const block = src.slice(i, next > i ? next : i + 2000);
      assert.ok(/markAccountHealthy\(/.test(block), action + ' 分支应调用 markAccountHealthy');
    }
    // 必须只写元数据，不能整条 upsert（会覆盖轮换后的 refresh_token）
    const fn = src.slice(src.indexOf('function markAccountHealthy'), src.indexOf('function scanCodeView'));
    assert.ok(/vault\.updateMeta\(/.test(fn), '应走 updateMeta 只写元数据');
    assert.ok(!/vault\.upsert\(acc\)/.test(fn), '不得整条 upsert，否则会覆盖刚轮换的 refresh_token');
  });

  t('前端切账户后会对异常账号重拉列表', () => {
    const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    // 选中账户后、以及刷新成功后，若本地状态不是 ok 就 loadAccounts()
    const hits = (src.match(/status !== 'ok'[\s\S]{0,120}loadAccounts\(\)/g) || []).length;
    assert.ok(hits >= 2, '选中账户与刷新成功后都应重拉列表，实际匹配 ' + hits + ' 处');
  });

  // 回归：服务端错误响应同时带 error（细节）和 reason（归类），两个都脱敏过。
  // 前端此前只读 error，reason 算完就被丢掉 —— 于是 500 类错误只剩下
  // "服务器内部错误"，而"网络超时 / 令牌失效"这类归类就在响应里没人展示。
  t('前端 api() 会读出 err.reason 并传给展示层', () => {
    const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    const i = src.indexOf('async function api(');
    assert.ok(i > 0, '应能定位 api()');
    const block = src.slice(i, src.indexOf('\nfunction ', i + 10));
    assert.ok(/err\.reason\s*=\s*data && data\.reason != null/.test(block),
      'api() 必须把 data.reason 挂到 err 上，否则服务端算好的归类白算');
    // 不许改写 message：批量收码轮询等分支按 message 文本判断
    assert.ok(!/err\.message\s*=/.test(block), 'api() 不得改写 err.message 的语义');

    // errText 是唯一把 reason 融进展示文案的地方：有内容且与 message
    // 不同才追加，避免出现"超时（超时）"这种重复。
    const e = src.indexOf('function errText(');
    assert.ok(e > 0, '应有 errText 展示辅助函数');
    const helper = src.slice(e, src.indexOf('\nfunction ', e + 10));
    assert.ok(/reason === msg/.test(helper), 'reason 与 message 相同时不应重复追加');
    // 展示层真的用上了它（绝不是定义了却没人调）
    const uses = (src.match(/errText\(/g) || []).length;
    assert.ok(uses >= 6, 'errText 应被多处展示路径使用，实际只有 ' + (uses - 1) + ' 处');
  });

  console.log('\n=== 13. 验证码历史 ===');
  const osMod = require('os');
  const histDir = fs.mkdtempSync(path.join(osMod.tmpdir(), 'maildesk-hist-test-'));
  const { History } = require('./lib/history');

  t('History 模块加载', () => {
    assert.ok(typeof History === 'function');
    const v = new Vault(histDir);
    const h = new History(v, path.join(histDir, 'history.enc'));
    assert.ok(h && typeof h.upsertMany === 'function');
  });

  t('历史加密落盘，磁盘无明文', () => {
    const v = new Vault(histDir);
    const fp = path.join(histDir, 'history.enc');
    const h = new History(v, fp);
    h.upsertMany([{
      accountId: 'a1', accountEmail: 'x@outlook.com', code: '483920',
      senderDomain: 'github.com', receivedAt: '2026-11-04T10:00:00.000Z',
      usedAt: null, confidence: 120, uid: 7,
    }]);
    assert.ok(fs.existsSync(fp), '应生成 history.enc');
    const raw = fs.readFileSync(fp, 'utf8');
    assert.ok(!raw.includes('483920'), '磁盘上不得出现明文验证码');
    assert.ok(!raw.includes('x@outlook.com'), '磁盘上不得出现明文邮箱');
    assert.ok(!raw.trim().startsWith('{'), '不能是明文 JSON');
  });

  t('历史幂等：同一封邮件重复写只留一条', () => {
    const v = new Vault(histDir);
    const h = new History(v, path.join(histDir, 'history.enc'));
    const item = {
      accountId: 'idem', accountEmail: 'y@outlook.com', code: '111222',
      senderDomain: 'a.com', receivedAt: null, usedAt: null, confidence: 100, uid: 1,
    };
    const r1 = h.upsertMany([item]);
    const r2 = h.upsertMany([item]);
    assert.strictEqual(r2.added, 0, '第二次不应新增');
    assert.ok(h.all().filter(x => x.accountEmail === 'y@outlook.com').length === 1);
    assert.ok(r1.added >= 0);
  });

  t('历史拒绝非法字段而不是抛异常', () => {
    const v = new Vault(histDir);
    const h = new History(v, path.join(histDir, 'history.enc'));
    const before = h.all().length;
    const r = h.upsertMany([
      { accountId: 'a', accountEmail: 'not-an-email', code: '123456', senderDomain: 'x.com', receivedAt: null, usedAt: null, confidence: 0, uid: 1 },
      { accountId: 'b', accountEmail: 'ok@outlook.com', code: 'x'.repeat(50), senderDomain: 'x.com', receivedAt: null, usedAt: null, confidence: 0, uid: 2 },
      { accountId: '__proto__', accountEmail: 'c@outlook.com', code: '654321', senderDomain: 'ok.com', receivedAt: null, usedAt: null, confidence: 0, uid: 3 },
    ]);
    assert.ok(typeof r.rejected === 'number', '应返回 rejected 计数');
    assert.ok(r.rejected >= 2, '至少两条应被拒，实际 ' + r.rejected);
    assert.ok(!h.all().some(x => x.accountEmail === 'not-an-email'));
  });

  t('历史文件必须落在 DATA_DIR 而不是 public/', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(/history\.enc/.test(src), '应使用 history.enc');
    assert.ok(!/PUBLIC_DIR[^;\n]*history/i.test(src), '历史文件绝不能放 public 下（会被静态托管吐出去）');
    assert.ok(!/public[^;\n]*history\.enc/i.test(src), '历史文件路径不能含 public');
  });

  t('history action 已注册且在 codes.scan.cancel 之后', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    for (const a of ['history.list', 'history.mark', 'history.clear', 'history.export']) {
      assert.ok(src.includes(`case '${a}'`), '缺少 ' + a);
    }
    assert.ok(src.indexOf("case 'history.list'") > src.indexOf("case 'codes.scan.cancel'"),
      'history 必须排在 codes.scan.cancel 之后，避免影响既有静态切片断言');
  });

  t('vault 暴露 encryptText/decryptText 且可往返', () => {
    const v = new Vault(histDir);
    const plain = 'hello-验证码-483920';
    const enc = v.encryptText(plain);
    assert.notStrictEqual(enc, plain);
    assert.strictEqual(v.decryptText(enc), plain);
  });

  t('前端不再使用 prompt/alert/confirm', () => {
    const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    assert.ok(!/\bprompt\s*\(/.test(src), '不应再用 prompt');
    assert.ok(!/\balert\s*\(/.test(src), '不应再用 alert');
    // confirm( 可能出现在 askConfirm 定义里，用词边界排除
    assert.ok(!/(^|[^a-zA-Z_$])confirm\s*\(/m.test(src.replace(/function\s+askConfirm/g, '')), '不应再用原生 confirm');
  });

  t('复制邮箱按钮已接入', () => {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    const app = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    assert.ok(html.includes('btnCopyEmail'), 'index.html 应有 btnCopyEmail');
    assert.ok(app.includes('btnCopyEmail'), 'app.js 应绑定 btnCopyEmail');
  });

  try { fs.rmSync(histDir, { recursive: true, force: true }); } catch { /* 忽略 */ }

  /* ==================================================================
   * 14. 密钥分离（K2）：vault.key 与 accounts.enc 不再同目录
   *
   * 这一节全部在 fs.mkdtempSync 出来的临时目录里跑，绝对不碰真实的
   * D:\Projects\Account\MailDesk\data\。覆盖启动分支表的五个分支。
   * ================================================================== */
  console.log('\n=== 14b. 单条损坏不影响整库 ===');

  // 回归：all() 曾经整个 map 包在一个 try 里，任意一条 blob 解不开就全库失败。
  // 后果链：一条位翻转 → all() 抛 → updateRefreshToken 失败 →
  // REFRESH_TOKEN_PERSIST_FAILED → 该账号轮换后的新令牌只在内存、丢盘
  // → 一个本来完好的账号被连带毁掉。
  t('单条 blob 损坏时 all() 仍返回其余条目', () => {
  {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-corrupt-'));
    try {
      const V = new Vault(dir, dir);   // keyDir 同 dataDir，测试内隔离
      const mk = i => ({
        id: 'x' + i, email: 'u' + i + '@x.com', label: '', group: '', note: '',
        status: 'ok', createdAt: new Date().toISOString(),
        secrets: { refreshToken: 'RT-' + i },
      });
      V.save([mk(1), mk(2), mk(3)]);

      // 破坏第 2 条
      const sp = path.join(dir, 'accounts.enc');
      const raw2 = JSON.parse(fs.readFileSync(sp, 'utf8'));
      const t2 = raw2.accounts.find(a => a.id === 'x2');
      const b2 = Buffer.from(t2.blob, 'base64');
      b2[b2.length - 1] ^= 0xff;
      const brokenBlob = b2.toString('base64');
      t2.blob = brokenBlob;
      fs.writeFileSync(sp, JSON.stringify(raw2, null, 2));

      let list = null, threw = false;
      try { list = V.all(); } catch { threw = true; }
      assert.ok(!threw, 'all() 不应抛异常');
      assert.strictEqual(list.length, 2, '应返回其余 2 条');
      assert.strictEqual(V.corruptedEntries().length, 1, '应记录 1 条损坏');

      // save 不能把坏数据删掉
      V.save(list);
      const after2 = JSON.parse(fs.readFileSync(sp, 'utf8'));
      assert.strictEqual(after2.accounts.length, 3, '损坏条目的原始数据必须保留');
      assert.strictEqual(after2.accounts.find(a => a.id === 'x2').blob, brokenBlob,
        '损坏条目的 blob 应原样保留');

      // 轮换不再被连带失败
      const r = V.updateRefreshToken('x1', 'RT-1-NEW', 'RT-1');
      assert.strictEqual(r.applied, true, '单条损坏不应阻断其他账号的令牌轮换');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  });

  console.log('\n=== 14. 密钥分离 ===');

  const crypto14 = require('crypto');
  const { spawnSync } = require('child_process');

  const ALGO14 = 'aes-256-gcm';
  const IV14 = 12, TAG14 = 16;

  /** 手工按 vault.js 的格式加密一条 secrets，用来伪造"另一个密钥加密的库" */
  function sealWith(keyBuf, obj) {
    const iv = crypto14.randomBytes(IV14);
    const c = crypto14.createCipheriv(ALGO14, keyBuf, iv);
    const enc = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj), 'utf8')), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
  }

  /** 按 vault.js 的落盘格式写一份 accounts.enc（不经过 Vault，方便造场景） */
  function writeStore(dataDir, keyBuf, secretsList) {
    const out = {
      version: 1,
      updatedAt: new Date().toISOString(),
      accounts: secretsList.map((s, i) => ({
        id: 'acc' + i, email: 'u' + i + '@outlook.com',
        blob: sealWith(keyBuf, s),
      })),
    };
    fs.writeFileSync(path.join(dataDir, 'accounts.enc'), JSON.stringify(out, null, 2), { mode: 0o600 });
  }

  const hashFile = f => crypto14.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

  /** 造一对临时目录：dataDir（密文）+ keyDir（密钥） */
  function mkPair(tag) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-k2-' + tag + '-data-'));
    const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-k2-' + tag + '-key-'));
    return { dataDir, keyDir };
  }

  // --- 14.1 KEY_DIR 环境变量生效（子进程，避免污染本进程的 module 缓存）---
  t('KEY_DIR 环境变量生效：key 落到 MAILDESK_KEY_DIR，数据目录无密钥', () => {
    const a = mkPair('env');
    const b = mkPair('env2');
    try {
      const srv = JSON.stringify(path.join(__dirname, 'server'));
      const run = env => spawnSync(process.execPath, ['-e', 'require(' + srv + ')'], {
        cwd: __dirname, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 30000,
      });

      // 1) 显式 MAILDESK_KEY_DIR：密钥落在它下面
      const r1 = run({ MAILDESK_DATA_DIR: a.dataDir, MAILDESK_KEY_DIR: a.keyDir });
      assert.strictEqual(r1.status, 0, '子进程应正常退出：' + (r1.stderr || ''));
      assert.ok(fs.existsSync(path.join(a.keyDir, 'vault.key')), 'MAILDESK_KEY_DIR 下应生成 vault.key');
      assert.ok(!fs.existsSync(path.join(a.dataDir, 'vault.key')), '数据目录不得再出现 vault.key');

      // 2) 只设 MAILDESK_DATA_DIR：向后兼容，密钥仍跟数据同目录
      const r2 = spawnSync(process.execPath, ['-e', 'require(' + srv + ')'], {
        cwd: __dirname,
        env: { ...process.env, MAILDESK_DATA_DIR: b.dataDir, MAILDESK_KEY_DIR: '' },
        encoding: 'utf8', timeout: 30000,
      });
      assert.strictEqual(r2.status, 0, '子进程应正常退出：' + (r2.stderr || ''));
      assert.ok(fs.existsSync(path.join(b.dataDir, 'vault.key')),
        '设置 MAILDESK_DATA_DIR 时密钥仍应在数据目录（既有测试依赖这个行为）');
    } finally {
      fs.rmSync(a.dataDir, { recursive: true, force: true });
      fs.rmSync(a.keyDir, { recursive: true, force: true });
      fs.rmSync(b.dataDir, { recursive: true, force: true });
      fs.rmSync(b.keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.2 首次运行：密钥生成在 KEY_DIR ---
  t('首次运行在 KEY_DIR 生成密钥，长度 32 字节', () => {
    const { dataDir, keyDir } = mkPair('fresh');
    try {
      const v = new Vault(dataDir, keyDir);
      assert.ok(fs.existsSync(path.join(keyDir, 'vault.key')), '应生成 keyDir/vault.key');
      assert.ok(!fs.existsSync(path.join(dataDir, 'vault.key')), '数据目录不应有 vault.key');
      assert.strictEqual(v.key.length, 32, '密钥应为 32 字节');
      assert.strictEqual(path.resolve(v.keyPath), path.resolve(path.join(keyDir, 'vault.key')));
      // 空库时读写往返
      v.save([{ id: 'k1', email: 'k@outlook.com', secrets: { refreshToken: 'RT-K1' } }]);
      assert.strictEqual(v.all()[0].secrets.refreshToken, 'RT-K1');
      // 重开：应复用同一把密钥，密文仍可解
      const v2 = new Vault(dataDir, keyDir);
      assert.strictEqual(v2.all()[0].secrets.refreshToken, 'RT-K1', '重开应能解开旧密文');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.3 迁移：legacy → primary，legacy 被删、内容一致 ---
  t('legacy 迁移到 primary：旧文件被删、内容一致、密文仍可解', () => {
    const { dataDir, keyDir } = mkPair('mig');
    try {
      // 造老部署：密钥和数据同目录
      const oldKey = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(dataDir, 'vault.key'), oldKey, { mode: 0o600 });
      writeStore(dataDir, oldKey, [{ refreshToken: 'RT-LEGACY' }, { refreshToken: 'RT-LEGACY-2' }]);
      const storeBefore = hashFile(path.join(dataDir, 'accounts.enc'));

      const v = new Vault(dataDir, keyDir);

      assert.ok(fs.existsSync(path.join(keyDir, 'vault.key')), '应在 keyDir 生成密钥');
      assert.ok(!fs.existsSync(path.join(dataDir, 'vault.key')), '旧的 data/vault.key 应被删除');
      assert.ok(fs.readFileSync(path.join(keyDir, 'vault.key')).equals(oldKey), '新位置内容必须与旧密钥逐字节一致');
      assert.strictEqual(hashFile(path.join(dataDir, 'accounts.enc')), storeBefore,
        '迁移不得改动 accounts.enc（密钥换、密文不换）');
      assert.strictEqual(v.all().length, 2);
      assert.strictEqual(v.all()[0].secrets.refreshToken, 'RT-LEGACY');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.4 迁移幂等：再跑一次不报错 ---
  t('迁移幂等：重复构造 Vault 不报错且密钥不变', () => {
    const { dataDir, keyDir } = mkPair('idem');
    try {
      const oldKey = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(dataDir, 'vault.key'), oldKey);
      writeStore(dataDir, oldKey, [{ refreshToken: 'RT-IDEM' }]);

      new Vault(dataDir, keyDir);                       // 第一次：迁移
      const keyAfter1 = fs.readFileSync(path.join(keyDir, 'vault.key'));
      const storeAfter1 = hashFile(path.join(dataDir, 'accounts.enc'));

      const v2 = new Vault(dataDir, keyDir);            // 第二次：分支 1
      const v3 = new Vault(dataDir, keyDir);            // 第三次
      assert.ok(fs.readFileSync(path.join(keyDir, 'vault.key')).equals(keyAfter1), '密钥不得被重新生成');
      assert.strictEqual(hashFile(path.join(dataDir, 'accounts.enc')), storeAfter1, '密文不得被重写');
      assert.strictEqual(v2.all()[0].secrets.refreshToken, 'RT-IDEM');
      assert.strictEqual(v3.all()[0].secrets.refreshToken, 'RT-IDEM');
      assert.ok(!fs.existsSync(path.join(dataDir, 'vault.key')), '不应残留旧密钥');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.5 两处内容不同 → 硬失败 ---
  t('primary 与 legacy 内容不同时抛异常拒绝启动', () => {
    const { dataDir, keyDir } = mkPair('conflict');
    try {
      const keyA = crypto14.randomBytes(32);
      const keyB = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(keyDir, 'vault.key'), keyA);
      fs.writeFileSync(path.join(dataDir, 'vault.key'), keyB);

      let caught = null;
      try { new Vault(dataDir, keyDir); } catch (e) { caught = e; }
      assert.ok(caught, '必须抛异常，不能静默选一个');
      assert.strictEqual(caught.code, 'VAULT_KEY_MISMATCH');
      // 两条绝对路径都要在信息里
      assert.ok(caught.message.includes(path.resolve(path.join(keyDir, 'vault.key'))), '应打印 primary 绝对路径');
      assert.ok(caught.message.includes(path.resolve(path.join(dataDir, 'vault.key'))), '应打印 legacy 绝对路径');
      assert.ok(/check-key/.test(caught.message), '应指引用 tools/check-key.js');
      // 抛异常时两个文件都不能被改动/删除
      assert.ok(fs.readFileSync(path.join(keyDir, 'vault.key')).equals(keyA), '不得改动 primary');
      assert.ok(fs.readFileSync(path.join(dataDir, 'vault.key')).equals(keyB), '不得删改 legacy');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  t('两处内容相同：用 primary，legacy 备份后删除', () => {
    const { dataDir, keyDir } = mkPair('same');
    try {
      const k = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(keyDir, 'vault.key'), k);
      fs.writeFileSync(path.join(dataDir, 'vault.key'), k);   // 内容相同
      writeStore(dataDir, k, [{ refreshToken: 'RT-SAME-KEY' }]);

      const v = new Vault(dataDir, keyDir);
      assert.ok(!fs.existsSync(path.join(dataDir, 'vault.key')), '重复的旧密钥应被删除');
      assert.ok(fs.readFileSync(path.join(keyDir, 'vault.key')).equals(k), '保留的应是同一把密钥');
      assert.strictEqual(v.all()[0].secrets.refreshToken, 'RT-SAME-KEY');
      // 数据目录里不应再有任何 vault.key 变体（备份也一并清掉）
      const leftovers = fs.readdirSync(dataDir).filter(f => f.startsWith('vault.key'));
      assert.deepStrictEqual(leftovers, [], '数据目录不应残留密钥副本，实际：' + leftovers.join(','));
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.6 迁移后密文字节未变（独立哈希对比，含 100 条规模）---
  t('迁移前后 accounts.enc 字节完全一致（哈希对比）', () => {
    const { dataDir, keyDir } = mkPair('hash');
    try {
      const oldKey = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(dataDir, 'vault.key'), oldKey);
      const list = [];
      for (let i = 0; i < 100; i++) {
        list.push({ clientId: 'CID-' + i, refreshToken: 'RT-' + i, password: 'PW-' + i });
      }
      writeStore(dataDir, oldKey, list);
      const before = {
        hash: hashFile(path.join(dataDir, 'accounts.enc')),
        size: fs.statSync(path.join(dataDir, 'accounts.enc')).size,
      };

      const v = new Vault(dataDir, keyDir);

      const after = {
        hash: hashFile(path.join(dataDir, 'accounts.enc')),
        size: fs.statSync(path.join(dataDir, 'accounts.enc')).size,
      };
      assert.strictEqual(after.hash, before.hash, '密文内容不得变化');
      assert.strictEqual(after.size, before.size, '密文大小不得变化');
      assert.strictEqual(v.all().length, 100, '迁移后应能解出全部 100 条');
      assert.strictEqual(v.all()[99].secrets.refreshToken, 'RT-99');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  // --- 14.7 向后兼容：不传 keyDir 时密钥仍在数据目录 ---
  t('不传 keyDir 时密钥仍在数据目录（向后兼容）', () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-k2-compat-'));
    try {
      const v = new Vault(dataDir);   // 单参数，老签名
      assert.ok(fs.existsSync(path.join(dataDir, 'vault.key')), '缺省应与数据同目录');
      assert.strictEqual(path.resolve(v.keyPath), path.resolve(path.join(dataDir, 'vault.key')));
      v.save([{ id: 'c1', email: 'c@x.com', secrets: { refreshToken: 'RT-COMPAT' } }]);
      assert.strictEqual(new Vault(dataDir).all()[0].secrets.refreshToken, 'RT-COMPAT');
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  });

  // --- 14.8 server.js 的 KEY_DIR 解析顺序（静态断言，不改文件）---
  t('server.js 的 KEY_DIR 解析顺序：KEY_DIR > DATA_DIR > ~/.maildesk', () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(/require\('os'\)/.test(src), 'server.js 应引入 os');
    assert.ok(/MAILDESK_KEY_DIR/.test(src), '应支持 MAILDESK_KEY_DIR');
    assert.ok(/new Vault\(DATA_DIR,\s*KEY_DIR\)/.test(src), '应把 KEY_DIR 传给 Vault');
    assert.ok(/Key dir\s*:\s*' \+ KEY_DIR/.test(src), '启动横幅应打印 Key dir');
    // 中间分支是关键：设了 MAILDESK_DATA_DIR 时密钥必须仍跟数据同目录，
    // 既有 140 项测试的行为才不会变。
    const m = src.match(/const KEY_DIR =([\s\S]{0,400}?);/);
    assert.ok(m, '应能定位 KEY_DIR 定义');
    const def = m[1];
    assert.ok(/MAILDESK_KEY_DIR/.test(def) && /MAILDESK_DATA_DIR/.test(def) && /homedir/.test(def),
      'KEY_DIR 三段式解析缺失：' + def);
    assert.ok(def.indexOf('MAILDESK_KEY_DIR') < def.indexOf('MAILDESK_DATA_DIR'),
      'MAILDESK_KEY_DIR 优先级必须高于 MAILDESK_DATA_DIR');
    assert.ok(def.indexOf('MAILDESK_DATA_DIR') < def.indexOf('homedir'),
      'MAILDESK_DATA_DIR 分支必须早于 ~/.maildesk');
  });

  // --- 14.9 check-key.js 的判定逻辑 ---
  t('check-key.js：能解密的密钥判定为可用，不能解密的判为不可用', () => {
    const ck = require('./tools/check-key');
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-k2-ck-'));
    try {
      const good = crypto14.randomBytes(32);
      const bad = crypto14.randomBytes(32);
      writeStore(dataDir, good, [{ refreshToken: 'RT-CK-1' }, { refreshToken: 'RT-CK-2' }]);
      const store = path.join(dataDir, 'accounts.enc');

      const okRes = ck.tryDecrypt(good, store);
      assert.strictEqual(okRes.ok, true, '正确密钥应判定可解：' + okRes.reason);
      assert.strictEqual(okRes.count, 2, '应数出 2 个账户');

      const badRes = ck.tryDecrypt(bad, store);
      assert.strictEqual(badRes.ok, false, '错误密钥必须判定为解不开');
      assert.ok(/认证失败/.test(badRes.reason), '应说明认证失败，实际：' + badRes.reason);

      const shortRes = ck.tryDecrypt(Buffer.alloc(16), store);
      assert.strictEqual(shortRes.ok, false);
      assert.ok(/长度/.test(shortRes.reason));
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  });

  // --- 14.10 端到端：check-key.js 可执行，退出码符合约定 ---
  t('tools/check-key.js 可运行且退出码正确', () => {
    const { dataDir, keyDir } = mkPair('cli');
    try {
      const good = crypto14.randomBytes(32);
      fs.writeFileSync(path.join(keyDir, 'vault.key'), good);
      writeStore(dataDir, good, [{ refreshToken: 'RT-CLI' }]);

      const env = { ...process.env, MAILDESK_DATA_DIR: dataDir, MAILDESK_KEY_DIR: keyDir };
      const tool = path.join(__dirname, 'tools', 'check-key.js');

      const r1 = spawnSync(process.execPath, [tool], { env, encoding: 'utf8', timeout: 30000 });
      assert.strictEqual(r1.status, 0, '能解应退出 0，实际 ' + r1.status + '\n' + (r1.stderr || ''));
      assert.ok(/解出 1 个账户/.test(r1.stdout), '应报告解出的账户数，实际输出：\n' + r1.stdout);

      // 把密钥换成错的 → 两处都解不开 → 退出码 1
      fs.writeFileSync(path.join(keyDir, 'vault.key'), crypto14.randomBytes(32));
      const r2 = spawnSync(process.execPath, [tool], { env, encoding: 'utf8', timeout: 30000 });
      assert.strictEqual(r2.status, 1, '都不能解应退出 1，实际 ' + r2.status + '\n' + (r2.stderr || ''));
    } finally {
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(keyDir, { recursive: true, force: true });
    }
  });

  console.log('\n=== 16. 平台标注 ===');

  await tAsync('normalizePlatforms 防御各种垃圾输入', async () => {
    const pf = require('./lib/platforms');
    for (const bad of [undefined, null, '', 123, {}, [1, null, undefined, [], {}]]) {
      const r = pf.normalizePlatforms(bad);
      assert.deepStrictEqual(r.platforms, [], '垃圾输入应得空数组：' + JSON.stringify(bad));
      assert.deepStrictEqual(r.platformNames, {});
    }
  });

  await tAsync('normalizePlatforms 归一化与去重', async () => {
    const pf = require('./lib/platforms');
    const r = pf.normalizePlatforms(['GitHub', 'github', ' GITHUB ']);
    assert.deepStrictEqual(r.platforms, ['github'], '三种写法应合成一个');
    // 内置平台的名字走 BUILTIN_MAP，不进 platformNames
    assert.deepStrictEqual(r.platformNames, {}, '内置平台不该占用 platformNames');
  });

  await tAsync('自定义平台保留原始大小写', async () => {
    const pf = require('./lib/platforms');
    const r = pf.normalizePlatforms(['Vercel', 'VERCEL', 'MyBlog']);
    // key 归一小写（用于去重/筛选），但显示名必须是用户输入的原样
    assert.ok(r.platforms.includes('vercel'));
    assert.ok(r.platforms.includes('myblog'));
    assert.strictEqual(r.platformNames.vercel, 'Vercel', 'Vercel 不能变成 vercel');
    assert.strictEqual(r.platformNames.myblog, 'MyBlog');
    assert.strictEqual(pf.displayName('vercel', r.platformNames), 'Vercel');
  });

  await tAsync('中文平台名不被破坏', async () => {
    const pf = require('./lib/platforms');
    const r = pf.normalizePlatforms(['我的博客', '知乎']);
    assert.deepStrictEqual(r.platforms, ['我的博客', '知乎']);
    assert.strictEqual(pf.displayName('我的博客', r.platformNames), '我的博客');
  });

  await tAsync('原型污染防护', async () => {
    const pf = require('./lib/platforms');
    const r = pf.normalizePlatforms(['__proto__', 'constructor', 'toString']);
    // 这三个 key 允许入表，但绝不能改动 Object.prototype
    assert.strictEqual(Object.getPrototypeOf({}), Object.prototype);
    assert.strictEqual({}.polluted, undefined);
    assert.strictEqual(Object.getPrototypeOf(r.platformNames), Object.prototype,
      'platformNames 必须是普通对象');
  });

  await tAsync('超长与超量截断', async () => {
    const pf = require('./lib/platforms');
    const many = Array.from({ length: 60 }, (_, i) => 'plat' + i);
    assert.strictEqual(pf.normalizePlatforms(many).platforms.length, pf.MAX_PLATFORMS);
    const long = 'x'.repeat(100);
    assert.strictEqual(pf.normalizePlatforms([long]).platforms[0].length, pf.MAX_ITEM_LEN);
    // 代理对不能被切半个
    const emoji = '🎉'.repeat(30);
    const s = pf.normalizePlatforms([emoji]).platforms[0];
    assert.ok(s.isWellFormed ? s.isWellFormed() : !/\uD8[0-9a-f]{2}$/i.test(s),
      'emoji 不应被截出半个代理对');
  });

  await tAsync('老数据（无 platforms 字段）读出来是空数组而不是 undefined', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-pf-'));
    try {
      const dataDir = path.join(tmpRoot, 'data');
      const keyDir = path.join(tmpRoot, 'keys');
      fs.mkdirSync(keyDir, { recursive: true });
      const v = new Vault(dataDir, keyDir);
      v.upsert({ id: 'id-a', email: 'a@x.com', clientId: 'cid', secrets: { refreshToken: 'rt' } });

      // 手工把 platforms 字段从文件里抹掉，模拟升级前的老数据
      const file = path.join(dataDir, 'accounts.enc');
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const a of raw.accounts) { delete a.platforms; delete a.platformNames; }
      fs.writeFileSync(file, JSON.stringify(raw));

      const v2 = new Vault(dataDir, keyDir);
      const list = v2.all();
      assert.strictEqual(list.length, 1);
      assert.strictEqual(list[0].platforms, undefined, 'vault 层不补默认值（由 accountPublic 补）');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  await tAsync('平台字段随库落盘并能重读', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-pf2-'));
    try {
      const dataDir = path.join(tmpRoot, 'data');
      const keyDir = path.join(tmpRoot, 'keys');
      fs.mkdirSync(keyDir, { recursive: true });
      const pf = require('./lib/platforms');
      const v = new Vault(dataDir, keyDir);
      const n = pf.normalizePlatforms(['GitHub', 'Vercel']);
      v.upsert({
        id: 'id-a', email: 'a@x.com', clientId: 'cid', secrets: { refreshToken: 'rt' },
        platforms: n.platforms, platformNames: n.platformNames,
      });

      const v2 = new Vault(dataDir, keyDir);
      const got = v2.all()[0];
      assert.deepStrictEqual(got.platforms, ['github', 'vercel']);
      assert.strictEqual(got.platformNames.vercel, 'Vercel');
      // 关键：新字段是明文元数据，不能把 refresh_token 挤掉或让它变明文
      assert.strictEqual(got.secrets.refreshToken, 'rt');
      const rawTxt = fs.readFileSync(path.join(dataDir, 'accounts.enc'), 'utf8');
      assert.ok(rawTxt.includes('github'), '平台名应在明文元数据层');
      assert.ok(!rawTxt.includes('"rt"'), 'refresh_token 必须仍在密文里');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  await tAsync('CSV 导出转义符合 RFC 4180', async () => {
    // 直接验 server.js 里的 csvCell：它决定了导出的 CSV 会不会被 Excel 解错列
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    const m = src.match(/function csvCell\([\s\S]*?\n\}/);
    assert.ok(m, '应能找到 csvCell');
    const csvCell = new Function('return ' + m[0].replace(/^function/, 'function') + '; csvCell;')();
    assert.strictEqual(csvCell('plain'), 'plain');
    assert.strictEqual(csvCell('a,b'), '"a,b"', '含逗号要加引号');
    assert.strictEqual(csvCell('say "hi"'), '"say ""hi"""', '内部引号要翻倍');
    assert.strictEqual(csvCell('line\nbreak'), '"line\nbreak"');
    assert.strictEqual(csvCell(' pad '), '" pad "', '首尾空格也要加引号，否则会被吃掉');
  });

  await tAsync('导出文本不含任何凭据', async () => {
    // accounts.exportPlatforms 只读元数据。这里做静态检查：
    // 那个 case 分支里不能出现 a.secrets / refreshToken 之类的**读取**。
    //
    // 关键细节：必须先剥掉注释再检查。代码里有一句"绝不碰 a.secrets"的
    // 说明性注释，直接扫原文会把这条注释当成违规命中——那种测试会逼着人
    // 删掉有价值的注释来让测试变绿，是本末倒置。
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    const i = src.indexOf("case 'accounts.exportPlatforms'");
    assert.ok(i > 0);
    const branch = src.slice(i, i + 2000)
      .replace(/\/\*[\s\S]*?\*\//g, '')   // 块注释
      .replace(/(^|[^:])\/\/.*$/gm, '$1'); // 行注释（避开 http:// 里的 //）
    assert.ok(!/\.secrets\b/.test(branch), '导出分支不得读 secrets');
    assert.ok(!/refreshToken|clientId/.test(branch), '导出分支不得引用凭据字段');
  });

  console.log('\n=== 15. AAD 绑定与版本迁移（H2）===');

  await tAsync('v2 库：密文搬到别的账号会认证失败，且只影响那一条', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-aad-'));
    try {
      const dataDir = path.join(tmpRoot, 'data');
      const keyDir = path.join(tmpRoot, 'keys');
      fs.mkdirSync(keyDir, { recursive: true });
      const v = new Vault(dataDir, keyDir);
      v.upsert({ id: 'id-a', email: 'a@x.com', clientId: 'cid-a', secrets: { refreshToken: 'rt-a' } });
      v.upsert({ id: 'id-b', email: 'b@x.com', clientId: 'cid-b', secrets: { refreshToken: 'rt-b' } });

      const file = path.join(dataDir, 'accounts.enc');
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      assert.strictEqual(raw.version, 2, '新库应写成 v2');

      // 移植攻击：把 a 的密文拷到 b 的位置
      const a = raw.accounts.find(x => x.id === 'id-a');
      const b = raw.accounts.find(x => x.id === 'id-b');
      b.blob = a.blob;
      fs.writeFileSync(file, JSON.stringify(raw));

      const v2 = new Vault(dataDir, keyDir);
      const list = v2.all();
      // b 解不开（AAD 不匹配），但 a 必须还能读 —— 这是 H3 逐条兜底的交叉验证：
      // 任何"一条坏了就全库失败"的实现都会让这里只剩 0 条。
      assert.ok(!list.find(x => x.id === 'id-b'), '移植的密文不应解得开');
      assert.ok(list.find(x => x.id === 'id-a'), '其余条目必须仍可读');
      assert.strictEqual(v2.corruptedEntries().length, 1, '应记录 1 条损坏');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  await tAsync('v1 老文件仍可读（向后兼容）', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-v1-'));
    try {
      const dataDir = path.join(tmpRoot, 'data');
      const keyDir = path.join(tmpRoot, 'keys');
      fs.mkdirSync(keyDir, { recursive: true });
      const v = new Vault(dataDir, keyDir);
      v.upsert({ id: 'id-a', email: 'a@x.com', clientId: 'cid-a', secrets: { refreshToken: 'rt-a' } });

      const file = path.join(dataDir, 'accounts.enc');
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      // 降级成 v1：去掉文件级版本和条目级 v 标记
      raw.version = 1;
      for (const acc of raw.accounts) delete acc.v;
      fs.writeFileSync(file, JSON.stringify(raw));

      const v1 = new Vault(dataDir, keyDir);
      const list = v1.all();
      assert.strictEqual(list.length, 1, 'v1 文件必须仍能读');
      assert.strictEqual(list[0].email, 'a@x.com');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  await tAsync('隔离条目在 save 时原样写回，不会被静默删除', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'md-q-'));
    try {
      const dataDir = path.join(tmpRoot, 'data');
      const keyDir = path.join(tmpRoot, 'keys');
      fs.mkdirSync(keyDir, { recursive: true });
      const v = new Vault(dataDir, keyDir);
      v.upsert({ id: 'id-a', email: 'a@x.com', clientId: 'cid-a', secrets: { refreshToken: 'rt-a' } });
      v.upsert({ id: 'id-b', email: 'b@x.com', clientId: 'cid-b', secrets: { refreshToken: 'rt-b' } });

      const file = path.join(dataDir, 'accounts.enc');
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      const b = raw.accounts.find(x => x.id === 'id-b');
      b.blob = { iv: 'AAAA', ct: 'BBBB', tag: 'CCCC' };   // 故意写坏
      // 把这条降级成 v1 形态：模拟"老库里本来就有一条 v1 数据，升级后解不开"。
      // 必须是 v1 才测得出关键点 —— 如果是 v2，save 时标成 v2 本来就正确，
      // 断言"不应是 v2"就成了空测。
      b.v = 1;
      fs.writeFileSync(file, JSON.stringify(raw));

      const v2 = new Vault(dataDir, keyDir);
      const list = v2.all();
      assert.strictEqual(list.length, 1, '只应返回能解的那条');
      v2.save(list);   // 写回

      const after = JSON.parse(fs.readFileSync(file, 'utf8'));
      assert.strictEqual(after.accounts.length, 2, '坏条目的原始数据必须留在文件里');
      const stillBad = after.accounts.find(x => x.id === 'id-b');
      assert.ok(stillBad && stillBad.blob, '坏条目应带 blob 原样保留');
      // 关键：不能被偷偷打上 v2。v1 形态的密文一旦标成 v2，下次读取会用
      // 'maildesk/2|id' 的 AAD 去解一段根本没有这个 AAD 的密文，
      // 本来还有希望（比如密钥补回来后）能救的数据从此永久解不开。
      assert.strictEqual(stillBad.v, 1, '隔离条目应保持原来的 v1 标记');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  console.log('\n=== 17. 平台标注 — 前后端契约与注入防护（F4 回归） ===');

  /**
   * 从 server.js / app.js 源码里取出一个顶层函数的完整源码。
   *
   * 用 `\n}` 作右边界：函数体内的 `}` 都带缩进，只有顶层函数的收尾花括号顶格。
   * 这和文件里已有的 csvCell 用例是同一套做法，不再引入第二种抽取方式。
   *
   * 取出来之后一律用 new Function 真正解析一次。抽取规则一旦被格式变化打坏，
   * 这里会直接抛语法错误，而不是让后面的断言在空函数上"通过"——
   * 空测比没测更糟，它会给出覆盖率已经补上的错觉。
   */
  function grabFn(src, name) {
    const m = src.match(new RegExp('function ' + name + '\\([\\s\\S]*?\\n\\}'));
    assert.ok(m, '源码里找不到函数 ' + name);
    return m[0];
  }

  /** 解析一段函数源码，返回可调用的函数；依赖项按名字注入 */
  function loadFn(fnSrc, name, deps) {
    const keys = Object.keys(deps || {});
    const vals = keys.map(k => deps[k]);
    return new Function(keys.join(','), fnSrc + '\nreturn ' + name + ';')(...vals);
  }

  /**
   * 惰性加载 + 转发调用：抽取/解析失败要变成**一条红色断言**，而不是在测试文件
   * 顶层抛出、让整个自检脚本中断。中断的后果是后面所有用例都不再执行，
   * 而"通过数掉了"和"这条没测"看起来完全一样，排查时会白走很多路。
   *
   * 返回的是转发函数而不是 getter：测试里写 `csvCell(x)` 才自然，
   * 用 getter 的话每次都得 `csvCell()(x)`，漏一个括号就变成"拿函数当值比"，
   * 断言会以极难看懂的方式失败。
   */
  function lazyLoad(label, factory) {
    let cache;
    let failed = null;
    const get = () => {
      if (failed) throw new Error('加载 ' + label + ' 失败：' + failed.message);
      if (cache === undefined) {
        try { cache = factory(); }
        catch (e) { failed = e; throw new Error('加载 ' + label + ' 失败：' + e.message); }
      }
      return cache;
    };
    const wrapped = function (...args) { return get()(...args); };
    wrapped.get = get;
    return wrapped;
  }

  const pf = require('./lib/platforms');
  const serverSrc = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  const appSrc = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');

  // ---- 1. 前后端常量一致性 ----
  // lib/platforms.js:14-16 与 public/app.js:4-6 的注释都写着"汇总阶段会有测试比对"，
  // 而在此之前一条比对都没有。前端一旦和 BUILTIN 分叉，用户点 GitHub 可能落到
  // 另一个 key 上，界面上却看不出任何区别。
  await tAsync('前端 PLATFORMS 与后端 BUILTIN 逐项一致（key/name/color/顺序）', async () => {
    const m = appSrc.match(/^const PLATFORMS = \[[\s\S]*?^\];/m);
    assert.ok(m, 'public/app.js 里找不到 const PLATFORMS = [...] 定义');
    const fe = new Function(m[0] + '\nreturn PLATFORMS;')();
    assert.ok(Array.isArray(fe) && fe.length > 0, '抽取出来的 PLATFORMS 必须是非空数组');
    // 先比条数，给出可读的失败信息；再逐项比。deepStrictEqual 连**顺序**一起比，
    // 而顺序就是选择器里的展示顺序，错位会让用户点到相邻的平台。
    assert.strictEqual(fe.length, pf.BUILTIN.length,
      '条目数不一致：前端 ' + fe.length + ' / 后端 ' + pf.BUILTIN.length);
    for (let i = 0; i < pf.BUILTIN.length; i++) {
      assert.deepStrictEqual(fe[i], pf.BUILTIN[i],
        '第 ' + i + ' 项不一致：前端 ' + JSON.stringify(fe[i]) + ' / 后端 ' + JSON.stringify(pf.BUILTIN[i]));
    }
  });

  // ---- 2. 17 个内置平台 round-trip ----
  // 这是本组最关键的一条：早先只有 X / Twitter 会失败（显示名 "X / Twitter"
  // 归一化后变成 "x / twitter"，一个根本不存在的 key）。如果这条测试在写代码
  // 当天就存在，那个缺陷会立刻暴露，而不是靠六个人读代码才发现。
  await tAsync('17 个内置平台按显示名 round-trip 回自己的 key', async () => {
    // 前置假设写死：内置表扩容时这条测试必须跟着复核，而不是悄悄放宽
    assert.strictEqual(pf.BUILTIN.length, 17, '内置平台数量变了，需复核本用例的前置假设');
    const bad = [];
    for (const p of pf.BUILTIN) {
      const r = pf.normalizePlatforms([p.name]);
      if (r.platforms.length !== 1 || r.platforms[0] !== p.key) {
        bad.push('  ' + JSON.stringify(p.name) + ' → ' + JSON.stringify(r.platforms)
          + '（应为 ' + JSON.stringify([p.key]) + '）');
      }
      // 内置平台不该占用 platformNames：显示名从 BUILTIN_MAP 取，
      // 落盘一份只会在内置表改名后变成过时的值。
      if (Object.keys(r.platformNames).length) {
        bad.push('  ' + JSON.stringify(p.name) + ' 不应写进 platformNames');
      }
    }
    assert.deepStrictEqual(bad, [], 'round-trip 失败：\n' + bad.join('\n'));
  });

  await tAsync('内置 key 自身及大小写变体都收敛到同一个 key', async () => {
    const bad = [];
    for (const p of pf.BUILTIN) {
      for (const v of [p.key, p.key.toUpperCase(), p.name.toUpperCase()]) {
        const got = pf.normalizePlatforms([v]).platforms[0];
        if (got !== p.key) bad.push('  ' + JSON.stringify(v) + ' → ' + JSON.stringify(got) + '（应为 ' + p.key + '）');
      }
    }
    assert.deepStrictEqual(bad, [], '归一化失败：\n' + bad.join('\n'));
  });

  await tAsync('X / Twitter 的多种写法合成同一个 key（F2-1 回归）', async () => {
    const r = pf.normalizePlatforms(['twitter', 'X / Twitter', 'x / twitter', 'X / TWITTER', ' x/twitter '.replace('/', ' / ')]);
    assert.deepStrictEqual(r.platforms, ['twitter'],
      '不应出现 "x / twitter" 这个假 key，实际：' + JSON.stringify(r.platforms));
    // 反向：假 key 一旦被写进老数据，也要能读回真 key
    assert.deepStrictEqual(pf.normalizePlatforms(['x / twitter']).platforms, ['twitter']);
    assert.strictEqual(pf.displayName('twitter', {}), 'X / Twitter', '显示名必须是 "X / Twitter"');
  });

  // ---- 3. 前端截断与后端 truncateSafe 等价（代理对）----
  // 之前那条 emoji 用例只测了后端 truncateSafe，前端 slice(0,40) 那条路径没测。
  // 而用户能看到的是前端算出来的 key，前后端对不上就等于"选中的和存进去的不是一个"。
  const feNormalizeKey = lazyLoad('normalizePlatformKey', () =>
    loadFn(grabFn(appSrc, 'normalizePlatformKey'), 'normalizePlatformKey', {}));
  const feBuiltinKeyOf = lazyLoad('builtinKeyOf', () =>
    loadFn(grabFn(appSrc, 'builtinKeyOf'), 'builtinKeyOf', {
      PF_BY_KEY: new Map(pf.BUILTIN.map(p => [p.key, p])),
      PF_BY_NAME: new Map(pf.BUILTIN.map(p => [p.name.toLowerCase(), p.key])),
    }));

  await tAsync('前端 normalizePlatformKey 39a+emoji 不留孤立高位代理（F2-2 回归）', async () => {
    const raw = 'a'.repeat(39) + '🎉';          // 41 个 UTF-16 码元，截断点正好劈开代理对
    assert.strictEqual(raw.length, 41, '用例前提：输入应为 41 码元');
    const got = feNormalizeKey(raw);
    assert.strictEqual(got.length, 39, '应回退到 39 码元，实际 ' + got.length);
    const last = got.charCodeAt(got.length - 1);
    assert.ok(!(last >= 0xd800 && last <= 0xdbff), '末尾不能是高位代理，实际 U+' + last.toString(16));
    if (typeof got.isWellFormed === 'function') assert.ok(got.isWellFormed(), '结果必须是格式良好的字符串');
  });

  await tAsync('前端与后端的平台 key 归一化逐项等价', async () => {
    const cases = [
      'GitHub', '  github  ', 'X / Twitter', 'Vercel', '我的博客',
      'A'.repeat(100), 'a'.repeat(39) + '🎉', '__proto__', 'constructor',
      'My Blog', 'my blog', 'ＧＭＡＩＬ',
    ];
    const bad = [];
    for (const c of cases) {
      const fe = feBuiltinKeyOf(feNormalizeKey(c));
      const be = pf.normalizePlatforms([c]).platforms[0];
      if (fe !== be) bad.push('  ' + JSON.stringify(c) + '：前端 ' + JSON.stringify(fe) + ' / 后端 ' + JSON.stringify(be));
    }
    assert.deepStrictEqual(bad, [], '前后端 key 对不上（选择器高亮与落库值会分叉）：\n' + bad.join('\n'));
  });

  // ---- 4. CSV 公式注入 ----
  // 现存的 "CSV 转义符合 RFC 4180" 只覆盖引号/逗号/换行，恰好绕过了公式前缀。
  // 真实载体是导入的邮箱与 group 列（都无字符限制），Excel 打开就会执行。
  //
  // csvCell 可能把危险前缀正则写成模块作用域常量，也可能内联在函数体里。
  // 两种形态都要能取到函数并跑起来：只认其中一种，实现一改测试就静默失效。
  const csvCell = lazyLoad('csvCell', () => {
    const src = grabFn(serverSrc, 'csvCell');
    // 函数体里引用到的顶层常量（如 CSV_DANGEROUS）按名字注入。
    // 逐个试求值：有些顶层常量依赖运行时（路径、实例），求不出来就跳过。
    const deps = {};
    for (const m of serverSrc.matchAll(/^const ([A-Za-z_$][\w$]*) = ([^\n]*);/gm)) {
      const name = m[1];
      if (!new RegExp('\\b' + name + '\\b').test(src)) continue;
      try { deps[name] = new Function('return (' + m[2] + ');')(); } catch { /* 依赖运行时，跳过 */ }
    }
    return loadFn(src, 'csvCell', deps);
  });

  await tAsync('csvCell 阻断公式前缀（= + - @ 制表符 回车）', async () => {
    for (const evil of ['=1+1', '+SUM(1+1)', '-my-app', '@evil.example', '\tcmd', '\rcmd',
      '=cmd|\'/c calc\'!A1']) {
      const got = csvCell(evil);
      // 前缀必须是单引号。两者都能让 Excel 把单元格当**文本**而不是公式。
      assert.ok(got.startsWith("'") || got.startsWith("\"'"),
        JSON.stringify(evil) + ' 未加防注入前缀，实际：' + JSON.stringify(got));
    }
  });

  await tAsync('csvCell 的防注入前缀落在引号内，且不误伤普通值', async () => {
    // 顺序错（先加引号再加前缀）会得到 `'=HYPERLINK(...)` —— 单引号在 CSV 引号外面，
    // 既不是合法 CSV，Excel 也不认，等于两边的防护都失效。
    const got = csvCell('=HYPERLINK("http://evil","click")');
    assert.strictEqual(got, '"\'=HYPERLINK(""http://evil"",""click"")"',
      '实际：' + JSON.stringify(got));
    assert.ok(got.startsWith("\"'"), '单引号必须在双引号之内');
    assert.strictEqual(csvCell('normal'), 'normal', '普通值不应被加前缀');
    assert.strictEqual(csvCell('my-app'), 'my-app', '连字符只在**开头**才危险');
    assert.strictEqual(csvCell('a=b'), 'a=b', '等号只在开头才危险');
    // 原有 RFC 4180 行为不能被前缀逻辑带坏
    assert.strictEqual(csvCell('a,b'), '"a,b"');
    assert.strictEqual(csvCell(' pad '), '" pad "');
  });

  // ---- 5. applyPlatformMode 共用合并逻辑（F1-6）----
  // 单账户入口和批量入口必须共用同一个合并函数。分叉本身比任何一条具体差异都危险：
  // 用户在两个入口看到的是同一个界面概念，行为却不同。
  const applyPlatformMode = lazyLoad('applyPlatformMode', () =>
    loadFn(grabFn(serverSrc, 'applyPlatformMode'), 'applyPlatformMode', {
      normalizePlatforms: pf.normalizePlatforms,
      BUILTIN_MAP: pf.BUILTIN_MAP,
      MAX_PLATFORMS: pf.MAX_PLATFORMS,
    }));

  await tAsync('applyPlatformMode: 库里 "Github" 再加 github 不产生重复（F1-6）', async () => {
    const r = applyPlatformMode(['Github'], {}, ['github'], {}, 'add');
    assert.deepStrictEqual(r.keys, ['github'],
      '合并前应先归一化当前值，实际：' + JSON.stringify(r.keys));
  });

  await tAsync('applyPlatformMode: __proto__ 作为平台名不会静默丢失（F1-5）', async () => {
    const addNames = {};
    Object.defineProperty(addNames, '__proto__', {
      value: 'X', enumerable: true, configurable: true, writable: true,
    });
    const r = applyPlatformMode([], {}, ['__proto__'], addNames, 'add');
    assert.deepStrictEqual(r.keys, ['__proto__']);
    assert.ok(Object.prototype.hasOwnProperty.call(r.names, '__proto__'),
      '__proto__ 必须作为**自有属性**存在，实际：' + JSON.stringify(Object.keys(r.names)));
    assert.strictEqual(r.names['__proto__'], 'X', '显示名必须是 X');
    // 直接赋值会走原型 setter，属性静默消失甚至污染原型
    assert.strictEqual(Object.getPrototypeOf({}).polluted, undefined, '不得污染 Object.prototype');
    assert.strictEqual(Object.getPrototypeOf(r.names), Object.prototype, 'platformNames 必须是普通对象');
  });

  await tAsync('applyPlatformMode: 已达 50 上限时只拒绝新增，不截断已有项（F1-6）', async () => {
    const cur = Array.from({ length: pf.MAX_PLATFORMS }, (_, i) => 'plat' + i);
    const r = applyPlatformMode(cur, {}, ['extra'], {}, 'add');
    assert.strictEqual(r.keys.length, pf.MAX_PLATFORMS, '上限内数量不应变化');
    // 关键：原来这里是 cur.concat(add).slice(0,50)，会永久删掉历史数据的第 51-60 项。
    // 用户只是想"再加一个平台"，结果丢了十个。
    assert.deepStrictEqual(r.keys, cur, '已有项必须一个不动，实际：' + JSON.stringify(r.keys.slice(-3)));
  });

  await tAsync('applyPlatformMode: replace 用传入的平台替换当前值', async () => {
    const r = applyPlatformMode(['github', 'twitter'], {}, ['apple'], {}, 'replace');
    assert.deepStrictEqual(r.keys, ['apple'],
      'replace 必须丢掉原有标注，实际：' + JSON.stringify(r.keys));
    assert.deepStrictEqual(r.names, {}, '内置平台不应留 platformNames');
  });

  // ---- 6. 跨进程 tmp 冲突 ----
  // 两个实例同时写盘时共用一个 tmp 名，实测能把主文件从 80 字节污染到 5902 字节，
  // JSON 完全损坏 —— 整库不可读。这条做静态断言：tmp 名必须含 pid。
  await tAsync('save() 的 tmp 名含 pid 与时间戳（防跨进程互相撕碎）', async () => {
    const vaultSrc = fs.readFileSync(path.join(__dirname, 'lib', 'vault.js'), 'utf8');
    const m = vaultSrc.match(/const tmp = this\.storePath \+ '\.tmp[^;]*;/);
    assert.ok(m, '找不到 save() 里的 tmp 名');
    assert.ok(/process\.pid/.test(m[0]), 'tmp 名必须含 process.pid，实际：' + m[0]);
    assert.ok(/Date\.now\(\)/.test(m[0]), 'tmp 名必须含时间戳，实际：' + m[0]);
  });

  /* ==================================================================
   * 18. ACL 在每次 save 后必须仍是收紧态（回归）
   *
   * 修的是这个 bug：首次建库后 accounts.enc 是 `<user>:(F)`，但**再存一次**
   * 就退回父目录的继承态（实测出现 CodexSandboxUsers/SYSTEM/Administrators
   * 的 (I) 条目），本机其他账户又能读走全部 refresh_token 密文。
   *
   * 根因：NTFS 的 rename 保留被移动文件自己的 ACL，不是被覆盖目标的 ACL。
   * 旧流程 write tmp → rename → 之后才（或才不）收紧主文件，于是每一轮
   * rename 都用一份继承态的新 tmp 把上一轮收紧的结果覆盖掉。
   *
   * 这些断言读的是**真实 ACL 文本**（execFileSync('icacls')），不是源码里
   * 有没有出现过 "tightenAcl" 字样 —— 后者在 bug 存在时同样是绿的，是假测试。
   * ================================================================== */
  console.log('\n=== 18. ACL 在每次 save 后仍是收紧态 ===');

  const { execFileSync } = require('child_process');

  /**
   * 读出文件的实际 ACL 文本。
   *
   * 返回数组，每个元素是 icacls 输出里含 `:(` 的那一行（即一条 ACE）。
   * 非 Windows 返回 null，调用方据此跳过。
   *
   * **不吞异常**：取不到 ACL 时把原因交给调用方显式跳过，而不是返回空数组
   * 让 `!(I)` 断言恒真 —— 那种"静默通过"正是这个 bug 能藏这么久的原因。
   */
  function readAcl(file) {
    if (process.platform !== 'win32') return null;
    const out = execFileSync('icacls', [file], { encoding: 'utf8', windowsHide: true });
    // icacls 每行形如 `<path> <DOMAIN>\<user>:(F)` 或后续行的 `  <SID>:(I)(M)`。
    // 只看含 `:(` 的片段，路径前缀和末尾的本地化"已处理 1 个文件"提示都不参与判断。
    return out.split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l.includes(':('));
  }

  /** 目录里所有形如 <basename>.tmp* 的残留文件 */
  function tmpLeftovers(dir, basename) {
    const re = new RegExp('^' + basename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.tmp');
    return fs.readdirSync(dir).filter(f => re.test(f));
  }

  /** 一条能通过 History 白名单的最小记录 */
  const histItem = i => ({
    accountId: 'acl' + i, accountEmail: 'acl' + i + '@outlook.com', code: '10000' + i,
    senderDomain: 'example.com', receivedAt: '2026-11-04T10:00:0' + i + '.000Z',
    usedAt: null, confidence: 100, uid: i,
  });

  const aclDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-acl-test-'));
  try {
    const { Vault: VaultAcl } = require('./lib/vault');
    const { History: HistoryAcl } = require('./lib/history');
    const vault = new VaultAcl(aclDir);
    const accFile = path.join(aclDir, 'accounts.enc');
    const histFile = path.join(aclDir, 'history.enc');

    // --- 18.1 accounts.enc：连续两次 save 后不含继承标记 ---
    // 一次 save 可能碰巧还留着首次收紧的结果，必须**两次**才能暴露
    // 「每轮 rename 覆盖成继承态」这个问题。断言用 >=2 次，与实际复现一致。
    vault.save([{ id: 'acl1', email: 'acl1@outlook.com', secrets: { refreshToken: 'RT-ACL-1' } }]);
    vault.save([
      { id: 'acl1', email: 'acl1@outlook.com', secrets: { refreshToken: 'RT-ACL-1' } },
      { id: 'acl2', email: 'acl2@outlook.com', secrets: { refreshToken: 'RT-ACL-2' } },
    ]);

    let accAcl = null;
    let aclSkipReason = '';
    try { accAcl = readAcl(accFile); } catch (e) { aclSkipReason = 'icacls 读不到 ACL：' + e.message; }

    if (process.platform !== 'win32') {
      tSkip('accounts.enc 连续两次 save 后 ACL 不含继承标记 (I)', '非 Windows 平台，无 NTFS ACL');
    } else if (accAcl === null) {
      tSkip('accounts.enc 连续两次 save 后 ACL 不含继承标记 (I)', aclSkipReason);
    } else {
      t('accounts.enc 连续两次 save 后 ACL 不含继承标记 (I)', () => {
        assert.ok(accAcl.length > 0, 'ACL 解析结果为空，说明 readAcl 没读到任何 ACE');
        const inherited = accAcl.filter(l => l.includes('(I)'));
        assert.strictEqual(inherited.length, 0,
          'save 之后仍带继承 ACE（本机其他账户可读），实际 ACL：\n        ' + accAcl.join('\n        '));
      });
    }

    // --- 18.2 accounts.enc：save 后目录里没有 tmp 残留 ---
    // 平台无关，每个平台都跑。
    t('save() 之后数据目录没有 accounts.enc.tmp* 残留', () => {
      const left = tmpLeftovers(aclDir, 'accounts.enc');
      assert.strictEqual(left.length, 0, '残留：' + left.join(', '));
      assert.ok(fs.existsSync(accFile), '前置：accounts.enc 应存在（否则这条测的是空目录）');
    });

    // --- 18.3 history.enc：写入两次后不含继承标记 ---
    const hist = new HistoryAcl(vault, histFile);
    hist.upsertMany([histItem(1)]);
    hist.upsertMany([histItem(2)]);

    let histAcl = null;
    let histSkipReason = '';
    try { histAcl = readAcl(histFile); } catch (e) { histSkipReason = 'icacls 读不到 ACL：' + e.message; }

    if (process.platform !== 'win32') {
      tSkip('history.enc 写入两次后 ACL 不含继承标记 (I)', '非 Windows 平台，无 NTFS ACL');
    } else if (histAcl === null) {
      tSkip('history.enc 写入两次后 ACL 不含继承标记 (I)', histSkipReason);
    } else {
      t('history.enc 写入两次后 ACL 不含继承标记 (I)', () => {
        assert.ok(histAcl.length > 0, 'ACL 解析结果为空，说明 readAcl 没读到任何 ACE');
        const inherited = histAcl.filter(l => l.includes('(I)'));
        assert.strictEqual(inherited.length, 0,
          'history.enc 仍带继承 ACE（里面有邮箱与验证码），实际 ACL：\n        ' + histAcl.join('\n        '));
      });
    }

    // --- 18.4 history.enc：无 tmp 残留（所有平台） ---
    t('history 写入之后数据目录没有 history.enc.tmp* 残留', () => {
      const left = tmpLeftovers(aclDir, 'history.enc');
      assert.strictEqual(left.length, 0, '残留：' + left.join(', '));
      assert.ok(fs.existsSync(histFile), '前置：history.enc 应存在');
    });

    // --- 18.5 tmp 名唯一性（所有平台） ---
    // 固定名 .tmp 在两个实例并发写时会互相截断，最终把主文件撕成解不开的密文。
    // 这条用源码 + 实际行为双重确认：源码里历史 tmp 名必须含 pid 与时间戳。
    t('history 的 tmp 名含 pid 与时间戳（防跨进程互相撕碎）', () => {
      const src = fs.readFileSync(path.join(__dirname, 'lib', 'history.js'), 'utf8');
      const m = src.match(/const tmp = this\.filePath \+ '\.tmp[^;]*;/);
      assert.ok(m, '找不到 history._write() 里的 tmp 名');
      assert.ok(/process\.pid/.test(m[0]), 'tmp 名必须含 process.pid，实际：' + m[0]);
      assert.ok(/Date\.now\(\)/.test(m[0]), 'tmp 名必须含时间戳，实际：' + m[0]);
      // 顺带确认没有退回固定名（固定名 = 上面两个断言都过不了，但这条更直白）
      assert.ok(!/const tmp = this\.filePath \+ '\.tmp';/.test(src),
        'tmp 名不能是固定的 .tmp');
    });

    // --- 18.6 收紧发生在 rename 之前（顺序断言） ---
    // 这一条必须做**源码顺序**断言：ACL 只在 rename 之前收紧才有效，
    // 反过来写（rename 后收紧主文件）在「只 save 一次」时同样能通过上面的
    // 用例，却在第二次 save 时退回去 —— 正是这个 bug 的形状。
    t('save() 在 rename 之前收紧 tmp 的 ACL', () => {
      const src = fs.readFileSync(path.join(__dirname, 'lib', 'vault.js'), 'utf8');
      const body = src.slice(src.indexOf('save(accounts) {'));
      const iAcl = body.indexOf('tightenAcl(tmp)');
      const iRename = body.indexOf('fs.renameSync(tmp, this.storePath)');
      assert.ok(iAcl >= 0, 'save() 里找不到 tightenAcl(tmp)');
      assert.ok(iRename >= 0, 'save() 里找不到 renameSync');
      assert.ok(iAcl < iRename,
        'tightenAcl(tmp) 必须排在 rename 之前，实际位置 acl=' + iAcl + ' rename=' + iRename);
      // 旧写法（只在新建时对主文件收紧）必须彻底消失：它和上面那条同时存在时，
      // 会让人误以为两条路径都覆盖到了。
      assert.ok(!/if \(!existedBefore\)\s*tightenAcl/.test(src),
        '不得保留 "if (!existedBefore) tightenAcl(...)" 的旧逻辑');
    });

    t('history._write() 在 rename 之前收紧 tmp 的 ACL', () => {
      const src = fs.readFileSync(path.join(__dirname, 'lib', 'history.js'), 'utf8');
      const body = src.slice(src.indexOf('_write(items) {'));
      const iAcl = body.indexOf('tightenAcl(tmp)');
      const iRename = body.indexOf('fs.renameSync(tmp, this.filePath)');
      assert.ok(iAcl >= 0, 'history._write() 里找不到 tightenAcl(tmp)');
      assert.ok(iRename >= 0, 'history._write() 里找不到 renameSync');
      assert.ok(iAcl < iRename,
        'tightenAcl(tmp) 必须排在 rename 之前，实际位置 acl=' + iAcl + ' rename=' + iRename);
    });
  } finally {
    fs.rmSync(aclDir, { recursive: true, force: true });
  }

  console.log('');
  console.log('----------------------------------------');
  console.log('  通过 ' + pass + '   失败 ' + fail + (skipped ? '   跳过 ' + skipped : ''));
  console.log('----------------------------------------');
  process.exit(fail ? 1 : 0);
})();
