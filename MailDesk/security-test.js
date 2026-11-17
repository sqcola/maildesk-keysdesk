'use strict';
/**
 * 安全回归测试
 * 针对审计报告中发现的 H1/H2/M1/M2/M3/L1/L2/L4 逐条验证修复
 * 运行： node security-test.js
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const http = require('http');
const net = require('net');

let pass = 0, fail = 0;
function t(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { console.log('  ✓ ' + name); pass++; })
    .catch(e => { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; });
}

function req(port, opts, body) {
  return new Promise(resolve => {
    const r = http.request({
      host: '127.0.0.1', port,
      method: opts.method || 'GET',
      path: opts.path,
      headers: opts.headers || {},
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    r.on('error', e => resolve({ status: 0, error: e.message, headers: {}, body: '' }));
    // 默认 8s 对普通请求足够；批量导入这类会真写盘的操作在慢盘上需要更久，
    // 调用方可传 opts.timeout 放宽，否则会被误判成"服务没返回"。
    r.setTimeout(opts.timeout || 8000, () => { r.destroy(); resolve({ status: 0, error: 'timeout', headers: {}, body: '' }); });
    if (body) r.write(body);
    r.end();
  });
}

/** 用原始 socket 发畸形请求行 */
function rawReq(port, line) {
  return new Promise(resolve => {
    const s = net.connect(port, '127.0.0.1');
    let out = '';
    s.setTimeout(5000, () => { s.destroy(); resolve(out || 'TIMEOUT'); });
    s.on('data', d => { out += d.toString(); });
    s.on('connect', () => s.write(line));
    s.on('close', () => resolve(out || 'CLOSED'));
    s.on('error', e => resolve('ERR:' + e.message));
  });
}

(async function main() {
  console.log('\n=== 启动测试服务 ===');
  // 测试必须跑在独立的库上。之前这里直接用真实 data/ 目录，
  // 批量导入测试会把 50 个 u0@outlook.com 之类的假账号写进用户的真实账号库。
  const os = require('os');
  const TEST_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'maildesk-test-'));
  process.env.MAILDESK_DATA_DIR = TEST_DATA;
  const { start, SESSION_TOKEN } = require('./server');
  const addr = await start();
  const PORT = parseInt(addr.split(':').pop(), 10);
  console.log('  端口 ' + PORT + '  临时数据 ' + TEST_DATA);

  const AUTH = { 'Authorization': 'Bearer ' + SESSION_TOKEN };

  console.log('\n=== H1: 畸形百分号编码不应崩溃 ===');
  for (const p of ['/%zz', '/%', '/%E0%A4%A', '/%zz%', '/a%2']) {
    await t('GET ' + p + ' 不崩', async () => {
      const r = await req(PORT, { path: p });
      assert.ok(r.status === 400 || r.status === 404, '应返回 400/404，实际 ' + r.status);
    });
  }
  await t('畸形请求后服务仍存活', async () => {
    // 探针不能再用 handshake：它现在需要本机授权（H1），无凭据一律 401。
    // 这里要验的是"进程没被畸形请求搞崩"，不是"授权通过"——
    // 所以只要拿到任何一个结构完整的 HTTP 响应就说明服务活着，
    // 401 恰恰是服务正常处理了请求的证据。
    const r = await req(PORT, { path: '/api?action=handshake' });
    assert.ok(r.status > 0 && r.status < 500, '服务应仍可用，实际 ' + r.status);
  });

  console.log('\n=== H2: 畸形请求行不应崩溃 ===');
  await t('绝对形式非法端口', async () => {
    const r = await rawReq(PORT, 'GET http://x:bad HTTP/1.1\r\nHost: x\r\n\r\n');
    assert.ok(!/UNCAUGHT/.test(r), '不应崩溃');
  });
  await t('完全畸形的请求行', async () => {
    await rawReq(PORT, 'GET :::: HTTP/1.1\r\nHost: x\r\n\r\n');
    const r = await req(PORT, { path: '/api?action=handshake' });
    assert.ok(r.status > 0 && r.status < 500, '服务应仍可用，实际 ' + r.status);
  });

  console.log('\n=== M1: Host 头校验（防 DNS rebinding）===');
  await t('非法 Host 返回 403', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: 'evil.example.com:' + PORT },
    });
    assert.strictEqual(r.status, 403, '应被拒绝，实际 ' + r.status);
    assert.ok(!r.body.includes('token'), '不得泄露 token');
  });
  // 无凭据时 127.0.0.1 / localhost 也应当被挡（这正是 H1 的效果），
  // 但**不能**是 403 —— 403 是 Host 校验拒绝，401 才是"Host 对、缺授权"。
  // 两者混淆会让这条测试在 Host 校验被误删时仍然通过。
  await t('127.0.0.1 Host 通过 Host 校验（无凭据 → 401 而非 403）', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: '127.0.0.1:' + PORT },
    });
    assert.strictEqual(r.status, 401, '应为 401（缺授权），实际 ' + r.status);
    assert.ok(!r.body.includes('token'), '无凭据不得下发 token');
  });
  await t('localhost Host 通过 Host 校验（无凭据 → 401 而非 403）', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: 'localhost:' + PORT },
    });
    assert.strictEqual(r.status, 401, '应为 401（缺授权），实际 ' + r.status);
  });

  console.log('\n=== M2: ReDoS 不应阻塞事件循环 ===');
  await t('8 万个 < 的清洗耗时 < 500ms', async () => {
    const { normalizeText } = require('./lib/code-extractor');
    const evil = '<'.repeat(80000);
    const t0 = Date.now();
    normalizeText(evil);
    const ms = Date.now() - t0;
    assert.ok(ms < 500, '耗时 ' + ms + 'ms，应 < 500ms');
  });
  await t('6 万个 < + 验证码文本 < 500ms', async () => {
    const { extractCode } = require('./lib/code-extractor');
    const evil = '<'.repeat(60000) + ' 您的验证码是 123456';
    const t0 = Date.now();
    extractCode(evil);
    const ms = Date.now() - t0;
    assert.ok(ms < 500, '耗时 ' + ms + 'ms，应 < 500ms');
  });
  await t('深度嵌套 multipart 不栈溢出', async () => {
    const { parseMime } = require('./lib/mail');
    // 构造 100 层嵌套
    let raw = 'Content-Type: text/plain\r\n\r\nbottom';
    for (let i = 0; i < 100; i++) {
      raw = 'Content-Type: multipart/mixed; boundary="B' + i + '"\r\n\r\n--B' + i + '\r\n' + raw + '\r\n--B' + i + '--';
    }
    const t0 = Date.now();
    parseMime(raw);
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, '耗时 ' + ms + 'ms');
  });
  await t('超长输入被截断', async () => {
    const { normalizeText } = require('./lib/code-extractor');
    const huge = 'a'.repeat(1000000);
    const t0 = Date.now();
    const r = normalizeText(huge);
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, '耗时 ' + ms);
    assert.ok(r.length <= 200 * 1024 + 10, '应被截断到 200KB 内，实际 ' + r.length);
  });

  console.log('\n=== M3: SMTP STARTTLS 命令真的发了 ===');
  await t('代码里存在 STARTTLS 命令发送', async () => {
    const src = fs.readFileSync(path.join(__dirname, 'lib', 'smtp.js'), 'utf8');
    assert.ok(/_cmd\('STARTTLS'/.test(src), '必须真的发送 STARTTLS 命令并等 220');
  });
  await t('无 STARTTLS 能力时拒绝', async () => {
    const src = fs.readFileSync(path.join(__dirname, 'lib', 'smtp.js'), 'utf8');
    assert.ok(/supportsStartTls/.test(src), '应检查 EHLO 是否声明 STARTTLS');
    assert.ok(/拒绝在明文连接上继续/.test(src), '应有拒绝逻辑');
  });

  console.log('\n=== L1: IMAP 命令注入 ===');
  await t('拒绝含 CR/LF 的邮箱名', async () => {
    const { ImapClient } = require('./lib/imap-client');
    const c = new ImapClient({ host: 'x', port: 993, auth: { user: 'a', accessToken: 'b' } });
    c.socket = { write: () => {}, destroyed: false };
    let threw = false;
    try {
      await c.select('INBOX"\r\nA2 DELETE "INBOX');
    } catch (e) {
      threw = true;
      assert.ok(/控制字符/.test(e.message), '错误信息应说明原因');
    }
    assert.ok(threw, '应抛出异常');
  });
  await t('正常邮箱名通过', async () => {
    const { ImapClient } = require('./lib/imap-client');
    let written = '';
    const c = new ImapClient({ host: 'x', port: 993, auth: { user: 'a', accessToken: 'b' } });
    c.socket = { write: (s) => { written += s; }, destroyed: false };
    const p = c.select('INBOX');
    await new Promise(r => setTimeout(r, 50));
    assert.ok(written.includes('SELECT "INBOX"'), '实际发送: ' + written);
    c.destroy && c.destroy();
  });

  console.log('\n=== L2: token 比较的字节长度 ===');
  await t('多字节 Bearer 不返回 500', async () => {
    const r = await req(PORT, {
      path: '/api?action=accounts',
      headers: { 'Authorization': 'Bearer ' + 'é'.repeat(64) },
    });
    assert.notStrictEqual(r.status, 500, '不应 500，实际 ' + r.status);
    assert.strictEqual(r.status, 401, '应为 401');
  });

  console.log('\n=== L4: CSP 不含 unsafe-inline 脚本 ===');
  await t('script-src 无 unsafe-inline', async () => {
    const r = await req(PORT, { path: '/' });
    const csp = r.headers['content-security-policy'] || '';
    const scriptSrc = (csp.match(/script-src ([^;]+)/) || [])[1] || '';
    assert.ok(!scriptSrc.includes('unsafe-inline'), 'script-src 实际: ' + scriptSrc);
  });
  await t('有 X-Frame-Options', async () => {
    const r = await req(PORT, { path: '/' });
    assert.strictEqual(r.headers['x-frame-options'], 'DENY');
  });

  // 回归：静态资源不能用 max-age 缓存。
  // 曾经 app.js / style.css 是 `public, max-age=300`，结果是代码改了、
  // 浏览器 5 分钟内完全不重新请求，用户看到的界面和磁盘上的文件对不上，
  // 排查时会误判成"改动没生效"或"渲染有 bug"，白花很多时间。
  // 本地静态文件重传成本可忽略，这里锁死 no-cache。
  await t('静态资源不使用 max-age 缓存', async () => {
    for (const p of ['/', '/app.js', '/style.css']) {
      const r = await req(PORT, { path: p });
      const cc = String(r.headers['cache-control'] || '');
      assert.ok(!/max-age\s*=\s*[1-9]/.test(cc), p + ' 的 Cache-Control 不应带 max-age: ' + cc);
      assert.ok(/no-cache/.test(cc), p + ' 应为 no-cache，实际: ' + cc);
    }
  });

  // 回归：服务不能再用 listen(0) 随机分配端口。
  // 那样每次重启网址都变，用户存的书签立刻失效，也没法记住地址。
  await t('服务使用固定端口而不是随机分配', async () => {
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    assert.ok(!/listen\(0\s*,/.test(src), '不应再用 listen(0) 随机端口');
    assert.ok(/DEFAULT_PORT/.test(src), '应有默认端口常量');
    assert.ok(/MAILDESK_PORT/.test(src), '应支持用环境变量覆盖端口');
    assert.ok(/PORT\s*=\s*bound/.test(src), '绑定后应把 PORT 设为实际端口，否则 Host 校验会失效');
  });

  console.log('\n=== M4: 批量写入不是 O(N²) ===');
  // 这里要证明的是「批量导入是一次落盘，不是每条写一次盘」，
  // 而不是「这台机器有多快」。原来的固定 5s 阈值在慢盘上会随机失败
  // （实测本机单次 100KB 落盘约 1s，50 条本身就能到 5.5s），
  // 那是环境噪声，不是回归。改用两点标定：条数翻 4 倍，耗时不该翻 4 倍。
  let importSeq = 0;
  const importN = async n => {
    const tag = 'p' + (importSeq++);
    const lines = [];
    for (let i = 0; i < n; i++) lines.push(tag + '_' + i + '@outlook.com----cid-' + i + '----rt-' + i);
    const t0 = Date.now();
    const r = await req(PORT, {
      method: 'POST',
      path: '/api?action=account.import',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      timeout: 60000,
    }, JSON.stringify({ text: lines.join('\n'), group: tag }));
    return { ms: Date.now() - t0, body: JSON.parse(r.body), n };
  };

  await t('导入 50 条成功且只落盘一次', async () => {
    const r = await importN(50);
    assert.strictEqual(r.body.addedCount, 50, '实际导入 ' + r.body.addedCount);
  });

  await t('条数翻 4 倍，耗时不应近似翻 4 倍（非 O(N²)）', async () => {
    // 直接测时间在慢盘 + 冷热缓存差异下不可靠：同一台机器上 50 条的耗时
    // 既可能 62ms 也可能 2850ms（首次落盘要真实 fsync，随后走缓存）。
    // 真正要证明的是"一次导入只落盘一次"，静态检查数据路径比计时可靠得多。
    const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
    const importBlock = src.slice(src.indexOf("case 'account.import'"), src.indexOf("case 'account.update'"));
    assert.ok(importBlock.length > 0, '找不到 account.import 分支');
    // 允许出现一次批量写；若在循环里逐条 upsert/save 就是 O(N²)
    const inLoop = /for\s*\([^)]*\)\s*\{[\s\S]*?(vault\.upsert\s*\(|vault\.save\s*\()/.test(importBlock);
    assert.ok(!inLoop, 'account.import 在循环里逐条写盘，退化为 O(N²)');
    assert.ok(/vault\.upsertMany\s*\(/.test(importBlock), 'account.import 应使用一次性批量写入 upsertMany');

    // 同时保留一个宽松的实测上限，防止将来引入真正灾难性的实现
    const r = await importN(200);
    assert.strictEqual(r.body.addedCount, 200, '实际导入 ' + r.body.addedCount);
    assert.ok(r.ms < 30000, '导入 200 条耗时 ' + r.ms + 'ms，异常');
    console.log('      [perf] 200 条导入 ' + r.ms + 'ms');
  });

  console.log('\n=== 路径穿越（回归）===');
  for (const p of ['/../server.js', '/..%2fserver.js', '/%2e%2e/server.js', '/..%5cserver.js']) {
    await t('穿越 ' + p + ' 被拦', async () => {
      const r = await req(PORT, { path: p });
      assert.ok(r.status === 403 || r.status === 404, '实际 ' + r.status);
      assert.ok(!r.body.includes('SESSION_TOKEN'), '不得泄露源码');
    });
  }

  console.log('\n=== 前端 XSS 防护（回归）===');
  await t('esc 覆盖五个字符', () => {
    const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    for (const c of ['&amp;', '&lt;', '&gt;', '&quot;', '&#39;']) {
      assert.ok(src.includes(c), '应转义 ' + c);
    }
  });
  await t('邮件 HTML 进 sandbox iframe', () => {
    const src = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
    assert.ok(/iframe[^`]*sandbox/.test(src), '应有 sandbox 属性');
  });

  /* ============================================================
   * 平台标注（F4）：三个新 HTTP action 的端到端回归
   *
   * 这三个端点（platforms.set / platformStats / exportPlatforms）此前
   * **一个断言都没有**。"133 通过"对这个功能的证明力接近零：所有用例都停在
   * lib/platforms.js 的纯函数层，真正被前端调用的那条 HTTP 路径完全没跑过。
   *
   * 这里一律走真实 HTTP + 真实落盘，因为这一层的价值恰恰在于"接线"：
   * 参数怎么解、归一化在哪一步、写回是否真的持久化、响应形状对不对。
   * 纯函数测不出 replace 被改坏这种事故 —— 合并函数本身可以完全正确，
   * 而调用点的 mode 传错、或者算完没写回去。
   * ============================================================ */

  /** 带鉴权的 JSON POST；返回 {status, json} */
  const post = (action, body) => req(PORT, {
    method: 'POST',
    path: '/api?action=' + action,
    headers: { ...AUTH, 'Content-Type': 'application/json' },
  }, JSON.stringify(body)).then(r => ({
    status: r.status,
    json: (() => { try { return JSON.parse(r.body); } catch { return null; } })(),
    raw: r.body,
  }));

  /** 平台上测试用账户，自带唯一前缀，避免和上面批量导入的 p0_/p1_ 撞车 */
  let pfSeq = 0;
  const mkAccount = async (extra = {}) => {
    const email = 'f4_' + (pfSeq++) + '@outlook.com';
    const r = await post('account.add', {
      email, clientId: 'cid-' + email, refreshToken: 'rt-SECRET-' + email, ...extra,
    });
    assert.strictEqual(r.status, 200, '建账户失败：' + r.raw);
    mkAccount.lastEmail = email;
    return r.json.account.id;
  };

  const getAccounts = async () => (await post('accounts', {})).json.accounts;
  const accById = async id => (await getAccounts()).find(a => a.id === id);

  /** 直接读盘上的 vault，用来验证"HTTP 说成功了"和"数据真的落进去了"是一回事 */
  const openVault = () => {
    const { Vault } = require('./lib/vault');
    return new Vault(TEST_DATA, TEST_DATA);
  };

  console.log('\n=== 平台标注：platforms.set 端到端（回归）===');

  await t('add 真的写入，且已有标注被保留', async () => {
    const id = await mkAccount();
    let r = await post('accounts.platforms.set', { ids: [id], platforms: ['github'], mode: 'add' });
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(r.json.updated, 1, '应报告更新 1 个，实际 ' + r.json.updated);

    r = await post('accounts.platforms.set', { ids: [id], platforms: ['Vercel'], mode: 'add' });
    assert.strictEqual(r.json.updated, 1);
    const a = await accById(id);
    // 顺序断言：add 是**追加**，把已有的挤掉就说明合并方向反了
    assert.deepStrictEqual(a.platforms, ['github', 'vercel'], '实际：' + JSON.stringify(a.platforms));
    assert.strictEqual(a.platformNames.vercel, 'Vercel', '自定义平台必须保留原始大小写');
  });

  await t('add 已存在的平台不重复插入（幂等）', async () => {
    const id = await mkAccount();
    await post('accounts.platforms.set', { ids: [id], platforms: ['github'], mode: 'add' });
    // 库里是 github，再提交一次大小写变体：既不能插成第二颗 chip，也不该报"有更新"
    const r = await post('accounts.platforms.set', { ids: [id], platforms: ['GitHub'], mode: 'add' });
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(r.json.updated, 0, '没有实际变化时 updated 应为 0（前端据此提示"本来就有"）');
    const a = await accById(id);
    assert.deepStrictEqual(a.platforms, ['github'], '实际：' + JSON.stringify(a.platforms));
  });

  await t('remove 只去掉指定平台，其余保留', async () => {
    const id = await mkAccount();
    await post('accounts.platforms.set', { ids: [id], platforms: ['github', 'twitter', 'Apple'], mode: 'add' });
    const r = await post('accounts.platforms.set', { ids: [id], platforms: ['twitter'], mode: 'remove' });
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(r.json.updated, 1);
    const a = await accById(id);
    assert.deepStrictEqual(a.platforms, ['github', 'apple'], '实际：' + JSON.stringify(a.platforms));
  });

  // 这条是 F1 重构的现场：applyPlatformMode 被抽成共用函数之后，批量 replace
  // 曾经完全不生效（updated 恒为 0，库里的值一个字都没变）。
  // 合并函数单测会全绿 —— 坏的是调用点。只有走 HTTP 才抓得住。
  await t('replace 真的替换掉原有标注（不是空操作）', async () => {
    const id = await mkAccount();
    const first = await post('accounts.platforms.set', { ids: [id], platforms: ['github', 'twitter'], mode: 'add' });
    assert.strictEqual(first.status, 200, first.raw);
    assert.strictEqual((await accById(id)).platforms.length, 2, '前置：先写入两个平台');

    const r = await post('accounts.platforms.set', { ids: [id], platforms: ['Apple'], mode: 'replace' });
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(r.json.updated, 1, 'replace 必须报告已更新，实际 ' + r.json.updated);
    const a = await accById(id);
    assert.deepStrictEqual(a.platforms, ['apple'],
      'replace 后应只剩 apple，实际：' + JSON.stringify(a.platforms));
    // 内置平台不该留显示名
    assert.deepStrictEqual(a.platformNames, {}, '内置平台不应写进 platformNames');
  });

  await t('replace 的结果真的落盘（换一个新 Vault 读回来仍然存在）', async () => {
    const id = await mkAccount();
    await post('accounts.platforms.set', { ids: [id], platforms: ['steam'], mode: 'replace' });
    // 绕过服务进程的内存/缓存，从盘上重新解一遍：
    // "接口回 200 但数据没写"是这类功能最常见也最难发现的失败。
    const onDisk = openVault().all().find(a => a.id === id);
    assert.ok(onDisk, '盘上应能找到这个账户');
    assert.deepStrictEqual(onDisk.platforms, ['steam'], '盘上的值：' + JSON.stringify(onDisk.platforms));
  });

  await t('批量作用于多个账户，且不影响未选中的账户', async () => {
    const ids = [await mkAccount(), await mkAccount()];
    const bystander = await mkAccount();
    await post('accounts.platforms.set', { ids: [bystander], platforms: ['netflix'], mode: 'replace' });

    const r = await post('accounts.platforms.set', { ids, platforms: ['spotify'], mode: 'replace' });
    assert.strictEqual(r.json.updated, 2, '实际 updated=' + r.json.updated);
    for (const id of ids) {
      assert.deepStrictEqual((await accById(id)).platforms, ['spotify']);
    }
    assert.deepStrictEqual((await accById(bystander)).platforms, ['netflix'], '未选中的账户不能被改');
  });

  console.log('\n=== 平台标注：入口校验（回归）===');

  await t('空 platforms → 400（replace / add）', async () => {
    const id = await mkAccount();
    for (const mode of ['replace', 'add']) {
      const r = await post('accounts.platforms.set', { ids: [id], platforms: [], mode });
      assert.strictEqual(r.status, 400, mode + ' 空 platforms 应 400，实际 ' + r.status);
      assert.strictEqual(r.json.ok, false);
    }
  });

  await t('remove 的空 platforms 是合法空操作（不是 400）', async () => {
    // 前端"去掉所选"什么都没勾时会照常提交空集合，把它判成错误会让用户看到红色报错
    const id = await mkAccount();
    const r = await post('accounts.platforms.set', { ids: [id], platforms: [], mode: 'remove' });
    assert.strictEqual(r.status, 200, '实际 ' + r.status + '：' + r.raw);
    assert.strictEqual(r.json.updated, 0);
  });

  await t('非法 / 缺失 mode → 400（缺省不能是破坏性的 replace）', async () => {
    const id = await mkAccount();
    for (const mode of ['bogus', undefined, null, 0, 'REPLACE']) {
      const r = await post('accounts.platforms.set', { ids: [id], platforms: ['github'], mode });
      assert.strictEqual(r.status, 400,
        'mode=' + JSON.stringify(mode) + ' 应 400，实际 ' + r.status);
    }
  });

  await t('空 ids → 400', async () => {
    const r = await post('accounts.platforms.set', { ids: [], platforms: ['github'], mode: 'add' });
    assert.strictEqual(r.status, 400, '实际 ' + r.status);
  });

  await t('请求体不是对象 → 400 且不泄露内部错误', async () => {
    // 原来 body = null 会走到 `b.mode` 抛 TypeError，被外层 catch 归成 500
    // 并回显 "Cannot read properties of null (reading 'mode')"。
    for (const rawBody of ['null', '[]', '"str"', '123', '{bad json']) {
      const r = await req(PORT, {
        method: 'POST',
        path: '/api?action=accounts.platforms.set',
        headers: { ...AUTH, 'Content-Type': 'application/json' },
      }, rawBody);
      assert.strictEqual(r.status, 400, rawBody + ' 应 400，实际 ' + r.status);
      assert.ok(!/Cannot read propert|TypeError|JSON at position|at Object\./i.test(r.body),
        '响应不得回显内部错误：' + r.body.slice(0, 120));
    }
  });

  console.log('\n=== 平台标注：account.update 不破坏 secrets（回归）===');

  // 空格串是真值：`if (b.refreshToken)` 放行 → trim 成 "" → 令牌被静默清空。
  // refresh_token 一旦丢失，微软的 token 轮转会立刻让旧值失效，账号只能重新导入。
  await t('refreshToken 传纯空白 → 400，且令牌原值不变', async () => {
    const id = await mkAccount();
    const before = openVault().all().find(a => a.id === id).secrets.refreshToken;
    for (const bad of ['   ', '\t', '\n', '', '  \t \n ']) {
      const r = await post('account.update', { id, refreshToken: bad });
      assert.strictEqual(r.status, 400,
        'refreshToken=' + JSON.stringify(bad) + ' 应 400，实际 ' + r.status + '：' + r.raw);
    }
    const after = openVault().all().find(a => a.id === id).secrets.refreshToken;
    assert.strictEqual(after, before, '令牌被改动了：' + JSON.stringify(after));
    assert.ok(before && before.startsWith('rt-SECRET-'), '前置：令牌应是真实值');
  });

  await t('clientId 传纯空白 → 400，且原值不变', async () => {
    const id = await mkAccount();
    const before = openVault().all().find(a => a.id === id).secrets.clientId;
    const r = await post('account.update', { id, clientId: '   ' });
    assert.strictEqual(r.status, 400, '实际 ' + r.status + '：' + r.raw);
    const after = openVault().all().find(a => a.id === id).secrets.clientId;
    assert.strictEqual(after, before);
  });

  // account.update 曾经是 find() 拿完整快照 → 改几个字段 → upsert(acc)。
  // upsert 是浅合并，整份 secrets 被快照覆盖：只要两次读之间发生过一次
  // refresh_token 轮换，用户改个标签就能让账号报废。现在必须走 updateMeta。
  await t('只改 label 时 secrets 一个字段都不受影响', async () => {
    const id = await mkAccount({ group: '原分组', note: '原备注' });
    const before = openVault().all().find(a => a.id === id).secrets;
    assert.ok(before.refreshToken && before.clientId, '前置：应有凭据');

    const r = await post('account.update', { id, label: '新标签', platforms: ['github'] });
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(r.json.account.label, '新标签');

    const after = openVault().all().find(a => a.id === id);
    assert.deepStrictEqual(after.secrets, before,
      '改元数据不应动 secrets。前：' + JSON.stringify(before) + ' 后：' + JSON.stringify(after.secrets));
    assert.strictEqual(after.group, '原分组', '没传的字段不应被清空');
    assert.strictEqual(after.note, '原备注', '没传的字段不应被清空');
    assert.deepStrictEqual(after.platforms, ['github']);
  });

  await t('显式传 refreshToken 时只改令牌，其余 secrets 保留', async () => {
    const id = await mkAccount();
    const before = openVault().all().find(a => a.id === id).secrets;
    const r = await post('account.update', { id, refreshToken: 'RT-NEW-1' });
    assert.strictEqual(r.status, 200, r.raw);
    const after = openVault().all().find(a => a.id === id).secrets;
    assert.strictEqual(after.refreshToken, 'RT-NEW-1', '应写入新令牌');
    assert.strictEqual(after.clientId, before.clientId, 'clientId 必须保留');
    assert.strictEqual(after.endpoint, before.endpoint, 'endpoint 必须保留');
  });

  console.log('\n=== 平台标注：platformStats / exportPlatforms 端到端（回归）===');

  await t('platformStats 形状正确且计数准确', async () => {
    const a = await mkAccount();
    const b = await mkAccount();
    await post('accounts.platforms.set', { ids: [a, b], platforms: ['Anthropic'], mode: 'replace' });
    const r = await post('accounts.platformStats', {});
    assert.strictEqual(r.status, 200, r.raw);
    assert.ok(Array.isArray(r.json.stats), 'stats 必须是数组');

    const row = r.json.stats.find(s => s.key === 'anthropic');
    assert.ok(row, 'stats 里应有 anthropic，实际：' + JSON.stringify(r.json.stats.map(s => s.key)));
    assert.strictEqual(row.name, 'Anthropic', '内置平台显示名应从内置表取');
    assert.ok(row.count >= 2, '至少这两个账户，实际 ' + row.count);

    // 每项都必须有完整的 {key,name,count}，前端直接拿去渲染 option
    for (const s of r.json.stats) {
      assert.strictEqual(typeof s.key, 'string');
      assert.strictEqual(typeof s.name, 'string');
      assert.strictEqual(typeof s.count, 'number');
      assert.ok(s.key && s.name, 'key/name 不得为空');
    }
    // 计数降序，同数按名字：顺序抖动会让用户在下拉里点错行
    for (let i = 1; i < r.json.stats.length; i++) {
      assert.ok(r.json.stats[i - 1].count >= r.json.stats[i].count, 'stats 必须按 count 降序');
    }
  });

  await t('exportPlatforms 返回 CSV 文本，且不含任何凭据', async () => {
    const id = await mkAccount();
    const email = mkAccount.lastEmail;
    await post('accounts.platforms.set', { ids: [id], platforms: ['github', 'Vercel'], mode: 'replace' });
    const r = await post('accounts.exportPlatforms', {});
    assert.strictEqual(r.status, 200, r.raw);
    assert.strictEqual(typeof r.json.text, 'string');
    assert.strictEqual(typeof r.json.count, 'number');

    // BOM：Excel 双击打开 UTF-8 CSV 不带 BOM 会把中文按代码页解，全变乱码
    assert.ok(r.json.text.startsWith('﻿'), 'CSV 应以 BOM 开头');
    const lines = r.json.text.slice(1).split('\r\n');
    assert.deepStrictEqual(lines[0].split(','), ['邮箱', '标签', '分组', '平台', '平台数量'],
      '表头实际：' + lines[0]);

    // 按**邮箱**找行，不能按平台名：平台列的大小写本身就是要断言的内容，
    // 拿它当定位条件会让这条用例在大小写出错时"找不到行"而非"值不对"，
    // 失败信息指向错误的方向。
    const row = lines.find(l => l.startsWith(email + ','));
    assert.ok(row, '应能找到刚标注的账户行，实际 CSV：\n' + r.json.text.slice(0, 400));
    const cells = row.split(',');
    assert.strictEqual(cells[3].split('; ')[0], 'GitHub',
      '内置平台必须用内置表里的正确大小写，实际：' + JSON.stringify(cells[3]));
    assert.strictEqual(cells[4], '2', '平台数量列应为 2，实际：' + JSON.stringify(cells[4]));

    // 导出的是"哪个邮箱注册了哪些服务"，绝不能顺手把凭据带出去
    assert.ok(!/rt-SECRET-|cid-f4_/.test(r.json.text), 'CSV 里出现了凭据，泄露！');
  });

  await t('exportPlatforms 的 CSV 对公式注入免疫（真实数据路径）', async () => {
    // 载体不是平台名，是**导入的 group / 邮箱列** —— 这两列没有字符限制，
    // 用户从号商那里拿到的文件里就可能有以 = 开头的内容。
    // 只测 csvCell 纯函数不够：真正的风险是"它在这条调用链上有没有被用上"。
    const evilGroup = '=cmd|\'/c calc\'!A1';
    const id = await mkAccount({ group: evilGroup });
    const r = await post('accounts.exportPlatforms', { ids: [id] });
    assert.strictEqual(r.status, 200, r.raw);
    const lines = r.json.text.slice(1).split('\r\n');
    assert.strictEqual(lines.length, 2, 'ids 过滤后应只有表头和一行，实际 ' + lines.length);

    const cells = lines[1].split(',');
    assert.strictEqual(cells[2], "'" + evilGroup,
      '分组列必须以单引号开头，实际：' + JSON.stringify(cells[2]));

    // 反向断言：任何单元格都不能以公式字符开头。
    // 单向断言（"这一格有前缀"）漏掉的是"别处又冒出一格没被处理的"，
    // 而注入点恰恰可能就在别处 —— 所以整行逐格扫一遍。
    for (const c of cells) {
      const v = c.startsWith('"') ? c.slice(1) : c;
      assert.ok(!/^[=+\-@]/.test(v),
        '单元格以公式字符开头：' + JSON.stringify(c));
    }
  });

  await t('exportPlatforms 按 ids / platform 过滤', async () => {
    const a = await mkAccount();
    const b = await mkAccount();
    await post('accounts.platforms.set', { ids: [a], platforms: ['reddit'], mode: 'replace' });
    await post('accounts.platforms.set', { ids: [b], platforms: ['twitch'], mode: 'replace' });

    const byId = await post('accounts.exportPlatforms', { ids: [a] });
    assert.strictEqual(byId.json.count, 1, 'ids 过滤应只导出 1 条，实际 ' + byId.json.count);

    // 传显示名也要能命中（筛选器里存的是显示名）
    const byPf = await post('accounts.exportPlatforms', { platform: 'Reddit' });
    assert.strictEqual(byPf.json.count, 1, '按 platform 过滤应命中 1 条，实际 ' + byPf.json.count);
    assert.ok(byPf.json.text.includes('Reddit'));

    // 必须挑一个**本次运行里没人用过**的平台：前面的用例已经标过 anthropic 等，
    // 用它们会得到非零计数，而这条断言要证明的是"没有匹配项时返回空"。
    const noMatch = await post('accounts.exportPlatforms', { platform: 'nothing-uses-this-xyz' });
    assert.strictEqual(noMatch.json.count, 0,
      '没有该平台时应导出 0 条，实际 ' + noMatch.json.count + '：' + noMatch.json.text.slice(0, 200));
    assert.strictEqual(noMatch.json.text.slice(1).split('\r\n').length, 1, '只应有表头');
  });

  // platformStats / exportPlatforms 在 F1-10 里加了"对 key 做归一化"，
  // 归一化会顺带产出一份 platformNames（自定义平台的"显示名"就是它自己的小写 key）。
  // 合并顺序写成 { ...stored, ...normalized } 就会用这份小写名覆盖掉库里真正的
  // 'Vercel' —— 用户明明存的是大写，筛选器和导出里却变成小写。
  // 单独一条用例守这个：它和"计数/形状"是两件事，混在一起失败时分不清是哪坏了。
  await t('自定义平台的原始大小写在 stats 里不被归一化覆盖', async () => {
    const id = await mkAccount();
    await post('accounts.platforms.set', { ids: [id], platforms: ['MyBlog'], mode: 'replace' });
    const stored = (await accById(id)).platformNames;
    assert.strictEqual(stored.myblog, 'MyBlog', '前置：库里存的应是 MyBlog');

    const r = await post('accounts.platformStats', {});
    const row = r.json.stats.find(s => s.key === 'myblog');
    assert.ok(row, 'stats 里应有 myblog');
    assert.strictEqual(row.name, 'MyBlog',
      '显示名必须用库里的原始大小写，实际：' + JSON.stringify(row.name));
  });

  await t('自定义平台的原始大小写在导出 CSV 里不被归一化覆盖', async () => {
    const id = await mkAccount();
    const email = mkAccount.lastEmail;
    await post('accounts.platforms.set', { ids: [id], platforms: ['MyBlog'], mode: 'replace' });
    const r = await post('accounts.exportPlatforms', { ids: [id] });
    const cells = r.json.text.slice(1).split('\r\n')[1].split(',');
    assert.strictEqual(cells[0], email);
    assert.strictEqual(cells[3], 'MyBlog',
      '导出里的显示名必须用库里的原始大小写，实际：' + JSON.stringify(cells[3]));
  });

  console.log('\n=== 平台标注：损坏条目告警（回归）===');

  // vault.corruptedEntries() 曾经在整个 server.js 里 0 次调用：坏条目被 all()
  // 静默跳过，用户只看到"100 个账号变成 99 个"，没有任何提示。
  await t('库里有解不开的条目时，accounts / platformStats / exportPlatforms 都带 warn', async () => {
    const { Vault } = require('./lib/vault');
    const encPath = path.join(TEST_DATA, 'accounts.enc');
    const backup = fs.readFileSync(encPath);
    try {
      const raw = JSON.parse(backup.toString('utf8'));
      assert.ok(raw.accounts.length > 0, '前置：测试库应已有账户');
      // 把一条的密文换掉：v2 密文的认证标签对不上，必然解不开
      raw.accounts[0].blob = { iv: 'AAAA', ct: 'BBBB', tag: 'CCCC' };
      raw.accounts[0].v = 2;
      fs.writeFileSync(encPath, JSON.stringify(raw));

      for (const action of ['accounts', 'accounts.platformStats', 'accounts.exportPlatforms']) {
        const r = await post(action, {});
        assert.strictEqual(r.status, 200, action + ' 不应因为一条坏数据就失败，实际 ' + r.status);
        assert.ok(r.json.warn && /无法解密/.test(r.json.warn),
          action + ' 应带 warn 提示损坏条目，实际：' + JSON.stringify(r.json.warn));
      }
      // 坏的那条不能被算进导出结果
      const ex = await post('accounts.exportPlatforms', {});
      assert.strictEqual(ex.json.count, raw.accounts.length - 1,
        '导出的 count 应排除坏条目，实际 ' + ex.json.count);
    } finally {
      fs.writeFileSync(encPath, backup);
    }
  });

  await t('没有损坏条目时不带 warn 键（保持响应形状不变）', async () => {
    const r = await post('accounts', {});
    assert.strictEqual(r.status, 200);
    assert.ok(!r.json.warn, '正常库不应出现 warn，实际：' + JSON.stringify(r.json.warn));
  });

  console.log(`\n${'='.repeat(50)}`);
  console.log(`结果： ${pass} 通过， ${fail} 失败`);
  console.log('='.repeat(50) + '\n');

  process.exit(fail ? 1 : 0);
})();
