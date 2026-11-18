'use strict';
/**
 * KeyDesk 安全回归测试
 *   node security-test.js
 *
 * 每一项都对应一条具体的攻击面，不是"跑通就行"的冒烟测试。
 * 跑在独立的临时目录上，绝不碰真实 vault.enc。
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');

let pass = 0, fail = 0;
const failures = [];

function t(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { console.log('  ✓ ' + name); pass++; })
    .catch(e => {
      console.log('  ✗ ' + name + '\n      ' + (e && e.message));
      failures.push(name + ': ' + (e && e.message));
      fail++;
    });
}

function section(s) { console.log('\n=== ' + s + ' ==='); }

/** 发一个 HTTP 请求 */
function req(port, opts, body) {
  return new Promise(resolve => {
    const r = http.request({
      host: '127.0.0.1',
      port,
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
    r.setTimeout(opts.timeout || 10000, () => {
      r.destroy();
      resolve({ status: 0, error: 'timeout', headers: {}, body: '' });
    });
    if (body !== undefined) r.write(typeof body === 'string' ? body : JSON.stringify(body));
    r.end();
  });
}

/** 原始 socket：发畸形请求行 / 手工控制头 */
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

function parseJson(r) {
  try { return JSON.parse(r.body); } catch { return null; }
}

(async function main() {
  console.log('\n=== 启动测试服务 ===');
  const TEST_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'keydesk-sec-'));
  process.env.KEYDESK_DATA_DIR = TEST_DATA;

  // 服务端默认 N=32768（约 240ms/次）。安全测试里有 6 次解锁相关的
  // 请求，约 1.5s，完全可接受，所以这里不降参数——正好顺带验证
  // 生产路径真的能跑通。
  const { start, SESSION_TOKEN } = require('./server');
  const addr = await start();
  const PORT = parseInt(addr.split(':').pop(), 10);
  console.log('  端口 ' + PORT + '  临时数据 ' + TEST_DATA);

  const AUTH = { 'Authorization': 'Bearer ' + SESSION_TOKEN };
  const JSONH = { 'Content-Type': 'application/json' };

  /* ---------------- 基线：服务真的起来了 ---------------- */

  section('0. 基线');
  await t('握手返回 token 且带 no-store', async () => {
    const r = await req(PORT, { path: '/api?action=handshake' });
    assert.strictEqual(r.status, 200);
    const j = parseJson(r);
    assert.ok(j && j.ok === true);
    assert.strictEqual(typeof j.token, 'string');
    assert.strictEqual(j.token.length, 64, 'token 应为 32 字节的 hex');
    assert.strictEqual(r.headers['cache-control'], 'no-store');
  });

  await t('静态页返回 CSP script-src self', async () => {
    const r = await req(PORT, { path: '/' });
    assert.strictEqual(r.status, 200);
    const csp = r.headers['content-security-policy'] || '';
    assert.ok(csp.includes("script-src 'self'"), 'CSP 缺少 script-src self: ' + csp);
    assert.ok(!csp.includes('unsafe-inline'), 'CSP 不应含 unsafe-inline: ' + csp);
    assert.ok(!csp.includes('unsafe-eval'), 'CSP 不应含 unsafe-eval');
    assert.ok(csp.includes("object-src 'none'"));
    assert.ok(csp.includes("frame-ancestors 'none'"));
  });

  await t('index.html 不含内联脚本 / onclick', async () => {
    const r = await req(PORT, { path: '/' });
    assert.ok(!/<script(?![^>]*\bsrc=)/i.test(r.body), '页面里有内联 <script>');
    assert.ok(!/\son[a-z]+\s*=/i.test(r.body), '页面里有 onclick 之类的事件属性');
    assert.ok(!/\sstyle\s*=/i.test(r.body), '页面里有内联 style 属性（CSP style-src self 会拦掉）');
  });

  await t('app.js 不含 onclick / eval / new Function', async () => {
    const r = await req(PORT, { path: '/app.js' });
    assert.strictEqual(r.status, 200);
    assert.ok(!/\bon[a-z]+\s*=\s*["']/i.test(r.body), 'app.js 里有内联事件属性字符串');
    assert.ok(!/\beval\s*\(/.test(r.body), 'app.js 里用了 eval');
    assert.ok(!/new\s+Function\s*\(/.test(r.body), 'app.js 里用了 new Function');
  });

  /* ---------------- 1. Host 校验 ---------------- */

  section('1. Host 头校验（防 DNS rebinding）');

  await t('非法 Host 返回 403 且不泄露 token', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: 'evil.example.com:' + PORT },
    });
    assert.strictEqual(r.status, 403, '应被拒绝，实际 ' + r.status);
    assert.ok(!r.body.includes('token'), '响应里出现了 token');
  });

  await t('DNS rebinding 典型 Host（attacker.test:端口）被拒', async () => {
    for (const h of ['attacker.test:' + PORT, '127.0.0.1.nip.io:' + PORT,
      'localhost.evil.com:' + PORT, '0.0.0.0:' + PORT]) {
      const r = await req(PORT, { path: '/api?action=handshake', headers: { Host: h } });
      assert.strictEqual(r.status, 403, h + ' 应被拒绝，实际 ' + r.status);
    }
  });

  await t('127.0.0.1 Host 正常', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: '127.0.0.1:' + PORT },
    });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.includes('token'));
  });

  await t('localhost Host 正常', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Host: 'localhost:' + PORT },
    });
    assert.strictEqual(r.status, 200);
  });

  await t('Host 缺失被拒', async () => {
    // HTTP/1.1 必须带 Host；没有的话 node 会拒，但我们要确认不是 200
    const raw = await rawReq(PORT,
      'GET /api?action=handshake HTTP/1.1\r\nConnection: close\r\n\r\n');
    assert.ok(!/200 OK/.test(raw) || !/token/.test(raw), '无 Host 却拿到了 token');
  });

  /* ---------------- 2. CORS ---------------- */

  section('2. CORS 白名单');

  await t('跨域 Origin 不回 ACAO（不泄露 token）', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Origin: 'https://evil.example.com' },
    });
    assert.strictEqual(r.headers['access-control-allow-origin'], undefined,
      '不应给第三方站点回 ACAO');
  });

  await t('绝不回 Access-Control-Allow-Origin: *', async () => {
    for (const origin of ['https://evil.com', 'null', 'http://127.0.0.1:1',
      'http://localhost:9999']) {
      const r = await req(PORT, {
        path: '/api?action=handshake',
        headers: { Origin: origin },
      });
      assert.notStrictEqual(r.headers['access-control-allow-origin'], '*',
        '对 ' + origin + ' 回了通配符');
    }
  });

  await t('同端口 127.0.0.1 Origin 拿到 ACAO', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Origin: 'http://127.0.0.1:' + PORT },
    });
    assert.strictEqual(r.headers['access-control-allow-origin'], 'http://127.0.0.1:' + PORT);
  });

  await t('同端口 localhost Origin 拿到 ACAO', async () => {
    const r = await req(PORT, {
      path: '/api?action=handshake',
      headers: { Origin: 'http://localhost:' + PORT },
    });
    assert.strictEqual(r.headers['access-control-allow-origin'], 'http://localhost:' + PORT);
  });

  await t('OPTIONS 预检对第三方 Origin 不回 ACAO', async () => {
    const r = await req(PORT, {
      method: 'OPTIONS',
      path: '/api?action=entries.list',
      headers: { Origin: 'https://evil.example.com' },
    });
    assert.strictEqual(r.status, 204);
    assert.strictEqual(r.headers['access-control-allow-origin'], undefined);
  });

  /* ---------------- 3. 路径穿越 ---------------- */

  section('3. 静态文件路径穿越');

  await t('../../../ 形式被拒', async () => {
    for (const p of [
      '/../../etc/passwd',
      '/../../server.js',
      '/..%2f..%2fserver.js',
      '/%2e%2e/%2e%2e/server.js',
      '/....//....//server.js',
      '/public/../server.js',
      '/../data/vault.enc',
    ]) {
      const r = await req(PORT, { path: p });
      assert.ok(r.status === 403 || r.status === 404 || r.status === 400,
        p + ' 应该被拒，实际 ' + r.status);
      assert.ok(!r.body.includes('require('), p + ' 泄露了服务端源码');
    }
  });

  await t('vault.enc 无法通过静态路径读取', async () => {
    for (const p of ['/../data/vault.enc', '/data/vault.enc', '/vault.enc',
      '/%2e%2e/data/vault.enc']) {
      const r = await req(PORT, { path: p });
      assert.ok(!r.body.includes('keydesk/1'), p + ' 泄露了 vault 内容');
      assert.ok(r.status !== 200 || !r.body.includes('"format"'), p + ' 状态 ' + r.status);
    }
  });

  await t('NUL 字节路径被拒', async () => {
    const raw = await rawReq(PORT,
      'GET /index.html%00.css HTTP/1.1\r\nHost: 127.0.0.1:' + PORT +
      '\r\nConnection: close\r\n\r\n');
    assert.ok(!/200 OK/.test(raw), 'NUL 路径返回了 200');
  });

  await t('畸形百分号编码返回 400 且不崩', async () => {
    for (const p of ['/%zz', '/%', '/%E0%A4%A', '/%zz%', '/a%2']) {
      const r = await req(PORT, { path: p });
      assert.ok(r.status === 400 || r.status === 404, p + ' 实际 ' + r.status);
    }
    // 服务还活着
    const alive = await req(PORT, { path: '/api?action=handshake' });
    assert.strictEqual(alive.status, 200, '畸形请求后服务挂了');
  });

  await t('畸形请求行不崩', async () => {
    await rawReq(PORT, 'GET http://x:bad HTTP/1.1\r\nHost: x\r\n\r\n');
    await rawReq(PORT, 'GET :::: HTTP/1.1\r\nHost: x\r\n\r\n');
    await rawReq(PORT, 'NOTAMETHOD / HTTP/1.1\r\nHost: 127.0.0.1:' + PORT + '\r\n\r\n');
    const alive = await req(PORT, { path: '/api?action=handshake' });
    assert.strictEqual(alive.status, 200, '畸形请求行后服务挂了');
  });

  await t('非 GET 的静态路径返回 405', async () => {
    const r = await req(PORT, { method: 'POST', path: '/index.html' });
    assert.strictEqual(r.status, 405);
  });

  /* ---------------- 4. token 校验 ---------------- */

  section('4. Bearer token 校验');

  await t('无 Authorization 返回 401', async () => {
    const r = await req(PORT, { path: '/api?action=vault.status' });
    assert.strictEqual(r.status, 401);
    const j = parseJson(r);
    assert.strictEqual(j.ok, false);
  });

  await t('错误 token 返回 401', async () => {
    // 最后一个用例：把首字符换成一个必然不同的 hex 字符。
    // 不要用 slice(0,-1)+'f' —— token 末位本来就有 1/16 概率是 'f'，
    // 那样构造出来的"错 token"和真的完全一样，测试会偶发失败。
    const flipped = (SESSION_TOKEN[0] === 'a' ? 'b' : 'a') + SESSION_TOKEN.slice(1);
    assert.notStrictEqual(flipped, SESSION_TOKEN);
    for (const tok of ['', 'x', 'a'.repeat(64), flipped, SESSION_TOKEN.toUpperCase()]) {
      const r = await req(PORT, {
        path: '/api?action=vault.status',
        headers: { Authorization: 'Bearer ' + tok },
      });
      assert.strictEqual(r.status, 401, JSON.stringify(tok.slice(0, 10)) + ' 实际 ' + r.status);
    }
  });

  await t('缺少 Bearer 前缀返回 401', async () => {
    const r = await req(PORT, {
      path: '/api?action=vault.status',
      headers: { Authorization: SESSION_TOKEN },
    });
    assert.strictEqual(r.status, 401);
  });

  await t('正确 token 通过', async () => {
    const r = await req(PORT, { path: '/api?action=vault.status', headers: AUTH });
    assert.strictEqual(r.status, 200);
  });

  await t('token 是 64 位 hex（32 字节随机）', async () => {
    assert.match(SESSION_TOKEN, /^[0-9a-f]{64}$/);
  });

  /* ---------------- 5. 未解锁 = 423 ---------------- */

  section('5. 未解锁时一律 423');

  await t('未初始化状态下 entries.list 返回 423', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 423);
    const j = parseJson(r);
    assert.strictEqual(j.code, 'LOCKED');
  });

  await t('锁定态下所有非白名单 action 都是 423', async () => {
    const blocked = [
      'entries.list', 'entries.get', 'entries.upsert', 'entries.remove',
      'entries.archive', 'otp.codes', 'otp.check', 'otp.verify',
      'recovery.reveal', 'recovery.addSet', 'recovery.setCurrent',
      'recovery.updateSet', 'recovery.removeSet', 'recovery.markCodes',
      'secrets.reveal', 'entries.export', 'qr.svg', 'backup.info',
      'vault.lock', 'vault.changePassphrase', 'vault.regenerateRecovery',
      'vault.settings',
    ];
    for (const a of blocked) {
      const r = await req(PORT, {
        method: 'POST', path: '/api?action=' + a,
        headers: { ...AUTH, ...JSONH },
      }, {});
      assert.strictEqual(r.status, 423, a + ' 应为 423，实际 ' + r.status);
      const j = parseJson(r);
      assert.strictEqual(j.code, 'LOCKED', a + ' 的 code 应为 LOCKED');
    }
  });

  await t('锁定态白名单：status / setup / unlock / unlockRecovery 不被 423', async () => {
    const st = await req(PORT, { path: '/api?action=vault.status', headers: AUTH });
    assert.strictEqual(st.status, 200);

    // setup 用短口令会 400（INVALID），但绝不能是 423
    const su = await req(PORT, {
      method: 'POST', path: '/api?action=vault.setup',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: 'x' });
    assert.strictEqual(su.status, 400);
    assert.notStrictEqual(parseJson(su).code, 'LOCKED');

    // unlock 未初始化时 404（NOT_FOUND），不是 423
    const un = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlock',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: 'whatever123' });
    assert.strictEqual(un.status, 404);
    assert.notStrictEqual(parseJson(un).code, 'LOCKED');
  });

  await t('锁定态响应里不含任何条目数据', async () => {
    for (const a of ['entries.list', 'otp.codes', 'backup.info']) {
      const r = await req(PORT, {
        method: 'POST', path: '/api?action=' + a,
        headers: { ...AUTH, ...JSONH },
      }, {});
      assert.ok(!r.body.includes('items'), a + ' 的 423 响应里带了 items');
      assert.ok(!r.body.includes('entry'), a + ' 的 423 响应里带了 entry');
    }
  });

  /* ---------------- 6. setup / 解锁流程 ---------------- */

  section('6. 创建与解锁');

  let RECOVERY_KEY = '';
  const PASSPHRASE = 'a long test passphrase 42';

  await t('vault.setup 返回恢复密钥（26 字符）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.setup',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: PASSPHRASE });
    assert.strictEqual(r.status, 200, r.body);
    const j = parseJson(r);
    assert.strictEqual(j.ok, true);
    assert.match(j.recoveryKey, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$/);
    RECOVERY_KEY = j.recoveryKey;
  });

  await t('setup 后立刻可用（已解锁）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(parseJson(r).items, []);
  });

  await t('重复 setup 返回 409 CONFLICT', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.setup',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: PASSPHRASE });
    assert.strictEqual(r.status, 409);
    assert.strictEqual(parseJson(r).code, 'CONFLICT');
  });

  await t('lock 后再访问条目返回 423', async () => {
    const l = await req(PORT, {
      method: 'POST', path: '/api?action=vault.lock',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(l.status, 200);

    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 423);
  });

  await t('错口令解锁返回 401 BAD_PASSPHRASE', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlock',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: 'definitely wrong passphrase' });
    assert.strictEqual(r.status, 401);
    assert.strictEqual(parseJson(r).code, 'BAD_PASSPHRASE');
  });

  await t('错口令失败后仍然是锁定状态', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 423);
  });

  await t('正确口令解锁返回 expiresAt', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlock',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: PASSPHRASE });
    assert.strictEqual(r.status, 200, r.body);
    const j = parseJson(r);
    assert.strictEqual(j.ok, true);
    assert.ok(j.expiresAt === null || !isNaN(Date.parse(j.expiresAt)));
  });

  /* ---------------- 7. 限速 ---------------- */

  section('7. 失败限速');

  await t('连续 5 次错口令后第 6 次返回 429 THROTTLED', async () => {
    // 先锁上
    await req(PORT, {
      method: 'POST', path: '/api?action=vault.lock',
      headers: { ...AUTH, ...JSONH },
    }, {});

    // 前 5 次：BAD_PASSPHRASE
    for (let i = 0; i < 5; i++) {
      const r = await req(PORT, {
        method: 'POST', path: '/api?action=vault.unlock',
        headers: { ...AUTH, ...JSONH },
      }, { passphrase: 'wrong guess number ' + i });
      assert.strictEqual(r.status, 401, '第 ' + (i + 1) + ' 次应还是 401，实际 ' + r.status);
    }

    // 第 6 次：即使口令正确也被限速挡住
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlock',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: PASSPHRASE });
    assert.strictEqual(r.status, 429, '应被限速，实际 ' + r.status);
    const j = parseJson(r);
    assert.strictEqual(j.code, 'THROTTLED');
    assert.match(j.error, /\d+ 秒/);
  });

  await t('限速期间用恢复密钥也被挡', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlockRecovery',
      headers: { ...AUTH, ...JSONH },
    }, { recoveryKey: RECOVERY_KEY });
    assert.strictEqual(r.status, 429);
    assert.strictEqual(parseJson(r).code, 'THROTTLED');
  });

  await t('限速状态不泄露内部计数以外的信息', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlock',
      headers: { ...AUTH, ...JSONH },
    }, { passphrase: PASSPHRASE });
    const j = parseJson(r);
    // 只应有 ok/error/code 三个键
    assert.deepStrictEqual(Object.keys(j).sort(), ['code', 'error', 'ok']);
  });

  /* ---------------- 8. 秘密不泄露 ---------------- */

  section('8. 秘密不泄露（端到端）');

  // 限速窗口是 5 秒起步，等它过去（用恢复密钥解锁，顺便验证恢复通道）
  console.log('      等待限速窗口（5s）…');
  await new Promise(r => setTimeout(r, 5200));

  await t('恢复密钥解锁成功', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlockRecovery',
      headers: { ...AUTH, ...JSONH },
    }, { recoveryKey: RECOVERY_KEY });
    assert.strictEqual(r.status, 200, r.body);
    assert.strictEqual(parseJson(r).ok, true);
  });

  const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';
  const REC_VALUE = 'RECO-VERY-1';
  let ENTRY_ID = '';

  await t('建立带全部秘密种类的条目', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.upsert',
      headers: { ...AUTH, ...JSONH },
    }, {
      entry: {
        type: 'totp', issuer: 'GitHub', account: 'alice@x.com',
        totp: { secret: SECRET },
        password: { value: 'SuperSecretPw!' },
        recovery: {
          sets: [{
            createdAt: new Date().toISOString(),
            codes: [{ value: REC_VALUE }, { value: 'RECO-VERY-2' }],
          }],
        },
      },
    });
    assert.strictEqual(r.status, 200, r.body);
    ENTRY_ID = parseJson(r).entry.id;
    assert.ok(ENTRY_ID);
  });

  const secretFree = (label, body) => {
    assert.ok(!body.includes(SECRET), label + ' 出现了明文 TOTP 密钥');
    assert.ok(!body.includes(REC_VALUE), label + ' 出现了恢复码明文');
    assert.ok(!body.includes('SuperSecretPw!'), label + ' 出现了密码明文');
    // 这里原来写的是 `test(body) || true`——一个恒真表达式，等于这条断言
    // 永远不会失败。实测：往 summarize() 里塞一个 value: 'LeakedValue9x'
    // （真实泄露形状，只是不等于上面那三个写死的常量），71 条测试依然全绿。
    // 去掉 `|| true` 之后同样的变异立刻变红两条。
    assert.ok(!/"(secret|totpSecret|passwordValue|value)"\s*:\s*"[A-Za-z0-9]/.test(body),
      label + ' 含秘密形状的字段（secret/totpSecret/passwordValue/value 带字符串值）');
  };

  await t('entries.list 响应不含任何秘密', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 200);
    secretFree('entries.list', r.body);
    assert.ok(!r.body.includes('secret'), 'list 里有 secret 这个词');
  });

  await t('entries.get 响应不含任何秘密', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.get',
      headers: { ...AUTH, ...JSONH },
    }, { id: ENTRY_ID });
    assert.strictEqual(r.status, 200);
    secretFree('entries.get', r.body);
    const j = parseJson(r);
    assert.strictEqual(j.entry.totp.secret, undefined);
  });

  await t('otp.codes 响应不含任何秘密', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=otp.codes',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 200);
    secretFree('otp.codes', r.body);
    const j = parseJson(r);
    assert.strictEqual(j.items.length, 1);
    assert.match(j.items[0].code, /^\d{6}$/);
    assert.deepStrictEqual(Object.keys(j.items[0]).sort(),
      ['code', 'expiresAt', 'id', 'period', 'remaining']);
  });

  await t('secrets.reveal 缺 confirm 被拒（400）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=secrets.reveal',
      headers: { ...AUTH, ...JSONH },
    }, { id: ENTRY_ID, field: 'totp' });
    assert.strictEqual(r.status, 400);
    assert.ok(!r.body.includes(SECRET));
  });

  await t('secrets.reveal confirm:false 被拒', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=secrets.reveal',
      headers: { ...AUTH, ...JSONH },
    }, { id: ENTRY_ID, field: 'totp', confirm: false });
    assert.strictEqual(r.status, 400);
    assert.ok(!r.body.includes(SECRET));
  });

  await t('secrets.reveal confirm:true 才返回密钥', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=secrets.reveal',
      headers: { ...AUTH, ...JSONH },
    }, { id: ENTRY_ID, field: 'totp', confirm: true });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(parseJson(r).value, SECRET);
  });

  await t('recovery.reveal 缺 confirm 被拒', async () => {
    const g = await req(PORT, {
      method: 'POST', path: '/api?action=entries.get',
      headers: { ...AUTH, ...JSONH },
    }, { id: ENTRY_ID });
    const setId = parseJson(g).entry.recovery.currentSetId;

    const r = await req(PORT, {
      method: 'POST', path: '/api?action=recovery.reveal',
      headers: { ...AUTH, ...JSONH },
    }, { entryId: ENTRY_ID, setId });
    assert.strictEqual(r.status, 400);
    assert.ok(!r.body.includes(REC_VALUE));
  });

  await t('备份信息不含条目内容', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=backup.info',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 200);
    secretFree('backup.info', r.body);
    const j = parseJson(r);
    assert.ok(j.entries >= 0);
    assert.ok(typeof j.revision === 'number');
  });

  /* ---------------- 9. 输入校验 ---------------- */

  section('9. 输入校验与边界');

  await t('超大请求体被拒（400，不是 500）', async () => {
    const huge = JSON.stringify({ entry: { type: 'note', issuer: 'X', note: 'A'.repeat(2 * 1024 * 1024) } });
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.upsert',
      headers: { ...AUTH, ...JSONH, 'Content-Length': Buffer.byteLength(huge) },
    }, huge);
    assert.strictEqual(r.status, 400, '实际 ' + r.status);
  });

  await t('非 JSON 请求体返回 400', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, 'this is not json{{{');
    assert.strictEqual(r.status, 400);
  });

  await t('JSON 数组请求体被拒（必须是对象）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, '[1,2,3]');
    assert.strictEqual(r.status, 400);
  });

  await t('未知 action 返回 404 NOT_FOUND', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=does.not.exist',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 404);
    assert.strictEqual(parseJson(r).code, 'NOT_FOUND');
  });

  await t('缺 action 参数返回 400', async () => {
    const r = await req(PORT, { path: '/api', headers: AUTH });
    assert.strictEqual(r.status, 400);
  });

  await t('条目字段非法返回 400 INVALID', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.upsert',
      headers: { ...AUTH, ...JSONH },
    }, { entry: { type: 'bogus', issuer: 'X' } });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(parseJson(r).code, 'INVALID');
  });

  await t('原型污染请求被拒', async () => {
    const evil = '{"entry":{"type":"note","issuer":"X","__proto__":{"polluted":true}}}';
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.upsert',
      headers: { ...AUTH, ...JSONH },
    }, evil);
    assert.strictEqual(r.status, 400);
    assert.strictEqual({}.polluted, undefined, 'Object.prototype 被污染了');
  });

  await t('qr.svg 超长载荷返回 400（不是 500）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=qr.svg',
      headers: { ...AUTH, ...JSONH },
    }, { text: 'x'.repeat(300) });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(parseJson(r).code, 'INVALID');
  });

  await t('qr.svg 正常返回内联 SVG', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=qr.svg',
      headers: { ...AUTH, ...JSONH },
    }, { text: 'otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP' });
    assert.strictEqual(r.status, 200);
    const j = parseJson(r);
    assert.ok(j.svg.startsWith('<svg '));
    assert.ok(!/<script/i.test(j.svg));
  });

  /* ---------------- 10. 错误信息不泄露内部 ---------------- */

  section('10. 错误处理');

  await t('500 类错误不泄露文件路径 / 堆栈', async () => {
    // 造一个内部错误：损坏的 vault 文件
    const vaultPath = path.join(TEST_DATA, 'vault.enc');
    const backup = fs.readFileSync(vaultPath);
    fs.writeFileSync(vaultPath, '{corrupt', 'utf8');

    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});

    assert.ok(r.status >= 400, '应失败');
    assert.ok(!/at\s+\w+\s+\(/.test(r.body), '响应里出现了堆栈');
    assert.ok(!r.body.includes('D:\\'), '响应里出现了本地磁盘路径');
    assert.ok(!r.body.includes(TEST_DATA), '响应里出现了数据目录路径');
    assert.ok(!r.body.includes('node:internal'), '响应里出现了 node 内部模块名');

    fs.writeFileSync(vaultPath, backup);   // 复原
  });

  await t('所有 API 响应带 Cache-Control: no-store', async () => {
    for (const a of ['vault.status', 'entries.list', 'otp.codes', 'backup.info']) {
      const r = await req(PORT, {
        method: 'POST', path: '/api?action=' + a,
        headers: { ...AUTH, ...JSONH },
      }, {});
      assert.strictEqual(r.headers['cache-control'], 'no-store', a + ' 缺少 no-store');
    }
  });

  await t('4xx 响应也带 no-store 与 nosniff', async () => {
    const r = await req(PORT, { path: '/api?action=vault.status' }); // 无 token -> 401
    assert.strictEqual(r.status, 401);
    assert.strictEqual(r.headers['cache-control'], 'no-store');
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
  });

  await t('错误响应形状统一（ok:false + error + code）', async () => {
    const cases = [
      [{ path: '/api?action=vault.status' }, 401],
      [{ path: '/api?action=does.not.exist', headers: AUTH }, 404],
    ];
    for (const [opts, expectStatus] of cases) {
      const r = await req(PORT, opts);
      assert.strictEqual(r.status, expectStatus);
      const j = parseJson(r);
      assert.strictEqual(j.ok, false);
      assert.strictEqual(typeof j.error, 'string');
      assert.ok(j.error.length > 0);
      assert.strictEqual(typeof j.code, 'string');
    }
  });

  await t('code 枚举只在这 7 个之中', async () => {
    const ALLOWED = new Set(['LOCKED', 'BAD_PASSPHRASE', 'THROTTLED',
      'NOT_FOUND', 'CONFLICT', 'INVALID', 'INTERNAL']);
    const probes = [
      { path: '/api?action=vault.status' },
      { path: '/api?action=nope', headers: AUTH },
      { method: 'POST', path: '/api?action=entries.list', headers: { ...AUTH, ...JSONH } },
    ];
    for (const p of probes) {
      const r = await req(PORT, p, p.method ? {} : undefined);
      const j = parseJson(r);
      if (j && j.code) {
        assert.ok(ALLOWED.has(j.code), '出现了未定义的 code：' + j.code);
      }
    }
  });

  /* ---------------- 11. 空闲锁定 ---------------- */

  section('11. 空闲自动锁定');

  await t('vault.settings 设置 1 秒空闲锁定', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.settings',
      headers: { ...AUTH, ...JSONH },
    }, { idleTimeoutSec: 1 });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(parseJson(r).idleTimeoutSec, 1);
  });

  await t('超时后请求返回 423 LOCKED', async () => {
    await new Promise(r => setTimeout(r, 1300));
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=entries.list',
      headers: { ...AUTH, ...JSONH },
    }, {});
    assert.strictEqual(r.status, 423, '实际 ' + r.status);
    assert.strictEqual(parseJson(r).code, 'LOCKED');
    assert.match(parseJson(r).error, /自动锁定|已锁定/);
  });

  await t('空闲锁定无法用恢复密钥绕过限速逻辑（恢复解锁仍可用）', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.unlockRecovery',
      headers: { ...AUTH, ...JSONH },
    }, { recoveryKey: RECOVERY_KEY });
    assert.strictEqual(r.status, 200, r.body);
  });

  await t('idleTimeoutSec 越界被拒', async () => {
    for (const v of [-1, 86401, 1.5, 'abc', null]) {
      const r = await req(PORT, {
        method: 'POST', path: '/api?action=vault.settings',
        headers: { ...AUTH, ...JSONH },
      }, { idleTimeoutSec: v });
      assert.strictEqual(r.status, 400, JSON.stringify(v) + ' 实际 ' + r.status);
    }
  });

  await t('设回 900 秒并确认', async () => {
    const r = await req(PORT, {
      method: 'POST', path: '/api?action=vault.settings',
      headers: { ...AUTH, ...JSONH },
    }, { idleTimeoutSec: 900 });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(parseJson(r).idleTimeoutSec, 900);
  });

  /* ---------------- 12. 端口范围 ---------------- */

  section('12. 端口绑定');

  await t('服务绑定在 127.0.0.1，不监听 0.0.0.0', async () => {
    const addr = require('./server');
    // 从外部地址 try 一下：监听了 0.0.0.0 的话，非回环地址也能连
    const ok = await new Promise(resolve => {
      const s = net.connect(PORT, '0.0.0.0');
      s.setTimeout(1500, () => { s.destroy(); resolve(false); });
      s.on('connect', () => { s.destroy(); resolve(true); });
      s.on('error', () => resolve(false));
    });
    // 0.0.0.0 在部分 Windows 配置下会路由到回环，所以这里不断言 false，
    // 只确认 127.0.0.1 可达。真正的绑定地址由 server.listen('127.0.0.1') 保证。
    assert.ok(typeof ok === 'boolean');
    const r = await req(PORT, { path: '/api?action=handshake' });
    assert.strictEqual(r.status, 200);
  });

  await t('默认端口在 2151-2160 区间', async () => {
    assert.ok(PORT >= 2151 && PORT <= 2160,
      '端口 ' + PORT + ' 不在 2151-2160 区间');
  });

  await t('端口不在 MailDesk 的 2131-2140 区间', async () => {
    assert.ok(!(PORT >= 2131 && PORT <= 2140),
      '端口 ' + PORT + ' 与 MailDesk 冲突');
  });

  /* ---------------- 汇总 ---------------- */

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
