#!/usr/bin/env node
'use strict';
/**
 * check-key.js —— 密钥体检 / 清理工具
 *
 * 用途：
 *   node tools/check-key.js                 体检：各自尝试解密 accounts.enc
 *   node tools/check-key.js --purge-legacy  清理：确认 primary 可用后删掉数据目录里的旧密钥
 *        --yes    跳过交互确认（脚本里用）
 *        --force  即使两份密钥内容不同也删除旧密钥（默认拒绝：那可能是另一批数据的唯一钥匙）
 *
 * 退出码：能解开 = 0，都不能解开 = 1。
 *   判定标准是"这把钥匙能不能开这个库"，不是"库是不是完美无缺"：
 *   只要**有一条**带密文的账户能解开，就证明密钥正确 → 退出码 0，
 *   并在输出里单独列出解不开的条目数。反过来，把"库里有坏条目"报成"钥匙不对"，
 *   用户会去删/换密钥，那是把整库数据推向永久丢失 —— 两种错的代价完全不对称。
 *   只有**全部**带密文的条目都认证失败时，才判 1（那才是"拿错钥匙了"）。
 *
 * 背景（K2：密钥与密文分离）：
 *   vault.key 现在放 ~/.maildesk/（或 MAILDESK_KEY_DIR），accounts.enc 仍在 data/。
 *   老版本把两者放在一起，升级时由 Vault 自动搬家。两处密钥内容不一致时
 *   Vault 会硬失败，本工具就是用来判断"到底该留哪一份"的。
 *
 * 判据只有一条：能不能真的解开 accounts.enc —— 而且必须是按 Vault 真实的读法去解：
 * 同样判定格式版本、同样在 v2 条目上设置 AAD、同样两版都试一次。
 * 判定规则与 vault.js 有任何一处偏差，本工具就会给出与真实读取路径相反的结论。
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/**
 * 下面两个常量与两个函数是 maildesk/2 格式的**复刻**（replica），
 * 来源：MailDesk/lib/vault.js 的 AAD_PREFIX / accountAad() / entryVersion()。
 *
 * 为什么复刻而不是 require('../lib/vault')：
 *   vault.js 的 Vault 构造函数会 mkdirSync、读/生成密钥、spawn icacls —— 那是副作用，
 *   本工具只想要"给定一把密钥和一份文件，能不能解开"这一个纯判定。
 *   而且本文件被设计成可以单独拷到任意机器上跑（用户换机/救数据时就是这么用的），
 *   保持零本地依赖比省几行代码重要。
 *
 * !! 改 vault.js 的 AAD_PREFIX / accountAad / entryVersion / FORMAT_VERSION 时，
 * !! 这三处（常量、accountAad、entryVersion）必须同步修改，否则本工具会给出
 * !! 与真实读取路径相反的结论。check-key-test.js 里有对拍用例守着这条。
 */
const AAD_PREFIX = 'maildesk/2|';

/** 复刻 vault.js:accountAad —— v2 每条密文绑定的附加认证数据 */
function accountAad(id) {
  const s = id == null ? '' : String(id);
  // 超长 id 先摘要：与 vault.js 完全一致。不做这一步的话，一个被改成几十 KB 的 id
  // 会让本工具算出不同的 AAD，把一个完好的库误判成"钥匙不对"。
  if (s.length > 512) return AAD_PREFIX + 'sha256:' + crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  return AAD_PREFIX + s;
}

/** 复刻 vault.js:entryVersion —— 条目声明的是哪一版（1 或 2） */
function entryVersion(a, fileVersion) {
  const v = Number(a && a.v);
  if (v === 1 || v === 2) return v;
  // 条目没有自己的标记时退回看文件级 version，规则与 vault.js 逐字一致：
  // 只有文件声明 2 才当 v2，其余（缺失 / 1 / 其它垃圾）一律当 v1。
  return Number(fileVersion) === 2 ? 2 : 1;
}

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = process.env.MAILDESK_DATA_DIR || path.join(ROOT, 'data');
const KEY_DIR = process.env.MAILDESK_KEY_DIR
  || (process.env.MAILDESK_DATA_DIR ? DATA_DIR : path.join(os.homedir(), '.maildesk'));

const PRIMARY_KEY = path.join(KEY_DIR, 'vault.key');
const LEGACY_KEY = path.join(DATA_DIR, 'vault.key');
const STORE = path.join(DATA_DIR, 'accounts.enc');

/**
 * 用一把密钥试着解开整个账户库。
 *
 * 判定规则与 vault.js 的 all() **逐条对齐**：
 *   · 先按条目声明的版本解（entryVersion），失败了再试另一版；
 *   · v2 条目解密时必须带 accountAad(id)，v1 不带。
 * 为什么必须两版都试：声明和密文是两份独立的字节，文件被手工编辑过、
 * 或某个工具改写了 version 之后，只信声明会让一个完好的库被判成"打不开"。
 * 两版都试不削弱安全性：v2 的标签是在 AAD 参与下算出来的，无 AAD 必失败；
 * v1 密文带 AAD 解也必失败。两种都失败才是真的有问题。
 *
 * @param {Buffer} keyBuf 32 字节密钥
 * @param {string} [store] 账户库路径，缺省用 DATA_DIR/accounts.enc（自检时可指向临时目录）
 * @returns {{ok:boolean, count?:number, reason?:string, verdict?:string,
 *            corrupted?:Array<{id:string, reason:string}>}}
 *   ok=true 表示"这把密钥能开这个库的一部分或全部"；
 *   部分条目损坏时 ok 仍为 true，坏条目在 corrupted 里。
 */
function tryDecrypt(keyBuf, store) {
  const storePath = store || STORE;
  if (!keyBuf || keyBuf.length !== KEY_LEN) {
    return { ok: false, verdict: 'bad-key-file', reason: 'key 长度 ' + (keyBuf ? keyBuf.length : 0) + '，应为 ' + KEY_LEN };
  }
  if (!fs.existsSync(storePath)) return { ok: false, verdict: 'no-store', reason: 'accounts.enc 不存在' };

  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  } catch (e) {
    return { ok: false, verdict: 'no-store', reason: 'accounts.enc 无法解析：' + e.message };
  }

  const accounts = Array.isArray(raw && raw.accounts) ? raw.accounts : [];
  if (!accounts.length) {
    // 空库：没有密文可验，密钥"可用"但证明不了什么
    return { ok: true, count: 0, verdict: 'empty', reason: '账户库为空，无法验证密钥（视作可用）' };
  }

  const fileVersion = Number(raw && raw.version) || 1;
  let decrypted = 0;   // 能解开的带密文条目数
  let blobbed = 0;     // 带密文的条目数（判定"全失败"时的分母）
  let authFails = 0;   // 其中因认证失败而解不开的（=看上去像密钥不对）
  const corrupted = [];

  for (const a of accounts) {
    if (!a || !a.blob) { decrypted++; continue; }   // 没有 secrets 的条目不含密文
    blobbed++;

    const buf = Buffer.from(String(a.blob), 'base64');
    if (buf.length <= IV_LEN + TAG_LEN) {
      // 长度都不够放 iv+tag，这不是密钥问题，是这一条本身坏了。
      // 以前这里直接 return ok:false —— 一条坏数据就能让正确的密钥被判成"打不开"，
      // 和缺 AAD 那个 bug 是同一类误报，所以改成记为坏条目后继续。
      corrupted.push({ id: String(a.id || '?'), reason: '密文长度异常（' + buf.length + ' 字节）' });
      continue;
    }

    const preferred = entryVersion(a, fileVersion);
    const order = preferred >= 2 ? [2, 1] : [1, 2];
    let lastErr = null;
    let ok = false;
    for (const ver of order) {
      // 认证通过但内容不是合法 JSON：这一条已经**确定**解不开，而且失败原因
      // 是"数据坏了"，不是"钥匙不对"。必须在这里 break ——
      // 继续去试另一版只会拿到一个认证失败的错误，把 lastErr 覆盖掉，
      // 于是诊断从"内容损坏"退化成"认证失败"，用户看到"认证失败"就会去换密钥。
      let plain = null;
      try {
        const d = crypto.createDecipheriv(ALGO, keyBuf, buf.subarray(0, IV_LEN));
        // 关键：v2 必须设置 AAD，且必须与本条目 id 绑定（与 vault.js 一致）。
        // 漏了这行，v2 库上正确的密钥也会认证失败 —— 本工具最危险的一种误报。
        if (ver >= 2) d.setAAD(Buffer.from(accountAad(a.id), 'utf8'));
        d.setAuthTag(buf.subarray(IV_LEN, IV_LEN + TAG_LEN));
        plain = Buffer.concat([d.update(buf.subarray(IV_LEN + TAG_LEN)), d.final()]).toString('utf8');
      } catch (e) {
        lastErr = e;
        continue;   // 认证/解密失败：可以换一版再试
      }
      try {
        JSON.parse(plain);   // 认证通过还不够，内容也得是合法 JSON
        ok = true;
      } catch {
        // 见上：这是"坏数据"，不再试另一版。
        lastErr = { code: 'BAD_JSON' };
      }
      break;
    }
    if (ok) { decrypted++; continue; }

    // 解不开：GCM 认证失败在 Node 里是固定文案 "Unsupported state or unable to
    // authenticate data"，靠错误码区分比靠文案稳（文案会随 Node 版本变）。
    const isAuth = !!lastErr && (lastErr.code === 'ERR_OSSL_BAD_DECRYPT'
      || /authenticat|Unsupported state/i.test(lastErr.message || ''));
    if (isAuth) authFails++;
    corrupted.push({
      id: String(a.id || '?'),
      // 认证失败的信息是固定文案，可以原样带出。
      // 但"解密成功、JSON 解析失败"这条路上的 e.message 会**带上明文片段**
      // （Node 的 JSON.parse 报错里有 `"not-json RT" is not valid JSON`），
      // 那里面就是 refresh_token。这里只给固定文案，绝不把明文往终端吐。
      reason: isAuth ? '认证失败' : '解密后内容不是合法 JSON',
    });
  }

  const bad = corrupted.length;
  const badList = corrupted.map(c => c.id + '：' + c.reason).join('；');

  if (bad === 0) {
    return { ok: true, count: decrypted, verdict: 'ok', corrupted: [] };
  }
  if (decrypted > 0) {
    // 部分失败：至少有一条解开了 ⇒ 密钥正确。坏条目是库的问题，不是钥匙的问题，
    // 两者用户动作完全不同（换钥匙 vs 备份/修数据），必须说清楚。
    // 这里不再重复 count —— 调用方已经在它前面打了"解出 N 个账户"。
    return {
      ok: true, count: decrypted, verdict: 'partial', corrupted,
      reason: '另有 ' + bad + ' 条解不开，这不是密钥问题（' + badList + '）',
    };
  }

  // 一条都解不开。区分"钥匙不对"和"整库损坏"：前者所有失败都是认证失败，
  // 后者会出现长度异常/内容损坏这类与密钥无关的失败。
  if (authFails === blobbed) {
    return {
      ok: false, count: 0, verdict: 'auth-failed', corrupted,
      reason: '全部 ' + blobbed + ' 条都认证失败（账户 ' + badList + '）—— 这把密钥不是本库的',
    };
  }
  return {
    ok: false, count: 0, verdict: 'corrupted', corrupted,
    reason: '全部 ' + blobbed + ' 条都解不开，但失败原因不全是认证失败，库本身可能已损坏（' + badList + '）',
  };
}

function readKey(file) {
  try { return fs.readFileSync(file); }
  catch { return null; }
}

/** 交互式读一行（只在 TTY 下调用） */
function readLineSync(prompt) {
  process.stdout.write(prompt);
  const buf = Buffer.alloc(256);
  let line = '';
  try {
    const n = fs.readSync(0, buf, 0, buf.length, null);
    line = buf.subarray(0, n).toString('utf8');
  } catch { /* 读不到就当没确认 */ }
  return line;
}

function describe(role, file) {
  const key = readKey(file);
  const exists = key !== null;
  console.log('  ' + role.padEnd(7) + ': ' + file);
  if (!exists) {
    console.log('           -> 不存在');
    console.log('');
    return { exists: false, key: null, result: { ok: false, reason: '不存在' } };
  }
  const sizeNote = key.length === KEY_LEN
    ? KEY_LEN + ' 字节'
    : key.length + ' 字节（异常，应为 ' + KEY_LEN + '）';
  console.log('           -> 存在，' + sizeNote);
  const result = tryDecrypt(key);
  if (result.ok) {
    console.log('           -> 能解密 accounts.enc，解出 ' + result.count + ' 个账户'
      + (result.reason ? '（' + result.reason + '）' : ''));
    if (result.corrupted && result.corrupted.length) {
      // 明确区分"钥匙不对"和"库里有坏条目"：这两种情况用户要做的事完全相反。
      // 这里是后者 —— 钥匙是对的。最要紧的一句是"不要动密钥"，因为看到"解不开"
      // 就删/换 vault.key 是最常见、也最不可逆的误操作。
      console.log('           -> 注意：钥匙是对的，请勿删除或更换 vault.key；'
        + '先备份整个数据目录再排查下面这些坏条目。');
      for (const c of result.corrupted) {
        console.log('              坏条目 ' + c.id + '：' + c.reason);
      }
    }
  } else {
    console.log('           -> 解不开 accounts.enc：' + result.reason);
    if (result.verdict === 'auth-failed') {
      console.log('              这把密钥不是本库的：库里所有条目都认证失败，说明密钥与密文不配对。');
    }
  }
  console.log('');
  return { exists: true, key, result };
}

function purgeLegacy(opts) {
  const p = describe('primary', PRIMARY_KEY);
  console.log('');

  if (!p.exists) {
    console.log('  [拒绝] primary 密钥不存在，不能删旧密钥 —— 删了就再也解不开了。');
    return 1;
  }
  if (!p.result.ok) {
    console.log('  [拒绝] primary 密钥解不开 accounts.enc，不能删旧密钥。');
    return 1;
  }
  if (p.result.corrupted && p.result.corrupted.length) {
    // 有坏条目但密钥是对的 —— 不影响清理旧密钥：这个工具只删密钥文件，不碰密文。
    // 但要说清楚，免得用户把"有坏条目"误读成"密钥有问题"，反过来去删 primary。
    console.log('  [注意] primary 密钥是对的，但有 ' + p.result.corrupted.length
      + ' 条数据解不开（坏数据）。本次只删旧密钥，不改动 accounts.enc。');
  }
  if (path.resolve(PRIMARY_KEY) === path.resolve(LEGACY_KEY)) {
    console.log('  [跳过] 新旧路径是同一个文件（MAILDESK_DATA_DIR 模式），无需清理。');
    return 0;
  }
  if (!fs.existsSync(LEGACY_KEY)) {
    console.log('  [跳过] 旧密钥不存在，已经是干净状态。');
    return 0;
  }

  const legacyKey = readKey(LEGACY_KEY);
  const same = legacyKey && legacyKey.length === p.key.length
    && crypto.timingSafeEqual(legacyKey, p.key);

  if (!same && !opts.force) {
    // 内容不同：旧密钥可能对应另一批数据，删掉就是永久销毁。
    // 这种情况必须人工确认，不能用一条命令顺手删掉。
    console.log('  [拒绝] 旧密钥与 primary 内容不同，可能对应另一批账户数据。');
    console.log('         旧位置：' + path.resolve(LEGACY_KEY));
    console.log('         本工具不会默认删除独一无二的密钥。请先确认它确实没用，');
    console.log('         然后明确加 --force 重跑，或手工改名备份。');
    return 1;
  }

  if (!opts.yes) {
    if (!process.stdin.isTTY) {
      console.log('  [拒绝] 需要确认，但当前不是交互终端。确认无误后加 --yes 重跑。');
      console.log('         将删除：' + path.resolve(LEGACY_KEY));
      return 1;
    }
    const answer = readLineSync('  确认删除 ' + path.resolve(LEGACY_KEY) + ' ？[y/N] ');
    if (!/^y(es)?$/i.test(answer.trim())) {
      console.log('  [取消] 未删除任何文件。');
      return 1;
    }
  }

  if (!same) {
    console.log('  [注意] 正在删除一把与 primary 内容不同的密钥（--force）。');
  }
  try {
    fs.rmSync(LEGACY_KEY, { force: true });
  } catch (e) {
    console.log('  [失败] 删除旧密钥出错：' + e.message);
    return 1;
  }
  console.log('  [完成] 已删除旧密钥：' + path.resolve(LEGACY_KEY));
  console.log('         数据目录现在只剩密文，拷走整个 data/ 也无法解密。');
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  const wantPurge = argv.includes('--purge-legacy');
  const opts = {
    yes: argv.includes('--yes') || argv.includes('-y'),
    force: argv.includes('--force'),
  };

  console.log('');
  console.log('  MailDesk 密钥体检');
  console.log('  ' + '-'.repeat(60));
  console.log('  Data dir : ' + DATA_DIR);
  console.log('  Key dir  : ' + KEY_DIR);
  console.log('  Store    : ' + STORE + (fs.existsSync(STORE) ? '' : '（不存在）'));
  console.log('  ' + '-'.repeat(60));
  console.log('');

  if (wantPurge) {
    const code = purgeLegacy(opts);
    console.log('');
    return code;
  }

  const samePath = path.resolve(PRIMARY_KEY) === path.resolve(LEGACY_KEY);

  const p = describe('primary', PRIMARY_KEY);
  const l = samePath
    ? (console.log('  legacy : 与 primary 是同一个文件（MAILDESK_DATA_DIR 模式），不重复检查\n'),
       { exists: p.exists, key: p.key, result: p.result })
    : describe('legacy ', LEGACY_KEY);

  console.log('  ' + '-'.repeat(60));
  if (samePath) {
    console.log(p.exists
      ? '  当前处于 MAILDESK_DATA_DIR 模式：密钥与密文同目录（测试/自定义部署）。'
      : '  当前处于 MAILDESK_DATA_DIR 模式，且还没有密钥。下次启动会生成一把新的。');
  } else if (p.exists && l.exists) {
    const same = p.key.length === l.key.length && crypto.timingSafeEqual(p.key, l.key);
    if (same) {
      console.log('  两处密钥内容相同 —— 迁移只差最后一步删除。');
      console.log('  运行 `node tools/check-key.js --purge-legacy` 清理数据目录里的旧副本。');
    } else {
      console.log('  两处密钥内容不同！Vault 会拒绝启动，这是有意的：');
      console.log('  随便选一个都会让另一批账户永久无法解密。');
      console.log('  请保留上面"能解密"的那一份，把另一份改名备份收好。');
    }
  } else if (p.exists && !l.exists) {
    console.log('  正常状态：密钥只在 keyDir，数据目录里没有密钥副本。');
  } else if (!p.exists && l.exists) {
    console.log('  待迁移：密钥还在数据目录里，下次启动会自动搬到 keyDir。');
  } else {
    console.log('  两处都没有密钥。下次启动会生成一把新的（旧密文将无法解密）。');
  }

  console.log('');
  if (!fs.existsSync(STORE)) {
    console.log('  注意：accounts.enc 不存在，无法验证密钥是否可用。');
    console.log('');
    return p.exists || l.exists ? 0 : 1;
  }

  const usable = (p.exists && p.result.ok) || (l.exists && l.result.ok);
  console.log(usable ? '  结论：至少有一份密钥能解开账户库。' : '  结论：没有任何一份密钥能解开账户库。');
  // 有坏条目时把"钥匙没问题、数据有问题"再强调一次：结论行的语气是"能解开"，
  // 容易被读成"库完全正常"，而这两件事对用户意味着完全不同的下一步。
  const badCount = [p, l].filter(x => x.exists && x.result.ok && x.result.corrupted)
    .reduce((n, x) => n + x.result.corrupted.length, 0);
  if (usable && badCount) {
    console.log('  但库里有 ' + badCount + ' 条数据解不开（坏数据，不是密钥问题）。'
      + '先备份整个数据目录再排查，不要动 vault.key。');
  }
  console.log('');
  return usable ? 0 : 1;
}

if (require.main === module) {
  let code = 1;
  try {
    code = main();
  } catch (e) {
    console.error('\n  [错误] ' + (e && e.message));
    code = 1;
  }
  process.exit(code);
}

// accountAad / entryVersion 一并导出，测试要拿它们与 vault.js 的真身做对拍 ——
// 复刻最容易出的错就是"某天两边悄悄分叉"，只有对拍能发现。
module.exports = {
  tryDecrypt, accountAad, entryVersion, AAD_PREFIX,
  PRIMARY_KEY, LEGACY_KEY, STORE, KEY_DIR, DATA_DIR,
};
