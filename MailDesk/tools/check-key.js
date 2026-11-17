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
 *
 * 背景（K2：密钥与密文分离）：
 *   vault.key 现在放 ~/.maildesk/（或 MAILDESK_KEY_DIR），accounts.enc 仍在 data/。
 *   老版本把两者放在一起，升级时由 Vault 自动搬家。两处密钥内容不一致时
 *   Vault 会硬失败，本工具就是用来判断"到底该留哪一份"的。
 *
 * 判据只有一条：能不能真的解开 accounts.enc。
 * 密钥内容不同时，AES-256-GCM 会直接认证失败，没有"解出一半"这种中间状态。
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = process.env.MAILDESK_DATA_DIR || path.join(ROOT, 'data');
const KEY_DIR = process.env.MAILDESK_KEY_DIR
  || (process.env.MAILDESK_DATA_DIR ? DATA_DIR : path.join(os.homedir(), '.maildesk'));

const PRIMARY_KEY = path.join(KEY_DIR, 'vault.key');
const LEGACY_KEY = path.join(DATA_DIR, 'vault.key');
const STORE = path.join(DATA_DIR, 'accounts.enc');

/**
 * 用一把密钥试着解开整个账户库。
 * @param {Buffer} keyBuf 32 字节密钥
 * @param {string} [store] 账户库路径，缺省用 DATA_DIR/accounts.enc（自检时可指向临时目录）
 * @returns {{ok:boolean, count?:number, reason?:string}}
 */
function tryDecrypt(keyBuf, store) {
  const storePath = store || STORE;
  if (!keyBuf || keyBuf.length !== KEY_LEN) {
    return { ok: false, reason: 'key 长度 ' + (keyBuf ? keyBuf.length : 0) + '，应为 ' + KEY_LEN };
  }
  if (!fs.existsSync(storePath)) return { ok: false, reason: 'accounts.enc 不存在' };

  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  } catch (e) {
    return { ok: false, reason: 'accounts.enc 无法解析：' + e.message };
  }

  const accounts = Array.isArray(raw && raw.accounts) ? raw.accounts : [];
  if (!accounts.length) {
    // 空库：没有密文可验，密钥"可用"但证明不了什么
    return { ok: true, count: 0, reason: '账户库为空，无法验证密钥（视作可用）' };
  }

  let decrypted = 0;
  for (const a of accounts) {
    if (!a || !a.blob) { decrypted++; continue; }   // 没有 secrets 的条目不含密文
    try {
      const buf = Buffer.from(String(a.blob), 'base64');
      if (buf.length <= IV_LEN + TAG_LEN) return { ok: false, reason: '密文长度异常（账户 ' + (a.id || '?') + '）' };
      const d = crypto.createDecipheriv(ALGO, keyBuf, buf.subarray(0, IV_LEN));
      d.setAuthTag(buf.subarray(IV_LEN, IV_LEN + TAG_LEN));
      const plain = Buffer.concat([d.update(buf.subarray(IV_LEN + TAG_LEN)), d.final()]);
      JSON.parse(plain.toString('utf8'));   // 认证通过还不够，内容也得是合法 JSON
      decrypted++;
    } catch {
      return { ok: false, reason: '认证失败（账户 ' + (a.id || '?') + '）' };
    }
  }
  return { ok: true, count: decrypted };
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
  } else {
    console.log('           -> 解不开 accounts.enc：' + result.reason);
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

module.exports = { tryDecrypt, PRIMARY_KEY, LEGACY_KEY, STORE, KEY_DIR, DATA_DIR };
