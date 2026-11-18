'use strict';
/**
 * 验证码历史（持久化）
 *
 * 设计要点：
 *  1. 整份 JSON 用账号库同一把密钥（vault.key）AES-256-GCM 加密后落盘，
 *     磁盘上不出现任何明文验证码 —— 本文件只是 base64 密文。
 *  2. 原子写：tmp + rename，权限 0600（与 vault.save 一致）。
 *  3. 只存 8 个契约字段。**绝不存** subject / from（完整地址）/ fromName /
 *     正文 / 附件名 / site —— 那些是攻击者可控内容，持久化会把一次性注入
 *     升级成存储型注入（三个月后仍被渲染进 DOM）。
 *     code 与 senderDomain 额外过白名单正则，即便将来前端漏转义也没有注入面。
 *  4. 去重靠 id = sha1(accountId + ':' + uid + ':' + code)：同一封邮件扫 10 次
 *     只产生 1 条。
 *  5. 保留策略 MAX_ITEMS / MAX_AGE_DAYS，每次 upsertMany 后自动裁剪并单次落盘。
 *
 * 本模块零第三方依赖，不做任何网络/文件系统以外的副作用。
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// 与 vault.js 共用同一份 ACL 收紧实现（见 _write 里的注释）。
// vault.js 不 require 本模块，不构成循环依赖。
const { tightenAcl } = require('./vault');

const FILE_VERSION = 1;
const MAX_ITEMS = 2000;          // 最多留 2000 条
const MAX_AGE_DAYS = 7;          // 只留最近 7 天（按 receivedAt）
const MAX_DOMAIN_LEN = 253;

/* ---------------- 字段白名单 ---------------- */

// 邮箱：非空白、非 @ 的本地部分 1..64，域名部分 1..255
const RE_EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
// 验证码：4~16 位字母数字（正则允许 3..16 全长），允许内部空格和连字符
const RE_CODE = /^[0-9A-Za-z][0-9A-Za-z -]{2,15}$/;
// 域名：小写化后逐段校验，至少两段
const RE_DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
// id 是 sha1 十六进制
const RE_ID = /^[0-9a-f]{40}$/;

/** 只接受能被 Date.parse 解析的字符串，统一归一成 ISO（顺带丢掉尾部垃圾字符） */
function isoOrNull(v) {
  if (typeof v !== 'string' || !v) return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return null;
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

/** senderDomain 不合法一律置空串（不整条丢弃） */
function domainOrEmpty(v) {
  if (typeof v !== 'string') return '';
  const s = v.trim().toLowerCase();
  if (s.length < 1 || s.length > MAX_DOMAIN_LEN) return '';
  return RE_DOMAIN.test(s) ? s : '';
}

/** confidence 必须是 0..1000 的整数，否则 0 */
function confidenceOf(v) {
  if (v === null || v === undefined || v === '') return 0;
  const n = Number(v);
  return (Number.isInteger(n) && n >= 0 && n <= 1000) ? n : 0;
}

/** id = sha1(accountId + ':' + uid + ':' + code) */
function makeId(accountId, uid, code) {
  return crypto.createHash('sha1')
    .update(String(accountId) + ':' + String(uid) + ':' + String(code), 'utf8')
    .digest('hex');
}

/** receivedAt 降序，null 排最后；同值时按 id 升序保证顺序稳定 */
function sortItems(items) {
  return items.slice().sort((a, b) => {
    const ta = a.receivedAt ? Date.parse(a.receivedAt) : NaN;
    const tb = b.receivedAt ? Date.parse(b.receivedAt) : NaN;
    const va = Number.isFinite(ta);
    const vb = Number.isFinite(tb);
    if (va && vb && ta !== tb) return tb - ta;
    if (va !== vb) return va ? -1 : 1;    // 有时间的排前面
    if (a.id === b.id) return 0;
    return a.id < b.id ? -1 : 1;
  });
}

class History {
  /**
   * @param {import('./vault').Vault} vault  提供 encryptText / decryptText
   * @param {string} filePath                形如 path.join(DATA_DIR, 'history.enc')
   */
  constructor(vault, filePath) {
    if (!vault || typeof vault.encryptText !== 'function' || typeof vault.decryptText !== 'function') {
      throw new TypeError('History 需要一个提供 encryptText/decryptText 的 Vault');
    }
    const p = path.resolve(String(filePath || ''));
    if (!String(filePath || '').trim()) throw new TypeError('History 需要落盘路径');
    // 兜底：public/ 下的一切都会被 serveStatic 当静态文件吐出去
    if (p.toLowerCase().split(/[\\/]+/).includes('public')) {
      throw new Error('验证码历史不能存放在 public 目录下');
    }
    this.vault = vault;
    this.filePath = p;
  }

  /* ---------------- 内部：读写 ---------------- */

  /** 坏文件挪走留证，然后当作空库继续（绝不因为一个坏文件让服务起不来） */
  _backup(reason) {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const dst = this.filePath + '.bad-' + Date.now();
      fs.renameSync(this.filePath, dst);
      console.error('[history] 历史文件' + reason + '，已备份为 ' + path.basename(dst));
    } catch (e) {
      console.error('[history] 备份损坏文件失败：' + (e && e.message));
    }
  }

  /**
   * 读盘并解密。文件不存在返回空结构；解密/JSON 失败返回空结构并备份坏文件。
   * @returns {{version:number, items:Array<object>}}
   */
  load() {
    const empty = { version: FILE_VERSION, items: [] };
    let cipher = '';
    try {
      if (!fs.existsSync(this.filePath)) return empty;
      cipher = fs.readFileSync(this.filePath, 'utf8');
    } catch (e) {
      console.error('[history] 读取失败：' + (e && e.message));
      return empty;
    }
    if (!cipher || !cipher.trim()) return empty;   // 空文件（比如首次落盘的极短窗口）

    let obj = null;
    try {
      obj = JSON.parse(this.vault.decryptText(cipher.trim()));
    } catch {
      this._backup('损坏或密钥不匹配');
      return empty;
    }
    if (!obj || typeof obj !== 'object' || !Array.isArray(obj.items)) {
      this._backup('结构不合法');
      return empty;
    }

    const items = [];
    const seen = new Set();
    for (const raw of obj.items) {
      const it = this._sanitizeStored(raw);
      if (!it || seen.has(it.id)) continue;
      seen.add(it.id);
      items.push(it);
    }
    return { version: FILE_VERSION, items: sortItems(items) };
  }

  /**
   * 加密 + 原子写，权限 0600。
   *
   * ACL 处理与 vault.js 的 save() 完全同构，理由见那里的长注释：
   * NTFS 的 rename 保留的是**被移动文件自己**的 ACL，不是被覆盖目标的 ACL。
   * 所以「write tmp → rename → 之后才收紧主文件」这条路走不通：下一轮
   * rename 会用一个继承态的新 tmp 把它换掉，ACL 退回父目录的继承态。
   * 正确顺序是 write → close → 收紧 tmp → rename，让 rename 把收紧后的
   * ACL 原样带到 history.enc 上。
   *
   * 为什么这里值得管：history.enc 里是验证码历史，含邮箱地址和验证码原文
   * （加密后），与 accounts.enc 同级敏感 —— 拿到验证码就等于能登进那个邮箱。
   *
   * tmp 名带 pid + 时间戳的理由与 vault.js 相同：固定名 `.tmp` 在两个实例
   * 并发写时会被互相截断/撕碎，最终把主文件污染成解不开的密文。
   */
  _write(items) {
    const payload = JSON.stringify({
      version: FILE_VERSION,
      updatedAt: new Date().toISOString(),
      items,
    });
    const cipher = this.vault.encryptText(payload);
    const dir = path.dirname(this.filePath);
    try { fs.mkdirSync(dir, { recursive: true }); } catch { /* 已存在 */ }
    const tmp = this.filePath + '.tmp-' + process.pid + '-' + Date.now();
    fs.writeFileSync(tmp, cipher, { mode: 0o600 });
    // chmod 在 Windows 上是 no-op（只切只读位），留着是为了 POSIX 上的 0600。
    // 它**不能**替代下面的 tightenAcl：Windows 的继承 ACE 一点没动。
    try { fs.chmodSync(tmp, 0o600); } catch { /* Windows 上语义有限 */ }
    try {
      // 必须在 rename 之前收紧 tmp：rename 带过去的就是这一份 ACL。
      // 直接用 vault.js 里那一个实现（模块级 require，不绕实例），
      // 避免第二份 icacls 逻辑各写各的、将来只修好一处。
      tightenAcl(tmp);
    } catch { /* 收紧失败不阻断落盘，下次写入会再试 */ }
    try {
      fs.renameSync(tmp, this.filePath);   // 原子替换，避免写一半断电留下半份历史
    } catch (e) {
      // rename 失败（杀毒软件锁文件、权限、跨盘）：删掉本次的 tmp 再抛。
      // 不删的话每失败一次数据目录里就多一个残骸，而残骸里是加密的验证码。
      try { fs.rmSync(tmp, { force: true }); } catch { /* 忽略 */ }
      throw e;
    }
  }

  /* ---------------- 内部：字段校验 ---------------- */

  /**
   * 校验"待写入"的一条：必须有 accountId / accountEmail / code，用它们算 id。
   * 任何一条不合规返回 null（调用方计入 rejected），不抛异常。
   */
  _sanitizeIncoming(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

    const accountId = raw.accountId;
    if (typeof accountId !== 'string' || accountId.length < 1 || accountId.length > 64) return null;

    const accountEmail = raw.accountEmail;
    if (typeof accountEmail !== 'string' || !RE_EMAIL.test(accountEmail)) return null;

    const code = raw.code;
    if (typeof code !== 'string' || !RE_CODE.test(code)) return null;

    // uid 只参与算 id，不落盘
    let uid = '';
    if (raw.uid !== undefined && raw.uid !== null) {
      if (typeof raw.uid === 'number') {
        if (!Number.isFinite(raw.uid)) return null;
        uid = String(raw.uid);
      } else if (typeof raw.uid === 'string') {
        if (raw.uid.length > 32) return null;
        uid = raw.uid;
      } else {
        return null;
      }
    }

    // 调用方若显式带了 id，类型必须是字符串（否则视为非法输入整条丢弃）；
    // 值本身不用 —— id 永远由 accountId:uid:code 推导，保证幂等。
    if (raw.id !== undefined && raw.id !== null) {
      if (typeof raw.id !== 'string' || raw.id.length < 1 || raw.id.length > 64) return null;
    }

    let usedAt = null;
    if (raw.usedAt !== undefined && raw.usedAt !== null) {
      usedAt = isoOrNull(raw.usedAt);   // 解析不了按未用处理
    }

    // 逐字段重建，天然挡掉 __proto__ / constructor 之类的额外键
    return {
      id: makeId(accountId, uid, code),
      accountId,
      accountEmail,
      code,
      senderDomain: domainOrEmpty(raw.senderDomain),
      receivedAt: isoOrNull(raw.receivedAt),
      usedAt,
      confidence: confidenceOf(raw.confidence),
    };
  }

  /** 校验"从盘上读到"的一条：id 必须是 sha1 十六进制，其余字段同白名单 */
  _sanitizeStored(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

    const id = raw.id;
    if (typeof id !== 'string' || !RE_ID.test(id)) return null;

    const accountId = raw.accountId;
    if (typeof accountId !== 'string' || accountId.length < 1 || accountId.length > 64) return null;

    const accountEmail = raw.accountEmail;
    if (typeof accountEmail !== 'string' || !RE_EMAIL.test(accountEmail)) return null;

    const code = raw.code;
    if (typeof code !== 'string' || !RE_CODE.test(code)) return null;

    return {
      id,
      accountId,
      accountEmail,
      code,
      senderDomain: domainOrEmpty(raw.senderDomain),
      receivedAt: isoOrNull(raw.receivedAt),
      usedAt: (raw.usedAt === undefined || raw.usedAt === null) ? null : isoOrNull(raw.usedAt),
      confidence: confidenceOf(raw.confidence),
    };
  }

  /** 按 MAX_ITEMS / MAX_AGE_DAYS 裁剪（输入须已按 receivedAt 降序） */
  _applyRetention(items) {
    const cutoff = Date.now() - MAX_AGE_DAYS * 24 * 3600 * 1000;
    const kept = [];
    let removed = 0;
    for (const it of items) {
      const t = it.receivedAt ? Date.parse(it.receivedAt) : NaN;
      // 时间未知的条目没法判龄，保留（仍受 MAX_ITEMS 限制）
      if (Number.isFinite(t) && t < cutoff) { removed++; continue; }
      kept.push(it);
    }
    if (kept.length > MAX_ITEMS) {
      removed += kept.length - MAX_ITEMS;
      kept.length = MAX_ITEMS;
    }
    return { items: kept, removed };
  }

  /* ---------------- 对外 ---------------- */

  /** 全部历史，按 receivedAt 降序（null 排最后）。每条只有那 8 个字段。 */
  all() {
    return this.load().items;
  }

  /**
   * 批量写入（幂等）。
   * @returns {{added:number, updated:number, total:number, rejected:number}}
   */
  upsertMany(newItems) {
    const list = Array.isArray(newItems) ? newItems : [];
    let rejected = 0;
    const fresh = [];
    for (const raw of list) {
      const it = this._sanitizeIncoming(raw);
      if (!it) { rejected++; continue; }
      fresh.push(it);
    }
    const state = this.load();
    if (!fresh.length) {
      return { added: 0, updated: 0, total: state.items.length, rejected };
    }

    const byId = new Map(state.items.map(it => [it.id, it]));
    let added = 0;
    let updated = 0;
    for (const it of fresh) {
      const old = byId.get(it.id);
      if (old) {
        // 已标记已用的条目不能被一次重扫打回未用
        byId.set(it.id, { ...it, usedAt: old.usedAt || it.usedAt });
        updated++;
      } else {
        byId.set(it.id, it);
        added++;
      }
    }

    // 排序 -> 裁剪 -> 单次落盘
    const pruned = this._applyRetention(sortItems([...byId.values()]));
    this._write(pruned.items);
    return { added, updated, total: pruned.items.length, rejected };
  }

  /**
   * 标记已用 / 未用。
   * @param {string[]} ids
   * @param {boolean} used
   * @returns {{updated:number}}  真正发生变化的条数（重复标记返回 0）
   */
  mark(ids, used) {
    const wanted = new Set();
    if (Array.isArray(ids)) {
      for (const id of ids) {
        if (typeof id === 'string' && id.length >= 1 && id.length <= 64) wanted.add(id);
      }
    }
    if (!wanted.size) return { updated: 0 };

    const state = this.load();
    const nowIso = new Date().toISOString();
    const wantUsed = used !== false;
    let updated = 0;
    const items = state.items.map(it => {
      if (!wanted.has(it.id)) return it;
      // 幂等：状态没变就不动，也不刷新已用时间戳
      if (wantUsed ? it.usedAt !== null : it.usedAt === null) return it;
      updated++;
      return { ...it, usedAt: wantUsed ? nowIso : null };
    });

    if (updated > 0) this._write(items);
    return { updated };
  }

  /**
   * 清空历史；带 olderThanHours 时只清更早的。
   * receivedAt 为 null 的条目在按时间清理时保留（无从判断年龄）。
   * @param {{olderThanHours?:number}} [opts]
   * @returns {{removed:number}}
   */
  clear(opts) {
    const state = this.load();
    const rawHours = opts && opts.olderThanHours;
    const n = Number(rawHours);
    const hours = (rawHours !== undefined && rawHours !== null && Number.isFinite(n) && n > 0) ? n : null;

    let kept;
    let removed = 0;
    if (hours === null) {
      removed = state.items.length;
      kept = [];
    } else {
      const cutoff = Date.now() - hours * 3600 * 1000;
      kept = state.items.filter(it => {
        const t = it.receivedAt ? Date.parse(it.receivedAt) : NaN;
        if (Number.isFinite(t) && t < cutoff) { removed++; return false; }
        return true;
      });
    }

    if (removed > 0) this._write(kept);
    return { removed };
  }

  /** 按 MAX_ITEMS / MAX_AGE_DAYS 裁剪并落盘 */
  prune() {
    const state = this.load();
    const pruned = this._applyRetention(sortItems(state.items));
    if (pruned.removed > 0) this._write(pruned.items);
    return { removed: pruned.removed };
  }
}

module.exports = { History, MAX_ITEMS, MAX_AGE_DAYS };
