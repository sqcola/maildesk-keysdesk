'use strict';
/**
 * 条目仓库
 *
 * 负责三件事：
 *  1. 磁盘结构（payload）的读写，实际加密交给 KeyStore
 *  2. 每条字段的严格校验（逐字段重建，绝不 {...raw} 合并）
 *  3. 对外只暴露 Summary / Detail 两种形状，任何秘密都不出现在里面
 *
 * 字段校验为什么必须「逐字段重建」：
 *  - 对象字面量展开会把输入里的一切原样带进来，包括 __proto__、
 *    constructor 这种原型相关键，以及未来某天新加的、还没被校验的字段。
 *  - 重建一次的成本可以忽略，换来的是「磁盘里永远只有已知的字段」。
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const totpLib = require('./totp');
// 只从这里拿「已经导出」的东西（KDF 参数、口令长度下限），
// 不在本文件里另抄一份常量——两处各写一份 KDF 参数迟早会漂移，
// 漂移的结果是导出包能用、vault 打不开，或者反过来。
const keystoreLib = require('./keystore');

const ENTRY_TYPES = new Set(['totp', 'recovery-only', 'note']);
const ALGORITHMS = new Set(['SHA1', 'SHA256', 'SHA512']);

const LIMITS = {
  issuerMax: 64,
  accountMax: 128,
  groupMax: 64,
  urlMax: 512,
  noteMax: 2000,
  tagsMax: 20,
  tagLenMax: 32,
  passwordMax: 1024,
  setsMax: 20,
  codesPerSetMax: 50,
  codeLenMin: 4,
  codeLenMax: 40,
  labelMax: 64,
  setIdNoteMax: 200,
  iconTextMax: 4,
};

const RE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RE_CODE = /^[A-Z0-9-]{4,40}$/;
const RE_COLOR = /^#[0-9a-fA-F]{6}$/;
const RE_SET_ID = /^rs_[0-9a-f]{8,32}$/;
const RE_CODE_ID = /^rc_[0-9a-f]{8,32}$/;

const STALE_DAYS = 365;

/* ---------------- 导出包（加密备份）参数 ---------------- */

/**
 * 导出包是**独立于 vault.enc 的第二种密文**，所以要有自己的版本串和 AAD。
 *
 * 为什么 AAD 必须和 vault.enc 不同：AAD 决定「这份密文只在这个语境下有效」。
 * 如果两种文件共用同一个域分离串，那么用同一句口令派生出的密钥在两个容器里
 * 可以互换使用——攻击者拿导出包冒充 vault.enc、或者反过来，都能走到解密
 * 成功那一支。现在只要换了容器，GCM tag 立刻校验失败。
 *
 * 数字 1 是格式版本：将来字段结构变化时改成 2，老包仍然能被认出来。
 */
const EXPORT_FORMAT = 'keydesk-export/1';
const EXPORT_AAD = 'keydesk/export/1';
const EXPORT_SALT_LEN = 16;      // 每次导出都重新随机：同一口令导出两次也必须得到不同密文
const EXPORT_KEYLEN = 32;        // AES-256
const EXPORT_IV_LEN = 12;        // GCM 标准 nonce 长度
const EXPORT_TAG_LEN = 16;
const EXPORT_PASSPHRASE_MAX = 1024;   // 与 vault 主口令同一上限
const EXPORTS_DIRNAME = 'exports';

/* ---------------- HTML 转义（打印视图用） ---------------- */

/**
 * 打印视图会把用户数据（issuer / 恢复码）拼进 HTML 片段，再由前端写进
 * #printRoot。任何一处漏转义都是一个注入点，所以这里宁可对**所有**插入值
 * 无条件调用，不区分「这个字段看起来安全吗」。
 * 恢复码在磁盘上已被 RE_CODE 限制为 A-Z0-9-，但导出视图不该依赖上游校验
 * 仍然成立——校验规则是会变的，转义不是。
 */
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => HTML_ESCAPES[c]);
}

function fail(message, code) {
  const e = new Error(message);
  e.code = code || 'INVALID';
  return e;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/* ---------------- 基础字段校验 ---------------- */

function vString(v, max, label, { trim = true, min = 0 } = {}) {
  if (v == null) v = '';
  if (typeof v !== 'string') throw fail(label + ' 必须是字符串');
  const s = trim ? v.trim() : v;
  if (s.length < min) throw fail(label + ' 不能为空');
  if (s.length > max) throw fail(label + ' 太长（最多 ' + max + ' 个字符）');
  return s;
}

/** 时间字段：能被 Date.parse 解析就返回 ISO，否则 null（不抛错，脏数据降级为 null） */
function vTime(v) {
  if (v == null || v === '') return null;
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return null;
  return new Date(t).toISOString();
}

function vBool(v, dflt = false) {
  if (v === true || v === false) return v;
  return dflt;
}

/* ---------------- 子结构校验 ---------------- */

function vTotp(raw, type, existingTotp, lenient) {
  const hasRaw = raw != null && isPlainObject(raw);
  const rawSecret = hasRaw ? raw.secret : null;
  const hasSecret = rawSecret != null && String(rawSecret).trim() !== '';

  // 编辑场景：客户端不回传明文密钥（Detail 里本来就没有 secret）。
  // 这时从 existing 继承密钥，算法/位数/周期仍以本次提交的为准。
  // 只有目标类型仍是 totp 才继承 —— 改成 note 时必须真的把密钥清掉。
  const inherit = existingTotp && type === 'totp';
  if (!hasSecret && inherit) {
    if (!hasRaw) return { ...existingTotp };
    // ⚠ 继承路径必须走与新建路径**完全相同**的校验。
    //
    // 这里曾经什么校验都不做，而前端「周期」是普通文本框：用户把它清空
    // （Number('') === 0）再保存，就写进了一个 period=0 的条目。下一次任何
    // 读盘操作会发现这条非法 → 加载时跳过 → _read() 立刻把跳过后的结果写回
    // 磁盘 → **条目被永久删除**，UI 上连报错都没有。
    // 三个非法值（algorithm/digits/period）任意一个都能触发这条链。
    const algorithm = raw.algorithm == null || raw.algorithm === ''
      ? existingTotp.algorithm
      : String(raw.algorithm).toUpperCase();
    if (!ALGORITHMS.has(algorithm)) {
      throw fail('totp.algorithm 必须是 SHA1 / SHA256 / SHA512');
    }

    const digits = raw.digits == null ? existingTotp.digits : Number(raw.digits);
    if (digits !== 6 && digits !== 8) throw fail('totp.digits 只能是 6 或 8');

    const period = raw.period == null ? existingTotp.period : Number(raw.period);
    if (!Number.isInteger(period) || period < 10 || period > 120) {
      throw fail('totp.period 必须是 10..120 之间的整数');
    }

    return {
      secret: existingTotp.secret, algorithm, digits, period,
      // 防重放游标也要继承，否则改一次备注就重置了重放保护
      lastAcceptedStep: Number.isInteger(existingTotp.lastAcceptedStep) ? existingTotp.lastAcceptedStep : null,
    };
  }

  if (!rawSecret || String(rawSecret).trim() === '') {
    if (type === 'totp') throw fail('type 为 totp 时必须提供 totp.secret');
    return null;
  }
  if (!hasRaw) throw fail('totp 段结构不正确');

  let secret;
  try { secret = totpLib.normalizeSecret(rawSecret, { strictLength: !lenient }); }
  catch (e) { throw fail('totp.secret 不合法：' + e.message); }

  const algorithm = raw.algorithm == null || raw.algorithm === ''
    ? 'SHA1'
    : String(raw.algorithm).toUpperCase();
  if (!ALGORITHMS.has(algorithm)) {
    throw fail('totp.algorithm 必须是 SHA1 / SHA256 / SHA512');
  }

  const digits = raw.digits == null ? 6 : Number(raw.digits);
  if (digits !== 6 && digits !== 8) throw fail('totp.digits 只能是 6 或 8');

  const period = raw.period == null ? 30 : Number(raw.period);
  if (!Number.isInteger(period) || period < 10 || period > 120) {
    throw fail('totp.period 必须是 10..120 之间的整数');
  }

  return {
    secret, algorithm, digits, period,
    lastAcceptedStep: raw.lastAcceptedStep === undefined
      ? (existingTotp && Number.isInteger(existingTotp.lastAcceptedStep) ? existingTotp.lastAcceptedStep : null)
      : (Number.isInteger(raw.lastAcceptedStep) ? raw.lastAcceptedStep : null),
  };
}

function vCodes(raw, setLabel) {
  if (!Array.isArray(raw)) throw fail(setLabel + '：codes 必须是数组');
  if (raw.length > LIMITS.codesPerSetMax) {
    throw fail(setLabel + '：一组最多 ' + LIMITS.codesPerSetMax + ' 个恢复码（当前 ' + raw.length + ' 个）');
  }
  const seen = new Set();
  const out = [];
  for (const c of raw) {
    if (!isPlainObject(c)) throw fail(setLabel + '：恢复码条目结构不正确');
    const value = normalizeCodeValue(c.value);
    if (!RE_CODE.test(value)) {
      throw fail(setLabel + '：恢复码 "' + String(c.value == null ? '' : c.value).slice(0, 40) +
        '" 不合法（只能是 A-Z、0-9、连字符，长度 4..40）');
    }
    if (seen.has(value)) continue;   // 组内去重：同一组里重复的码只留第一个
    seen.add(value);
    out.push({
      id: RE_CODE_ID.test(String(c.id || '')) ? String(c.id) : newCodeId(),
      value,
      usedAt: vTime(c.usedAt),
    });
  }
  return out;
}

function normalizeCodeValue(v) {
  return String(v == null ? '' : v)
    .toUpperCase()
    .replace(/\s+/g, '')      // 去空白，但保留连字符
    .trim();
}

function vSet(raw, label) {
  if (!isPlainObject(raw)) throw fail(label + '：结构不正确');
  const createdAt = vTime(raw.createdAt);
  if (!createdAt) throw fail(label + '：createdAt 不合法');
  return {
    id: RE_SET_ID.test(String(raw.id || '')) ? String(raw.id) : newSetId(),
    label: vString(raw.label, LIMITS.labelMax, label + '.label'),
    createdAt,
    supersededAt: vTime(raw.supersededAt),
    trackUsage: vBool(raw.trackUsage, true),
    note: vString(raw.note, LIMITS.setIdNoteMax, label + '.note'),
    codes: vCodes(raw.codes, label),
  };
}

function vRecovery(raw) {
  if (raw == null) return { sets: [] };
  if (!isPlainObject(raw)) throw fail('recovery 段结构不正确');
  if (raw.sets == null) return { sets: [] };
  if (!Array.isArray(raw.sets)) throw fail('recovery.sets 必须是数组');
  if (raw.sets.length > LIMITS.setsMax) {
    throw fail('恢复码最多保留 ' + LIMITS.setsMax + ' 组（当前 ' + raw.sets.length + ' 组）');
  }
  const sets = raw.sets.map((s, i) => vSet(s, 'recovery.sets[' + i + ']'));
  return { sets };
}

function vPassword(raw) {
  if (raw == null) return { value: '', updatedAt: null };
  if (!isPlainObject(raw)) throw fail('password 段结构不正确');
  const value = vString(raw.value, LIMITS.passwordMax, 'password.value', { trim: false });
  const updatedAt = vTime(raw.updatedAt);
  // 有值却没时间戳：补一个，避免界面上"已设置密码但时间是空的"
  if (value && !updatedAt) return { value, updatedAt: new Date().toISOString() };
  return { value, updatedAt };
}

function vIcon(raw, fallbackIssuer) {
  if (raw == null) {
    const text = String(fallbackIssuer || '').slice(0, 2).toUpperCase();
    return { text: text || '?', color: '#24292f' };
  }
  if (!isPlainObject(raw)) return { text: '?', color: '#24292f' };
  let text = String(raw.text == null ? '' : raw.text).trim().slice(0, LIMITS.iconTextMax);
  if (!text) text = String(fallbackIssuer || '').slice(0, 2).toUpperCase() || '?';
  const color = RE_COLOR.test(String(raw.color || '')) ? String(raw.color) : '#24292f';
  return { text, color };
}

/** 恢复码集合的深拷贝（继承时用，避免两条记录共享同一份数组引用） */
function cloneSet(s) {
  return {
    id: s.id,
    label: s.label,
    createdAt: s.createdAt,
    supersededAt: s.supersededAt,
    trackUsage: s.trackUsage,
    note: s.note,
    codes: s.codes.map(c => ({ id: c.id, value: c.value, usedAt: c.usedAt })),
  };
}

function vTags(raw) {
  if (raw == null) return [];
  if (!Array.isArray(raw)) throw fail('tags 必须是数组');
  const seen = new Set();
  const out = [];
  for (const x of raw) {
    if (typeof x !== 'string') throw fail('tags 里的每一项都必须是字符串');
    const s = x.trim();
    if (!s) continue;
    if (s.length > LIMITS.tagLenMax) throw fail('单个标签太长（最多 ' + LIMITS.tagLenMax + ' 个字符）');
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
    if (out.length > LIMITS.tagsMax) throw fail('标签最多 ' + LIMITS.tagsMax + ' 个');
  }
  return out;
}

function vUrl(raw) {
  const s = vString(raw, LIMITS.urlMax, 'url');
  if (!s) return '';
  if (!/^https?:\/\//i.test(s)) throw fail('url 必须以 http:// 或 https:// 开头');
  return s;
}

/* ---------------- ID ---------------- */

function newEntryId() { return crypto.randomUUID(); }
function newSetId() { return 'rs_' + crypto.randomBytes(8).toString('hex'); }
function newCodeId() { return 'rc_' + crypto.randomBytes(6).toString('hex'); }

function vEntryId(v) {
  const s = String(v == null ? '' : v).trim();
  if (!RE_UUID.test(s)) throw fail('条目 id 不合法');
  return s;
}

/* ---------------- 单条规范化 ---------------- */

/**
 * 把一个可能来自用户/磁盘的原始对象，重建为规范条目。
 * existing 是库里的旧版本（新建时为 null），用来保留客户端不该改的字段。
 */
/**
 * @param {object} raw
 * @param {object|null} existing
 * @param {{lenient?: boolean}} [opts]
 *   lenient=true 表示这是**读盘**路径：已知的历史数据要尽量接受，
 *   不能因为新加的校验规则把老条目踢进隔离区（用户会看到"条目消失"）。
 */
function normalizeEntry(raw, existing, opts) {
  const lenient = !!(opts && opts.lenient);
  if (!isPlainObject(raw)) throw fail('entry 必须是一个对象');

  // 原型污染防护：显式拒绝这些键。
  //
  // 注意用 Object.getOwnPropertyNames 而不是 hasOwnProperty：
  // JSON.parse('{\"__proto__\":{...}}') 会把 __proto__ 建成自有属性，
  // hasOwnProperty 能查到；但 Object.create({issuer:'x'}) 这种
  // 原型链继承来的字段 hasOwnProperty 查不到，却会被 raw.issuer 读到。
  // 两件事都要挡：
  //   a) 有 __proto__ / constructor / prototype 自有键 → 直接拒
  //   b) 关键字段不是自有属性、而是从原型链读出来的 → 也拒
  for (const bad of ['__proto__', 'constructor', 'prototype']) {
    if (Object.prototype.hasOwnProperty.call(raw, bad)) {
      throw fail('entry 含有非法字段：' + bad);
    }
  }
  // 输入必须是"自足"的普通对象：关键字段要么是自有属性，要么根本不存在。
  // 从原型链上摸到一个 issuer 说明这个对象不是 JSON.parse 产出的，
  // 不接受。
  for (const key of ['type', 'issuer', 'account', 'totp', 'recovery', 'password']) {
    if (raw[key] !== undefined && !Object.prototype.hasOwnProperty.call(raw, key)) {
      throw fail('entry 含有非法字段：' + key + '（不能来自原型链）');
    }
  }

  const now = new Date().toISOString();

  const type = String(raw.type == null ? '' : raw.type).trim();
  if (!ENTRY_TYPES.has(type)) {
    throw fail('type 必须是 totp / recovery-only / note 之一');
  }

  const issuer = vString(raw.issuer, LIMITS.issuerMax, 'issuer', { min: 1 });
  const account = vString(raw.account, LIMITS.accountMax, 'account');

  // 只有「仍然是 totp 类型」才允许继承旧密钥。改成 note/recovery-only 时
  // 必须真的清掉，否则用户以为密钥没了、实际还在库里。
  const totp = vTotp(raw.totp, type, existing && type === 'totp' ? existing.totp : null, lenient);

  // 恢复码 / 密码 / 图标都走「未提供则继承」的语义。
  // 这很关键：编辑条目时前端只提交基本信息（Detail 里根本没有恢复码的 value，
  // 也没有 password.value），如果这里把"未提供"当成"清空"，
  // 用户改一下备注就会把整组恢复码和密码抹掉，而那是不可恢复的数据丢失。
  // 判据是「字段是否出现在请求里」，不是「值是否为空」：
  // 显式传 recovery:{sets:[]} 是清空，不传才是继承。
  const hasRecoveryField = Object.prototype.hasOwnProperty.call(raw, 'recovery');
  const recovery = hasRecoveryField
    ? vRecovery(raw.recovery)
    : (existing ? { sets: existing.recovery.sets.map(cloneSet) } : { sets: [] });

  const hasPasswordField = Object.prototype.hasOwnProperty.call(raw, 'password');
  const password = hasPasswordField
    ? vPassword(raw.password)
    : (existing ? { ...existing.password } : { value: '', updatedAt: null });

  // 三种类型各自的必需条件。
  // 只有 totp 是硬要求；recovery-only 允许暂时为空——新建条目和
  // 「贴入恢复码」是两次调用，强制同时满足会让"先建条目再补码"
  // 这个正常流程走不通。
  if (type === 'totp' && !totp) throw fail('type 为 totp 时必须填 secret');

  const id = raw.id == null || raw.id === ''
    ? (existing ? existing.id : newEntryId())
    : vEntryId(raw.id);

  if (existing && id !== existing.id) throw fail('不能通过 upsert 修改条目 id');

  const hasIconField = Object.prototype.hasOwnProperty.call(raw, 'icon');
  const icon = hasIconField
    ? vIcon(raw.icon, issuer)
    : (existing ? { ...existing.icon } : vIcon(null, issuer));

  // 可选展示字段同样「未提供则继承」。它们都在 Detail 里，
  // 正常客户端每次都会带全；但少带一个字段不该等于静默清空它。
  // 新建条目（existing 为 null）时没有可继承的值，走默认空值。
  const has = k => Object.prototype.hasOwnProperty.call(raw, k);
  const keepOr = (k, fallback, parse) => (has(k) ? parse() : fallback);

  const url = keepOr('url', existing ? existing.url : '', () => vUrl(raw.url));
  const group = keepOr('group', existing ? existing.group : '',
    () => vString(raw.group, LIMITS.groupMax, 'group'));
  const tags = keepOr('tags', existing ? existing.tags.slice() : [], () => vTags(raw.tags));
  const note = keepOr('note', existing ? existing.note : '',
    () => vString(raw.note, LIMITS.noteMax, 'note', { trim: false }));

  return {
    id,
    type,
    issuer,
    account,
    url,
    group,
    tags,
    note,
    icon,
    totp,
    recovery,
    password,
    createdAt: existing ? existing.createdAt : (vTime(raw.createdAt) || now),
    updatedAt: now,
    lastUsedAt: existing ? existing.lastUsedAt : vTime(raw.lastUsedAt),
    pinned: vBool(raw.pinned, existing ? existing.pinned : false),
    archived: vBool(raw.archived, existing ? existing.archived : false),
  };
}

/* ---------------- 代际自愈 ---------------- */

/**
 * 保证「每一组「同一时刻最多只有一个 supersededAt === null」」。
 *
 * 正常路径（addSet / setCurrent）会自己维护好，这里是兜底：
 * 手工编辑过文件、从旧版本迁移、或者两次写入之间崩溃过，
 * 都可能留下多个"当前代"。多个 current 的后果是
 * 「哪个才是真的当前码」变成随机结果，用户可能拿着已作废的码去登录。
 *
 * 修复规则：保留 createdAt 最新的那个，其余把 supersededAt 写成它的 createdAt。
 */
function healSets(sets) {
  let changed = false;
  const currents = sets.filter(s => s.supersededAt === null);
  if (currents.length <= 1) return changed;

  currents.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  const winner = currents[0];
  for (const s of currents) {
    if (s === winner) continue;
    s.supersededAt = winner.createdAt;
    changed = true;
  }
  return changed;
}

/* ---------------- Summary / Detail ---------------- */

function currentSet(sets) {
  const currents = sets.filter(s => s.supersededAt === null);
  if (!currents.length) return null;
  currents.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  return currents[0];
}

function isStale(set) {
  if (!set) return false;
  const t = Date.parse(set.createdAt);
  if (!Number.isFinite(t)) return false;
  return (Date.now() - t) > STALE_DAYS * 24 * 3600 * 1000;
}

/** 严格按白名单构造，绝不把 entry 本身展开进来 */
function summarize(e, nowMs) {
  const sets = e.recovery.sets;
  const cur = currentSet(sets);
  const total = cur ? cur.codes.length : 0;
  const unused = cur ? cur.codes.filter(c => c.usedAt === null).length : 0;

  return {
    id: e.id,
    type: e.type,
    issuer: e.issuer,
    account: e.account,
    group: e.group,
    tags: e.tags.slice(),
    pinned: e.pinned,
    archived: e.archived,
    hasTotp: e.totp !== null,
    digits: e.totp ? e.totp.digits : null,
    period: e.totp ? e.totp.period : null,
    recovery: {
      setCount: sets.length,
      currentSetId: cur ? cur.id : null,
      total,
      unused,
      currentCreatedAt: cur ? cur.createdAt : null,
      stale: isStale(cur),
    },
    passwordSet: e.password.value.length > 0,
    icon: { text: e.icon.text, color: e.icon.color },
    createdAt: e.createdAt,
    updatedAt: e.updatedAt,
    lastUsedAt: e.lastUsedAt,
  };
}

function detail(e) {
  const s = summarize(e);
  s.totp = e.totp
    ? { algorithm: e.totp.algorithm, digits: e.totp.digits, period: e.totp.period }
    : null;
  s.recovery.sets = e.recovery.sets.map(set => ({
    id: set.id,
    label: set.label,
    createdAt: set.createdAt,
    supersededAt: set.supersededAt,
    trackUsage: set.trackUsage,
    note: set.note,
    codeCount: set.codes.length,
    unusedCount: set.codes.filter(c => c.usedAt === null).length,
  }));
  s.note = e.note;
  s.url = e.url;
  s.icon = { text: e.icon.text, color: e.icon.color };
  return s;
}

/* ---------------- Store ---------------- */

class Store {
  /** @param {import('./keystore').KeyStore} keystore */
  constructor(keystore) {
    this.ks = keystore;
  }

  _emptyPayload() {
    return { version: 1, revision: 0, updatedAt: new Date().toISOString(), entries: [] };
  }

  /**
   * 读盘 + 规范化 + 自愈。
   * 返回 {payload, repaired}。repaired=true 表示数据被修过，调用方应写回。
   *
   * @param {{touch?: boolean}} opts 透传给 keystore.load()。
   *   touch=false 用于纯读路径（如 otp.codes 轮询），不重置空闲计时器。
   */
  _loadNormalized(opts) {
    const raw = this.ks.load(opts);
    if (!isPlainObject(raw)) throw fail('数据顶层结构不正确', 'INTERNAL');
    if (!Array.isArray(raw.entries)) throw fail('数据缺少 entries 数组', 'INTERNAL');

    const entries = [];
    const seenIds = new Set();
    const quarantined = [];   // 校验失败但必须原样保留下来的条目
    let repaired = false;

    for (const item of raw.entries) {
      let e;
      try {
        // lenient：读盘路径对历史数据宽容。新加的校验（如 Base32 长度）
        // 只该拦住新输入，不该让已经能正常算码的老条目被踢进隔离区——
        // 那会让用户看到"条目凭空消失"，而 UI 根本不显示隔离区。
        e = normalizeEntry(item, null, { lenient: true });
      } catch (err) {
        // 磁盘上的单条坏数据不应该让整个库打不开，但**也绝不能静默删除**——
        // 这是用户唯一的凭据副本，删了就永久没了。
        //
        // 早先的实现是 continue（跳过）+ 标记 repaired，而 _read() 看到
        // repaired 会把「跳过之后」的 payload 写回磁盘，等于一键抹掉用户数据。
        // 现在改为：坏条目原样保留（quarantined=true 标记），只是不进 entries
        // 列表、不参与任何计算。用户仍可通过导出的原始文件抢救内容。
        repaired = true;
        if (item && typeof item === 'object') {
          const keep = Object.assign({}, item);
          keep._quarantined = true;
          keep._quarantineReason = (err && err.message) ? String(err.message).slice(0, 200) : 'unknown';
          quarantined.push(keep);
        }
        continue;
      }
      if (seenIds.has(e.id)) { repaired = true; continue; }
      seenIds.add(e.id);
      // 自愈可能改动 set 的 supersededAt，需要写回
      if (healSets(e.recovery.sets)) repaired = true;
      entries.push(e);
    }

    const payload = {
      version: 1,
      revision: Number.isInteger(raw.revision) && raw.revision >= 0 ? raw.revision : 0,
      updatedAt: vTime(raw.updatedAt) || new Date().toISOString(),
      entries,
    };
    // 隔离区跟正常条目一起落盘，保证坏数据一个字节都不丢
    if (quarantined.length) payload.quarantined = quarantined;
    else if (Array.isArray(raw.quarantined) && raw.quarantined.length) {
      payload.quarantined = raw.quarantined;   // 之前隔离的继续保留
    }
    if (!Number.isInteger(raw.revision)) repaired = true;
    return { payload, repaired };
  }

  /**
   * 读（必要时把自愈结果写回），返回 payload。
   *
   * @param {{touch?: boolean}} opts touch=false 表示这次读不算用户活动。
   *   纯查询/轮询必须传它，否则空闲自动锁定永远触发不了。
   */
  _read(opts) {
    const { payload, repaired } = this._loadNormalized(opts);
    if (repaired) {
      payload.revision += 1;
      payload.updatedAt = new Date().toISOString();
      this.ks.save(payload);
    }
    return payload;
  }

  _write(payload, mutate) {
    mutate(payload);
    payload.revision += 1;
    payload.updatedAt = new Date().toISOString();
    this.ks.save(payload);
    return payload;
  }

  /* ---- 查询 ---- */

  list({ q, group, includeArchived } = {}) {
    const payload = this._read();
    const needle = String(q == null ? '' : q).trim().toLowerCase();
    const wantGroup = String(group == null ? '' : group).trim();
    const nowMs = Date.now();

    let items = payload.entries;
    if (!includeArchived) items = items.filter(e => !e.archived);
    if (wantGroup) items = items.filter(e => e.group === wantGroup);
    if (needle) {
      items = items.filter(e => {
        const hay = [
          e.issuer, e.account, e.group, e.note, e.url,
          e.tags.join(' '),
          e.recovery.sets.map(s => s.label).join(' '),
        ].join('\n').toLowerCase();
        return hay.includes(needle);
      });
    }

    // 排序：置顶优先，然后按 issuer/account 字母序，最后按创建时间
    const sorted = items.slice().sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      const ka = (a.issuer + '\u0000' + a.account).toLowerCase();
      const kb = (b.issuer + '\u0000' + b.account).toLowerCase();
      if (ka !== kb) return ka < kb ? -1 : 1;
      return String(a.createdAt).localeCompare(String(b.createdAt));
    });

    return sorted.map(e => summarize(e, nowMs));
  }

  /** 所有分组名（给前端筛选下拉用） */
  groups() {
    const payload = this._read();
    const set = new Set();
    for (const e of payload.entries) if (e.group && !e.archived) set.add(e.group);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }

  /**
   * 审计视图：只返回「有问题的条目」。
   *
   * 为什么值得单独做一条 action：这四个判据所需的字段（hasTotp / recovery.setCount /
   * recovery.stale / passwordSet）在 summarize() 里**本来就已经算好了**，所以
   * 这里是一次纯过滤，不需要任何新存储。而它把「季度安全审计」从"逐个点开 30 个
   * 条目"变成"看一眼列表"——不做这一步，用户就是不做审计。
   *
   * 已归档条目不计入：归档的语义是「这个账号已经不用了」，把它列进审计清单
   * 只会制造噪音，让"看一眼"重新变成"看一堆"，最后连这条视图也被无视。
   * 真要审旧账号，列表里勾选"包含已归档"就能看到。
   */
  auditList() {
    const payload = this._read();
    const items = [];
    for (const e of payload.entries) {
      if (e.archived) continue;
      const s = summarize(e);   // 与 entries.list 完全同一份判据，避免两套口径

      // 顺序固定：前端按这个顺序渲染徽章，跨版本对比时不会看到顺序乱跳
      const problems = [];
      if (!s.hasTotp) problems.push('no-totp');
      if (s.recovery.setCount === 0) problems.push('no-recovery');
      // 四条判据彼此独立，理论上能同时命中。no-recovery 与 stale-recovery
      // 实际上不会同时出现：stale 判的是「当前代」的 createdAt，而没有组时
      // currentSet() 返回 null、isStale(null) 恒为 false。
      if (s.recovery.stale) problems.push('stale-recovery');
      if (!s.passwordSet) problems.push('no-password');

      if (!problems.length) continue;
      items.push({ id: s.id, issuer: s.issuer, account: s.account, problems });
    }
    // 问题多的排前面：用户的处理顺序天然就是"先救最危险的"
    items.sort((a, b) => b.problems.length - a.problems.length ||
      String(a.issuer).localeCompare(String(b.issuer)));
    return { items };
  }

  get(id) {
    const want = vEntryId(id);
    const payload = this._read();
    const e = payload.entries.find(x => x.id === want);
    if (!e) throw fail('条目不存在', 'NOT_FOUND');
    return detail(e);
  }

  /** 内部用：拿到原始条目（含秘密）。仅供 otp.* / recovery.* / secrets.* */
  _raw(id) {
    const want = vEntryId(id);
    const payload = this._read();
    const e = payload.entries.find(x => x.id === want);
    if (!e) throw fail('条目不存在', 'NOT_FOUND');
    return { payload, entry: e };
  }

  /* ---- 写入 ---- */

  upsert(raw) {
    const payload = this._read();
    if (!isPlainObject(raw)) throw fail('entry 必须是一个对象');

    let existing = null;
    if (raw.id != null && raw.id !== '') {
      const id = vEntryId(raw.id);
      existing = payload.entries.find(e => e.id === id) || null;
    }

    const entry = normalizeEntry(raw, existing);

    if (existing) {
      const i = payload.entries.indexOf(existing);
      payload.entries[i] = entry;
    } else {
      // 新建时如果客户端硬塞了一个已被占用的 id（上面没查到，说明没占用），直接加
      payload.entries.push(entry);
    }

    this._write(payload, () => {});
    return detail(entry);
  }

  remove(ids) {
    const list = Array.isArray(ids) ? ids : [];
    if (!list.length) throw fail('ids 不能为空');
    if (list.length > 500) throw fail('一次最多删除 500 条');
    const want = new Set(list.map(vEntryId));
    let removed = 0;
    const payload = this._read();

    const before = payload.entries.length;
    payload.entries = payload.entries.filter(e => !want.has(e.id));
    removed = before - payload.entries.length;

    if (removed > 0) this._write(payload, p => { p.entries = payload.entries; });
    return removed;
  }

  archive(ids, archived) {
    const list = Array.isArray(ids) ? ids : [];
    if (!list.length) throw fail('ids 不能为空');
    if (list.length > 500) throw fail('一次最多操作 500 条');
    const want = new Set(list.map(vEntryId));
    const flag = archived === true;

    const payload = this._read();
    let updated = 0;
    const now = new Date().toISOString();
    for (const e of payload.entries) {
      if (!want.has(e.id)) continue;
      if (e.archived !== flag) { e.archived = flag; e.updatedAt = now; updated++; }
    }
    if (updated > 0) this._write(payload, () => {});
    return updated;
  }

  /* ---- 一次性验证码 ---- */

  /**
   * @param {string[]|undefined} ids 不传则返回全部（含 hasTotp 的）
   */
  /**
   * 取验证码。前端每 5 秒轮询一次，所以这条路径**不算用户活动**。
   * 传 touch:false 是空闲自动锁定能真正生效的前提。
   */
  codes(ids) {
    const payload = this._read({ touch: false });
    let targets = payload.entries.filter(e => e.totp && !e.archived);
    if (ids != null) {
      if (!Array.isArray(ids)) throw fail('ids 必须是数组');
      const want = new Set(ids.map(vEntryId));
      targets = payload.entries.filter(e => want.has(e.id));
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const items = [];
    for (const e of targets) {
      if (!e.totp) continue;
      let secretBuf;
      try { secretBuf = totpLib.base32Decode(e.totp.secret); }
      catch { continue; }   // 单条坏了就跳过，不能让整批没有码

      const period = e.totp.period;
      const counter = Math.floor(nowSec / period);
      let code;
      try {
        code = totpLib.hotp(secretBuf, counter, e.totp.digits, e.totp.algorithm);
      } catch { continue; }

      const remaining = period - (nowSec % period);
      items.push({
        id: e.id,
        code,
        period,
        remaining,
        expiresAt: new Date((counter + 1) * period * 1000).toISOString(),
      });
    }

    // now 必须是毫秒时间戳（数字），不是 ISO 字符串。
    // 前端拿它校准本地倒计时：服务端和浏览器可能是同一台机器的不同时钟源，
    // 用字符串没法直接做减法，而且 new Date(str) 解析失败的边缘情况会让倒计时卡住。
    return { now: Date.now(), items };
  }

  verify(id, code) {
    const { payload, entry } = this._raw(id);
    if (!entry.totp) throw fail('该条目没有 TOTP 密钥');

    const given = String(code == null ? '' : code).replace(/\s+/g, '');
    const digits = entry.totp.digits;
    if (!new RegExp('^[0-9]{' + digits + '}$').test(given)) {
      throw fail('请输入 ' + digits + ' 位数字验证码');
    }

    const secretBuf = totpLib.base32Decode(entry.totp.secret);
    const nowSec = Math.floor(Date.now() / 1000);
    const baseCounter = Math.floor(nowSec / entry.totp.period);

    let matched = false;
    let matchedCounter = null;
    const window = [-1, 0, 1];
    for (const w of window) {
      const counter = baseCounter + w;
      // RFC 6238 §5.2 是 MUST：成功的 OTP 不能被第二次接受。
      // 只靠时间窗口不够——同一个码在 30 秒内可以重复验证成功。
      // 记下"上次成功时用的时间步"，要求本次必须严格更大。
      if (Number.isInteger(entry.totp.lastAcceptedStep) && counter <= entry.totp.lastAcceptedStep) {
        continue;
      }
      const expect = totpLib.hotp(secretBuf, counter, digits, entry.totp.algorithm);
      // 定长比较，虽然这里不是保密场景，但代码风格保持一致
      if (expect.length === given.length &&
          crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(given))) {
        matched = true;
        matchedCounter = counter;
        break;
      }
    }

    if (matched) {
      const now = new Date().toISOString();
      entry.lastUsedAt = now;
      entry.totp.lastAcceptedStep = matchedCounter;   // 防重放
      entry.updatedAt = now;
      this._write(payload, () => {});
    }

    return { matched, window, counter: matchedCounter };
  }

  /* ---- 秘密揭示 ---- */

  revealSecret(id, field) {
    const { entry } = this._raw(id);
    if (field === 'totp') {
      if (!entry.totp) throw fail('该条目没有 TOTP 密钥');
      return { field: 'totp', value: entry.totp.secret, algorithm: entry.totp.algorithm };
    }
    if (field === 'password') {
      if (!entry.password.value) throw fail('该条目没有保存密码');
      return { field: 'password', value: entry.password.value };
    }
    throw fail('field 只能是 totp 或 password');
  }

  /* ---- 恢复码 ---- */

  /** 找到某条目的某个 set，附带 payload 供写回 */
  _findSet(entryId, setId) {
    const { payload, entry } = this._raw(entryId);
    const sid = String(setId == null ? '' : setId).trim();
    const set = entry.recovery.sets.find(s => s.id === sid);
    if (!set) throw fail('恢复码集合不存在', 'NOT_FOUND');
    return { payload, entry, set };
  }

  revealRecovery(entryId, setId) {
    const { set } = this._findSet(entryId, setId);
    return set.codes.map(c => ({ id: c.id, value: c.value, usedAt: c.usedAt }));
  }

  /**
   * 新增一组恢复码。
   * 上一代（当前 supersededAt === null 的那些）会把 supersededAt
   * 写成新组的 createdAt —— 这样"谁被谁的哪一天替换"是可追溯的。
   */
  addSet(entryId, { label, createdAt, trackUsage, text } = {}) {
    const payload = this._read();
    const id = vEntryId(entryId);
    const entry = payload.entries.find(e => e.id === id);
    if (!entry) throw fail('条目不存在', 'NOT_FOUND');

    const created = vTime(createdAt) || new Date().toISOString();
    const codes = parseCodesText(text);
    if (!codes.length) throw fail('没有识别到任何恢复码');
    if (codes.length > LIMITS.codesPerSetMax) {
      throw fail('一组最多 ' + LIMITS.codesPerSetMax + ' 个恢复码（识别到 ' + codes.length + ' 个）');
    }
    if (entry.recovery.sets.length >= LIMITS.setsMax) {
      throw fail('恢复码最多保留 ' + LIMITS.setsMax + ' 组，请先删掉旧的一组');
    }

    const set = {
      id: newSetId(),
      label: vString(label, LIMITS.labelMax, 'label'),
      createdAt: created,
      supersededAt: null,
      trackUsage: trackUsage === false ? false : true,
      note: '',
      codes: codes.map(c => ({ id: newCodeId(), value: c, usedAt: null })),
    };

    // 把现有的当前代全部置为"已被这一代替换"
    for (const s of entry.recovery.sets) {
      if (s.supersededAt === null) s.supersededAt = created;
    }
    entry.recovery.sets.push(set);
    healSets(entry.recovery.sets);

    const now = new Date().toISOString();
    entry.updatedAt = now;
    if (entry.type === 'recovery-only') { /* 类型不变 */ }

    this._write(payload, () => {});
    return {
      id: set.id,
      label: set.label,
      createdAt: set.createdAt,
      supersededAt: set.supersededAt,
      trackUsage: set.trackUsage,
      note: set.note,
      codeCount: set.codes.length,
      unusedCount: set.codes.length,
    };
  }

  setCurrentSet(entryId, setId) {
    const { payload, entry } = this._raw(entryId);
    const sid = String(setId == null ? '' : setId).trim();
    const target = entry.recovery.sets.find(s => s.id === sid);
    if (!target) throw fail('恢复码集合不存在', 'NOT_FOUND');

    for (const s of entry.recovery.sets) {
      if (s.id === target.id) s.supersededAt = null;
      else if (s.supersededAt === null) s.supersededAt = target.createdAt;
    }
    // 防御：万一还有别的 current（数据脏），一并按自愈规则收敛
    healSets(entry.recovery.sets);

    entry.updatedAt = new Date().toISOString();
    this._write(payload, () => {});
    return true;
  }

  updateSet(entryId, setId, { label, note, trackUsage } = {}) {
    const { payload, entry, set } = this._findSet(entryId, setId);
    if (label !== undefined) set.label = vString(label, LIMITS.labelMax, 'label');
    if (note !== undefined) set.note = vString(note, LIMITS.setIdNoteMax, 'note');
    if (trackUsage !== undefined) set.trackUsage = trackUsage === true;
    entry.updatedAt = new Date().toISOString();
    this._write(payload, () => {});
    return {
      id: set.id,
      label: set.label,
      createdAt: set.createdAt,
      supersededAt: set.supersededAt,
      trackUsage: set.trackUsage,
      note: set.note,
      codeCount: set.codes.length,
      unusedCount: set.codes.filter(c => c.usedAt === null).length,
    };
  }

  removeSet(entryId, setId) {
    const { payload, entry } = this._raw(entryId);
    const sid = String(setId == null ? '' : setId).trim();
    const i = entry.recovery.sets.findIndex(s => s.id === sid);
    if (i < 0) throw fail('恢复码集合不存在', 'NOT_FOUND');

    const wasCurrent = entry.recovery.sets[i].supersededAt === null;
    entry.recovery.sets.splice(i, 1);

    // 删掉的正好是当前代：把剩下最新的一组接回"当前"，否则
    // 条目会变成"有历史代但当前为空"，界面上看起来像恢复码丢了。
    if (wasCurrent && entry.recovery.sets.length) {
      const sorted = entry.recovery.sets.slice()
        .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
      for (const s of sorted) s.supersededAt = s.id === sorted[0].id ? null : s.supersededAt;
      if (!sorted.some(s => s.supersededAt === null)) sorted[0].supersededAt = null;
      healSets(entry.recovery.sets);
    }

    entry.updatedAt = new Date().toISOString();
    this._write(payload, () => {});
    return 1;
  }

  markCodes(entryId, setId, codeIds, used) {
    const { payload, entry, set } = this._findSet(entryId, setId);
    if (!Array.isArray(codeIds) || !codeIds.length) throw fail('codeIds 不能为空');
    if (codeIds.length > 200) throw fail('一次最多标记 200 个');

    const want = new Set(codeIds.map(x => String(x == null ? '' : x).trim()));
    const usedAt = used === true ? new Date().toISOString() : null;
    let updated = 0;
    for (const c of set.codes) {
      if (!want.has(c.id)) continue;
      if (c.usedAt === usedAt) continue;
      if (usedAt === null && c.usedAt === null) continue;
      c.usedAt = usedAt;
      updated++;
    }
    if (updated) {
      entry.updatedAt = new Date().toISOString();
      this._write(payload, () => {});
    }
    return updated;
  }

  /* ---- 导出 ---- */

  exportOtpauth() {
    const payload = this._read();
    const items = [];
    for (const e of payload.entries) {
      if (!e.totp) continue;
      let uri;
      try {
        uri = totpLib.buildOtpauth({
          issuer: e.issuer,
          account: e.account,
          secret: e.totp.secret,
          algorithm: e.totp.algorithm,
          digits: e.totp.digits,
          period: e.totp.period,
        });
      } catch {
        continue;
      }
      items.push({ id: e.id, issuer: e.issuer, account: e.account, otpauthUri: uri });
    }
    const text = items.map(i => i.otpauthUri).join('\n');
    return { items, text };
  }

  /**
   * 生成一份**独立于 vault.enc 的加密备份包**。
   *
   * 为什么必须有这个东西：vault.enc 的 .bak.1/.2/.3 全在同一个目录里，
   * 磁盘一坏三份一起没；而 otpauth 导出是明文，用户不敢往别处放。
   * 结果就是「备份策略」这件事实际上没有可执行的动作。加密导出包是
   * 唯一能让用户把第二份副本安全放到另一块盘 / 另一个地方的路径。
   *
   * 三条硬约束：
   *  1. 明文只能来自内存里已解开的 payload（this._read() 走 DEK），
   *     绝不从磁盘读密文直接转存 —— 那样导出的只是"换个名字的 vault.enc"，
   *     口令也换不了，等于没做加密。
   *  2. 独立 salt + 独立 IV：同一口令导出两次必须得到不同密文，否则
   *     "这两份备份是不是同一时刻的"从密文就能看出来，且 GCM 的 nonce
   *     一旦复用就是灾难。
   *  3. AAD 用 'keydesk/export/1' 而不是 vault 的格式串：导出包与
   *     vault.enc 不能互换（见 EXPORT_AAD 的注释）。
   *
   * 返回 { path, bytes }。路径落在 vault 同级的 exports/ 下 —— 和 .bak 分开，
   * 用户把整个 exports/ 目录拷到移动盘时不会顺手把 .bak 也带走。
   */
  exportEncrypted({ passphrase } = {}) {
    if (typeof passphrase !== 'string') throw fail('导出包口令必须是字符串');
    // 与主口令同一把尺子：备份包是"第二份全部秘密"，口令强度不能比主库松。
    // 走 checkPassphrase 而不是只比长度 —— 长度够但内容弱（password12345678）
    // 的备份包，和没有备份在敌人眼里是一回事。
    try {
      keystoreLib.checkPassphrase(passphrase);
    } catch (e) {
      // 注意 store.js 的 fail 签名是 fail(message, code)，**和 keystore.js 的
      // fail(code, message) 顺序相反**。写反了不会报错，只会让 e.code 变成
      // 一段中文，路由层认不出 INVALID 就兜底成 INTERNAL —— 用户看到
      // "服务器内部错误"而不是"口令太弱"，排查时完全找不到方向。
      throw fail('导出包口令不合格：' + (e && e.message ? e.message : '强度不足'), 'INVALID');
    }
    if (passphrase.length > EXPORT_PASSPHRASE_MAX) {
      throw fail('导出包口令太长（最多 ' + EXPORT_PASSPHRASE_MAX + ' 个字符）');
    }

    // 未解锁时这里会抛 LOCKED（keystore.load 的第一件事），正是我们要的：
    // 锁定态下连"库有多大"都不该被探到，更不该产出备份文件。
    const payload = this._read();
    // 这份明文是整库秘密（TOTP 密钥 / 恢复码 / 密码），和 DEK 一样只在
    // 内存里短暂存在。用完必须 fill(0)：留着它就是让明文在堆上继续待着，
    // 而威胁模型里"本机其他进程"是明确要防的。
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');

    try {
      const envelope = sealExport(passphrase, plaintext);

      // 输出目标固定为 vault 同级的 exports/，**不接受调用方传入路径**：
      // 这是一个返回文件路径给前端的写操作，一旦路径可注入，就等于把
      // "往任意位置写一份全库密文"变成了一个 API。
      const outDir = path.join(path.dirname(this.ks.vaultPath), EXPORTS_DIRNAME);

      // Windows 文件名不允许 ':'，把 ISO 时间里的 ':' 和 '.' 都换成 '-'
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      let file = path.join(outDir, 'keydesk-export-' + stamp + '.enc');
      fs.mkdirSync(outDir, { recursive: true });

      // 同一毫秒内导出两次（脚本/双击重试）会撞名。撞名时加随机后缀，
      // 绝不覆盖上一份 —— 覆盖备份包等于删掉用户刚做的那一份副本。
      if (fs.existsSync(file)) {
        file = path.join(outDir, 'keydesk-export-' + stamp + '-' +
          crypto.randomBytes(3).toString('hex') + '.enc');
      }

      const text = JSON.stringify(envelope, null, 2);
      const tmp = file + '.tmp';
      const fd = fs.openSync(tmp, 'w', 0o600);
      try {
        fs.writeSync(fd, text, null, 'utf8');
        fs.fsyncSync(fd);          // 备份包没落盘就回复"成功"，是最坏的一种失败
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, file);
      try { fs.chmodSync(file, 0o600); } catch { /* Windows 上语义有限，尽力 */ }

      // 读回来用同一口令解一遍，确认这份文件将来真的能恢复。
      // 备份包的价值完全取决于"需要它的那天它能不能打开"，而那一刻往往是
      // 主库已经不在了、没有第二次机会。多花一次 scrypt 换这个保证是划算的。
      let bytes = 0;
      try {
        const back = JSON.parse(fs.readFileSync(file, 'utf8'));
        const plainAgain = openExport(passphrase, back);
        try {
          if (!plainAgain.equals(plaintext)) throw new Error('读回的明文与写入不一致');
        } finally {
          plainAgain.fill(0);
        }
        bytes = fs.statSync(file).size;
      } catch (e) {
        // 自检失败就把这份坏包删掉：留着它，用户会以为"备份已做好"。
        // fail 参数顺序是 (message, code)，与 keystore.js 相反（见上面
        // exportEncrypted 里的注释）。
        try { fs.unlinkSync(file); } catch { /* 忽略 */ }
        throw fail('导出包落盘自检失败：' + ((e && e.message) || '未知错误'), 'INTERNAL');
      }

      return { path: file, bytes };
    } finally {
      plaintext.fill(0);
    }
  }

  /**
   * 打印视图用的 HTML 片段。
   *
   * 为什么是 HTML 而不是纯文本：纸面上需要的是"码 + 勾选框 + 说明"的排版，
   * 两列、等宽、每码一个框 —— 纯文本排版在不同打印机上会散架。
   *
   * 只打**当前代**：历史代已经作废，印在纸上只会让人拿作废的码去恢复账号。
   * 已用的码也印出来（纸上那份和库里要保持一致，否则用户无法核对），
   * 但额外标注"已用"。
   */
  printRecovery(entryId) {
    const id = vEntryId(entryId);
    const payload = this._read();
    const e = payload.entries.find(x => x.id === id);
    if (!e) throw fail('条目不存在', 'NOT_FOUND');

    const set = currentSet(e.recovery.sets);
    if (!set) throw fail('该条目还没有恢复码，无法打印', 'NOT_FOUND');
    if (!set.codes.length) throw fail('该条目的当前恢复码组是空的，无法打印', 'NOT_FOUND');

    const n = set.codes.length;
    // 页眉里的时间用 <time datetime="完整ISO"> 显示为日期：
    // 既是给人看的，也让机器能从片段里取回完整时间戳。
    // 所有插入值一律走 escapeHtml，不区分"这个字段看起来安全吗"——
    // 上游的 RE_CODE / 长度校验规则是会变的，转义不是。
    const created = escapeHtml(set.createdAt);
    const createdDate = escapeHtml(formatDateOnly(set.createdAt));

    const rows = set.codes.map((c, i) => {
      const used = c.usedAt !== null;
      // 每个码前面都留一个 ☐：纸上标记"已用"的唯一可行方式是手写，
      // 而手写需要一个固定的落笔位置。已用的额外标出日期，方便核对。
      return '<li class="print-code' + (used ? ' used' : '') + '">' +
        '<span class="print-mark" aria-hidden="true">☐</span>' +
        '<span class="print-value">' + escapeHtml(c.value) + '</span>' +
        '<span class="print-index">' + (i + 1) + '</span>' +
        (used ? '<span class="print-used">已用 · ' + escapeHtml(formatDateOnly(c.usedAt)) + '</span>' : '') +
        '</li>';
    }).join('');

    return '<section class="print-recovery">' +
      '<header class="print-head">' +
        '<h2 class="print-title">' + escapeHtml(e.issuer) + ' 恢复码</h2>' +
        (e.account ? '<p class="print-account">' + escapeHtml(e.account) + '</p>' : '') +
        '<p class="print-meta">生成于 <time datetime="' + created + '">' + createdDate + '</time>' +
        ' · 共 ' + n + ' 个</p>' +
      '</header>' +
      '<ol class="print-codes">' + rows + '</ol>' +
      '<footer class="print-foot">每个码只能用一次。用过的划掉。切勿拍照外传。</footer>' +
      '</section>';
  }

  /* ---- 统计 ---- */

  /** 统计信息。前端也会轮询（vault.status），同样不算用户活动。 */
  stats() {
    const payload = this._read({ touch: false });
    const entries = payload.entries;
    let currentRecoveryCodes = 0;
    for (const e of entries) {
      const cur = currentSet(e.recovery.sets);
      if (cur) currentRecoveryCodes += cur.codes.filter(c => c.usedAt === null).length;
    }
    return {
      // 与 vault.status 的 entryCount 对齐：不把已归档的算进去
      entryCount: entries.filter(e => !e.archived).length,
      total: entries.length,
      archived: entries.filter(e => e.archived).length,
      revision: payload.revision,
      updatedAt: payload.updatedAt,
      unusedRecoveryCodes: currentRecoveryCodes,
    };
  }
}

/**
 * 把用户粘贴的恢复码文本拆成规范化后的数组。
 *
 * 支持 GitHub / 各家服务商常见的几种排版：
 *  - 每行一个
 *  - 空格 / 逗号 / 制表符分隔
 *  - 带序号前缀（"1. abcd-efgh"、"1) abcd-efgh"）
 *  - 分组连字符保留（"abcd-efgh"）
 *
 * 归一后去重（用户可能粘两遍），保持首次出现的顺序。
 *
 * 关于「散文」的取舍：GitHub 导出的恢复码是纯小写字母+数字的 16 位串
 * （"abcd-efgh-ijkl-mnop" 这种才是老格式），但用户也可能手工输入
 * "ABCD-EFGH"。所以不能简单地"纯字母就说它是标题"。
 * 这里采用的判据是「行结构」：
 *   - 一行里只有 1 个片段，且该行含有空格或明显是句子 → 视为说明文字
 *   - 一行里有多个片段 → 全都当码（"Recovery codes" 这种恰好也是两个词，
 *     所以再用「含数字」和「大小写混合/长度」做二次排除）
 * 实际最常用的是「每行一个」，这条路径完全不受影响。
 */
function parseCodesText(text) {
  const raw = String(text == null ? '' : text);
  if (!raw.trim()) return [];

  // 先按行切，收集每行的候选片段
  const lines = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const pieces = [];
    for (let piece of trimmed.split(/[\s,;]+/)) {
      piece = piece.trim();
      if (!piece) continue;
      piece = piece.replace(/^\d+[.)、:]\s*/, '');       // 去掉行首序号
      piece = piece.replace(/^[<"'([]+/, '').replace(/[>"')\]]+$/, '');
      const norm = normalizeCodeValue(piece);
      if (norm && RE_CODE.test(norm)) pieces.push(norm);
    }
    if (pieces.length) lines.push(pieces);
  }

  // 单片段行：如果整行是「像自然语言」的（>2 个纯字母单词、或含常见
  // 提示词），跳过。多片段行：只有当行内每个片段都「像码」才算数。
  const PROSE = /^(recovery|codes?|backup|codes?:|以下是|恢复|备用)/i;

  // 判据：**块识别**。
  //
  // 之前的两种字符层面判据都不够（实测漏）：
  //   v1「有数字就是码行」 → "Generated 2026-01-01" 含数字，被当成码行
  //   v2「全纯字母时长度须一致」 → "Each code can be used only once."
  //      里 can/be 被过滤掉，剩 Each/Code/Used/Only 恰好全 4 字符
  //
  // 真正可靠的结构信号：**真实恢复码总是成块出现**——连续多行，每行形状
  // 完全一致（GitHub 是 16 行 "xxxxx-xxxxx"）。而说明文字不会有这种规律。
  //
  // 所以先给每行算一个「形状签名」，再把连续同签名的行聚成块，
  // 只接受「块大小 ≥ 2」或「整份输入只有一行」的行。
  // 单个孤立行（前后签名都不同）视为说明文字。
  const shapeOf = (pieces) => {
    // 签名 = 片段数 + 每段长度 + 是否含数字 + 是否含连字符
    return pieces.length + '|' +
      pieces.map(p => p.length).join(',') + '|' +
      (pieces.some(p => /[0-9]/.test(p)) ? 'd' : 'a') + '|' +
      (pieces.some(p => p.includes('-')) ? 'h' : 'n');
  };

  const rows = lines.map(pieces => ({
    pieces,
    shape: shapeOf(pieces),
    // 明显的说明句标记：整行含句号/冒号结尾、或首个片段是 PROSE 词
    prose: pieces.length === 1 && PROSE.test(pieces[0]),
  }));

  const out = [];
  const seen = new Set();

  if (rows.length === 1) {
    // 只有一行：无法用块判据，接受（用户可能就贴了一个码）
    for (const p of rows[0].pieces) {
      if (!PROSE.test(p)) out.push(p);
    }
  } else {
    // 多行：按形状聚块
    let i = 0;
    while (i < rows.length) {
      const shape = rows[i].shape;
      let j = i;
      while (j < rows.length && rows[j].shape === shape) j++;
      const blockSize = j - i;

      const isProseBlock = rows[i].prose;
      // 块大小 ≥ 2 视为真码块；孤立单行只有在「它自己明显不像散文」时才收
      const accept = !isProseBlock && (blockSize >= 2 || !looksLikeSentence(rows[i].pieces));

      if (accept) {
        for (let k = i; k < j; k++) {
          for (const p of rows[k].pieces) {
            if (PROSE.test(p)) continue;
            if (seen.has(p)) continue;
            seen.add(p);
            out.push(p);
          }
        }
      }
      i = j;
    }
  }

  return out;
}

/**
 * 单个片段集合「像不像一句英文」——用于在块大小不足时兜底。
 *
 * 判据（任一命中即认为是句子，不是码）：
 *  - 片段是常见英文单词
 *  - 看起来像日期（2026-01-01 / 01-01-2026）
 *  - 全是纯字母且不是全大写（真码习惯全大写或大小写混合，而英文词是小写/首字母大写）
 */
const COMMON_WORDS = new Set([
  'EACH', 'ONLY', 'USED', 'CODE', 'CODES', 'THESE', 'SHARE', 'SAFE', 'KEEP',
  'THIS', 'THAT', 'WITH', 'FROM', 'YOUR', 'THE', 'AND', 'FOR', 'ARE', 'NOT',
  'GENERATED', 'CREATED', 'PRINTED', 'STORED', 'SIGN', 'LOGIN', 'ACCOUNT',
  'DEVICE', 'LOSE', 'ACCESS', 'EACH', 'ONCE', 'WHEN', 'WHAT', 'WILL', 'HAVE',
  'RECOVERY', 'BACKUP', 'NOTE', 'WARNING', 'IMPORTANT', 'PLEASE', 'ABOUT',
]);

function looksLikeSentence(pieces) {
  for (const p of pieces) {
    if (COMMON_WORDS.has(p)) return true;
    // 日期形态：YYYY-MM-DD 或 MM-DD-YYYY，或纯数字串（时间戳/年份）
    if (/^\d{4}-\d{2}-\d{2}$/.test(p)) return true;
    if (/^\d{2}-\d{2}-\d{4}$/.test(p)) return true;
    if (/^\d{4,}$/.test(p)) return true;   // 纯长数字：年份、编号、时间戳
  }
  return false;
}

/* ---------------- 导出包：封装 / 解密 ---------------- */

/**
 * 用口令把明文封成导出包。
 *
 * 这里刻意**没有**直接 import keystore 的 aesGcmEncrypt / _derive：那两个是
 * 模块私有函数（keydesktop 只导出了常量和类），而 keystore 的类方法把
 * AAD 写死成 vault 的域分离串。所以宁可在这里用 Node 内置 crypto 重写
 * 十几行"scrypt 派生 + AES-256-GCM 加密"，也不去改 A4 的文件或调用
 * 它的私有方法 —— 前者越界，后者是把两个容器的安全边界耦合在一起。
 *
 * scrypt 参数取自 keystoreLib.KDF（导入而不是重抄），保证导出包和主库
 * 用同一档成本：将来主库调 KDF 时，导出包跟着一起变强。
 */
function sealExport(passphrase, plaintextBuf) {
  const kdf = keystoreLib.KDF;
  const salt = crypto.randomBytes(EXPORT_SALT_LEN);   // 每次导出独立：口令相同也不该产出相同密文
  const iv = crypto.randomBytes(EXPORT_IV_LEN);

  const key = crypto.scryptSync(
    Buffer.from(passphrase, 'utf8'),
    salt,
    EXPORT_KEYLEN,
    {
      N: kdf.N, r: kdf.r, p: kdf.p,
      // maxmem 必须由参数推导（同 keystore 的理由）：硬编码会在将来
      // 调高 N 时直接把导出功能弄坏，而错误信息会伪装成"口令错误"。
      maxmem: Math.max(64 * 1024 * 1024, 128 * kdf.r * kdf.N * 2),
    }
  );

  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: EXPORT_TAG_LEN });
    cipher.setAAD(Buffer.from(EXPORT_AAD, 'utf8'));
    const enc = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      format: EXPORT_FORMAT,
      createdAt: new Date().toISOString(),
      kdf: {
        algo: 'scrypt', N: kdf.N, r: kdf.r, p: kdf.p,
        salt: salt.toString('base64'),
      },
      iv: iv.toString('base64'),
      ct: Buffer.concat([enc, tag]).toString('base64'),
    };
  } finally {
    // 派生出的密钥用完即抹：它由口令直接得来，残留在 Buffer 池里
    // 等于把"口令可用"这件事多留了一份副本在进程堆上。
    key.fill(0);
  }
}

/**
 * 解一个导出包（自检路径用，也是将来"从备份恢复"的唯一入口）。
 * 结构不对 / 口令不对 / 被改过，一律以同一句"解不开"结束 —— 区分这三种
 * 只会把信息送给攻击者，对用户没有帮助。
 */
function openExport(passphrase, envelope) {
  if (!isPlainObject(envelope)) throw new Error('导出包结构不正确');
  if (envelope.format !== EXPORT_FORMAT) {
    throw new Error('不是 ' + EXPORT_FORMAT + ' 格式的导出包（实际 ' + String(envelope.format) + '）');
  }
  const kdf = envelope.kdf;
  if (!isPlainObject(kdf) || kdf.algo !== 'scrypt') throw new Error('导出包缺少 KDF 段');
  if (typeof kdf.salt !== 'string') throw new Error('导出包缺少 kdf.salt');
  if (typeof envelope.iv !== 'string') throw new Error('导出包缺少 iv');
  if (typeof envelope.ct !== 'string') throw new Error('导出包缺少 ct');
  const salt = Buffer.from(String(kdf.salt), 'base64');
  const iv = Buffer.from(String(envelope.iv), 'base64');
  const ctBuf = Buffer.from(String(envelope.ct), 'base64');
  if (salt.length !== EXPORT_SALT_LEN) throw new Error('导出包的盐长度不正确');
  if (iv.length !== EXPORT_IV_LEN) throw new Error('导出包的 IV 长度不正确');
  if (ctBuf.length < EXPORT_TAG_LEN) throw new Error('导出包的密文太短');

  const key = crypto.scryptSync(
    Buffer.from(passphrase, 'utf8'),
    salt,
    EXPORT_KEYLEN,
    { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: Math.max(64 * 1024 * 1024, 128 * kdf.r * kdf.N * 2) }
  );
  try {
    const ct = ctBuf.subarray(0, ctBuf.length - EXPORT_TAG_LEN);
    const tag = ctBuf.subarray(ctBuf.length - EXPORT_TAG_LEN);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: EXPORT_TAG_LEN });
    // 同一个域分离串：换了它，任何合法导出包都解不开 —— 这正是我们要的
    // "这份密文只属于导出包这个语境"。
    decipher.setAAD(Buffer.from(EXPORT_AAD, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error('导出包解不开：口令不正确，或文件被篡改');
  } finally {
    key.fill(0);
  }
}

/** ISO → YYYY/MM/DD（本地时区）。解析失败就原样返回，绝不显示 "Invalid Date"。 */
function formatDateOnly(iso) {
  const t = Date.parse(String(iso == null ? '' : iso));
  if (!Number.isFinite(t)) return String(iso == null ? '' : iso);
  const d = new Date(t);
  const p = n => String(n).padStart(2, '0');
  // 用本地时间：用户看的是自己墙上的日历，不是 UTC。
  return d.getFullYear() + '/' + p(d.getMonth() + 1) + '/' + p(d.getDate());
}

module.exports = {
  Store,
  normalizeEntry,
  summarize,
  detail,
  parseCodesText,
  normalizeCodeValue,
  healSets,
  currentSet,
  newEntryId,
  newSetId,
  newCodeId,
  escapeHtml,
  formatDateOnly,
  sealExport,
  openExport,
  LIMITS,
  ENTRY_TYPES,
  EXPORT_FORMAT,
  EXPORT_AAD,
};
