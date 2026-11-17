'use strict';
/**
 * 平台账号标注（platforms）：内置平台表与归一化逻辑。
 *
 * 数据放在账户的**明文元数据**里（不是 secrets）：平台名不是凭据，塞进加密段
 * 会让「导出清单」必须先解锁，而导出其实不需要任何凭据。
 * vault.save() 的 `{...meta}` 展开会自动保留任意字段，加密层一行不用改。
 *
 * 存两份：
 *   platforms:     ['github', 'vercel']   归一化 key，用于筛选/去重/统计
 *   platformNames: { vercel: 'Vercel' }   仅自定义平台的原始显示名
 * 内置平台的正确大小写从 BUILTIN_MAP 取，不落盘 —— 内置表以后加条目时
 * 老数据也能自动显示成新的名字，不用做数据迁移。
 *
 * 注意：前端不能 require（MailDesk 零依赖、无构建），public/app.js 里有一份
 * 常量副本。两边必须保持一致，汇总阶段会有测试比对。
 */

/** 单条平台名最长 40 个 UTF-16 码元（超出截断） */
const MAX_ITEM_LEN = 40;
/** 每个账户最多 50 个平台 */
const MAX_PLATFORMS = 50;

// 顺序即前端选择器里的展示顺序，改动会直接影响 UI。
const BUILTIN = [
  { key: 'google',    name: 'Google',    color: '#4285f4' },
  { key: 'github',    name: 'GitHub',    color: '#24292f' },
  { key: 'microsoft', name: 'Microsoft', color: '#00a4ef' },
  { key: 'apple',     name: 'Apple',     color: '#333333' },
  { key: 'steam',     name: 'Steam',     color: '#171a21' },
  { key: 'discord',   name: 'Discord',   color: '#5865f2' },
  { key: 'telegram',  name: 'Telegram',  color: '#26a5e4' },
  { key: 'twitter',   name: 'X / Twitter', color: '#1d9bf0' },
  { key: 'facebook',  name: 'Facebook',  color: '#1877f2' },
  { key: 'reddit',    name: 'Reddit',    color: '#ff4500' },
  { key: 'twitch',    name: 'Twitch',    color: '#9146ff' },
  { key: 'netflix',   name: 'Netflix',   color: '#e50914' },
  { key: 'spotify',   name: 'Spotify',   color: '#1db954' },
  { key: 'amazon',    name: 'Amazon',    color: '#ff9900' },
  { key: 'paypal',    name: 'PayPal',    color: '#00457c' },
  { key: 'openai',    name: 'OpenAI',    color: '#10a37f' },
  { key: 'anthropic', name: 'Anthropic', color: '#d97757' },
];

// 冻结：内置表是前后端共享的契约，被任何一处代码顺手 push 一下就会
// 让前台和后台的 key 集合悄悄分叉，这类 bug 极难查。
for (const p of BUILTIN) Object.freeze(p);
Object.freeze(BUILTIN);

// key → 条目。用 Map 语义的对象查表；Object.create(null) 避免原型链上的
// 'constructor' / 'toString' 之类被当成内置平台。
const BUILTIN_MAP = Object.create(null);
for (const p of BUILTIN) BUILTIN_MAP[p.key] = p;

// name（小写）→ 条目。**反查表**，只在「按 key 查不到」时兜底：
// 17 个内置平台里 16 个 key === name.toLowerCase()，只有 'X / Twitter'
// （key = 'twitter'）。前端旧版本 / 手抄脚本会把显示名当 key 提交，
// 只按 key 查就会把 twitter 永久改写成 'x / twitter'：chip 变灰、
// 筛选器分裂、批量「去掉 twitter」静默失效。
const BUILTIN_NAME_MAP = Object.create(null);
for (const p of BUILTIN) BUILTIN_NAME_MAP[p.name.toLowerCase()] = p;

/**
 * 把一个小写串解析成内置平台的 key：先按 key 精确查，未命中再按显示名反查。
 * 都不是内置平台时原样返回（调用方按自定义平台处理）。
 */
function builtinKeyOf(lower) {
  if (BUILTIN_MAP[lower]) return lower;
  const byName = BUILTIN_NAME_MAP[lower];
  return byName ? byName.key : lower;
}

/**
 * 截断到 max 个码元，但**绝不把代理对（emoji 等）切成半个**。
 * 半个代理对写进 JSON 会变成 U+FFFD，用户看到的就是一个方块，
 * 而且下次比较 key 时和真实字符对不上。
 */
function truncateSafe(s, max) {
  if (s.length <= max) return s;
  let cut = s.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  // 截断点落在代理对中间：cut 末尾是高位代理，而原串该位置后面还有低位代理
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return cut;
}

/**
 * 归一化平台列表。输入可能是任何东西（前端传 null、把单个字符串当数组传、
 * 数组里混着数字和 null、老数据里根本没这个字段），一律不抛异常。
 *
 * @param {*} input 期望是 string[]，但任意值都安全
 * @returns {{platforms: string[], platformNames: Object<string,string>}}
 */
function normalizePlatforms(input) {
  const platforms = [];
  const platformNames = {};
  const seen = new Set();

  // 单个字符串按「只有一个平台」处理：前端旧版本 / 手抄脚本常这么传，
  // 报错不如按直觉收下。
  let list;
  if (typeof input === 'string') list = [input];
  else if (Array.isArray(input)) list = input;
  else return { platforms, platformNames };   // undefined / null / 数字 / 对象 → 空

  for (const raw of list) {
    if (platforms.length >= MAX_PLATFORMS) break;
    if (typeof raw !== 'string') continue;      // 跳过数字、null、嵌套数组等
    const trimmed = raw.trim();                 // 去首尾空白（含全角空格 　）
    if (!trimmed) continue;                     // 空串 / 纯空白

    const display = truncateSafe(trimmed, MAX_ITEM_LEN);
    // 中文等无大小写的文字 toLowerCase() 原样返回，不需要特殊分支
    const rawKey = truncateSafe(display.toLowerCase(), MAX_ITEM_LEN);
    if (!rawKey) continue;
    // 反查：'X / Twitter' 这类显示名要落回 true key。必须在 truncated 之后做，
    // 否则超长串会在反查后再被截一次，两次截断点不一致。
    // 反查后再截一次：内置 key 都很短，这里只对自定义串兜底。
    const key = truncateSafe(builtinKeyOf(rawKey), MAX_ITEM_LEN);
    if (!key) continue;
    if (seen.has(key)) continue;                // 按 key 去重（Github / GITHUB 视为同一个）
    seen.add(key);
    platforms.push(key);

    // 内置平台走内置表，不落盘；只有自定义平台才需要记原始大小写
    if (!BUILTIN_MAP[key]) {
      // 用 defineProperty 而不是 names[key] = display：用户完全可能输入
      // '__proto__' 或 'constructor'，直接赋值会静默失败（甚至污染原型）。
      Object.defineProperty(platformNames, key, {
        value: display, enumerable: true, configurable: true, writable: true,
      });
    }
  }

  return { platforms, platformNames };
}

/**
 * 取显示名：内置表优先（老数据里即使存错了大小写也能纠正），
 * 其次 platformNames 里的自定义名，最后退回 key 本身。
 *
 * 反查同样覆盖显示名：库里若已经存了修复前落下的 'x / twitter'
 * （历史上 normalizePlatforms 直接把它当 key 写进去了），
 * 这里也要能显示回 'X / Twitter'，否则修完归一化老数据仍然显示成
 * 一个没有颜色的自定义平台。
 */
function displayName(key, platformNames) {
  const k = typeof key === 'string' ? key : '';
  if (!k) return '';
  const lower = k.toLowerCase();
  const builtin = BUILTIN_MAP[k] || BUILTIN_MAP[lower] || BUILTIN_NAME_MAP[lower];
  if (builtin) return builtin.name;
  if (platformNames && typeof platformNames === 'object') {
    // 只认自有属性：否则 platformNames['constructor'] 会取到 Object 的构造函数
    if (Object.prototype.hasOwnProperty.call(platformNames, k)) {
      const v = platformNames[k];
      if (typeof v === 'string' && v) return v;
    }
  }
  return k;
}

module.exports = {
  BUILTIN,
  BUILTIN_MAP,
  BUILTIN_NAME_MAP,
  builtinKeyOf,
  normalizePlatforms,
  displayName,
  MAX_ITEM_LEN,
  MAX_PLATFORMS,
};
