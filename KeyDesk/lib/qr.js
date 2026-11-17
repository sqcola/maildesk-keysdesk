'use strict';
/**
 * QR 码生成（byte mode / version 1-10 / ECC level M / 自动选版本）
 *
 * 只做编码，不做解码。输出内联 SVG（<rect> 矩阵），不依赖 canvas/PNG。
 *
 * 为什么自己写而不装库：本项目的硬约束是零第三方依赖，而二维码
 * 是「把 otpauth URI 从电脑搬到手机」的唯一通道。完整实现包含
 * Reed-Solomon 纠错、掩码评分、功能图形布局，约 400 行，属于
 * 「写得下、也看得懂」的范围。
 *
 * 实现参照 ISO/IEC 18004。所有魔数表（容量、分块、对齐图形位置、
 * 格式信息 BCH）都是标准里固定的常量，不是经验值。
 */

/* ============ 标准常量表（ECC 级别 M） ============ */

/**
 * 每个版本的总码字数、数据码字数、每块 ECC 码字数、块数。
 * 只列 M 级，因为二维码只用于装 otpauth URI，M（约 15% 纠错）
 * 是容量和鲁棒性的平衡点。
 */
const VERSION_INFO = {
  1:  { totalCodewords: 26,  dataCodewords: 16,  eccPerBlock: 10, numBlocks: 1 },
  2:  { totalCodewords: 44,  dataCodewords: 28,  eccPerBlock: 16, numBlocks: 1 },
  3:  { totalCodewords: 70,  dataCodewords: 44,  eccPerBlock: 26, numBlocks: 1 },
  4:  { totalCodewords: 100, dataCodewords: 64,  eccPerBlock: 18, numBlocks: 2 },
  5:  { totalCodewords: 134, dataCodewords: 86,  eccPerBlock: 24, numBlocks: 2 },
  6:  { totalCodewords: 172, dataCodewords: 108, eccPerBlock: 16, numBlocks: 4 },
  7:  { totalCodewords: 196, dataCodewords: 124, eccPerBlock: 18, numBlocks: 4 },
  8:  { totalCodewords: 242, dataCodewords: 154, eccPerBlock: 22, numBlocks: 4 },
  9:  { totalCodewords: 292, dataCodewords: 182, eccPerBlock: 22, numBlocks: 5 },
  10: { totalCodewords: 346, dataCodewords: 216, eccPerBlock: 26, numBlocks: 5 },
};

/** 对齐图形中心坐标（版本 1 没有对齐图形） */
const ALIGN_POSITIONS = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

const MIN_VERSION = 1;
const MAX_VERSION = 10;

/** 载荷上限：version 10 / ECC M / byte mode 的精确容量是 213 字节 */
const MAX_PAYLOAD_BYTES = 210;

/** byte mode 下每个版本能装多少字节（扣掉模式指示符和字符计数） */
function byteCapacity(version) {
  const { dataCodewords } = VERSION_INFO[version];
  const ccBits = version <= 9 ? 8 : 16;
  const overheadBits = 4 + ccBits;
  return Math.floor((dataCodewords * 8 - overheadBits) / 8);
}

/* ============ GF(256) Reed-Solomon ============ */

/** GF(256) 乘法，本原多项式 0x11D */
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = ((z << 1) ^ ((z >>> 7) * 0x11d)) & 0xff;
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/** 生成多项式 ∏(x - α^i)，返回长度为 degree 的系数（最高次项固定为 1，省略） */
function rsDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

/** 计算 data 的 RS 余数（即 ECC 码字） */
function rsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= gfMul(divisor[i], factor);
    }
  }
  return result;
}

/* ============ 位流 ============ */

class BitBuffer {
  constructor() { this.bits = []; }
  push(value, length) {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  }
  get length() { return this.bits.length; }
  /** 补齐到 8 位边界，然后填充 0xEC / 0x11 */
  padToCodewords(targetCodewords) {
    const capacityBits = targetCodewords * 8;
    // 终止符：最多 4 个 0
    this.push(0, Math.min(4, capacityBits - this.bits.length));
    // 补 0 到字节边界
    this.push(0, (8 - (this.bits.length % 8)) % 8);
    // 交替填充 0xEC / 0x11
    for (let pad = 0xec; this.bits.length < capacityBits; pad ^= 0xec ^ 0x11) {
      this.push(pad, 8);
    }
    if (this.bits.length !== capacityBits) {
      throw new Error('QR 内部错误：位流长度与容量不一致');
    }
  }
  toBytes() {
    if (this.bits.length % 8 !== 0) throw new Error('QR 内部错误：位流不是整字节');
    const out = new Uint8Array(this.bits.length / 8);
    for (let i = 0; i < this.bits.length; i++) {
      out[i >>> 3] |= this.bits[i] << (7 - (i & 7));
    }
    return out;
  }
}

/* ============ 编码流程 ============ */

/** 根据字节长度选最小可用版本 */
function pickVersion(byteLen) {
  for (let v = MIN_VERSION; v <= MAX_VERSION; v++) {
    if (byteLen <= byteCapacity(v)) return v;
  }
  return 0;
}

/**
 * 把原始字节编码成最终的码字序列（数据 + ECC，已交织）。
 */
function encodeToCodewords(bytes, version) {
  const info = VERSION_INFO[version];
  const buf = new BitBuffer();

  // 模式指示符：byte mode = 0100
  buf.push(0b0100, 4);
  // 字符计数：v1-9 用 8 位，v10+ 用 16 位
  buf.push(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) buf.push(b, 8);

  buf.padToCodewords(info.dataCodewords);
  const data = buf.toBytes();

  // ---- 分块 ----
  const numBlocks = info.numBlocks;
  const eccLen = info.eccPerBlock;
  const totalData = info.dataCodewords;
  const shortBlockLen = Math.floor(totalData / numBlocks);
  const numShortBlocks = numBlocks - (totalData % numBlocks);

  const divisor = rsDivisor(eccLen);
  const dataBlocks = [];
  const eccBlocks = [];
  let offset = 0;
  for (let i = 0; i < numBlocks; i++) {
    const len = shortBlockLen + (i < numShortBlocks ? 0 : 1);
    const block = data.subarray(offset, offset + len);
    offset += len;
    dataBlocks.push(block);
    eccBlocks.push(rsRemainder(block, divisor));
  }

  // ---- 交织 ----
  const out = [];
  const maxDataLen = shortBlockLen + 1;
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      // 短块没有最后一位，跳过
      if (i < dataBlocks[b].length) out.push(dataBlocks[b][i]);
    }
  }
  for (let i = 0; i < eccLen; i++) {
    for (let b = 0; b < numBlocks; b++) out.push(eccBlocks[b][i]);
  }

  if (out.length !== info.totalCodewords) {
    throw new Error('QR 内部错误：码字数量 ' + out.length + ' 与标准值 ' + info.totalCodewords + ' 不符');
  }
  return Uint8Array.from(out);
}

/* ============ 矩阵构建 ============ */

function buildMatrix(version, codewords) {
  const size = version * 4 + 17;

  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  // 功能图形标记：这些格子不参与数据填充，也不参与掩码
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));

  const setFn = (x, y, dark) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    modules[y][x] = !!dark;
    isFunction[y][x] = true;
  };

  // ---- 定时图形 ----
  for (let i = 0; i < size; i++) {
    setFn(6, i, i % 2 === 0);
    setFn(i, 6, i % 2 === 0);
  }

  // ---- 三个定位图形（7x7 + 1 格分隔） ----
  const finderCenters = [[3, 3], [size - 4, 3], [3, size - 4]];
  for (const [cx, cy] of finderCenters) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        // dist 4 = 分隔带（浅），3 或 1 = 深，0/2 = 深/浅按环
        setFn(cx + dx, cy + dy, dist !== 2 && dist !== 4);
      }
    }
  }

  // ---- 对齐图形 ----
  const positions = ALIGN_POSITIONS[version];
  for (let i = 0; i < positions.length; i++) {
    for (let j = 0; j < positions.length; j++) {
      const cx = positions[i];
      const cy = positions[j];
      // 与定位图形重叠的三个角跳过
      const overlap =
        (cx === 6 && cy === 6) ||
        (cx === 6 && cy === size - 7) ||
        (cx === size - 7 && cy === 6);
      if (overlap) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy));
          setFn(cx + dx, cy + dy, dist !== 1);
        }
      }
    }
  }

  // ---- 预留格式信息区（先占位，后面按掩码写入真值） ----
  // 第 6 行/列是定时图形，格式信息在标准里刻意跳过它们，
  // 这里也必须跳过：否则会把 timing 的一格从深改成浅，
  // 解码器读到的定时序列就断了。
  for (let i = 0; i <= 8; i++) {
    if (i === 6) continue;
    setFn(8, i, false);
    setFn(i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    setFn(size - 1 - i, 8, false);
    setFn(8, size - 1 - i, false);
  }
  // 固定暗模块
  setFn(8, size - 8, true);

  // ---- 版本信息（v7+） ----
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = (bits >>> i) & 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFn(a, b, bit);
      setFn(b, a, bit);
    }
  }

  // ---- 数据填充（之字形） ----
  let bitIndex = 0;
  const totalBits = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;   // 跳过第 6 列（垂直定时图形）
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (isFunction[y][x]) continue;
        if (bitIndex < totalBits) {
          modules[y][x] = ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) === 1;
          bitIndex++;
        }
        // 剩余位（remainder bits）保持浅色
      }
    }
  }

  return { size, modules, isFunction, setFn };
}

/* ============ 掩码 ============ */

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** 把格式信息（15 位 BCH）写到两个位置 */
function drawFormatBits(modules, size, mask) {
  // ECC 级别 M 的 2 位编码是 00
  const eccBits = 0b00;
  const data = (eccBits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;

  const bit = i => (bits >>> i) & 1;
  const set = (x, y, v) => { modules[y][x] = !!v; };

  // 第一副本：围绕左上定位图形
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6));
  set(8, 8, bit(7));
  set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));

  // 第二副本：左下 + 右上
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));

  // 固定暗模块
  set(8, size - 8, true);
}

/** 按掩码翻转数据区 */
function applyMask(modules, isFunction, size, maskIdx) {
  const fn = MASKS[maskIdx];
  const out = modules.map(row => row.slice());
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (isFunction[y][x]) continue;
      if (fn(x, y)) out[y][x] = !out[y][x];
    }
  }
  return out;
}

/* ============ 掩码评分（ISO 18004 §8.8.2） ============ */

function penaltyScore(modules, size) {
  let score = 0;

  // 规则 1：同色连续 5 个及以上。3 + (run - 5)
  for (let y = 0; y < size; y++) {
    let run = 1;
    for (let x = 1; x < size; x++) {
      if (modules[y][x] === modules[y][x - 1]) {
        run++;
      } else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    if (run >= 5) score += 3 + (run - 5);
  }
  for (let x = 0; x < size; x++) {
    let run = 1;
    for (let y = 1; y < size; y++) {
      if (modules[y][x] === modules[y - 1][x]) {
        run++;
      } else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    if (run >= 5) score += 3 + (run - 5);
  }

  // 规则 2：2x2 同色块，每块 +3
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
        score += 3;
      }
    }
  }

  // 规则 3：类定位图形 1011101 带 4 个浅色空位，每次 +40
  const PATTERN_A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const PATTERN_B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const rowMatch = (arr, y, offset) => {
    for (let i = 0; i < 11; i++) {
      if ((modules[y][offset + i] ? 1 : 0) !== arr[i]) return false;
    }
    return true;
  };
  const colMatch = (arr, x, offset) => {
    for (let i = 0; i < 11; i++) {
      if ((modules[offset + i][x] ? 1 : 0) !== arr[i]) return false;
    }
    return true;
  };
  for (let y = 0; y < size; y++) {
    for (let x = 0; x + 11 <= size; x++) {
      if (rowMatch(PATTERN_A, y, x) || rowMatch(PATTERN_B, y, x)) score += 40;
    }
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y + 11 <= size; y++) {
      if (colMatch(PATTERN_A, x, y) || colMatch(PATTERN_B, x, y)) score += 40;
    }
  }

  // 规则 4：深色比例偏离 50%，每 5% +10
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) if (modules[y][x]) dark++;
  }
  const total = size * size;
  const percent = (dark * 100) / total;
  const k = Math.floor(Math.abs(percent - 50) / 5);
  score += k * 10;

  return score;
}

/* ============ 对外入口 ============ */

/**
 * 生成二维码矩阵。
 * @param {string} text
 * @returns {{version:number, size:number, modules:boolean[][]}}
 */
function generate(text) {
  const str = String(text == null ? '' : text);
  if (!str) throw new Error('二维码内容不能为空');

  const bytes = Buffer.from(str, 'utf8');
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw new Error('内容太长（' + bytes.length + ' 字节），二维码最多支持 ' +
      MAX_PAYLOAD_BYTES + ' 字节');
  }

  const version = pickVersion(bytes.length);
  if (!version) {
    throw new Error('内容太长（' + bytes.length + ' 字节），无法编码进 version ' +
      MIN_VERSION + '-' + MAX_VERSION + ' 的二维码');
  }

  const codewords = encodeToCodewords(bytes, version);
  const { size, modules, isFunction } = buildMatrix(version, codewords);

  // 逐一试 8 个掩码，取罚分最低的
  let best = null;
  let bestScore = Infinity;
  for (let m = 0; m < 8; m++) {
    const masked = applyMask(modules, isFunction, size, m);
    drawFormatBits(masked, size, m);
    const score = penaltyScore(masked, size);
    if (score < bestScore) {
      bestScore = score;
      best = masked;
    }
  }

  return { version, size, modules: best };
}

/**
 * 生成内联 SVG。
 * @param {string} text
 * @param {{scale?:number, margin?:number, dark?:string, light?:string, title?:string}} opts
 * @returns {string}
 */
function toSvg(text, opts) {
  const o = opts || {};
  const scale = Math.max(1, Math.min(20, Number.isInteger(o.scale) ? o.scale : 1));
  const margin = Number.isInteger(o.margin) ? Math.max(0, Math.min(10, o.margin)) : 4;
  const dark = /^#[0-9a-fA-F]{3,8}$/.test(String(o.dark || '')) ? String(o.dark) : '#000000';
  const light = /^#[0-9a-fA-F]{3,8}$/.test(String(o.light || '')) ? String(o.light) : '#ffffff';

  const { size, modules } = generate(text);

  // 把相邻的深色格子合并成横向长条：一张 v10 的图有 57x57 格，
  // 逐格输出 ~1000 个 rect，合并后通常只有 300 个左右，肉眼无差别
  // 但传输量少一半以上。
  //
  // 坐标不带 scale：viewBox 用格坐标，显示尺寸交给 width/height 和 CSS。
  // 这样每个 rect 的数字从 "x=120 y=48 width=18" 变成 "12 4 3 1"，
  // 整串 SVG 又能小一大截，视觉上完全一致（矢量缩放）。
  const dim = size + margin * 2;
  const rects = [];
  for (let y = 0; y < size; y++) {
    let x = 0;
    while (x < size) {
      if (!modules[y][x]) { x++; continue; }
      let run = 1;
      while (x + run < size && modules[y][x + run]) run++;
      rects.push('<rect x="' + (x + margin) + '" y="' + (y + margin) +
        '" width="' + run + '" height="1"/>');
      x += run;
    }
  }

  const title = typeof o.title === 'string' && o.title
    ? '<title>' + escapeXml(o.title) + '</title>'
    : '';

  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + (dim * scale) +
    '" height="' + (dim * scale) + '" viewBox="0 0 ' + dim + ' ' + dim +
    '" shape-rendering="crispEdges" role="img">' +
    title +
    '<rect width="100%" height="100%" fill="' + light + '"/>' +
    '<g fill="' + dark + '">' + rects.join('') + '</g>' +
    '</svg>';
}

function escapeXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = {
  generate,
  toSvg,
  MAX_PAYLOAD_BYTES,
  VERSION_INFO,
  byteCapacity,
};
