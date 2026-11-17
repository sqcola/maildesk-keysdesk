'use strict';
/**
 * 二维码反向解码（仅供测试用，服务端不加载）
 *
 * 为什么测试里要带一个解码器：二维码是本工具唯一「人眼无法校验」的
 * 输出——生成错了，界面看起来完全正常，直到用户拿手机扫才发现。
 * 单靠「矩阵非空」毫无意义。这个文件把 qr.js 的输出完整解回原文，
 * 顺带校验 Reed-Solomon 与格式信息 BCH，等于一份独立的交叉验证。
 *
 * 实现是仲裁者视角的最小解码器：不处理噪声、不做纠错，
 * 只假设输入是我们自己刚生成的、几何完全正确的矩阵。
 */

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = ((z << 1) ^ ((z >>> 7) * 0x11d)) & 0xff;
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

const ALIGN = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
  7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
};

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

function rsRemainder(data, divisor) {
  const res = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ res[0];
    res.copyWithin(0, 1);
    res[res.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) res[i] ^= gfMul(divisor[i], factor);
  }
  return res;
}

/**
 * @param {boolean[][]} mods 矩阵
 * @param {number} version 版本号
 * @param {object} VERSION_INFO qr.js 导出的容量表
 */
function decode(mods, version, VERSION_INFO) {
  const size = mods.length;

  // ---- 1) 格式信息（两个副本都读，顺便交叉校验） ----
  let fmt1 = 0;
  for (let i = 0; i <= 5; i++) fmt1 |= (mods[i][8] ? 1 : 0) << i;
  fmt1 |= (mods[7][8] ? 1 : 0) << 6;
  fmt1 |= (mods[8][8] ? 1 : 0) << 7;
  fmt1 |= (mods[8][7] ? 1 : 0) << 8;
  for (let i = 9; i < 15; i++) fmt1 |= (mods[8][14 - i] ? 1 : 0) << i;

  // 第二副本：位 0-7 在「第 8 行、右侧」；位 8-14 在「第 8 列、下方」。
  // （ISO 18004 图 25；第一副本绕左上定位图形。）
  let fmt2 = 0;
  for (let i = 0; i < 8; i++) fmt2 |= (mods[8][size - 1 - i] ? 1 : 0) << i;
  for (let i = 8; i < 15; i++) fmt2 |= (mods[size - 15 + i][8] ? 1 : 0) << i;

  const raw = fmt1 ^ 0x5412;
  const dataBits = raw >>> 10;
  const eccBits = raw & 0x3ff;

  let rem = dataBits;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const eccOk = (rem & 0x3ff) === eccBits && fmt1 === fmt2;

  const mask = dataBits & 0x7;

  // ---- 2) 重建功能图形标记 ----
  const isFunc = Array.from({ length: size }, () => new Array(size).fill(false));
  const mark = (x, y) => {
    if (x >= 0 && y >= 0 && x < size && y < size) isFunc[y][x] = true;
  };
  for (let i = 0; i < size; i++) { mark(6, i); mark(i, 6); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) mark(cx + dx, cy + dy);
    }
  }
  const pos = ALIGN[version] || [];
  for (const cx of pos) {
    for (const cy of pos) {
      if ((cx === 6 && cy === 6) || (cx === 6 && cy === size - 7) ||
          (cx === size - 7 && cy === 6)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) mark(cx + dx, cy + dy);
      }
    }
  }
  for (let i = 0; i <= 8; i++) { mark(8, i); mark(i, 8); }
  for (let i = 0; i < 8; i++) { mark(size - 1 - i, 8); mark(8, size - 1 - i); }
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      mark(a, b); mark(b, a);
    }
  }

  // ---- 3) 反掩码 ----
  const fn = MASKS[mask];
  const m = mods.map(r => r.slice());
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!isFunc[y][x] && fn(x, y)) m[y][x] = !m[y][x];
    }
  }

  // ---- 4) 之字形读位 ----
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (isFunc[y][x]) continue;
        bits.push(m[y][x] ? 1 : 0);
      }
    }
  }
  const codewords = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let k = 0; k < 8; k++) b = (b << 1) | bits[i + k];
    codewords.push(b);
  }

  // ---- 5) 反交织 ----
  const info = VERSION_INFO[version];
  const numBlocks = info.numBlocks;
  const eccLen = info.eccPerBlock;
  const totalData = info.dataCodewords;
  const shortLen = Math.floor(totalData / numBlocks);
  const numShort = numBlocks - (totalData % numBlocks);

  const blocks = Array.from({ length: numBlocks }, () => []);
  let idx = 0;
  const maxLen = shortLen + 1;
  for (let i = 0; i < maxLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      const len = shortLen + (b < numShort ? 0 : 1);
      if (i < len) blocks[b].push(codewords[idx++]);
    }
  }
  const eccBlocks = Array.from({ length: numBlocks }, () => []);
  for (let i = 0; i < eccLen; i++) {
    for (let b = 0; b < numBlocks; b++) eccBlocks[b].push(codewords[idx++]);
  }

  // ---- 6) Reed-Solomon 校验 ----
  const div = rsDivisor(eccLen);
  let rsOk = true;
  for (let b = 0; b < numBlocks; b++) {
    const r = rsRemainder(blocks[b], div);
    for (let i = 0; i < eccLen; i++) {
      if (r[i] !== eccBlocks[b][i]) rsOk = false;
    }
  }

  // ---- 7) 解 byte mode ----
  const data = [].concat(...blocks);
  const bitArr = [];
  for (const b of data) for (let k = 7; k >= 0; k--) bitArr.push((b >>> k) & 1);

  let p = 0;
  const readBits = n => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | bitArr[p++];
    return v;
  };

  const mode = readBits(4);
  const ccBits = version <= 9 ? 8 : 16;
  const count = readBits(ccBits);
  const bytes = [];
  for (let i = 0; i < count; i++) bytes.push(readBits(8));

  return {
    mask,
    eccOk,
    rsOk,
    mode,
    count,
    text: Buffer.from(bytes).toString('utf8'),
  };
}

module.exports = { decode };
