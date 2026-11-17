'use strict';
/**
 * 极简 IMAP 客户端（仅实现本工具需要的子集）
 *
 * 为什么自己写而不是用 imapflow：
 *  - 零第三方依赖 = 零供应链风险，你可以逐行审计
 *  - 只需要 XOAUTH2 认证 + SELECT + FETCH，用不到完整 IMAP 功能
 *
 * 安全基线：
 *  - 强制 TLS，rejectUnauthorized 恒为 true（不可配置关闭）
 *  - 只读操作，使用 BODY.PEEK 避免改变邮件已读状态
 *  - 所有命令带超时
 */
const tls = require('tls');
const { EventEmitter } = require('events');

const DEFAULT_TIMEOUT = 30000;
const MAX_LINE = 1024 * 1024; // 单行最大 1MB，防止畸形响应撑爆内存

class ImapClient extends EventEmitter {
  constructor(opts) {
    super();
    this.host = opts.host;
    this.port = opts.port || 993;
    this.user = opts.auth.user;
    this.accessToken = opts.auth.accessToken;
    this.timeout = opts.timeout || DEFAULT_TIMEOUT;
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.tagCounter = 0;
    this.pending = new Map(); // tag -> {resolve, reject, collect, literal}
    this.greeting = null;
    this.capabilities = [];
    this.mailbox = null;
    this._current = null; // { tag, resolve, reject, chunks, expectingLiteral, literalRemaining, literalChunks, sections }
  }

  connect() {
    return new Promise((resolve, reject) => {
      const sock = tls.connect({
        host: this.host,
        port: this.port,
        servername: this.host,
        rejectUnauthorized: true, // 硬编码：绝不接受无效证书
        minVersion: 'TLSv1.2',
      }, () => {
        // TLS 握手完成，等待服务端 greeting
      });

      sock.setTimeout(this.timeout, () => {
        sock.destroy(new Error('IMAP 连接超时'));
      });
      sock.on('error', err => {
        this._failAll(err);
        reject(err);
      });
      sock.on('close', () => {
        this._failAll(new Error('IMAP 连接已关闭'));
        this.emit('close');
      });
      sock.on('data', chunk => this._onData(chunk));

      this.socket = sock;

      // greeting：* OK ... / * BYE ... / * PREAUTH
      this._awaitGreeting = { resolve, reject };
    });
  }

  _failAll(err) {
    for (const [, p] of this.pending) {
      try { p.reject(err); } catch { /* 忽略 */ }
    }
    this.pending.clear();
    if (this._awaitGreeting) {
      this._awaitGreeting.reject(err);
      this._awaitGreeting = null;
    }
  }

  _onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this._pump();
  }

  _pump() {
    while (true) {
      const cur = this._current;

      // 正在等文字段（literal）：{n}\r\n 之后的 n 字节必须原样读取
      if (cur && cur.literalRemaining > 0) {
        if (this.buffer.length < cur.literalRemaining) return;
        const lit = this.buffer.subarray(0, cur.literalRemaining);
        this.buffer = this.buffer.subarray(cur.literalRemaining);
        cur.literalChunks.push(lit);
        cur.literalRemaining = 0;
        continue;
      }

      // 找一行
      const nl = this.buffer.indexOf(0x0a); // \n
      if (nl < 0) {
        if (this.buffer.length > MAX_LINE) {
          this._current = null;
          this.buffer = Buffer.alloc(0);
          this._failAll(new Error('IMAP 响应行过长，已中止'));
        }
        return;
      }
      const lineBuf = this.buffer.subarray(0, nl + 1);
      this.buffer = this.buffer.subarray(nl + 1);
      const line = lineBuf.toString('utf8').replace(/\r\n$/, '');

      if (this._awaitGreeting) {
        if (/^\*\s+(OK|PREAUTH)/i.test(line)) {
          const g = this._awaitGreeting;
          this._awaitGreeting = null;
          this.greeting = line;
          g.resolve(line);
        } else if (/^\*\s+BYE/i.test(line)) {
          const g = this._awaitGreeting;
          this._awaitGreeting = null;
          g.reject(new Error('服务器拒绝连接：' + line));
        }
        continue;
      }

      // 行尾的 {n} 表示后面跟 n 字节 literal
      const litMatch = line.match(/\{(\d+)\}$/);
      if (litMatch) {
        const n = parseInt(litMatch[1], 10);
        if (cur) {
          cur.chunks.push(lineBuf);
          cur.literalRemaining = n;
          cur.literalChunks = [];
        }
        continue;
      }

      if (cur) {
        if (cur.literalChunks && cur.literalChunks.length) {
          // 在并入 chunks 之前先留一份原始字节。
          // literal 一旦和其他片段拼进同一个 Buffer 再统一 toString('utf8')，
          // 多字节字符的字节边界信息就丢了——上层无法再按 `{n}` 精确切分，
          // 切点会落在字符中间，解码出一堆 U+FFFD 替换字符。
          if (!cur.literalBuf) cur.literalBuf = Buffer.concat(cur.literalChunks);
          cur.chunks.push(cur.literalBuf);
          cur.literalChunks = [];
          cur.literalRemaining = 0;
        }
        cur.chunks.push(lineBuf);
      }

      // 命令结束：tagged response
      const tagMatch = line.match(/^(A\d+)\s+(OK|NO|BAD)\b(.*)$/i);
      if (tagMatch) {
        const tag = tagMatch[1];
        const p = this.pending.get(tag);
        if (p) {
          this.pending.delete(tag);
          this._current = null;
          const buf = cur ? Buffer.concat(cur.chunks) : Buffer.alloc(0);
          if (tagMatch[2].toUpperCase() === 'OK') {
            // literal 的原始字节必须单独交出去。
            // 整段响应 toString('utf8') 之后，多字节字符的字节边界信息就没了，
            // 上层再想按 `{n}` 声明的字节数精确切 literal 就不可能——
            // 切出来会落在字符中间，解码得到一堆 U+FFFD。
            // 所以这里把 literalChunks 单独拼成 Buffer 一并返回。
            const literalBuf = cur && cur.literalBuf ? cur.literalBuf : null;
            p.resolve({ text: buf.toString('utf8'), tag, literalBuf });
          } else {
            const err = new Error('IMAP 命令失败：' + line);
            err.imapStatus = tagMatch[2].toUpperCase();
            p.reject(err);
          }
        }
        continue;
      }

      // 能力协商
      if (/^\*\s+CAPABILITY\s+(.*)$/i.test(line)) {
        this.capabilities = RegExp.$1.trim().split(/\s+/);
        continue;
      }
      // 选择邮箱后的 EXISTS 等
      const existsMatch = line.match(/^\*\s+(\d+)\s+EXISTS/i);
      if (existsMatch && this.mailbox) {
        this.mailbox.exists = parseInt(existsMatch[1], 10);
        continue;
      }
    }
  }

  _nextTag() {
    this.tagCounter += 1;
    return 'A' + this.tagCounter;
  }

  /**
   * 发一条 IMAP 命令。
   *
   * 这里统一拦 CR/LF：IMAP 以行分隔命令，命令体里出现换行就等于注入一条新命令
   * （例如 `SEARCH SUBJECT "x"\r\nA9 DELETE "INBOX"`）。
   * 此前只有 select() 自己做转义，其余调用点（fetch 的 seqSet/items、
   * 将来新增的 SEARCH 之类）全靠调用方自觉。放在这一层是最后一道闸。
   */
  _command(cmd) {
    return new Promise((resolve, reject) => {
      if (!this.socket || this.socket.destroyed) {
        return reject(new Error('IMAP 连接不可用'));
      }
      if (/[\r\n]/.test(String(cmd))) {
        return reject(new Error('IMAP 命令包含换行符，已拒绝发送'));
      }
      const tag = this._nextTag();
      this.pending.set(tag, { resolve, reject });
      this._current = { tag, chunks: [], literalRemaining: 0, literalChunks: [], literalBuf: null };
      this.socket.write(tag + ' ' + cmd + '\r\n', 'utf8');
    });
  }

  async capability() {
    const r = await this._command('CAPABILITY');
    return this.capabilities.slice();
  }

  async authenticateXoauth2() {
    // 格式为 base64("user=<email>\x01auth=Bearer <token>\x01\x01")
    const ir = `user=${this.user}\x01auth=Bearer ${this.accessToken}\x01\x01`;
    const b64 = Buffer.from(ir, 'utf8').toString('base64');
    const r = await this._command(`AUTHENTICATE XOAUTH2 ${b64}`);
    return r;
  }

  async select(mailbox = 'INBOX') {
    // 防御 IMAP 命令注入：mailbox 名里出现 CR/LF 就能注入任意命令
    // （例如 'INBOX"\r\nA2 DELETE "INBOX'）。
    // 这里拒绝控制字符，并对双引号和反斜杠做标准 quoted-string 转义。
    const name = String(mailbox);
    if (/[\x00-\x1f\x7f]/.test(name)) {
      throw new Error('邮箱名包含非法控制字符');
    }
    if (name.length > 512) {
      throw new Error('邮箱名过长');
    }
    const escaped = name.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    this.mailbox = { path: name, exists: 0 };
    const r = await this._command(`SELECT "${escaped}"`);
    return this.mailbox;
  }

  /**
   * FETCH 一批邮件（按序号区间）
   * items：如 'ENVELOPE FLAGS RFC822.SIZE UID BODYSTRUCTURE'
   */
  async fetch(seqSet, items) {
    const r = await this._command(`FETCH ${seqSet} (${items})`);
    return r.text;
  }

  /**
   * 取单封邮件完整内容（BODY.PEEK 不改变已读状态）
   *
   * 用 UID 而不是序号：序号会随邮件移动/删除漂移，UID 才是稳定的。
   * 参数用对象而不是位置参数——之前签名是 (seq, uid)，调用方传的是 (28, true)，
   * 布尔值被当成 UID 拼进命令，变成 `UID FETCH true (...)`，
   * 服务端返回 "BAD The specified message set is invalid"。
   */
  async fetchBody({ uid } = {}) {
    // 布尔必须先拦：Number(true) === 1，会混过整数校验，
    // 而原来正是把 `true` 当 uid 传进来的。
    if (typeof uid === 'boolean' || uid === null || uid === undefined) {
      throw new Error('fetchBody 需要一个正整数 uid，收到：' + String(uid));
    }
    const n = Number(uid);
    if (!Number.isInteger(n) || n <= 0) {
      throw new Error('fetchBody 需要一个正整数 uid，收到：' + String(uid));
    }
    const r = await this._command(`UID FETCH ${n} (UID FLAGS ENVELOPE BODY.PEEK[])`);
    return r;
  }

  async logout() {
    try {
      await this._command('LOGOUT');
    } catch { /* 忽略 */ }
    try {
      if (this.socket && !this.socket.destroyed) this.socket.end();
    } catch { /* 忽略 */ }
  }

  destroy() {
    try { if (this.socket) this.socket.destroy(); } catch { /* 忽略 */ }
  }
}

/* ---------------- ENVELOPE 解析 ---------------- */

/**
 * 解析 FETCH 响应中的一部分
 * 返回 [{seq, uid, flags:[], envelope:{...}, size}]
 */
function parseFetchResponse(text) {
  const results = [];
  // 逐行匹配 "* N FETCH (" 作为起点，再用括号配平找出该响应的结束位置，
  // 避免贪婪正则把多封响应吞成一条。
  const re = /^\*\s+(\d+)\s+FETCH\s+\(/gim;
  let m;
  while ((m = re.exec(text)) !== null) {
    const seq = parseInt(m[1], 10);
    const contentStart = m.index + m[0].length; // 指向 "(" 之后
    const end = matchParen(text, contentStart - 1);
    if (end < 0) break;
    const body = text.slice(contentStart, end);

    const item = { seq, uid: null, flags: [], envelope: null, size: 0 };
    const uidM = body.match(/\bUID\s+(\d+)/i);
    if (uidM) item.uid = parseInt(uidM[1], 10);
    const flagM = body.match(/\bFLAGS\s+\(([^)]*)\)/i);
    if (flagM) item.flags = flagM[1].split(/\s+/).filter(Boolean);
    const sizeM = body.match(/\bRFC822\.SIZE\s+(\d+)/i);
    if (sizeM) item.size = parseInt(sizeM[1], 10);
    const envM = body.match(/\bENVELOPE\s+\(/i);
    if (envM) {
      const envStart = envM.index + envM[0].length - 1;
      item.envelope = parseEnvelope(body, envStart);
    }
    results.push(item);
    re.lastIndex = end + 1;
  }
  return results;
}

/** 从 openIdx 处的 '(' 开始，返回与之配对的 ')' 的下标（跳过引号内括号） */
function matchParen(s, openIdx) {
  let depth = 0;
  let inQuote = false;
  let escaped = false;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i];
    if (escaped) { escaped = false; continue; }
    if (inQuote) {
      if (c === '\\') escaped = true;
      else if (c === '"') inQuote = false;
      continue;
    }
    if (c === '"') { inQuote = true; continue; }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 从 pos 处的 '(' 开始解析 S-expression 列表 */
function readToken(s, pos) {
  while (pos < s.length && /\s/.test(s[pos])) pos++;
  if (pos >= s.length) return { value: null, next: pos };
  const c = s[pos];
  if (c === '(') {
    const arr = [];
    pos++;
    while (pos < s.length) {
      while (pos < s.length && /\s/.test(s[pos])) pos++;
      if (s[pos] === ')') { pos++; return { value: arr, next: pos }; }
      const r = readToken(s, pos);
      arr.push(r.value);
      pos = r.next;
    }
    return { value: arr, next: pos };
  }
  if (c === '"') {
    let out = '';
    pos++;
    while (pos < s.length && s[pos] !== '"') {
      if (s[pos] === '\\' && pos + 1 < s.length) {
        out += s[pos + 1];
        pos += 2;
      } else {
        out += s[pos];
        pos++;
      }
    }
    return { value: out, next: pos + 1 };
  }
  if (c === '{') {
    // literal，在 ENVELOPE 里少见；按 NIL 处理以免卡死
    const end = s.indexOf('}', pos);
    return { value: null, next: end >= 0 ? end + 1 : pos + 1 };
  }
  let end = pos;
  while (end < s.length && !/[\s()]/.test(s[end])) end++;
  const word = s.slice(pos, end);
  return { value: /^NIL$/i.test(word) ? null : word, next: end };
}

function parseEnvelope(s, pos) {
  const r = readToken(s, pos);
  const a = r.value;
  if (!Array.isArray(a)) return null;
  // ENVELOPE: date subject from sender reply-to to cc bcc in-reply-to message-id
  return {
    date: a[0] || null,
    subject: a[1] || null,
    from: parseAddressList(a[2]),
    sender: parseAddressList(a[3]),
    replyTo: parseAddressList(a[4]),
    to: parseAddressList(a[5]),
    cc: parseAddressList(a[6]),
    messageId: a[9] || null,
  };
}

function parseAddressList(v) {
  if (!Array.isArray(v)) return [];
  return v.map(a => {
    if (!Array.isArray(a)) return null;
    // 个人名 name-addr: [name, adl, mailbox, host]
    return {
      name: decodeMimeWord(a[0] || ''),
      address: a[2] && a[3] ? `${a[2]}@${a[3]}` : (a[2] || ''),
    };
  }).filter(Boolean);
}

function decodeMimeWord(s) {
  if (!s || typeof s !== 'string') return '';
  return s.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g, (full, cs, enc, data) => {
    try {
      const buf = enc.toUpperCase() === 'B'
        ? Buffer.from(data, 'base64')
        : Buffer.from(data.replace(/_/g, ' '), 'latin1');
      const lower = String(cs).toLowerCase();
      if (lower.startsWith('gb') || lower === 'big5') {
        return new TextDecoder('gb18030').decode(buf);
      }
      return new TextDecoder('utf-8').decode(buf);
    } catch { return full; }
  });
}

module.exports = {
  ImapClient,
  parseFetchResponse,
  readToken,
  parseEnvelope,
  decodeMimeWord,
};
