'use strict';
/**
 * 极简 SMTP 发送（仅支持 XOAUTH2 + STARTTLS + AUTH）
 *
 * Outlook.com 的 SMTP：smtp-mail.outlook.com:587，必须 STARTTLS
 * 同样零第三方依赖，可逐行审计。
 *
 * 安全基线：
 *  - 强制 STARTTLS，且证书校验不可关闭
 *  - 拒绝在明文连接上发送任何凭据（先 STARTTLS 再 AUTH）
 */
const net = require('net');
const tls = require('tls');

const SMTP_HOST = 'smtp-mail.outlook.com';
const SMTP_PORT = 587;

class SmtpClient {
  constructor(opts = {}) {
    this.host = opts.host || SMTP_HOST;
    this.port = opts.port || SMTP_PORT;
    this.timeout = opts.timeout || 30000;
    this.socket = null;
    this.buffer = '';
    this.waiters = [];
    this.secured = false;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host: this.host, port: this.port });
      sock.setTimeout(this.timeout, () => sock.destroy(new Error('SMTP 连接超时')));

      const onErr = err => { this._flushWaiters(err); reject(err); };
      sock.once('error', onErr);
      sock.on('error', err => this._flushWaiters(err));
      sock.on('data', d => this._onData(d));

      this.socket = sock;
      sock.once('connect', () => {
        sock.removeListener('error', onErr);
        resolve();
      });
    });
  }

  _onData(d) {
    this.buffer += d.toString('utf8');
    // SMTP 响应以 "250 xxx\r\n" 结束；多行响应形如 "250-xxx\r\n250 yyy\r\n"
    const lines = this.buffer.split('\r\n');
    this.buffer = lines.pop(); // 最后一段可能不完整

    for (const line of lines) {
      if (!line) continue;
      const m = line.match(/^(\d{3})([ -])(.*)$/);
      if (!m) continue;
      if (m[2] === '-') continue; // 多行继续
      const code = parseInt(m[1], 10);
      const w = this.waiters.shift();
      if (w) w.resolve({ code, text: m[3], raw: line });
    }
  }

  _flushWaiters(err) {
    while (this.waiters.length) {
      const w = this.waiters.shift();
      try { w.reject(err); } catch { /* 忽略 */ }
    }
  }

  _read() {
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  async _cmd(line, expect = [250]) {
    this.socket.write(line + '\r\n');
    const r = await this._read();
    if (!expect.includes(r.code)) {
      const err = new Error(`SMTP 命令失败（${r.code}）：${r.text}`);
      err.smtpCode = r.code;
      throw err;
    }
    return r;
  }

  async ehlo() {
    const r = await this._cmd('EHLO maildesk.local', [250]);
    this.lastEhlo = r.text || '';
    return r.text;
  }

  /** 是否在 EHLO 响应里声明了 STARTTLS 能力 */
  supportsStartTls() {
    return /STARTTLS/i.test(this.lastEhlo || '');
  }

  /**
   * 发送 STARTTLS 命令并升级连接。
   *
   * 关键：必须先发 STARTTLS、等服务器回 220，再包 TLS。
   * 直接 tls.connect 是不行的 —— 服务器仍在明文命令模式，
   * 收到 TLS ClientHello 的二进制会直接断开。
   */
  async startTls() {
    if (!this.supportsStartTls()) {
      throw new Error('服务器未声明 STARTTLS 能力，拒绝在明文连接上继续');
    }

    await this._cmd('STARTTLS', [220]);

    return new Promise((resolve, reject) => {
      const plain = this.socket;

      // 摘掉明文 socket 上的 data 监听，否则 TLS 包装后
      // 加密字节仍会被明文解析器读一次，破坏状态机
      plain.removeAllListeners('data');
      plain.removeAllListeners('error');

      const secure = tls.connect({
        socket: plain,
        servername: this.host,
        rejectUnauthorized: true, // 硬编码，不接受无效证书
        minVersion: 'TLSv1.2',
      }, () => {
        this.socket = secure;
        this.secured = true;
        this.buffer = '';
        this.lastEhlo = '';
        secure.on('data', d => this._onData(d));
        secure.on('error', err => this._flushWaiters(err));
        secure.setTimeout(this.timeout, () => secure.destroy(new Error('SMTP TLS 超时')));
        resolve();
      });
      secure.once('error', reject);
    });
  }

  async authXoauth2(user, accessToken) {
    if (!this.secured) throw new Error('拒绝在未加密连接上发送凭据');
    const ir = `user=${user}\x01auth=Bearer ${accessToken}\x01\x01`;
    const b64 = Buffer.from(ir, 'utf8').toString('base64');
    const r = await this._cmd(`AUTH XOAUTH2 ${b64}`, [235]);
    return r;
  }

  async mailFrom(addr) { return this._cmd(`MAIL FROM:<${addr}>`, [250]); }
  async rcptTo(addr) { return this._cmd(`RCPT TO:<${addr}>`, [250, 251]); }
  async data(payload) {
    await this._cmd('DATA', [354]);
    // 点填充（RFC 5321 §4.5.2）
    const escaped = payload.replace(/^\./gm, '..');
    this.socket.write(escaped + '\r\n.\r\n');
    const r = await this._read();
    if (r.code !== 250) throw new Error(`邮件投递失败（${r.code}）：${r.text}`);
    return r;
  }
  async quit() {
    try { await this._cmd('QUIT', [221]); } catch { /* 忽略 */ }
    try { if (this.socket) this.socket.end(); } catch { /* 忽略 */ }
  }
  destroy() {
    try { if (this.socket) this.socket.destroy(); } catch { /* 忽略 */ }
  }
}

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }

/** 折行 base64（MIME 要求） */
function wrap76(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 76) out.push(s.slice(i, i + 76));
  return out.join('\r\n');
}

/**
 * 构造 MIME 邮件
 * @param {{from:string,fromName?:string,to:string[],subject:string,text?:string,html?:string,attachments?:Array}} m
 */
function buildMessage(m) {
  const boundary = '----MailDesk_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  const altBoundary = boundary + '_alt';
  const lines = [];

  const encodeHeader = s => {
    // 纯 ASCII 直接放；含中文用 RFC 2047 B 编码
    if (/^[\x20-\x7E]*$/.test(s)) return s;
    return `=?UTF-8?B?${b64(s)}?=`;
  };

  const fromName = m.fromName ? `${encodeHeader(m.fromName)} ` : '';
  lines.push(`From: ${fromName}<${m.from}>`);
  lines.push(`To: ${m.to.join(', ')}`);
  lines.push(`Subject: ${encodeHeader(m.subject || '')}`);
  lines.push(`Date: ${new Date().toUTCString()}`);
  lines.push(`Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@maildesk.local>`);
  lines.push('MIME-Version: 1.0');

  const hasAttach = Array.isArray(m.attachments) && m.attachments.length > 0;
  const hasBoth = !!(m.text && m.html);

  if (!hasAttach && !hasBoth) {
    const isHtml = !!m.html && !m.text;
    lines.push(`Content-Type: ${isHtml ? 'text/html' : 'text/plain'}; charset=UTF-8`);
    lines.push('Content-Transfer-Encoding: base64');
    lines.push('');
    lines.push(wrap76(b64(isHtml ? m.html : (m.text || ''))));
    return lines.join('\r\n');
  }

  lines.push(`Content-Type: multipart/${hasAttach ? 'mixed' : 'alternative'}; boundary="${boundary}"`);
  lines.push('');
  lines.push(`--${boundary}`);

  const bodyPart = (() => {
    if (!hasBoth) {
      const isHtml = !!m.html && !m.text;
      return [
        `Content-Type: ${isHtml ? 'text/html' : 'text/plain'}; charset=UTF-8`,
        'Content-Transfer-Encoding: base64',
        '',
        wrap76(b64(isHtml ? m.html : (m.text || ''))),
      ].join('\r\n');
    }
    return [
      `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
      '',
      `--${altBoundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      wrap76(b64(m.text)),
      `--${altBoundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      wrap76(b64(m.html)),
      `--${altBoundary}--`,
    ].join('\r\n');
  })();

  lines.push(bodyPart);

  if (hasAttach) {
    for (const a of m.attachments) {
      lines.push(`--${boundary}`);
      lines.push(`Content-Type: ${a.contentType || 'application/octet-stream'}; name="${encodeHeader(a.filename)}"`);
      lines.push('Content-Transfer-Encoding: base64');
      lines.push(`Content-Disposition: attachment; filename="${encodeHeader(a.filename)}"`);
      lines.push('');
      lines.push(wrap76(Buffer.from(a.content).toString('base64')));
    }
  }

  lines.push(`--${boundary}--`);
  return lines.join('\r\n');
}

/**
 * 发送一封邮件
 */
async function sendMail(account, accessToken, mail) {
  const client = new SmtpClient({ host: SMTP_HOST, port: SMTP_PORT, timeout: 45000 });
  try {
    await client.connect();
    await client.ehlo();
    await client.startTls();
    await client.ehlo(); // STARTTLS 后必须重新 EHLO
    await client.authXoauth2(account.email, accessToken);
    await client.mailFrom(account.email);
    const recipients = Array.isArray(mail.to) ? mail.to : [mail.to];
    for (const rcpt of recipients) await client.rcptTo(rcpt);
    const payload = buildMessage({ ...mail, from: account.email });
    const r = await client.data(payload);
    await client.quit();
    return { ok: true, response: r.text };
  } catch (e) {
    client.destroy();
    throw e;
  }
}

module.exports = { SmtpClient, sendMail, buildMessage, SMTP_HOST, SMTP_PORT };
