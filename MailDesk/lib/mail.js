'use strict';
/**
 * Outlook / Microsoft 账号认证与收发
 *
 * 凭据支持：
 *  - refresh_token（唯一可靠方式）— OAuth2 换 access_token，不受 MFA 影响
 *
 * 关于密码：微软已全面禁用 Outlook 的 IMAP 基本认证。
 * 本工具不会尝试用密码登录，因为那必然失败，且在日志里留下明文风险。
 *
 * 安全基线（不可通过配置更改）：
 *  - TLS 严格证书校验（rejectUnauthorized: true）
 *  - 读取用 BODY.PEEK，不改变邮件已读状态
 *  - 所有网络请求带超时
 */
const https = require('https');
const zlib = require('zlib');
const { ImapClient, parseFetchResponse, decodeMimeWord } = require('./imap-client');

const ENDPOINTS = {
  consumers: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
  common: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  organizations: 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
};

const IMAP_HOST = 'outlook.office365.com';
const SMTP_HOST = 'smtp-mail.outlook.com';

// IMAP + SMTP 需要的 scope
const SCOPE_IMAP = 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access';
const SCOPE_SMTP = 'https://outlook.office.com/SMTP.Send offline_access';
const SCOPE_BOTH = 'https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access';

/**
 * 自动探测：refresh_token 必须拿"签发它的那个端点"去兑换，
 * 否则报 AADSTS7000012 "The grant was obtained for a different tenant"。
 *
 * 批量来的账号来源五花八门：
 *  - 个人号          → consumers
 *  - 企业/学校号     → organizations（或具体 tenant id）
 *  - 旧版 MSA token  → login.live.com/oauth20_token.srf
 * 所以按顺序都试一遍，命中就记住。
 */
const ENDPOINT_CANDIDATES = [
  { key: 'consumers', url: ENDPOINTS.consumers, scope: SCOPE_BOTH },
  { key: 'common', url: ENDPOINTS.common, scope: SCOPE_BOTH },
  { key: 'organizations', url: ENDPOINTS.organizations, scope: SCOPE_BOTH },
  { key: 'live', url: 'https://login.live.com/oauth20_token.srf', scope: '' },
];

function httpPostForm(url, form) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(form).toString();
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'MailDesk/1.0',
      },
      timeout: 30000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = String(res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc === 'gzip') buf = zlib.gunzipSync(buf);
          else if (enc === 'deflate') buf = zlib.inflateSync(buf);
        } catch { /* 保持原样 */ }
        const text = buf.toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* 非 JSON */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('请求超时（30 秒）')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * 用 refresh_token 换 access_token（单端点）
 */
async function refreshAccessToken({ clientId, refreshToken, endpoint = 'consumers', scope = SCOPE_BOTH, tenant }) {
  if (!clientId || !refreshToken) throw new Error('缺少 client_id 或 refresh_token');

  let url;
  if (tenant) {
    // 明确指定了租户 id / 域名
    url = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`;
  } else if (endpoint === 'live') {
    url = 'https://login.live.com/oauth20_token.srf';
  } else {
    url = ENDPOINTS[endpoint] || ENDPOINTS.consumers;
  }

  const form = {
    client_id: clientId,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  };
  // live 端点不接受 scope 参数
  if (scope && endpoint !== 'live') form.scope = scope;

  const res = await httpPostForm(url, form);

  if (res.status !== 200 || !res.json) {
    const code = (res.json && res.json.error) || '';
    const desc = (res.json && res.json.error_description) || res.text || '';
    const first = String(desc).split('\n')[0].slice(0, 300);
    const err = new Error(`换取 token 失败（HTTP ${res.status}）${code ? ' [' + code + ']' : ''}：${first}`);
    err.oauthError = code;
    err.aadsts = (String(desc).match(/AADSTS\d+/) || [])[0] || '';
    err.endpointTried = endpoint;
    throw err;
  }
  if (!res.json.access_token) throw new Error('服务端返回 200 但没有 access_token');

  return {
    accessToken: res.json.access_token,
    expiresIn: res.json.expires_in || 3600,
    refreshToken: res.json.refresh_token || null,
    scope: res.json.scope || '',
    endpointUsed: endpoint,
  };
}

/**
 * 自动探测可用端点。
 * 只对"端点不匹配"这类错误继续尝试；凭据真的失效就不再试，
 * 免得一个坏 token 打十几次微软服务器。
 */
async function refreshAccessTokenAuto({ clientId, refreshToken, pinned, tenant, scope }) {
  const order = [];
  if (tenant) {
    order.push({ key: 'tenant', url: null, scope: scope || SCOPE_BOTH, tenant });
  }
  if (pinned && pinned !== 'auto') {
    const p = ENDPOINT_CANDIDATES.find(e => e.key === pinned);
    if (p) order.push(p);
  }
  for (const c of ENDPOINT_CANDIDATES) {
    if (!order.some(o => o.key === c.key)) order.push(c);
  }

  const errors = [];
  for (const cand of order) {
    try {
      const r = await refreshAccessToken({
        clientId,
        refreshToken,
        endpoint: cand.key === 'tenant' ? 'consumers' : cand.key,
        tenant: cand.tenant,
        scope: scope || cand.scope,
      });
      return { ...r, endpointUsed: cand.key };
    } catch (e) {
      errors.push({ endpoint: cand.key, message: e.message, aadsts: e.aadsts, code: e.oauthError });

      // 这些错误说明 token 本身有问题，换端点也没用
      if (e.aadsts === 'AADSTS70000' ||        // invalid_grant 通用
          e.aadsts === 'AADSTS700003' ||       // 会话过期
          e.aadsts === 'AADSTS700082' ||       // 已刷新过
          e.aadsts === 'AADSTS50173' ||        // 需要重新认证
          /invalid_client/i.test(e.oauthError || '') ||
          /service abuse/i.test(e.message)) {
        break;
      }
    }
  }

  // 全部失败：把最有信息量的那个错误抛出去
  const best = errors.find(x => x.aadsts === 'AADSTS7000012') ||
               errors.find(x => /service abuse/i.test(x.message)) ||
               errors[errors.length - 1] ||
               { message: '所有端点均失败' };

  const err = new Error(best.message);
  err.aadsts = best.aadsts;
  err.triedEndpoints = errors.map(e => e.endpoint);
  err.allErrors = errors;
  throw err;
}

const tokenCache = new Map(); // key -> {token, exp}
// 每个账户探测成功的端点，避免每次都把 4 个端点试一遍
const endpointMemory = new Map(); // accountId -> endpoint key
// accountId -> 本进程见过的最新 refresh_token。
// 微软每次刷新都会轮换 refresh_token，而不同请求各自从账户库读一份副本，
// 只改自己手里那个对象会让并发请求拿着旧令牌去换取 → invalid_grant。
const latestRefreshToken = new Map();
// accountId -> 当前排队中的刷新链尾（串行化同一账户的并发刷新）
const refreshQueues = new Map();

/**
 * refresh_token 持久化回调，由调用方注入（server.js 启动时注入）。
 * lib/mail.js 只认识一个不透明的异步函数，不依赖任何存储实现。
 */
let persistRefreshToken = null;

function setRefreshTokenPersister(fn) {
  persistRefreshToken = typeof fn === 'function' ? fn : null;
}

/**
 * 同一账户的刷新串行化。
 * 两个请求同时刷新会拿同一个 refresh_token 兑换两次：第二次必然 invalid_grant，
 * 而且先后顺序还可能把更旧的值写回账户库。
 */
function withRefreshLock(key, fn) {
  const prev = refreshQueues.get(key) || Promise.resolve();
  let release;
  const gate = new Promise(r => { release = r; });
  const tail = prev.then(() => gate);
  refreshQueues.set(key, tail);
  return prev.then(fn).finally(() => {
    release();
    if (refreshQueues.get(key) === tail) refreshQueues.delete(key);
  });
}

/**
 * 把轮换后的 refresh_token 落到账户库。必须在任何"兑换成功"之后、返回之前调用。
 * 写失败不能吞：此刻服务器侧旧令牌已作废，新令牌只存在于内存里。
 */
async function commitRotatedToken(account, newToken, previousToken, persist) {
  const lockKey = String(account.id || (account.secrets || {}).clientId);
  // 先更新进程内状态，再落盘：落盘万一失败，后续调用手里仍有最新值，还有机会补救。
  if (account.id) latestRefreshToken.set(lockKey, newToken);
  if (account.secrets) account.secrets.refreshToken = newToken;
  let outcome;
  try {
    // 第三个参数是"被换掉的那个旧令牌"，持久化方可以据此判断自己拿到的是不是
    // 一份过期快照（期间账户被重新导入过），从而避免用旧值覆盖新值。
    outcome = await persist(account, newToken, previousToken);
  } catch (e) {
    const err = new Error(
      'refresh_token 已轮换，但写入账户库失败（旧令牌已作废，账号随时会失效）：' +
      (e && e.message ? e.message : String(e))
    );
    err.code = 'REFRESH_TOKEN_PERSIST_FAILED';
    err.rotationPersisted = false;
    err.cause = e;
    throw err;
  }

  // 账户库里有别人写的更新的令牌：以库为准，把内存状态同步过去。
  // 不抛错（抛了下一轮还会撞同一个冲突，变成死循环），但要留下明显痕迹。
  if (outcome && outcome.skipped && outcome.reason === 'vault-has-different-token') {
    if (outcome.currentToken) {
      latestRefreshToken.set(lockKey, outcome.currentToken);
      if (account.secrets) account.secrets.refreshToken = outcome.currentToken;
    }
    console.warn(
      '[mail] 账户库中的 refresh_token 与本次轮换结果不一致，已以库中值为准' +
      '（account=' + String(account.id || '?') + '）。若该账号随后报 invalid_grant，需要重新导入。'
    );
  }
}

/**
 * 拿到可用 access_token（带内存缓存，端点自动探测）
 *
 * 轮换：refresh_token 一经兑换，旧值在服务端立即失效。
 * 因此只要返回了新值，就必须在返回前写回账户库，否则这个账号就废了。
 *
 * opts.persistRefreshToken  覆盖默认持久化回调（可选）
 * opts._exchange            替换网络兑换实现，仅供测试注入（可选）
 */
async function getAccessToken(account, opts = {}) {
  const s = account.secrets || {};
  if (!s.clientId || !s.refreshToken) {
    throw new Error('该账号缺少 client_id 或 refresh_token，无法登录。微软已禁用密码方式，请补充刷新令牌。');
  }

  const cacheKey = `${account.id}:${opts.endpoint || s.endpoint || 'auto'}:${opts.scope ? 'custom' : 'default'}`;
  const hit = tokenCache.get(cacheKey);
  if (hit && hit.exp > Date.now() + 60000) return { accessToken: hit.token, cached: true };

  const exchange = typeof opts._exchange === 'function' ? opts._exchange : refreshAccessTokenAuto;
  const persist = typeof opts.persistRefreshToken === 'function'
    ? opts.persistRefreshToken
    : persistRefreshToken;

  // 没有持久化能力就干脆不兑换：兑换成功即作废旧令牌，拿不到新值等于当场销毁凭据。
  // 宁可报错，也不做这种静默的破坏性操作。
  if (!persist) {
    const err = new Error('缺少 refresh_token 持久化回调，拒绝刷新：刷新会轮换令牌，不写回账户库等于销毁凭据');
    err.code = 'REFRESH_TOKEN_NO_PERSISTER';
    throw err;
  }

  const lockKey = String(account.id || s.clientId);
  return withRefreshLock(lockKey, async () => {
    // 排队期间别的调用可能已经刷新并填好缓存，直接复用，避免重复兑换
    const hit2 = tokenCache.get(cacheKey);
    if (hit2 && hit2.exp > Date.now() + 60000) return { accessToken: hit2.token, cached: true };

    // 始终用本进程见过的最新令牌，别拿旧副本去撞 invalid_grant
    const refreshToken = latestRefreshToken.get(lockKey) || s.refreshToken;

    const pinned = opts.endpoint || endpointMemory.get(account.id) ||
                   (s.endpoint && s.endpoint !== 'auto' ? s.endpoint : null);

    const t = await exchange({
      clientId: s.clientId,
      refreshToken,
      pinned,
      tenant: s.tenant || '',
      scope: opts.scope,
    });

    // 记住成功的端点
    if (t.endpointUsed) endpointMemory.set(account.id, t.endpointUsed);

    let rotated = false;
    if (t.refreshToken && t.refreshToken !== refreshToken) {
      rotated = true;
      await commitRotatedToken(account, t.refreshToken, refreshToken, persist);
    }

    tokenCache.set(cacheKey, { token: t.accessToken, exp: Date.now() + t.expiresIn * 1000 });
    return {
      accessToken: t.accessToken,
      newRefreshToken: t.refreshToken,
      refreshTokenRotated: rotated,
      cached: false,
      endpointUsed: t.endpointUsed,
    };
  });
}

/**
 * 用指定端点兑换一次并提交轮换（诊断用）。
 * 直接调 refreshAccessToken 会绕过持久化，成功一次就把账号令牌弄丢，
 * 所以这里必须走同一把锁 + 同一个提交路径。
 */
async function refreshAccountToken(account, opts = {}) {
  const s = account.secrets || {};
  if (!s.clientId || !s.refreshToken) throw new Error('该账户缺少 client_id 或 refresh_token');
  const persist = typeof opts.persistRefreshToken === 'function'
    ? opts.persistRefreshToken
    : persistRefreshToken;
  if (!persist) {
    const err = new Error('缺少 refresh_token 持久化回调，拒绝刷新');
    err.code = 'REFRESH_TOKEN_NO_PERSISTER';
    throw err;
  }

  const lockKey = String(account.id || s.clientId);
  return withRefreshLock(lockKey, async () => {
    const refreshToken = latestRefreshToken.get(lockKey) || s.refreshToken;
    const t = await refreshAccessToken({
      clientId: s.clientId,
      refreshToken,
      endpoint: opts.endpoint || 'consumers',
      tenant: opts.tenant,
      scope: opts.scope,
    });
    if (t.refreshToken && t.refreshToken !== refreshToken) {
      await commitRotatedToken(account, t.refreshToken, refreshToken, persist);
    }
    return t;
  });
}

function clearTokenCache(accountId) {
  for (const k of [...tokenCache.keys()]) {
    if (k.startsWith(accountId + ':')) tokenCache.delete(k);
  }
  endpointMemory.delete(accountId);
  // 用户手工改过 refresh_token（account.update 会调到这里），丢掉内存里的旧轮换值
  latestRefreshToken.delete(String(accountId));
}

/**
 * 微软的 IMAP 认证会对部分账号随机返回
 * `A1/A3/A5 NO User is authenticated but not connected.`，重试就能过。
 *
 * 实测结论（100 个真实账号，多轮对照）：
 *  - 和并发无关：串行零重试扫 30 个，照样失败 2 个
 *  - 和账号报废无关：最难缠的账号间隔 15 秒单测 6 次，仍有 2 次成功
 *  - 和连接复用无关：换新连接重试没有明显改善
 *  - **关键在于重试密度**。三套策略实测（4 个难缠账号）：
 *      稀疏 2.5/5/10s  → 3/4 成功（最难的那个 4 次尝试仍失败）
 *      密集 1/2/3/4/5s → 3/4 成功
 *      均匀 3s × 6     → **4/4 全成功**
 *    稀疏长间隔反而更容易撞上拒绝窗口，均匀密集重试命中率更高。
 *
 * 所以采用均匀 3 秒、最多 6 次（累计约 18 秒）。
 * 只对这一种错误重试：其它错误（token 失效、TLS 失败、网络断）重试没有意义。
 */
const AUTH_RETRY_DELAYS = [3000, 3000, 3000, 3000, 3000, 3000];
// 批量场景单账号有 25 秒总超时，压到 4 次（约 12 秒）留出扫描时间
const AUTH_RETRY_DELAYS_FAST = [3000, 3000, 3000, 3000];

async function authenticateWithRetry(client, email, opts = {}) {
  const delays = opts.fast ? AUTH_RETRY_DELAYS_FAST : AUTH_RETRY_DELAYS;
  let lastErr = null;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    try {
      await client.authenticateXoauth2();
      return;
    } catch (e) {
      lastErr = e;
      const transient = /User is authenticated but not connected/i.test(String(e && e.message));
      if (!transient) throw e;                       // 非瞬时错误立刻抛
      if (attempt === delays.length) {
        // 重试耗尽：标记出来，供上层区分"重试过也不行"和"一次就失败"
        e.imapAuthRetried = attempt;
        throw e;
      }
      await new Promise(r => setTimeout(r, delays[attempt]));
    }
  }
  throw lastErr || new Error('IMAP 认证失败');
}

/**
 * 建连接 + 认证，失败时换新连接重试。
 *
 * 微软的 "User is authenticated but not connected" 是概率性拒绝：
 * 实测同一批账号连测 4 轮，15 个账号里只有 1 个失败过 2 次，没有一个每轮都失败。
 * 而且在同一连接上反复 AUTHENTICATE 不一定管用——被拒的可能是这次 TCP 连接
 * 的会话状态，所以重试必须重建连接。
 *
 * 返回已认证的 client；全部重试都失败时抛最后一个错误。
 */
async function connectAndAuth(account, opts = {}) {
  const auth = await getAccessToken(account);
  const delays = opts.fast ? AUTH_RETRY_DELAYS_FAST : AUTH_RETRY_DELAYS;
  let lastErr = null;

  for (let attempt = 0; attempt <= delays.length; attempt++) {
    const client = new ImapClient({
      host: IMAP_HOST,
      port: 993,
      auth: { user: account.email, accessToken: auth.accessToken },
      timeout: opts.timeout || 30000,
    });
    try {
      await client.connect();
      await client.authenticateXoauth2();
      return client;
    } catch (e) {
      lastErr = e;
      // 这条连接没用了，先干净地关掉再重试
      try { client.destroy(); } catch { /* 忽略 */ }

      const transient = /User is authenticated but not connected/i.test(String(e && e.message));
      if (!transient) throw e;                        // 非瞬时错误立刻抛
      if (attempt === delays.length) {
        e.imapAuthRetried = attempt;                  // 标记重试次数，供上层区分
        throw e;
      }
      await new Promise(r => setTimeout(r, delays[attempt]));
    }
  }
  throw lastErr || new Error('IMAP 认证失败');
}

async function withImap(account, fn) {
  const client = await connectAndAuth(account);
  try {
    return await fn(client);
  } finally {
    try { await client.logout(); } catch { /* 忽略 */ }
    client.destroy();
  }
}

/**
 * 列出文件夹
 */
async function listFolders(account) {
  return withImap(account, async client => {
    const r = await client._command('LIST "" "*"');
    const out = [];
    const re = /^\*\s+LIST\s+(\([^)]*\))\s+"([^"]*)"\s+(.+)$/gim;
    let m;
    while ((m = re.exec(r.text)) !== null) {
      let name = m[3].trim();
      if (name.startsWith('"') && name.endsWith('"')) name = name.slice(1, -1);
      out.push(name);
    }
    return out;
  });
}

/**
 * 列出邮件
 * @param {object} account
 * @param {{mailbox?:string, limit?:number}} opts
 */
async function listMessages(account, opts = {}) {
  const mailbox = opts.mailbox || 'INBOX';
  const limit = Math.min(Math.max(parseInt(opts.limit, 10) || 20, 1), 100);

  return withImap(account, async client => {
    const mb = await client.select(mailbox);
    const exists = (mb && mb.exists) || 0;
    if (exists === 0) return [];

    const start = Math.max(1, exists - limit + 1);
    const text = await client.fetch(`${start}:*`, 'UID FLAGS RFC822.SIZE ENVELOPE');
    const items = parseFetchResponse(text);

    const out = items.map(it => {
      const env = it.envelope || {};
      const from = (env.from && env.from[0]) || {};
      return {
        uid: it.uid,
        seq: it.seq,
        date: env.date ? safeISO(env.date) : null,
        subject: env.subject ? decodeMimeWord(env.subject) : '(无主题)',
        from: from.address || '',
        fromName: from.name || '',
        to: (env.to || []).map(t => t.address).filter(Boolean).join(', '),
        size: it.size || 0,
        seen: it.flags.includes('\\Seen'),
        flagged: it.flags.includes('\\Flagged'),
      };
    });

    out.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    return out.slice(0, limit);
  });
}

/**
 * 读取单封邮件正文
 */
async function getMessage(account, opts = {}) {
  const mailbox = opts.mailbox || 'INBOX';
  const uid = parseInt(opts.uid, 10);
  if (!uid) throw new Error('缺少 uid');

  return withImap(account, async client => {
    await client.select(mailbox);
    const r = await client.fetchBody({ uid });

    // 从响应里抠出 literal（邮件原文）。
    // 优先用协议层保留的原始字节：整段响应转成字符串后，多字节字符的
    // 字节边界就丢了，无法再按 `{n}` 的字节数精确切分。
    const raw = r.literalBuf
      ? r.literalBuf.toString('utf8')
      : extractLiteral(r.text);
    const parsed = parseMime(raw);

    const items = parseFetchResponse(r.text);
    const env = (items[0] && items[0].envelope) || {};
    const from = (env.from && env.from[0]) || {};

    return {
      uid,
      subject: env.subject ? decodeMimeWord(env.subject) : (parsed.headers.subject || '(无主题)'),
      from: from.address || parsed.headers.from || '',
      fromName: from.name || '',
      to: (env.to || []).map(t => t.address).join(', ') || parsed.headers.to || '',
      date: env.date ? safeISO(env.date) : null,
      text: parsed.text,
      html: parsed.html,
      attachments: parsed.attachments,
      seen: items[0] ? items[0].flags.includes('\\Seen') : false,
    };
  });
}

function safeISO(s) {
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * 从 FETCH 响应里取出 literal 正文。
 *
 * literal 声明形如 `{20113}\r\n`，其中 20113 是**字节数**，不是字符数。
 * 中文字符在 UTF-8 里占 3 字节，所以把响应转成字符串后按字符数切一定会截断，
 * 截断处正好落在多字节字符中间 → 后续解码得到一堆 U+FFFD 替换字符。
 *
 * 两处都必须修：
 *  1. 定位 `{n}\r\n` 要按完整模式匹配。早先用 indexOf('{') + indexOf('}')，
 *     右花括号会落在声明中间，切点偏移，正文前半段变成 Received 头。
 *  2. 切片必须按字节做。先把字符串还原成 Buffer，按声明的字节数精确切。
 *
 * 响应形如：
 *   * 3 FETCH (UID 28 FLAGS () ENVELOPE (...){20113}\r\n<正文>)\r\nA3 OK ...
 */
function extractLiteral(text) {
  const src = String(text);
  const m = /\{(\d+)\}\r\n/.exec(src);
  if (!m) {
    // 没有 literal 声明（空邮件，或服务端用了非 literal 形式）
    const i = src.indexOf('{');
    const j = src.indexOf('}', i);
    if (i < 0 || j < 0) return '';
    return src.slice(j + 1).replace(/\r\n\)\s*$/, '');
  }

  const len = Number(m[1]);
  if (!Number.isFinite(len) || len <= 0) return '';

  const markerEnd = m.index + m[0].length;   // 字符串下标，必落在 ASCII 边界
  // 标记之前全是 ASCII（`* 3 FETCH (... ENVELOPE (...)`），所以字节数 == 字符数
  const startByte = Buffer.byteLength(src.slice(0, markerEnd), 'utf8');

  const buf = Buffer.from(src, 'utf8');
  if (startByte >= buf.length) return '';

  // 按声明字节数精确切；服务端可能多报，用剩余长度兜底
  const endByte = Math.min(startByte + len, buf.length);
  const out = buf.subarray(startByte, endByte).toString('utf8');

  // 去掉 fetch 响应的收尾 `)`
  return out.replace(/\r\n\)\s*$/, '');
}

// multipart 递归深度上限：防止构造的深层嵌套邮件把栈打爆
const MAX_MIME_DEPTH = 20;
// 单封邮件解析上限，防止超长正文拖死事件循环
const MAX_MIME_BYTES = 5 * 1024 * 1024;

/* ---------------- MIME 解析 ---------------- */

function parseMime(raw, depth = 0) {
  if (!raw) return { headers: {}, text: '', html: '', attachments: [] };
  if (depth > MAX_MIME_DEPTH) {
    return { headers: {}, text: '[嵌套层级过深，已跳过]', html: '', attachments: [] };
  }
  if (raw.length > MAX_MIME_BYTES) raw = raw.slice(0, MAX_MIME_BYTES);

  const sepIdx = raw.search(/\r?\n\r?\n/);
  const headerBlock = sepIdx >= 0 ? raw.slice(0, sepIdx) : raw;
  const bodyRaw = sepIdx >= 0 ? raw.slice(sepIdx).replace(/^\r?\n\r?\n/, '') : '';

  const headers = {};
  let lastKey = null;
  for (const line of headerBlock.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && lastKey) {
      headers[lastKey] += ' ' + line.trim();
    } else {
      const k = line.indexOf(':');
      if (k > 0) {
        lastKey = line.slice(0, k).toLowerCase().trim();
        headers[lastKey] = line.slice(k + 1).trim();
      }
    }
  }

  const result = { headers: {}, text: '', html: '', attachments: [] };
  result.headers.subject = decodeMimeWord(headers['subject'] || '');
  result.headers.from = decodeMimeWord(headers['from'] || '');
  result.headers.to = decodeMimeWord(headers['to'] || '');

  // 注意：boundary 大小写敏感，必须从原始 content-type 里取，
  // 不能从小写化后的副本取，否则 "--BOUND" 会匹配不到 "--bound"
  const ctRaw = headers['content-type'] || 'text/plain';
  const ct = ctRaw.toLowerCase();

  // multipart 判定必须看 media type，不能只看有没有 boundary 参数
  if (ct.startsWith('multipart/') && /boundary\s*=\s*"?([^";]+)"?/i.test(ctRaw)) {
    const boundaryMatch = ctRaw.match(/boundary\s*=\s*"?([^";]+)"?/i);
    const boundary = '--' + boundaryMatch[1].trim();
    const parts = bodyRaw.split(boundary);
    for (const part of parts) {
      let t = part;
      // 去掉分隔符后紧跟的换行
      t = t.replace(/^[ \t]*\r?\n/, '');
      if (!t.trim() || /^--\s*$/.test(t.trim())) continue;
      const sub = parseMime(t, depth + 1);
      if (sub.text && !result.text) result.text = sub.text;
      if (sub.html && !result.html) result.html = sub.html;
      if (sub.attachments.length) result.attachments.push(...sub.attachments);
    }
    return result;
  }

  const charsetM = ct.match(/charset\s*=\s*"?([^";]+)"?/);
  const charset = charsetM ? charsetM[1] : 'utf-8';
  const cte = (headers['content-transfer-encoding'] || '').toLowerCase().trim();
  const disp = headers['content-disposition'] || '';
  const nameM = (disp + ';' + (headers['content-type'] || '')).match(/name\s*=\s*"?([^";]+)"?/i);

  if (nameM && /attachment/i.test(disp)) {
    result.attachments.push({
      filename: decodeMimeWord(nameM[1].trim()),
      size: bodyRaw.length,
      contentType: ct.split(';')[0].trim(),
    });
    return result;
  }

  let buf;
  if (cte === 'base64') {
    buf = Buffer.from(bodyRaw.replace(/\s+/g, ''), 'base64');
  } else if (cte === 'quoted-printable') {
    buf = decodeQP(bodyRaw);
  } else if (cte === '8bit' || cte === '7bit' || cte === 'binary') {
    // 8bit/7bit/binary：正文在传输时就是原样字节，我们这里拿到的 bodyRaw
    // 已经是从原始字节解码出来的字符串。用 'binary'(latin1) 转 Buffer 会把
    // 每个 UTF-8 多字节字符硬截成一个字节，中文全变成替换字符或控制字符。
    // 必须按 UTF-8 还原。
    buf = Buffer.from(bodyRaw, 'utf8');
  } else {
    // 没有 Content-Transfer-Encoding 头：同上，按 UTF-8 处理。
    // 早期这里写成 'binary'，导致所有未声明编码的中文邮件正文全部乱码。
    buf = Buffer.from(bodyRaw, 'utf8');
  }

  const text = decodeWithCharset(buf, charset);
  if (ct.includes('text/html')) result.html = text;
  else if (ct.includes('text/plain')) result.text = text;
  return result;
}

function decodeQP(s) {
  const noSoft = s.replace(/=\r?\n/g, '');
  const bytes = [];
  for (let i = 0; i < noSoft.length; i++) {
    const c = noSoft[i];
    if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(noSoft.substr(i + 1, 2))) {
      bytes.push(parseInt(noSoft.substr(i + 1, 2), 16));
      i += 2;
    } else {
      bytes.push(c.charCodeAt(0) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function decodeWithCharset(buf, charset) {
  const cs = String(charset || 'utf-8').toLowerCase().replace(/["']/g, '');
  try {
    if (/^(gb2312|gbk|gb18030|x-gbk|cp936)$/.test(cs)) {
      return new TextDecoder('gb18030').decode(buf);
    }
    if (/^(big5|big5-hkscs)$/.test(cs)) return new TextDecoder('big5').decode(buf);
    if (/^(iso-8859-1|latin1)$/.test(cs)) return buf.toString('latin1');
    return new TextDecoder('utf-8').decode(buf);
  } catch {
    return buf.toString('utf8');
  }
}

/**
 * 检测账号是否可用（仅验证 token 和 IMAP 登录，不拉邮件）
 */
async function checkAccount(account, opts = {}) {
  const started = Date.now();
  try {
    const auth = await getAccessToken(account, { endpoint: opts.endpoint });
    // 用 connectAndAuth：内部换新连接重试微软的概率性拒绝
    const client = await connectAndAuth(account, { timeout: 20000, fast: true });
    try {
      const mb = await client.select('INBOX');
      return {
        ok: true,
        tokenOk: true,
        imapOk: true,
        exists: (mb && mb.exists) || 0,
        ms: Date.now() - started,
        tokenCached: !!auth.cached,
      };
    } finally {
      try { await client.logout(); } catch { /* 忽略 */ }
      client.destroy();
    }
  } catch (e) {
    return {
      ok: false,
      tokenOk: false,
      imapOk: false,
      error: e.message,
      oauthError: e.oauthError || null,
      // 常见错误归类，方便批量排查
      reason: classifyError(e),
      ms: Date.now() - started,
    };
  }
}

function classifyError(e) {
  const msg = String(e.message || '');
  const code = String(e.oauthError || '');
  const aadsts = String(e.aadsts || '');

  if (/service abuse|abuse mode/i.test(msg)) return '账号已被微软封禁（service abuse mode）';

  if (e.code === 'REFRESH_TOKEN_PERSIST_FAILED') {
    return 'refresh_token 已在微软侧轮换，但写回本地账户库失败——' +
           '旧令牌已作废，请立即重试（或重新导入该账号），否则该账号下次使用必定失效';
  }
  if (e.code === 'REFRESH_TOKEN_NO_PERSISTER') {
    return '内部错误：未启用 refresh_token 持久化，为避免销毁凭据已拒绝刷新';
  }

  switch (aadsts) {
    case 'AADSTS7000012':
      return '账号所属租户与端点不匹配（已自动试过 consumers/common/organizations/live 全部端点仍失败）——' +
             '这个 refresh_token 可能来自特定的企业租户，需要填写该租户的 tenant ID';
    case 'AADSTS40016':
      return '该 token 与组织端点不兼容（个人号请用 consumers，企业号请填 tenant ID）';
    case 'AADSTS70000':
    case 'AADSTS700003':
      return 'refresh_token 已失效（被撤销、过期，或已在别处刷新过）';
    case 'AADSTS700082':
      return 'refresh_token 已被使用过（微软一次性令牌，刷新后会换新值）';
    case 'AADSTS50173':
      return '会话已过期，需要用户重新授权';
    case 'AADSTS65001':
      return '用户或管理员未同意该应用所需的权限';
    case 'AADSTS70011':
      return 'scope 参数不被该端点接受';
    case 'AADSTS9002313':
      return '请求格式错误（可能该 token 属于另一套 API）';
    case 'AADSTS50020':
      return '该账号不在应用的租户内（个人号/app 是单租户应用）';
    case 'AADSTS50034':
      return '账号在该租户中不存在';
  }

  if (code === 'invalid_client' || /invalid_client/i.test(msg)) return 'client_id 无效或应用已被删除';
  if (code === 'invalid_grant' || /invalid_grant/i.test(msg)) {
    if (/different tenant/i.test(msg)) {
      return '端点不匹配（AADSTS7000012）：token 由另一个租户签发，需要在账号里填写该租户 ID';
    }
    return 'refresh_token 已失效（被撤销或过期）';
  }
  if (/AUTHENTICATIONFAILED/i.test(msg)) return 'IMAP 认证失败（token 无 IMAP 权限或已被吊销）';

  // 微软 IMAP 特有的拒绝响应。实测结论（100 个真实账号）：
  //  - 和并发无关：串行也会失败；和账号报废也无关：最难缠的账号单独测
  //    仍有约 1/3 的尝试能成功，说明凭据是好的
  //  - 是概率性的：同一批账号每轮失败的都不同
  //  - 均匀 3 秒重试命中率最高（实测 4 个难缠账号全过），稀疏长间隔反而更差
  // 所以在连接层做了 3 秒 × 6 次的重试。到这里还能抛出来，说明已重试耗尽。
  if (/User is authenticated but not connected/i.test(msg)) {
    return 'IMAP 认证被微软拒绝（已自动重试仍未通过）。这类拒绝是微软侧概率性的，' +
           '多数账号过一会儿再试就能成功；若某个账号长期如此，可能是该邮箱的 IMAP 被关闭或受限';
  }

  if (/ECONNRESET|ETIMEDOUT|timeout|超时/i.test(msg)) return '网络超时或连接被重置';
  if (/certificate|CERT_/i.test(msg)) return 'TLS 证书校验失败';
  return '未知错误';
}

module.exports = {
  refreshAccessToken,
  refreshAccessTokenAuto,
  getAccessToken,
  refreshAccountToken,
  authenticateWithRetry,
  clearTokenCache,
  setRefreshTokenPersister,
  listFolders,
  listMessages,
  getMessage,
  checkAccount,
  parseMime,
  classifyError,
  IMAP_HOST,
  SMTP_HOST,
  ENDPOINTS,
  ENDPOINT_CANDIDATES,
  SCOPE_IMAP,
  SCOPE_SMTP,
  SCOPE_BOTH,
};
