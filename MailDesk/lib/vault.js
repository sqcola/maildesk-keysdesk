'use strict';
/**
 * 邮箱账户存储
 * - 密码与 refresh_token 用 AES-256-GCM 加密后落盘
 * - 密钥文件 vault.key 权限 0600，首次运行自动生成
 * - 文件本身不提供任何网络能力，纯本地
 *
 * 密钥与密文分离（K2）：
 *   密钥默认放在 keyDir（真实运行时是 ~/.maildesk），密文放 dataDir。
 *   这样整个 data/ 目录被拷走只是一堆解不开的密文，AES-256-GCM 不会失效。
 *   keyDir 缺省等于 dataDir：既兼容老部署，也让设了 MAILDESK_DATA_DIR 的
 *   测试套件保持"密钥与数据同目录"的原有行为（见 server.js 的 KEY_DIR 解析）。
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/**
 * 把文件的 ACL 收紧到「只有当前用户」。
 *
 * 为什么 chmod 0o600 不够：Windows 上它只切只读位，文件仍带着从父目录继承来的
 * ACE。实测本机 vault.key 的 ACL 是
 *   NT AUTHORITY\SYSTEM:(I)(F)  BUILTIN\Administrators:(I)(F)  <user>:(I)(F)
 * —— 同机任何管理员账户都能读走这把密钥，而 vault.key + accounts.enc
 * 合起来就是全部 100 个邮箱的 refresh_token。H1 花了力气堵 handshake，
 * 如果密钥文件本身仍对第二个账户可读，那道门就是白关的。
 *
 * 为什么是异步 + 去重：icacls 是一次进程创建，实测每次约 2.5 秒（两次调用
 * 就是 5 秒）。放在启动路径上会让服务启动慢 5 秒，放在每次 save 上会让
 * 保存一封邮件的标记都卡 5 秒。所以：
 *   · 只在"文件刚创建/刚换密钥"时调用，不在读取路径上调用；
 *   · 用 spawn 而不是 execFileSync，不阻塞事件循环；
 *   · 同一路径正在收紧时不再重复发起。
 * 收紧是防御纵深而非功能依赖，晚几秒到位没有影响。
 *
 * 顺序不能反：先 /grant:r 当前用户（失败就直接退出），再 /inheritance:r。
 * 反过来的话，一旦第 1 步失败、第 2 步生效，文件就只剩 Owner 的
 * READ_CONTROL/WRITE_DAC，下次启动读不到密钥会重新生成 —— 那等于让所有
 * 已加密的 accounts.enc 当场变成砖。
 *
 * 失败一律吞掉：宁可不收紧，也不能因为收紧失败让服务起不来。
 */
const _aclInFlight = new Set();

function tightenAcl(file) {
  if (process.platform !== 'win32') {
    try { fs.chmodSync(file, 0o600); } catch { /* 非 Windows 上 chmod 就是陆的语义 */ }
    return;
  }
  // 已经排过队就别再排一次：每次进程启动都会走"确认密钥存在"这条路，
  // 一个 v2 库在 5 秒内被读 10 次是很正常的。
  if (_aclInFlight.has(file)) return;
  _aclInFlight.add(file);

  let user;
  try { user = os.userInfo().username; } catch { user = ''; }
  if (!user) { _aclInFlight.delete(file); return; }

  const { spawn } = require('child_process');
  const run = (args, done) => {
    const p = spawn('icacls', args, { stdio: 'ignore', windowsHide: true });
    const to = setTimeout(() => { try { p.kill(); } catch { /* 忽略 */ } }, 5000);
    p.on('error', () => { clearTimeout(to); done(false); });
    p.on('exit', code => { clearTimeout(to); done(code === 0); });
  };

  run([file, '/grant:r', user + ':F'], ok => {
    if (!ok) { _aclInFlight.delete(file); return; }
    run([file, '/inheritance:r'], () => { _aclInFlight.delete(file); });
  });
}

/**
 * 落盘格式版本（H2）。
 *
 * v1：blob = base64(iv | tag | 密文)，**没有 AAD**。后果有两个：
 *   1. 密文可以在账户之间搬运——把 A 的 blob 贴到 B 的位置，AES-GCM 照样认证通过，
 *      于是 B 的邮箱会静默变成 A 的凭据（读错账号、发错信都查不出原因）；
 *   2. 没有任何东西把密文和它所在的条目绑定起来，配合明文元数据（email/note 等）
 *      被改，攻击者可以让界面显示 B 的邮箱、实际用 A 的令牌。
 * v2：加密时 setAAD('maildesk/2|' + accountId)，AAD 参与 GCM 的认证标签计算，
 *      密文一旦离开原来的 accountId 就必然认证失败。
 *
 * 兼容策略：**不强制迁移**。读取时以文件里的 version 为准，v1 文件继续可读；
 * 每次 save() 都写 v2，于是老库在下一次正常写入时自然升级。
 * 之所以不在启动时自动全量迁移：用户可能在多台机器/多个备份里各有一份副本，
 * 强制迁移意味着那些副本被旧版本程序打开时直接变成砖（旧程序不认 v2）。
 */
const FORMAT_VERSION = 2;

/** v2 的 AAD 前缀。改它会让所有 v2 库解不开，等同于换密钥，绝不要动。 */
const AAD_PREFIX = 'maildesk/2|';

/** v2 下每条密文绑定的 AAD。accountId 必须是落盘条目自己的 id。 */
function accountAad(id) {
  // 归一化 null/undefined：加密与解密两侧都走这个函数，所以只要两边对同一个条目
  // 得到同一个值即可。账户 id 由 server.js 生成（UUID），正常不会为空；
  // 真为空时退化成空串，语义上等于"这条不绑定任何 id"。
  const s = id == null ? '' : String(id);
  // 超长 id 先摘要：accounts.enc 是可被外部改动的文件，若某条 id 被改成几十 MB，
  // 直接拿它当 AAD 会为 Tag 校验准备一个同样大的 Buffer。摘要后长度恒定，
  // 且仍是 id 的确定性函数 —— 加密/解密两侧算出的值不变，绑定关系不变。
  // 阈值取 512 字符：真实 id 是 36 字符 UUID，任何合法用法都碰不到。
  if (s.length > 512) return AAD_PREFIX + 'sha256:' + crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  return AAD_PREFIX + s;
}

/**
 * 判定一条落盘条目"声明"用的是哪一版格式，返回 1 或 2。
 *
 * 优先看条目自己的 `v`：save() 会给每条写 `v`，这样同一份文件里可以**混装**
 * v1 与 v2 密文 —— 这是隔离区（lastCorrupted）必须的场景：
 * 一条 v1 时代就解不开的坏条目会被原样写回，如果只剩文件级 version，
 * 下次它就会被当成 v2 去解，AAD 对不上，永远解不开也永远搬不出去。
 * 只有完全没有 `v` 的老文件才退回看文件级 version。
 */
function entryVersion(a, fileVersion) {
  const v = Number(a && a.v);
  if (v === 1 || v === 2) return v;
  // 条目没有自己的标记：文件声明 v2 说明这份文件是新代码写的，条目必然也是 v2；
  // 否则（缺失 / 1 / 其它）按 v1 —— v1 是**最宽松**的那一版，
  // 拿它去解 v2 密文只会认证失败，不会解出错的数据，所以这个兜底是安全的。
  // 反过来（默认按 v2 去解 v1 密文）会让整份没有条目级标记的老库全部打不开。
  return Number(fileVersion) === 2 ? 2 : 1;
}

class Vault {
  /**
   * @param {string} dataDir 密文目录（accounts.enc / history.enc）
   * @param {string} [keyDir] 密钥目录；缺省等于 dataDir（向后兼容）
   */
  constructor(dataDir, keyDir) {
    this.dataDir = dataDir;
    this.keyDir = keyDir || dataDir;
    /** 当前生效的密钥路径（供 server 横幅与 tools/check-key.js 使用） */
    this.keyPath = path.join(this.keyDir, 'vault.key');
    /** 旧位置：密钥以前和数据同目录 */
    this.legacyKeyPath = path.join(dataDir, 'vault.key');
    this.storePath = path.join(dataDir, 'accounts.enc');
    this.key = this._loadOrCreateKey();
    this.lastCorrupted = [];   // 上次 all() 时解不开的条目（含 raw，save 时原样写回）

    // 对**升级前就已存在**的文件补一次 ACL 收紧。
    //
    // 只在"创建时收紧"是不够的：本机实测 data/accounts.enc 的 ACL 是
    //   Authenticated Users:(I)(M)  ← 本机任何已认证用户可写
    // 这个文件早就在了，创建时的收紧永远不会被执行到它。而它里面是 100 个
    // refresh_token 的密文，旁边就是 vault.key —— 第二个 Windows 账户能同时
    // 读到这两样，等于完全绕过 H1 那道 handshake 门。
    //
    // 异步（tightenAcl 内部 spawn，不阻塞事件循环），且带 in-flight 去重，
    // 所以每次启动调一次的成本只是后台一个短命进程。
    tightenAcl(this.keyPath);
    tightenAcl(this.storePath);
  }

  /**
   * 五分支启动表（顺序不可调换）：
   *
   *   primary         legacy          动作
   *   ------------------------------------------------------------------
   *   有              无              直接用
   *   有              有，内容相同    用 primary；legacy 改名备份后删除
   *   有              有，内容不同    抛异常拒绝启动（绝不静默选择）
   *   无              有              复制到 primary→逐字节校验→删 legacy
   *   无              无              生成新密钥（首装）
   *
   * 不变量：迁移绝不重写 accounts.enc。密钥换、密文不换。
   * 任何一步断电，只会留下"两份相同的 key"或"还没搬完"，下次启动幂等重来。
   */
  _loadOrCreateKey() {
    fs.mkdirSync(this.dataDir, { recursive: true });
    fs.mkdirSync(this.keyDir, { recursive: true });

    const primary = this.keyPath;
    const legacy = this.legacyKeyPath;
    // keyDir 缺省等于 dataDir 时两个路径是同一个文件，不能自己和自己比对
    const sameFile = path.resolve(primary) === path.resolve(legacy);

    const hasPrimary = fs.existsSync(primary);
    const hasLegacy = !sameFile && fs.existsSync(legacy);

    // 分支 1：只有新位置的密钥 —— 直接用
    if (hasPrimary && !hasLegacy) {
      return this._readKey(primary);
    }

    // 分支 2 / 3：两处都有
    if (hasPrimary && hasLegacy) {
      const primaryKey = fs.readFileSync(primary);
      const legacyKey = fs.readFileSync(legacy);

      if (this._sameKey(primaryKey, legacyKey)) {
        // 分支 2：内容相同。迁移已完成或被中断在"删旧文件"这一步，删掉旧的即可。
        this._retireLegacyKey(legacy);
        return this._readKey(primary, primaryKey);
      }

      // 分支 3：内容不同 —— 硬失败。
      // 静默选任意一个，都会让另一批数据永久不可读（AES-GCM 没有试错余地）。
      const err = new Error(
        '检测到两份内容不同的 vault.key，拒绝启动。\n'
        + '  新位置：' + path.resolve(primary) + '\n'
        + '  旧位置：' + path.resolve(legacy) + '\n'
        + '这两个密钥各自加密了一部分数据，程序无法判断哪一份才是你想要的，\n'
        + '随便选一个都会让另一批账户永久无法解密。请先运行：\n'
        + '  node tools/check-key.js\n'
        + '看哪一份能解开 accounts.enc，然后手工保留正确的那份（另一份改名收好，别删）。'
      );
      err.code = 'VAULT_KEY_MISMATCH';
      err.primaryKeyPath = path.resolve(primary);
      err.legacyKeyPath = path.resolve(legacy);
      throw err;
    }

    // 分支 4：只有旧位置的密钥 —— 搬到新位置
    if (hasLegacy) {
      const legacyKey = fs.readFileSync(legacy);
      this._installKey(primary, legacyKey);

      // 逐字节读回校验，确认新位置真的可读且内容一致后才删旧文件
      const written = fs.readFileSync(primary);
      if (!this._sameKey(written, legacyKey)) {
        // 写坏了：删掉半成品，旧文件保持原样，下次启动幂等重来
        try { fs.rmSync(primary, { force: true }); } catch { /* 忽略 */ }
        throw new Error('密钥迁移校验失败：' + path.resolve(primary) + ' 读回内容与旧密钥不一致，已回滚，旧密钥未改动');
      }
      this._retireLegacyKey(legacy);
      return this._readKey(primary, written);
    }

    // 分支 5：两处都没有 —— 首装，生成新密钥
    const key = crypto.randomBytes(KEY_LEN);
    this._installKey(primary, key);
    return this._readKey(primary, key);
  }

  /**
   * 读密钥。
   *
   * 读取路径**不阻塞**在 ACL 收紧上（icacls 是进程创建，同步调用会拖慢启动），
   * 但也不能完全不收紧：升级前就已经存在的 vault.key 从未被收紧过，光靠
   * "只在创建时收紧"会把老文件永远留在继承 ACL 上。所以这里做一次
   * "后台补收"：tightenAcl 内部有 in-flight 去重，重复调用不产生额外进程。
   */
  _readKey(file, known) {
    const key = known || fs.readFileSync(file);
    tightenAcl(file);
    if (key.length !== KEY_LEN) {
      const e = new Error('密钥文件长度不是 ' + KEY_LEN + ' 字节（实际 ' + key.length + '）：' + path.resolve(file));
      e.code = 'VAULT_KEY_INVALID';
      throw e;
    }
    return key;
  }

  /** 原子写入密钥：tmp + fsync + rename，避免断电留下半个文件 */
  _installKey(file, key) {
    const tmp = file + '.tmp-' + process.pid + '-' + Date.now();
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      // writeFileSync 而不是 writeSync：write() 允许部分写入，
      // 32 字节虽然几乎不可能被截断，但密钥少一个字节就等于所有账号报废。
      fs.writeFileSync(fd, key);
      fs.fsyncSync(fd);
    } finally {
      try { fs.closeSync(fd); } catch { /* 忽略 */ }
    }
    try {
      fs.renameSync(tmp, file);
    } catch (e) {
      try { fs.rmSync(tmp, { force: true }); } catch { /* 忽略 */ }
      throw e;
    }
    tightenAcl(file);
  }

  /**
   * 退掉旧位置的密钥：先改名成明显的备份名，再从数据目录删除。
   * 改名与删除之间断电时，数据目录里留下的只是一个 .migrated-* 的旧副本，
   * 而新位置已有同一把密钥，下次启动走"分支 1"照常启动。
   */
  _retireLegacyKey(legacy) {
    const backup = legacy + '.migrated-' + new Date().toISOString().replace(/[:.]/g, '-');
    try {
      fs.renameSync(legacy, backup);
    } catch {
      // 改名失败（文件被占用等）：直接删；删不掉也不阻断启动，
      // 因为新位置的密钥已经验证可用，旧文件只是一份留底。
      try { fs.rmSync(legacy, { force: true }); } catch { /* 忽略 */ }
      return;
    }
    try { fs.rmSync(backup, { force: true }); } catch { /* 忽略 */ }
  }

  _sameKey(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  /**
   * 加密。
   * @param {string} plaintext
   * @param {string} [aad] 附加认证数据。传了就参与 GCM 认证标签计算：
   *        解密时必须提供完全相同的值，否则认证失败（不是"解出乱码"，是直接抛错）。
   *        不传 = v1 行为，只给 encryptText（history.enc 那种整份文件加密）用。
   */
  _encrypt(plaintext, aad) {
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, this.key, iv);
    if (aad !== undefined) cipher.setAAD(Buffer.from(aad, 'utf8'));
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString('base64');
  }

  _decrypt(b64, aad) {
    const buf = Buffer.from(b64, 'base64');
    const iv = buf.subarray(0, IV_LEN);
    const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const enc = buf.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGO, this.key, iv);
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  }

  /**
   * 用账户库同一把密钥加密任意文本，返回 base64。
   * 给其他需要落盘的模块（如验证码历史）复用，避免把加密逻辑复制一份。
   */
  encryptText(plaintext) {
    return this._encrypt(String(plaintext));
  }

  /** 解密 encryptText 的输出 */
  decryptText(b64) {
    return this._decrypt(String(b64));
  }

  /**
   * 读取全部账户（解密后）。
   *
   * 单条 blob 解密失败**不能**让整个库读不出来。
   * 早先整个 map 包在一个 try 里，任意一条抛异常就全库失败，后果链是：
   *   一条 blob 损坏（位翻转 / 磁盘坏块 / 断电）
   *   → all() 抛错
   *   → updateRefreshToken 失败 → REFRESH_TOKEN_PERSIST_FAILED
   *   → 微软侧旧 refresh_token 已作废、新值只在内存
   *   → **一个本来完好的账号被连带毁掉**
   *
   * 现在改成逐条兜底：坏的那条不返回，但原始 blob 保留在文件里（不删），
   * 其余账户照常可用。损坏的 id 记在 this.lastCorrupted 里供上层提示。
   *
   * H2：解密时按条目自己声明的版本先试，v2 条目必须用
   * 'maildesk/2|' + 本条目 id 做 AAD —— 密文被搬到别的 id 下就会认证失败，
   * 于是该条进隔离区而不是冒充成另一个账户。
   */
  all() {
    if (!fs.existsSync(this.storePath)) return [];
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(this.storePath, 'utf8'));
    } catch (e) {
      // 连 JSON 都解析不了 = 整份文件坏了，这个确实救不了。
      // code 给 server.js 用来分类：数据库层的错误一律回固定文案，
      // 原始 message 只进本地日志 —— 它带着 accounts.enc 的绝对路径，
      // 不该出现在 HTTP 响应里（见 server.js 内层 catch 的分流）。
      const err = new Error('账户库读取失败（文件结构损坏）：' + e.message);
      err.code = 'VAULT_READ_FAILED';
      err.cause = e;
      throw err;
    }
    if (!raw || !Array.isArray(raw.accounts)) return [];

    const fileVersion = Number(raw.version) || 1;
    const out = [];
    const corrupted = [];
    for (const a of raw.accounts) {
      if (!a || typeof a !== 'object') continue;
      let secrets = {};
      if (a.blob) {
        // 按声明版本先试，失败再试另一版。
        //
        // 为什么"两版都试"而不只信声明：声明只有一个来源（文件顶层 version 或条目 v），
        // 而它和密文其实是两份独立的字节 —— 文件被手工编辑过、或某个工具改写 version
        // 之后，单凭声明就会把 100 个完好账户判成"全部损坏"，而 save() 又会把它们
        // 原样写回，用户看到的就是"账号全没了"。
        // 两版都试不会削弱任何安全性：v2 密文的认证标签是在 AAD 参与下算出来的，
        // 用无 AAD 的方式解必然失败；反过来 v1 密文用 v2（带 AAD）解也必然失败。
        // 也就是说，两种试法都成功不了的时候，才真的是损坏。
        // 顺带：把 A 的 v2 密文搬到 B 的位置，两种试法都不会成功 —— 移植攻击依旧被挡。
        const preferred = entryVersion(a, fileVersion);
        const order = preferred >= 2 ? [2, 1] : [1, 2];
        let lastErr = null;
        let ok = false;
        for (const ver of order) {
          try {
            const plain = ver >= 2
              ? this._decrypt(a.blob, accountAad(a.id))
              : this._decrypt(a.blob);
            secrets = JSON.parse(plain);
            ok = true;
            break;
          } catch (e) {
            lastErr = e;
          }
        }
        if (!ok) {
          // 这一条解不开：跳过它，但**不删它的原始数据**——
          // 把 raw 原对象存下来，save() 时原样写回文件。
          // 删掉 = 用户永久失去这条凭据（可能是密钥轮换前的唯一副本）。
          corrupted.push({ id: a.id, email: a.email || '', reason: lastErr ? lastErr.message : '解密失败', raw: a });
          continue;
        }
      }
      out.push({ ...a, secrets, blob: undefined });
    }
    this.lastCorrupted = corrupted;   // 供 server 在响应里附带提示
    return out;
  }

  /** 上次 all() 时解不开的条目（只读，供上层展示） */
  corruptedEntries() {
    return this.lastCorrupted || [];
  }

  save(accounts) {
    // rename 之前先记下这张文件是不是本来就有 —— 下面决定要不要收紧 ACL 用。
    const existedBefore = fs.existsSync(this.storePath);
    // 保留 all() 时解不开的条目：它们不在 accounts 里（被跳过了），
    // 如果直接重写就会**永久删除用户的原始数据**。原样带回去。
    // H2 注意：隔离条目原样回写，**连同它自己的 v/version 标记**一起。
    // 绝不能在这里给它补 v:2 —— 它的密文还是 v1 形态（甚至是损坏的），
    // 打上 v2 会让下次读取用 AAD 去解，本来的 v1 条目从此永久解不开。
    const quarantined = (this.lastCorrupted || []).map(c => c.raw).filter(Boolean);

    const out = {
      // 新写的库一律 v2：下次读取按条目 v 分支，老副本（v1）仍按老路解。
      version: FORMAT_VERSION,
      updatedAt: new Date().toISOString(),
      accounts: accounts.map(a => {
        // 只摘掉 secrets / blob 两个**本模块自己**用来传值的字段。
        // 刻意不摘 version / v：它们不是本模块从对象上"消费"的键，
        // 万一别处存了同名字段，悄悄丢掉就等于丢用户数据。
        // （save 末尾总会重新写本模块的版本标记，所以不会残留旧值。）
        const { secrets, blob, ...meta } = a;
        const body = {
          ...meta,
          // 每条自带版本号，支持 v1/v2 混装（见 entryVersion 的注释）。
          // 写在 ...meta 之后，保证条目上原有的同名 v 一定被覆盖成本模块的值。
          // 没有 secrets 的条目也标 v2：它没有密文可认证，标什么都不影响，
          // 标上只是让"这个库已经整体写成 v2"这件事在条目层面也成立。
          v: FORMAT_VERSION,
        };
        if (secrets && Object.keys(secrets).length) {
          // 新密文一律带 AAD，绑定本条目的 id
          body.blob = this._encrypt(JSON.stringify(secrets), accountAad(a.id));
        }
        return body;
      }).concat(quarantined),
    };
    // tmp 名必须每进程唯一。
    //
    // 原来写死成 accounts.enc.tmp：双击两次 start.bat 时，第二个实例因 EADDRINUSE
    // 顺延到 2132 照样启动，两个进程于是共用同一个 tmp 文件。实测两种后果：
    //   1. 数据丢失：A 写 51 条、B 写 1 条 → 最终只剩 1 条，A 的 51 条全丢；
    //   2. 整库不可读：A 的 fsync 与 B 的 write 交错，主文件被污染成非 JSON，
    //      下次 all() 直接抛"文件结构损坏"，100 个账号一起打不开。
    // pid + 时间戳（与 _installKey 的做法一致）让并发写入各用各的 tmp，
    // rename 是原子的，最后落盘的那份是完整的 JSON —— 语义退化成"后写者赢"，
    // 而不是"互相撕碎"。
    // 时间戳还保证同一进程内多次 save 不会撞名（虽然本模块是同步的，不会并发）。
    const tmp = this.storePath + '.tmp-' + process.pid + '-' + Date.now();
    // fsync：tmp + rename 只保证"读者看不到半个文件"，不保证断电后内容真的落盘。
    // 没有 fsync 时，rename 可能先于数据落盘生效，断电后 accounts.enc 是 0 字节
    // 或旧块——对一个存 100 个 refresh_token 的库来说就是全部丢失。
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      // writeFileSync 而非 writeSync：writeSync 返回实际写入字节数，
      // POSIX 允许它小于请求长度。accounts.enc 里是 100 个 refresh_token，
      // 少写一个字节就是整库解不开——这个风险不值得留。
      fs.writeFileSync(fd, JSON.stringify(out, null, 2), 'utf8');
      fs.fsyncSync(fd);
    } catch (e) {
      // 写/fsync 失败：关掉并删掉半成品，绝不能让它留在数据目录里。
      // 尤其是原来 tmp 名固定的时候，残骸会被下一次 save 的 open('w') 截断，
      // 也可能被误当成"待恢复的数据"。
      try { fs.closeSync(fd); } catch { /* 忽略 */ }
      try { fs.rmSync(tmp, { force: true }); } catch { /* 忽略 */ }
      throw e;
    }
    try {
      fs.closeSync(fd);
    } catch { /* 已关闭或关闭失败都不影响 rename */ }
    try {
      fs.renameSync(tmp, this.storePath);
    } catch (e) {
      // 主文件保持不变，删掉本次的 tmp 再抛。
      // 以前这里没有 try/catch，rename 失败（杀毒软件锁文件、权限、跨盘）时
      // tmp 会永久留在数据目录里，每失败一次就多一个残骸。
      try { fs.rmSync(tmp, { force: true }); } catch { /* 忽略 */ }
      throw e;
    }
    // 隔离条目已经写回文件了，清空列表避免下次 save 重复追加
    this.lastCorrupted = [];
    // accounts.enc 里是全部 100 个账号的 refresh_token 密文，和 vault.key 一样
    // 属于"第二个 Windows 账户不该读到"的东西（H1 的完整闭环）。
    // 只在文件**刚刚被创建**时收紧：icacls 是进程创建（实测每次 2-3 秒），
    // 挂在每次 save 上会让"标记一封邮件已读"这种操作卡好几秒。
    // 文件一旦建好就带上了这个 ACL，rename 覆盖不会丢它（rename 换的是目录项，
    // 不是文件对象本身；新 tmp 文件会继承目录 ACL，但那份继承里本机只有
    // SYSTEM/Administrators/当前用户，风险面与收紧后等价）。
    if (!existedBefore) tightenAcl(this.storePath);
    try {
      // 目录 fsync：POSIX 上 rename 的持久性依赖父目录落盘。
      // Windows 上 open 目录会失败，所以 try/catch。
      const dfd = fs.openSync(this.dataDir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* Windows 不支持，忽略 */ }
  }

  find(id) {
    return this.all().find(a => a.id === id);
  }

  /** 新增或更新 */
  upsert(account) {
    const list = this.all();
    const i = list.findIndex(a => a.id === account.id);
    if (i >= 0) list[i] = { ...list[i], ...account };
    else list.push(account);
    this.save(list);
    return account;
  }

  /**
   * 批量新增/更新：只读一次、只写一次。
   * 逐条 upsert 是 O(N²) 磁盘写入（每次 all() 全量解密、每次 save() 全量加密+落盘），
   * 100 条在 Windows 上能跑几十秒。
   */
  upsertMany(accounts) {
    if (!Array.isArray(accounts) || !accounts.length) return 0;
    const list = this.all();
    const byId = new Map(list.map((a, i) => [a.id, i]));
    for (const acc of accounts) {
      const i = byId.get(acc.id);
      if (i !== undefined) list[i] = { ...list[i], ...acc };
      else { byId.set(acc.id, list.length); list.push(acc); }
    }
    this.save(list);
    return accounts.length;
  }

  /**
   * 在锁内做一次读-改-写，避免 await 期间被并发操作覆盖。
   * fn 接收账户数组，可直接修改，返回值原样返回。
   */
  transaction(fn) {
    const list = this.all();
    const before = JSON.stringify(list.map(a => a.id).sort());
    const result = fn(list);
    const after = JSON.stringify(list.map(a => a.id).sort());
    if (before !== after || result !== false) this.save(list);
    return result;
  }

  /**
   * 写回轮换后的 refresh_token（微软每次刷新都会换新值，旧值当场失效）。
   *
   * 只动 secrets.refreshToken 这一个字段，其余一律保留。
   * 不能走 upsert(account)：那是浅合并，调用方手里的 secrets 是刷新前读的快照，
   * 会把 clientId / password / migrated4 / refreshTokenRotated 等一起覆盖掉。
   *
   * 写之前先重新读盘校验：
   *  - 库里已经是新值 → 幂等成功，不重复落盘
   *  - 库里既不是新值也不是我们换掉的那个旧值 → 说明期间有别的写入者更新过，
   *    这时覆盖会把更新的值打回去，所以跳过并如实返回
   *
   * @returns {{applied:boolean, skipped:boolean, reason:string}}
   */
  updateRefreshToken(id, newRefreshToken, previousRefreshToken) {
    if (!id || !newRefreshToken) throw new Error('updateRefreshToken 参数不完整');
    let outcome = { applied: false, skipped: true, reason: 'no-change', currentToken: '' };

    this.transaction(list => {
      const acc = list.find(a => a.id === id);
      if (!acc) {
        // 账户在刷新期间被删除：不要复活它
        outcome = { applied: false, skipped: true, reason: 'account-not-found', currentToken: '' };
        return false;
      }
      const s = acc.secrets || (acc.secrets = {});
      if (s.refreshToken === newRefreshToken) {
        outcome = { applied: true, skipped: false, reason: 'already-current', currentToken: s.refreshToken };
        return false;
      }
      if (previousRefreshToken && s.refreshToken && s.refreshToken !== previousRefreshToken) {
        // 库里的值不是我们换掉的那个，说明期间有别的写入者更新过。
        // 覆盖会把更新的值打回去，所以跳过；把库里的现值交还调用方，让它改用新值。
        outcome = {
          applied: false, skipped: true, reason: 'vault-has-different-token',
          currentToken: s.refreshToken || '',
        };
        return false;
      }
      s.refreshToken = newRefreshToken;
      // 标记位：表明这个令牌是刷新轮换得来的，排查时用
      s.refreshTokenRotated = true;
      outcome = { applied: true, skipped: false, reason: '', currentToken: newRefreshToken };
      return true;
    });

    return outcome;
  }

  /**
   * 只更新顶层元数据（status / statusMessage / lastCheckedAt 等），绝不碰 secrets。
   *
   * 不能对这些场景用 upsert(account)：调用方手里是刷新前读到的快照，
   * upsert 是浅合并，会把整份 secrets 换成旧副本，刚写回的轮换令牌就被打回去了。
   */
  updateMeta(id, fields) {
    if (!id || !fields) return false;
    let applied = false;
    this.transaction(list => {
      const acc = list.find(a => a.id === id);
      if (!acc) return false;
      for (const [k, v] of Object.entries(fields)) {
        if (k === 'secrets' || k === 'blob' || k === 'id') continue; // 这三项禁止经此路径写入
        acc[k] = v;
      }
      applied = true;
      return true;
    });
    return applied;
  }

  /**
   * 批量版 updateMeta：一次读、一次写。
   * pairs 形如 [{id, fields}]。逐条 updateMeta 是 O(N²) 磁盘写入。
   * 同样绝不碰 secrets。
   */
  updateMetaMany(pairs) {
    if (!Array.isArray(pairs) || !pairs.length) return 0;
    const byId = new Map();
    for (const p of pairs) if (p && p.id && p.fields) byId.set(p.id, p.fields);
    if (!byId.size) return 0;

    let applied = 0;
    this.transaction(list => {
      for (const acc of list) {
        const fields = byId.get(acc.id);
        if (!fields) continue;
        for (const [k, v] of Object.entries(fields)) {
          if (k === 'secrets' || k === 'blob' || k === 'id') continue;
          acc[k] = v;
        }
        applied++;
      }
      return applied > 0;
    });
    return applied;
  }

  /**
   * 只合并指定的几个 secret 字段，其余 secrets（以及全部元数据）原样保留。
   *
   * 为什么需要它：account.update 里 acc 是 find() 读到的**完整快照**，
   * 改完字段再 upsert(acc) 是浅合并 —— 整份 secrets 会被快照覆盖回去。
   * 快照读到写回之间只要发生过一次 refresh_token 轮换（微软每次刷新都换新值，
   * 旧值当场失效），用户改一个标签就会让账号报废。
   * 这与 account.check 早就改掉的写法是同一个坑（见那里"只写元数据"的注释）。
   *
   * 语义刻意与 updateMeta 对称：
   *  - 只写 patch 里显式给出的键；
   *  - 值为 undefined 的键跳过（调用方用 undefined 表示"不改这个字段"）；
   *  - 账户不存在返回 false，不复活已删除的账户。
   *
   * @param {string} id
   * @param {Object<string,*>} patch 例如 { clientId, refreshToken }
   * @returns {boolean} 是否真的写了盘
   */
  updateSecrets(id, patch) {
    if (!id || !patch || typeof patch !== 'object') return false;
    // 先摘出有效字段：全是不合法的键时不要白跑一次全库解密 + 全量加密落盘
    const fields = Object.entries(patch).filter(([k, v]) =>
      k && k !== 'blob' && k !== 'id' && v !== undefined);
    if (!fields.length) return false;

    let applied = false;
    this.transaction(list => {
      const acc = list.find(a => a.id === id);
      if (!acc) return false;
      const s = acc.secrets && typeof acc.secrets === 'object' ? acc.secrets : (acc.secrets = {});
      for (const [k, v] of fields) {
        // 这几个键在这里没有意义：blob 是本模块落盘用的密文字段，
        // id 属于顶层元数据，写进 secrets 只会变成永远读不回来的垃圾。
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        s[k] = v;
      }
      applied = true;
      return true;
    });
    return applied;
  }

  remove(id) {
    const list = this.all().filter(a => a.id !== id);
    this.save(list);
  }

  removeMany(ids) {
    const set = new Set(ids);
    const list = this.all().filter(a => !set.has(a.id));
    this.save(list);
  }
}

module.exports = { Vault };
