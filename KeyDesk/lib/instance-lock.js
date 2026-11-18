'use strict';
/**
 * 单实例锁
 *
 * 为什么需要：双击两次 start.bat 时，第二个进程会因 EADDRINUSE 顺延到 2152
 * 照样启动。两个实例共用同一个 DATA_DIR：
 *   · 各自在内存里持有一份 vault 快照，保存时后写者覆盖前写者，条目丢失；
 *   · 写盘用的 tmp 文件（即使已经改成 pid 唯一）仍然只能保证"文件不被撕碎"，
 *     保证不了"两份内存状态不会互相覆盖"。
 * 所以在改端口、listen 之前先抢锁：拿不到就直接拒绝启动，而不是换个端口
 * 与第一个实例自杀式共存。
 *
 * 锁文件里放 pid + 启动时间 + 随机 token，用来回答两个问题：
 *   1. 持有者还活着吗？—— 判死才敢接手，否则可能真有实例在跑；
 *   2. 退出时删的是不是**自己那把**？—— token 不一致就不删，
 *      避免把下一任实例的锁误删。
 *
 * 判断方向刻意不对称：只有能确定"持有者已消失"时才接管；判断不了
 * （权限异常、系统调用返回意料之外的错误）按陈旧处理并打印警告，
 * 因为让用户被一个崩溃残留的锁永久挡在门外，比多开一次更糟。
 * 但"活着"（包括 pid 被别的进程复用）一律拒绝启动——放错方向的代价
 * 是数据损坏，而数据损坏不可逆。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 本进程此刻持有的锁。同一进程只允许持一把：KeyDesk 只有一个数据目录，
// 允许持多把只会让 release 的语义变得含混。
let own = null;
let released = false;
let exitHookInstalled = false;

/** 锁文件内容；不存在 / 不是 JSON / 不是对象都返回 null（按无锁处理） */
function readLock(lockPath) {
  try {
    const o = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    return (o && typeof o === 'object' && !Array.isArray(o)) ? o : null;
  } catch {
    return null;
  }
}

/**
 * pid 是否还活着：'alive' | 'dead' | 'unknown'。
 *
 * process.kill(pid, 0) 不发信号，只做存在性检查：
 *   ESRCH        → 进程不存在，可以确定是死锁
 *   EPERM        → 进程存在但不属于当前用户，仍然是活的
 *   其它错误     → 判断不了，交给调用方决定（这里不替它猜）
 * pid 等于当前进程时直接算活着：本进程当然存在。
 */
function pidState(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return 'dead';
  if (pid === process.pid) return 'alive';
  try {
    process.kill(pid, 0);
    return 'alive';
  } catch (e) {
    if (e && e.code === 'ESRCH') return 'dead';
    if (e && e.code === 'EPERM') return 'alive';
    return 'unknown';
  }
}

function instanceRunning(lockPath, info, extra) {
  const who = info && Number.isInteger(info.pid)
    ? 'pid ' + info.pid + '，启动于 ' + (info.startedAt || '未知时间')
    : '另一个进程';
  const e = new Error(
    '已经有一个 KeyDesk 在运行，请先用完那个再开新的。\n'
    + '（' + extra + '：' + who + '）\n'
    + '两个实例写同一份 vault.enc 会互相覆盖，可能丢条目甚至弄坏整库，所以这里拒绝启动。\n'
    + '如果确认那个进程已经不在了，删除锁文件后重试：\n  ' + lockPath
  );
  e.code = 'INSTANCE_RUNNING';
  e.lock = info || null;
  return e;
}

function installExitHook() {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // 'exit' 是最后一道：server.js 的 shutdown / uncaughtException 会显式
  // release 一次（更早，用户不必等 pid 回收），这里是兜底。
  process.on('exit', () => { try { release(); } catch { /* 忽略 */ } });
}

/**
 * 抢锁。成功返回 { ok:true, lockPath, adoptedStale }，
 * 已有活实例则抛 code === 'INSTANCE_RUNNING'。
 *
 * 用 'wx'（不存在才创建）而不是 existsSync + 写：两个进程同时启动时，
 * existsSync 那条路会让双方都以为"没有锁"，然后各写各的，锁当场失效。
 * 'wx' 的创建是原子操作，只有一个进程能成功。
 */
function acquire(lockPath) {
  if (!lockPath || typeof lockPath !== 'string') {
    throw new Error('instance-lock.acquire 需要一个锁文件路径');
  }
  if (own) {
    // 同进程重复抢锁：这正是"双击两次"在同一进程里的等价形态，
    // 必须失败，否则测试和真实场景的语义会分叉。
    throw instanceRunning(lockPath, own, '本进程已经持有实例锁');
  }

  const info = {
    pid: process.pid,
    startedAt: new Date().toISOString(),
    token: crypto.randomBytes(8).toString('hex'),
  };
  let adoptedStale = false;

  // 最多三轮：每一轮要么创建成功，要么删掉陈旧锁重来。
  // 三轮都失败说明有人在反复创建/删除，此时拒绝启动比无锁运行安全。
  for (let attempt = 0; attempt < 3; attempt++) {
    let fd = -1;
    let created = false;
    try {
      fs.mkdirSync(path.dirname(lockPath), { recursive: true });
      fd = fs.openSync(lockPath, 'wx', 0o600);
      created = true;
      try {
        fs.writeFileSync(fd, JSON.stringify(info, null, 2), 'utf8');
        // 锁本身落盘：不 fsync 的话，进程在写锁后立刻崩溃时可能留下
        // 0 字节锁文件。它虽然会被当成陈旧锁接管，但每次都要多一次告警。
        fs.fsyncSync(fd);
      } finally {
        try { fs.closeSync(fd); } catch { /* 忽略 */ }
      }
      own = { ...info, lockPath };
      released = false;
      installExitHook();
      return { ok: true, lockPath, adoptedStale };
    } catch (e) {
      if (fd >= 0) { try { fs.closeSync(fd); } catch { /* 忽略 */ } }

      // 文件已经建出来了但内容没写完（磁盘满 / I/O 错误）：删掉它。
      // 不删的话，本次启动明明失败了，却给下一次启动留了一个 0 字节锁，
      // 下次会把用户挡在门外直到有人手工处理——比不建这个文件还糟。
      if (created) {
        try { fs.rmSync(lockPath, { force: true }); } catch { /* 忽略 */ }
        throw e;
      }

      // EEXIST 之外都不是"有实例在跑"：目录不可写、只读盘之类。
      // 这种情况原样抛出，让启动流程把真实原因（而不是"已有实例"）告诉用户。
      if (!e || e.code !== 'EEXIST') throw e;

      const cur = readLock(lockPath);

      // 锁文件内容损坏（崩溃时只写了半截）：不可能是有效锁，按陈旧处理。
      if (!cur) {
        try { console.warn('[lock] 锁文件内容不可读，按陈旧锁覆盖：' + lockPath); } catch { /* 忽略 */ }
        adoptedStale = true;
        try { fs.rmSync(lockPath, { force: true }); } catch { /* 忽略 */ }
        continue;
      }

      const state = pidState(cur.pid);
      if (state === 'alive') {
        throw instanceRunning(lockPath, cur, '检测到正在运行的实例');
      }

      if (state === 'unknown') {
        // 判断不了 pid 的状态。按规格：按陈旧处理并覆盖，但必须留下警告——
        // 如果真的还活着，用户至少能在终端里看到"我们为什么敢接管"。
        try {
          console.warn('[lock] 无法判断锁持有者 pid ' + cur.pid
            + ' 是否仍在运行，按陈旧锁接管：' + lockPath);
        } catch { /* 忽略 */ }
      } else {
        try { console.warn('[lock] 发现陈旧锁（pid ' + cur.pid + ' 已不存在），已接管'); } catch { /* 忽略 */ }
      }
      adoptedStale = true;
      try { fs.rmSync(lockPath, { force: true }); } catch { /* 忽略 */ }
    }
  }

  const e = new Error(
    '已经有一个 KeyDesk 在运行，请先用完那个再开新的。\n'
    + '（反复争用实例锁失败：' + lockPath + '）'
  );
  e.code = 'INSTANCE_RUNNING';
  throw e;
}

/**
 * 释放锁：只删自己那把（pid + token 都对得上才删）。
 * 返回是否真的删了；重复调用安全。
 */
function release() {
  if (!own || released) return false;
  released = true;
  const mine = own;
  own = null;
  try {
    const cur = readLock(mine.lockPath);
    if (cur && cur.token === mine.token && cur.pid === mine.pid) {
      fs.rmSync(mine.lockPath, { force: true });
      return true;
    }
  } catch { /* 尽力而为：残留的锁下次启动会被判成陈旧锁接管 */ }
  return false;
}

/** 给测试与诊断用：本进程是否持有锁 */
function isHeld() {
  return !!(own && !released);
}

module.exports = { acquire, release, isHeld, pidState };
