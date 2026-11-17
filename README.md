# MailDesk & KeyDesk

两个**零依赖**的本地工具，解决同一件事的两面：**批量管理邮箱**，和**安全保管它们的 2FA 凭据**。

跑在你自己电脑上，数据不出本机，没有云、没有第三方依赖、没有 `npm install`。

<p align="center">
  <img src="docs/images/maildesk.png" alt="MailDesk 界面：按平台筛选邮箱" width="820">
</p>

---

## 这是什么

**MailDesk** —— 管邮箱。批量导入、检测可用性、收发信、批量收验证码，并给每个邮箱标注它注册过哪些第三方服务（Google / GitHub / Steam……），可按平台反查。

**KeyDesk** —— 管 2FA。存 TOTP 密钥和恢复码，用一个你记得住的口令加密。没有密钥文件，拷走数据目录也解不开。

两个工具**刻意不合并**：`refresh_token` 可以重新导入，TOTP 密钥一旦泄露就是永久的。它们的安全模型不同，放同一个库里等于把两者的风险绑在一起。

## 快速开始

需要 **Node.js 18+**。不需要 `npm install`——没有任何依赖。

```bash
git clone https://github.com/sqcola/maildesk-keysdesk.git
cd maildesk-keysdesk/MailDesk && node server.js
```

Windows 上双击 `start.bat` 也行。启动后打开终端打印的地址（默认 `http://127.0.0.1:2131`）。

KeyDesk 同理：

```bash
cd maildesk-keysdesk/KeyDesk && node server.js
```

## 两个工具各做什么

### MailDesk

| 能力 | 说明 |
|---|---|
| 批量导入 | 支持号商常见的四列格式，按内容识别列而不是按位置 |
| 可用性检测 | 单个或批量，区分"令牌失效"和"账号被封" |
| 收信 / 发信 | IMAP 收件箱，SMTP 发纯文本 |
| 批量收验证码 | 多选账户一次扫完，进度可取消，结果按账户分组 |
| 验证码历史 | 加密落盘，可标记已用、按账户检索、导出 |
| **平台标注** | 标出每个邮箱注册过哪些服务，按平台筛选，导出 CSV 清单 |
| 加密存储 | refresh_token 用 AES-256-GCM 加密，AAD 绑定账户 ID |

### KeyDesk

| 能力 | 说明 |
|---|---|
| TOTP | 服务端算码，密钥不进浏览器 |
| 恢复码 | 代际管理（哪一批是哪次生成的），逐码标记已用 |
| 双槽解锁 | 口令 或 恢复密钥，忘了口令不会永久失锁 |
| 加密导出 | 独立的盐和 IV，导出包不能当主库用 |
| 审计视图 | 一眼看出哪些账号缺 2FA、缺恢复码、恢复码过期 |

## 为什么值得一看

**零依赖不是口号。** 没有 `package.json`，没有 `node_modules`。所有密码学走 Node 内置 `crypto`，QR 编码是自己写的（含 Reed-Solomon），TOTP 过了 RFC 6238 全部 18 个官方向量。

**测试是真的在测。** 两个工具共 200+ 条断言，其中包括变异测试——把修复逐个改回 bug，确认测试会变红。

**威胁模型写清楚了。** 每个工具都明确列出"能防什么、防不住什么"。比如 KeyDesk 会告诉你：内存 dump 防不住，键盘记录防不住，云盘的历史版本管不到。不吹牛比吹牛更难，也更有用。

## 文档

- [MailDesk 详细说明](MailDesk/README.md) —— 包含本机鉴权模型、AAD 绑定、批量收码的实现
- [KeyDesk 详细说明](KeyDesk/README.md) —— 包含威胁模型、KDF 参数选择、恢复密钥设计
- [安全策略](SECURITY.md) —— 漏洞报告渠道
- [贡献指南](CONTRIBUTING.md) —— 怎么跑测试、怎么提 PR

## 已知边界

这两个工具**不是**：

- 不是密码管理器（不存网站密码、不自动填充）
- 不是多设备同步方案（单机本地，想要同步请自己放网盘——密文放网盘是安全的）
- 不是免于恶意软件的工具（infostealer 能读内存，加密对它无效）

## 许可证

[MIT](LICENSE)
