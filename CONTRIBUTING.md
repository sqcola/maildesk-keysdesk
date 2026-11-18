# 贡献指南

感谢有兴趣参与。这个项目有两个独立工具，改动前请先确认你在改哪一个。

## 环境

只需要 **Node.js 18+**。没有 `package.json`，没有 `npm install`——这是刻意的设计选择，请不要引入依赖。

如果你的改动确实需要新依赖，先开 Issue 说明理由：许可证兼容性、维护状态、以及为什么现有代码做不到。

## 跑测试

每个工具都有两套测试，都需要跑：

```bash
cd MailDesk
node selftest.js              # 159 项，功能正确性
node security-test.js         # 64 项，安全性（起真实 HTTP 服务）
node tools/check-key-test.js  # 27 项，密钥体检工具

cd ../KeyDesk
node selftest.js        # 241 项
node security-test.js   # 84 项
```

**全部必须通过。** 如果某个测试失败了而你认为它写错了，请先说明为什么——不要为了让它变绿而删断言。

### 测试会写文件吗

会，但只在临时目录。所有写测试都通过 `MAILDESK_DATA_DIR` / `MAILDESK_KEY_DIR` 隔离，不会碰你真实的库。KeyDesk 的测试用 `os.tmpdir()` 下的临时目录。

如果你要加新的写测试，也用同样的隔离方式。

## 改代码时的约定

**注释解释「为什么」，不解释「改了什么」。** 看现有代码的注释密度，保持一致的风格。例如：

```js
// 好的注释：解释约束
// tmp + rename 只保证"读者看不到半个文件"，不保证断电后内容真的落盘。
// 没有 fsync 时，rename 可能先于数据落盘生效，断电后 accounts.enc 是 0 字节。

// 不好的注释：复述代码
// 调用 fsyncSync
fs.fsyncSync(fd);
```

**密码学相关改动请格外谨慎。** 涉及 `lib/keystore.js`（KeyDesk）和 `lib/vault.js`（MailDesk）的改动，请在 PR 里说明：

- 会不会破坏现有数据的兼容性
- 有没有对应的测试覆盖
- 如果改变了加密格式，老文件还能不能读

**不要提交任何真实数据。** 测试用的邮箱一律 `example.com` / `*.test`，密钥一律用 RFC 文档里的公开示例值（如 `JBSWY3DPEHPK3PXP`）。

`.gitignore` 已经挡住了 `*.enc`、`vault.key`、`data/`，但**提交前请自己再确认一遍 `git status`**。

## 提 PR

1. 从 `main` 拉分支，分支名用 `fix/xxx` 或 `feat/xxx`
2. commit message 用 `type(scope): 描述` 格式，写清楚**为什么**改
3. 确保两套测试都通过
4. PR 描述里说明：改了什么、为什么改、怎么验证的

不需要 CLA，不需要签署任何东西。

## 报告问题

- **功能问题 / Bug**：开 Issue，用 Bug 模板，附上版本、系统、复现步骤
- **安全漏洞**：**不要开公开 Issue**，见 [SECURITY.md](SECURITY.md)

## 代码风格

没有 ESLint 配置，因为不想引入工具链。基本约定：

- 2 空格缩进
- 分号不省略
- 字符串用单引号（前端 HTML 模板里用反引号）
- 函数命名用 camelCase，常量用 UPPER_SNAKE

现有的代码风格比较统一，照着写就行。
