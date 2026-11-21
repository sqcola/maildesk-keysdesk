## 改了什么

<!-- 一句话说明这个 PR 做了什么 -->

## 为什么

<!-- 解决了什么问题？关联的 Issue 编号？ -->

Closes #

## 怎么验证的

- [ ] `cd MailDesk && node selftest.js` 通过（159 项）
- [ ] `cd MailDesk && node security-test.js` 通过（64 项）
- [ ] `cd MailDesk && node tools/check-key-test.js` 通过（27 项）
- [ ] `cd KeyDesk && node selftest.js` 通过（241 项）
- [ ] `cd KeyDesk && node security-test.js` 通过（84 项）

<!-- 如果改了行为，说明你是怎么手工验证的 -->

## 有没有改动加密格式或数据兼容性

- [ ] 没有
- [ ] 有，说明：<!-- 老文件还能不能读？需不需要迁移？ -->

## 提交前自检

- [ ] 没有提交任何真实数据（邮箱、令牌、密钥）
- [ ] `git status` 里没有意外加入的文件（`data/`、`*.enc`、`vault.key`）
- [ ] 注释解释的是「为什么」，不是「改了什么」
- [ ] 没有引入新的第三方依赖
