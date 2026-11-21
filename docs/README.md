[English](README-EN.md) | 简体中文

# 仓库文档索引

> 这里只登记**本仓库内**随代码版本化的文档。工作区层面的索引（规则、各项目清单）
> 在仓库之外，不在这里重复。
>
> 文档与代码同一次变更更新：改了行为、配置或接口，对应的文档要在同一个提交里跟着改。

---

## 版本说明

| 文件 | 内容 |
|---|---|
| [`RELEASES.md`](RELEASES.md) | **面向用户的版本说明**（中文）。GitHub Release 的正文就取自这里，按版本倒序排列 |
| [`RELEASES-EN.md`](RELEASES-EN.md) | 上面那份的英文版 |

版本号的真源是 [Releases 页](https://github.com/sqcola/maildesk-keysdesk/releases) 上的
tag。仓库里没有 `package.json`，任何文档里写的版本号都只是 tag 的副本。

## 仓库根的三份主文档

| 文件 | 内容 |
|---|---|
| [`../README.md`](../README.md) / [`../README-EN.md`](../README-EN.md) | 项目总览：适合谁、快速开始、架构、用途边界 |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) / [`../CONTRIBUTING-EN.md`](../CONTRIBUTING-EN.md) | 环境要求、怎么跑测试、代码约定、PR 流程 |
| [`../SECURITY.md`](../SECURITY.md) / [`../SECURITY-EN.md`](../SECURITY-EN.md) | 漏洞的私密报告渠道、响应时间、**不在范围内**的已知边界 |

## 两个子项目

| 文件 | 内容 |
|---|---|
| [`../MailDesk/README.md`](../MailDesk/README.md) | 批量账号管理：导入格式、AADSTS 错误排查、平台标注、验证码历史、本机鉴权模型、备份 |
| [`../KeyDesk/README.md`](../KeyDesk/README.md) | 2FA 保管：威胁模型、KDF 参数选择、恢复密钥设计、云盘与回滚的边界 |

> 两个子项目的 README 目前只有中文版。这是已知缺口，不是有意为之。

## 资源

| 路径 | 内容 |
|---|---|
| [`images/`](images/) | README 用的界面截图（`maildesk.jpg` / `keydesk.jpg`）与 1280×640 社交预览图（`social-preview.jpg`） |
| [`social-preview.html`](social-preview.html) | 社交预览图的生成器。用浏览器打开这个文件即可重新导出那张 1280×640 的图 |

## 不在本索引里的东西

- **各工具的源码注释**：设计取舍写在代码旁边的注释里（尤其是 `lib/vault.js`、
  `lib/keystore.js`），那是最近的一手资料。
- **测试文件**：`selftest.js` / `security-test.js` 既是回归测试也是行为说明，
  想看某个边界条件怎么定义的，直接搜断言。
