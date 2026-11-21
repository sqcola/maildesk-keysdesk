[简体中文](README.md) | English

# Documentation index

> This index covers **the docs that live in this repository** and are versioned with the
> code. The workspace-level index (project rules, the list of all projects) lives outside the
> repository and is not duplicated here.
>
> Docs are updated in the same change as the code: if behaviour, configuration or an interface
> changes, the matching doc changes in the same commit.

---

## Release notes

| File | Contents |
|---|---|
| [`RELEASES.md`](RELEASES.md) | **Release notes for users** (Chinese). GitHub Release bodies are taken from here, newest first |
| [`RELEASES-EN.md`](RELEASES-EN.md) | The English version |

The version number comes from the tag on the
[Releases page](https://github.com/sqcola/maildesk-keysdesk/releases). There is no
`package.json` in this repository, so any version number in a document is only a copy of that
tag.

## The three top-level documents

| File | Contents |
|---|---|
| [`../README.md`](../README.md) / [`../README-EN.md`](../README-EN.md) | Overview: who this is for, quick start, architecture, usage boundaries |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) / [`../CONTRIBUTING-EN.md`](../CONTRIBUTING-EN.md) | Environment, how to run the tests, code conventions, pull request flow |
| [`../SECURITY.md`](../SECURITY.md) / [`../SECURITY-EN.md`](../SECURITY-EN.md) | Private vulnerability reporting, response times, **known boundaries that are out of scope** |

## The two sub-projects

| File | Contents |
|---|---|
| [`../MailDesk/README.md`](../MailDesk/README.md) | Bulk account management: import formats, AADSTS troubleshooting, platform tags, verification-code history, local auth model, backups |
| [`../KeyDesk/README.md`](../KeyDesk/README.md) | 2FA storage: threat model, KDF parameter choices, recovery-key design, cloud-drive and rollback boundaries |

> The two sub-project READMEs are currently Chinese-only. That is a known gap, not a
> deliberate choice.

## Assets

| Path | Contents |
|---|---|
| [`images/`](images/) | UI screenshots used by the READMEs (`maildesk.jpg` / `keydesk.jpg`) and the 1280×640 social preview (`social-preview.jpg`) |
| [`social-preview.html`](social-preview.html) | Generator for the social preview. Open it in a browser to export the 1280×640 image again |

## What is not indexed here

- **The source code comments.** Design trade-offs are documented next to the code that makes
  them (especially `lib/vault.js` and `lib/keystore.js`) — that is the most current source.
- **The test files.** `selftest.js` / `security-test.js` are regression tests and a
  behavioural spec at the same time. If you want to know how an edge case is defined, search
  the assertions.
