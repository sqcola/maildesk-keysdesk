[简体中文](CONTRIBUTING.md) | English

# Contributing guide

Thanks for your interest in contributing. This project contains two independent tools — before you change anything, please make sure you know which one you are changing.

## Environment

You only need **Node.js 18+**. There is no `package.json` and no `npm install` — that is a deliberate design choice, so please do not introduce dependencies.

If your change genuinely needs a new dependency, open an Issue first and explain why: licence compatibility, maintenance status, and why the existing code cannot do the job.

## Running the tests

Each tool has its own test suites, and you need to run all of them (three for MailDesk, two for KeyDesk):

```bash
cd MailDesk
node selftest.js              # 159 checks, functional correctness
node security-test.js         # 64 checks, security (starts a real HTTP server)
node tools/check-key-test.js  # 27 checks, the key health-check tool

cd ../KeyDesk
node selftest.js        # 241 checks
node security-test.js   # 84 checks
```

**Everything must pass.** If a test fails and you believe the test itself is wrong, explain why first — do not delete an assertion just to make the suite go green.

### Do the tests write files?

Yes, but only in temporary directories. Every write test is isolated through `MAILDESK_DATA_DIR` / `MAILDESK_KEY_DIR`, so it never touches your real store. KeyDesk's tests use a temporary directory under `os.tmpdir()`.

If you add a new test that writes files, use the same isolation approach.

## Conventions when changing code

**Comments explain "why", not "what changed".** Look at the comment density in the existing code and match it. For example:

```js
// Good comment: explains the constraint
// tmp + rename only guarantees "a reader never sees half a file"; it does not
// guarantee the contents actually reached disk before a power loss. Without
// fsync, rename can take effect before the data lands, and after a power cut
// accounts.enc is 0 bytes.

// Bad comment: restates the code
// Call fsyncSync
fs.fsyncSync(fd);
```

**Be especially careful with cryptography-related changes.** For changes touching `lib/keystore.js` (KeyDesk) and `lib/vault.js` (MailDesk), please state in the PR:

- whether it breaks compatibility with existing data
- whether there is corresponding test coverage
- if the encrypted format changes, whether old files can still be read

**Do not commit any real data.** Test mailboxes are always `example.com` / `*.test`, and keys always use the public example values from RFC documents (such as `JBSWY3DPEHPK3PXP`).

`.gitignore` already covers `*.enc`, `vault.key` and `data/`, but **please check `git status` yourself before committing**.

## Opening a PR

1. Branch from `main`, using `fix/xxx` or `feat/xxx` as the branch name
2. Use the `type(scope): description` format for commit messages, and make the **why** clear
3. Make sure every test suite listed above passes
4. In the PR description, say what you changed, why you changed it, and how you verified it

No CLA, nothing to sign.

## Reporting problems

- **Functionality problems / bugs**: open an Issue using the bug template, including version, system, and reproduction steps
- **Security vulnerabilities**: **do not open a public Issue** — see [SECURITY.md](SECURITY-EN.md)

## Code style

There is no ESLint config, because we do not want to pull in a toolchain. Basic conventions:

- 2-space indentation
- Semicolons are not omitted
- Single quotes for strings (backticks in frontend HTML templates)
- camelCase for function names, UPPER_SNAKE for constants

The existing code is fairly consistent, so just follow it.
