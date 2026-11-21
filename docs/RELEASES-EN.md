[简体中文](RELEASES.md) | English

# Release notes (for users)

> One section per version, explaining **"what changes for you in this build"**.
> GitHub Release bodies are taken from here. Newest first.
>
> **There is exactly one source of truth for the version number**: the **tag** of that
> version on the GitHub Releases page. This repository has no `package.json` and no
> `gradle.properties`, so every version number written in a document is only a copy of the
> tag. If they disagree, the Releases page wins. The newest version in this file must match
> the newest tag.
>
> Current state: the newest tag on the Releases page is `v0.1.0` (`0.1.0-SNAPSHOT`). The
> `0.1.1-SNAPSHOT` section at the top of this file is **not released yet** — publishing it
> means tagging `v0.1.1` at the same time, otherwise this file becomes a second source of
> version numbers.
>
> How to write these: **one `##` per version → a one-sentence summary → category sections →
> upgrade notes**. Categories are Keep a Changelog's six (Added / Changed / Deprecated /
> Removed / Fixed / Security) plus `Known limitations` and `Upgrade notes`.
> Hard rules: `Fixed` appears only once per version (use list items for several fixes); no
> parentheses or technical nouns in headings; describe what the user experiences rather than
> which line changed; unsolved problems go under `Known limitations`, never hidden; upgrade
> notes contain only "what you need to know before installing" — test steps and assertion
> counts belong inside the entry they describe.
>
> **Historical sections keep their own numbers.** The `0.1.0-SNAPSHOT` section reports what
> that tag actually measured (498 assertions); `0.1.1-SNAPSHOT` reports 575. Rewriting the
> old number to match today's suite would make that section describe code it never shipped
> with, which is worse than being out of date.

---

## 0.1.1-SNAPSHOT

> **Other programs on your machine can no longer walk off with your codes, and opening the
> vault twice can no longer corrupt it.** This build is about security and data integrity.
> If you are still on 0.1.0, replace it.

### Added

- **Verification-code history went from "saved but invisible" to usable.** Scan results were
  already being written, encrypted, to `data/history.enc` — but there was no entry point
  anywhere in the UI. Unless you called the API by hand you could not read them, mark them
  used, or export them, which made the feature effectively absent. There is now a proper
  view: search by account or keyword, filter by time range, show unused codes only, mark one
  or many as used, export to text or CSV, and clear by time range. Clearing is a two-step
  confirmation (pick the range, then confirm), so it cannot wipe everything in one click.

### Fixed

- **Launching it twice no longer corrupts the vault.** The second instance used to roll over
  to the next free port and start anyway; both processes then shared one temporary file while
  writing `vault.enc`, and after a few alternating writes the whole vault became bytes that
  no longer parse. A second instance is now refused outright and tells you which process owns
  the lock and where the lock file is. A stale lock left behind by a crashed process is taken
  over automatically — if the recorded process no longer exists, the lock is adopted, so you
  never have to delete it by hand.

- **If you forgot your passphrase, recovery unlock now actually gets you back in.** This used
  to be a dead end: the recovery key unlocked the vault, but "change passphrase" still demanded
  the old passphrase — the exact thing you had forgotten. After a recovery unlock you can now
  set a new passphrase directly. The recovery key keeps working afterwards (that escape hatch
  must not disappear), and the old passphrase stops working. Strength checks on the new
  passphrase are unchanged, and a locked vault still cannot change its passphrase.

- **The key checker no longer calls a good key a bad one.** `tools/check-key.js` did not
  understand the AAD used by v2 vaults, so even the correct key reported an authentication
  failure with exit code 1. The only job that tool has is telling you which key opens the
  vault, and a false alarm sends people off to delete the right one. It now follows the
  vault's own format markers, and separates "this key is not for this vault" from "this
  vault has damaged entries" — the first tells you to switch keys, the second tells you not
  to touch them.

- **Bulk scans of hundreds of accounts no longer get cut off halfway.** The hard deadline was
  a flat 15 minutes, while 300 accounts need up to 42 minutes in the worst case — so a normal
  run was guaranteed to be truncated, with nothing but a "terminated" line in the UI and the
  remaining accounts never scanned. The deadline is now derived from queue length, per-account
  timeout and concurrency (about 46 minutes for 300 accounts), with a 10-minute floor and a
  60-minute ceiling. The ceiling has to exist: it is the only fallback that releases the
  single-instance lock.

- **Errors now show you the actual reason.** The server has always returned two things
  together: the detail (for example "per-account scan timed out after 25 s, connection
  closed") and the category (for example "network timeout or connection reset"). The frontend
  showed only the first and discarded the second, so a class of 500 errors read as "internal
  server error, see the terminal log" while the answer sat in the response. The category is
  now appended to the detail, and the original message text is left untouched — the bulk-scan
  polling branches on it.

### Security

- **Other programs can no longer just help themselves to your codes.** This is the serious
  one. Any process on the same machine could call `GET /api?action=handshake`, receive a
  session token, and — while you had the vault unlocked — read every TOTP secret in plaintext,
  export entries, and even set the idle auto-lock to zero and persist it. The rule "you need
  the master passphrase to see secrets" was simply open to anything running locally. The
  handshake now requires a 256-bit secret that lives in the data directory: the first time you
  open the page in a browser it asks you to paste it once (the startup banner prints its
  absolute path, normally `KeyDesk/data/handshake`), and a valid paste gets you an HttpOnly
  cookie good for a year. Scripts use an `X-KeyDesk-Handshake` header instead. The bootstrap
  endpoint only accepts same-origin requests, and repeated wrong pastes trigger a short
  cooldown.

  This boundary is not absolute, and we will not pretend it is: **any code running under the
  same OS account as KeyDesk can still read that file** and therefore fully control the vault.
  Only the operating-system account boundary can stop that; application-level auth cannot.

- **Other Windows accounts can no longer read your account store.** MailDesk used to tighten
  the permissions once at startup. Every later save replaced the file with a fresh temporary
  file carrying inherited permissions, wiping out that tightening on the spot (measured: after
  creation only your account could read it; after one more save it went back to being readable
  by SYSTEM, Administrators and Authenticated Users). So from the first save of a run onward,
  `accounts.enc` on disk stayed readable by every other account on the machine until the next
  restart briefly tightened it again — and the key file sits right beside it, so anyone with
  both had everything, making the authorisation gate in front of it pointless. Each write now
  tightens the temporary file **before** the replace (NTFS carries the moved file's own ACL
  across), and the verification-code history `history.enc` gets the same treatment; it had
  never been tightened at all.

  Regression suites: `MailDesk/selftest.js` 159, `MailDesk/security-test.js` 64,
  `MailDesk/tools/check-key-test.js` 27, `KeyDesk/selftest.js` 241,
  `KeyDesk/security-test.js` 84 — **575 assertions** in total, all green. Every fix above is
  pinned by an assertion. Mutation testing was done by hand during development; **there is no
  re-runnable mutation-testing script in the repository**.

### Known limitations

- **KeyDesk: the recovery key is a full spare key.** It unlocks the vault *and* can set a new
  passphrase. That is the price of "forgetting your passphrase does not lock you out forever".
  After changing your passphrase, regenerate the recovery key too, or the old one stays valid
  indefinitely.
- **KeyDesk: changing the passphrase does not change the data key.** Any old copy of
  `vault.enc` plus the old passphrase still decrypts your **current** data. If you suspect the
  passphrase leaked, changing it is not damage control — only rebuilding the vault and
  re-enrolling 2FA is.
- **KeyDesk: overwriting a newer `vault.enc` with an older one cannot be detected** — there is
  no external anchor, and the ciphertext check happily accepts a valid old ciphertext.
- **KeyDesk: encrypted exports can be produced but not imported.** There is no import path in
  the tool; you would have to write a script. Keep copying `vault.enc` for day-to-day backups.
- **KeyDesk: the instance lock only sees instances that take the lock.** The lock file is
  `data/server.lock`, and older builds do not write it. After upgrading, close the old build
  before starting the new one, or the lock will not see that process.
- **MailDesk: the bulk-scan ceiling is 60 minutes.** At concurrency 3 and 25 s per account,
  more than roughly 390 accounts can still hit the ceiling. The ceiling has to exist, but very
  large runs will be truncated by it.
- **MailDesk: `data/` and `~/.maildesk/vault.key` must be backed up as a pair.** Either one
  alone is useless, and they should not live on the same synced drive.
- **MailDesk: Outlook / Microsoft accounts only**, and you must supply `client_id` +
  `refresh_token` yourself. There is no authorisation flow in the tool, and the README does
  not yet explain how to obtain a token — a known documentation gap.
- **Neither tool defends against** memory dumps, keyloggers, screen recording, malicious
  browser extensions, or any code running under your own OS account. Node has no mlock, and
  encryption is close to irrelevant against these.

### Upgrade notes

- **Nothing to reinstall**: this project ships no installer. `git pull` (or clone again) and
  run `cd MailDesk && node server.js` as before.
- **No data migration**: `vault.enc` / `accounts.enc` / `history.enc` from 0.1.0 work as-is.
  No re-import, no conversion.
- **KeyDesk asks you to paste the local authorisation code once after upgrading.** The path is
  on the `Auth file:` line of the startup banner (normally `KeyDesk/data/handshake`). The
  browser remembers it for a year.
- **KeyDesk now refuses a second instance.** If you see "an instance is already running",
  close that window first. If you are sure it is gone, delete `data/server.lock` as the
  message suggests, then start again.
- **If `tools/check-key.js` previously told you "this key cannot open the vault", run it
  again.** That was most likely a false alarm — keep the key that actually works instead of
  deleting it.

---

## 0.1.0-SNAPSHOT

> **The first public build of both tools.** Bulk mailbox management and a local 2FA vault,
> both zero-dependency, both staying on your machine.

> **This section is a rewrite of the original release body**, correcting three claims that did
> not match the code: ① it said TOTP secrets "never enter browser memory, so neither XSS nor a
> malicious extension can get them" — in fact the "reveal secret" and "show QR code" paths put
> the plaintext secret into browser memory; ② it listed "cloud drive version history" as a
> shared boundary — it only applies to KeyDesk (MailDesk has no passphrase and keeps its key in
> a separate file); ③ it said the suite included re-runnable mutation tests — it does not;
> that was done by hand during development. It also listed verification-code history as a
> working feature, although this build had no UI for it (see Known limitations below).

### Added

**MailDesk**

- **Bulk import** — columns are identified by content (`client_id` looks like a GUID,
  `refresh_token` is the longest field), not by position; both four-column and three-column
  exports are accepted
- **Availability check** — single or bulk, distinguishing "token expired" from "account
  banned"; the latter is not retried
- **Read and send mail** — IMAP inbox (including Junk and Sent), SMTP for plain text
- **Bulk code retrieval** — select many accounts, scan them in one go, with a progress bar
  and cancellation; results grouped by account
- **Platform tagging** — record which services each mailbox signed up for (17 built in, plus
  any custom name), filter by platform, configure in bulk, export a CSV list

**KeyDesk**

- **TOTP** — the six-digit code in the list and detail views is computed on the server; the
  page receives digits only. ⚠️ But pressing "reveal secret" or "QR code" does put the
  plaintext secret into browser memory (it is needed to build the otpauth URI); on those two
  paths, CSP and same-origin policy are the only boundary
- **Recovery codes** — generation-based management (which batch came from which regeneration),
  marking codes used individually with dates
- **Dual-slot unlock** — passphrase or recovery key, so a forgotten passphrase is not a
  permanent lockout
- **Mandatory playback** — after first setup you must retype segments 2/5/7 of the recovery
  key to get in; a mis-copied key keeps you out
- **Encrypted export** — separate salt and IV, domain-separated AAD; the export cannot be used
  as the main vault
- **Audit view** — see at a glance which accounts lack 2FA, lack recovery codes, or have
  expired ones

**Shared**

- **Zero third-party dependencies** — no `package.json`, no `node_modules`; QR encoding
  (including Reed-Solomon) and TOTP are both implemented in-house
- **Security design written down** — KeyDesk has a line-by-line "what it protects against /
  what it does not" table; MailDesk documents its local auth model, why the key is kept
  separate from the ciphertext, the results of a red-team audit, and its known defects.
  Neither overstates the protection, but the **formats differ**: MailDesk has no equivalent
  of KeyDesk's single table.

**This build was covered by four suites totalling 498 assertions** (`MailDesk/selftest.js` 146,
`MailDesk/security-test.js` 55, `KeyDesk/selftest.js` 226, `KeyDesk/security-test.js` 71), all
passing. Those are **this tag's** numbers; after the fixes it is five suites and 575 assertions
(the extra 27 come from `MailDesk/tools/check-key-test.js`) — see the section above. The
original text also said the suite included mutation tests that revert each security fix and
check the assertions go red. **That was not true**: there is no re-runnable mutation-testing
script in the repository; it was done by hand during development.

### Known limitations

- **This build of KeyDesk has three confirmed defects, all fixed in 0.1.1**: the handshake
  handed out a token unconditionally (any local process could read plaintext TOTP), there was
  no instance lock (opening it twice corrupted `vault.enc`), and a recovery unlock could not
  change the passphrase (leaving the user locked out).
- **This build of MailDesk has five confirmed defects, all fixed in 0.1.1**: verification-code
  history existed only in the backend with no UI; `accounts.enc` and `history.enc` reverted to
  inherited ACLs after the first save; the bulk-scan deadline was a flat 15 minutes (300
  accounts were guaranteed to be cut off); `tools/check-key.js` did not understand v2 vaults
  and reported a failure even for the correct key; and the error category was computed and
  then discarded by the frontend, leaving only "internal server error".
- **Cloud drive version history (KeyDesk only)**: if `vault.enc` lives on a synced drive,
  changing the passphrase clears the local backups, but versions the drive retained can still
  be decrypted with the old passphrase and must be deleted by hand.
  **This does not apply to MailDesk.** Its key is a separate file, `~/.maildesk/vault.key`,
  which should never sit next to `data/accounts.enc` on a cloud drive anyway — leaking both
  means every account is lost. It also has no passphrase to change.
- **Rollback attacks (KeyDesk)**: overwriting a newer `vault.enc` with an older one cannot be
  detected without an external anchor.
- **Weak passphrases (KeyDesk)**: common patterns are blocked, but something like
  `Tr0ub4dor&3` — complex-looking yet patterned — cannot be assessed. Entropy comes from
  length, not from complexity.
- **MailDesk has no authorisation flow**: it only accepts `client_id` + `refresh_token`, only
  for Outlook / Microsoft accounts, and the README does not explain how to obtain a token.
- **Memory dumps, keyloggers, screen recording**: neither tool defends against these. Node has
  no mlock.

### Upgrade notes

- **This is a SNAPSHOT**: interfaces and data formats may still change during 0.1.x. Do not
  put irreplaceable data in it.
- **There is no prebuilt package**: Node.js 18+ is required; clone and run
  `cd MailDesk && node server.js` (KeyDesk likewise).
- **KeyDesk's `vault.enc` and the recovery key must never be stored together.** That is the
  core discipline of the whole design.
