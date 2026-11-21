[简体中文](SECURITY.md) | English

# Security Policy

## Reporting a vulnerability

**Please do not open a public Issue.**

Submit it through GitHub's private vulnerability reporting:

👉 https://github.com/sqcola/maildesk-keysdesk/security/advisories/new

If that link does not work for you, send email to the repository owner's public GitHub email address (see their profile), with `[SECURITY]` in the subject line.

Please include in your report:

- the affected tool (MailDesk / KeyDesk) and version (commit hash or tag)
- reproduction steps
- scope of impact (what can be read, what can be changed)
- a minimal PoC if convenient

## Response times

| Stage | Expected |
|---|---|
| Acknowledgement of receipt | Within 7 days |
| Initial assessment (whether it is valid, and severity) | Within 14 days |
| Fix or mitigation | Depends on severity; generally within 30 days |

This is a personally maintained project, not a company product. The times above are **best effort**, not an SLA. If you get no reply after that window, feel free to send it again.

## In scope

- Flaws in the cryptographic implementation (KeyDesk's scrypt/AES-GCM/dual-slot design, MailDesk's vault and AAD)
- Authentication bypass (MailDesk's handshake mechanism, ACL tightening)
- Injection (XSS, CSV formula injection, path traversal)
- Data integrity (atomicity of write paths, corruption caused by concurrency)
- Credential leakage (any path that leaks a refresh_token or TOTP secret in plaintext)

## Out of scope

The following are **known design boundaries**, not vulnerabilities:

| Item | Explanation |
|---|---|
| Memory dumps | Keys live in process memory while unlocked; Node has no mlock |
| Keyloggers / screen recording | Both the passphrase and the codes pass through them |
| Browser extensions | Being able to read the page is equivalent to obtaining the codes |
| Infostealers | Programs that can read memory or the keyboard are unaffected by encryption |
| Rollback attacks | Overwriting a newer `vault.enc` with an older one cannot be detected (would need an external anchor) |
| Cloud drive version history | Old versions retained by a cloud drive after a passphrase change can still be decrypted |
| Weak passphrases | Blocked as far as practical, but something like `Tr0ub4dor&3` still cannot be assessed |
| Malicious data you enter yourself | For example naming your own platform `=cmd\|calc` — that is self-harm |

The full threat model is in each tool's own README.

## Disclosure policy

Once a fix is released, I will describe it in the release notes. If you want to be credited, tell me when you report.

Please do not disclose details publicly before the fix is released.
