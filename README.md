# Skill Security Audit

**Check any Claude skill or plugin before you install it.**

[עברית](README.he.md)

Skills and plugins are powerful. A skill can tell Claude what to do, run scripts on your machine, install packages and use your connected apps. That also makes them an easy way to deliver malware. A skill that looks like a harmless "PDF helper" can quietly read your SSH keys, send your files to a remote server, or tell Claude to hide what it's doing.

Skill Security Audit makes Claude check a skill before you install it. You get a clear verdict:

- 🟢 **Safe to install** (static review)
- 🟡 **Install with caution**: lists exactly what to remove or change
- 🔴 **Do not install**: explains why, with file and line evidence

## What it checks

| Area | Examples |
|---|---|
| Remote access | reverse shells, download-and-execute, decode-and-execute |
| Data exfiltration | webhooks, paste sites, tunnels, data hidden in URLs and images |
| Prompt injection | "ignore previous instructions", "don't tell the user", hidden HTML comments, invisible Unicode |
| Credential theft | SSH keys, cloud credentials, browser cookies and saved passwords, API tokens |
| Crypto | wallet files, seed phrases, private keys, clipboard address swapping, transaction signing and approvals |
| Persistence and damage | startup items, cron jobs, mass deletion, disabling antivirus or OS protections |
| Agent tampering | changes to Claude settings, permissions, hooks or MCP servers |
| Supply chain | typosquatted packages, installs from unofficial sources, install-time scripts, hidden binaries, zip-slip archives |
| Purpose mismatch | code or instructions that don't match what the skill claims to do |

## How it works

1. **Isolation.** The candidate is placed in an empty folder. Archives go through a safe extractor that refuses path traversal, symlinks and zip bombs. **Nothing from the candidate is ever executed.**
2. **Automated triage.** A dependency-free Python scanner (`scripts/scan.py`) flags suspicious lines across 20+ risk categories and lists every domain the skill references.
3. **Full manual review.** Claude reads every file, judges each finding in context and checks whether the behaviour matches the stated purpose.
4. **Verdict and report** in your language, with file:line evidence.

## Install

**Claude.ai / Claude desktop app:** download this repo as a ZIP, then upload the `skills/skill-security-audit` folder (zipped) in **Settings → Capabilities → Skills**.

**Claude Code:**

```
/plugin marketplace add doobyflink/skill-security-audit
/plugin install skill-security-audit@skill-security-audit
```

## Use

Just say:

- "Check this skill before I install it" (and attach the file)
- "Is this plugin safe? https://github.com/someone/some-skill"
- "Audit all my installed skills"

Tip: ask Claude to remember to run this audit on every skill or plugin before you install it, and to re-run it on your installed skills once a month.

## Limitations, please read

This is a **static review**: it reads code and instructions without running them. It lowers your risk a lot, but **it cannot guarantee that a skill is safe**. Clever obfuscation, malicious dependencies and changes made after the audit can slip through. Install only from sources you trust, and re-audit after every update.

This project is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). It isn't a substitute for professional security review.

## Author

Built by **Dubi Flink**, crypto risk strategist ([OGen Family Office](https://ogen.capital/en)).

Issues and pull requests are welcome, especially new attack patterns and false-positive reports.

## License

MIT
