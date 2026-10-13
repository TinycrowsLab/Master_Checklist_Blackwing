# Secrets Hygiene

Two separate problems, often confused:

1. **Your own credentials** — tokens that let you push code, file advisories, or access bounty platforms.
2. **Credentials you find inside a target** — hardcoded keys in the code you are auditing. These have their own rules, and getting them wrong is the single easiest way to turn security research into a crime.

---

## 1. Your own credentials

### Never paste a credential into a chat, prompt, issue, or AI tool

Not into this repo, not into an AI assistant, not into a GitHub issue, not into a Slack message "just to test." Anything you paste lands in transcripts, logs, provider-side telemetry, and shell history. It is not retractable.

If a tool genuinely needs authentication, it reads it from a credential store that you never have to copy by hand:

```bash
gh auth login                 # GitHub CLI → system keyring, never echoed
git config --global credential.helper store   # or libsecret / osxkeychain
export SOME_TOKEN="$(secret-tool lookup service some-service)"
```

A token you can paste is a token you can leak. Prefer short-lived and minimally-scoped: a fine-grained GitHub PAT restricted to one repository beats a classic PAT carrying `admin:org` and `delete_repo`.

### Scope discipline

Before generating a token, ask what the absolute minimum is. For publishing advisories and pushing to your own repos, you need `repo` and nothing resembling `admin:*`. A leaked token is bounded by its scopes — that bound is the only thing that saves you.

### If you leak one

Order matters. Do these in sequence:

1. **Revoke it immediately.** Not after the session, not after you finish what you were doing. <https://github.com/settings/tokens> for GitHub PATs. Revocation is the only step that actually stops an attacker; everything else is cleanup.
2. **Rotate** anything that token could have reached.
3. **Check the audit log** for use you did not initiate (`https://github.com/settings/security-log`).
4. **Then** worry about history. If it was committed and pushed, assume it is permanently compromised — GitHub caches, forks, and third-party mirrors scrape public commits within minutes. Rewriting history with `git filter-repo` or BFG is housekeeping, not remediation. Revocation already did the real work.

Do not reverse this order. Cleaning history first while the credential stays live is the common and costly mistake.

### Scanning

This repo installs a `pre-commit` hook that blocks high-signal credential patterns and protected paths:

```bash
git config core.hooksPath .githooks    # required once per clone
```

It catches `ghp_*`, `github_pat_*`, AWS `AKIA*`/`ASIA*`, `sk-ant-*`, Slack `xox*`, Google `AIza*`, GitLab `glpat-*`, npm/PyPI tokens, and private-key headers. `git commit --no-verify` bypasses it — that flag exists for emergencies, not for silencing a complaint you disagree with.

For deeper scanning, including history:

```bash
gitleaks detect --source . --redact
trufflehog git file://. --only-verified
```

`--only-verified` matters: TruffleHog can live-check whether a found credential is active, which collapses the false-positive pile.

---

## 2. Credentials you find inside a target

This is the part with legal consequences.

While auditing you will find hardcoded API keys, database passwords, cloud credentials, and signing keys committed to public repositories. This is a legitimate and common finding class (CWE-798, *Use of Hard-coded Credentials*).

### The hard rule: do not use them. Ever.

Not to "confirm the finding." Not "just a read-only call." Not "only to check if it's still valid."

Authenticating to a system with a credential you found, however you found it, is unauthorized access. In the US that is the Computer Fraud and Abuse Act; the UK has the Computer Misuse Act; most jurisdictions have an equivalent. The credential being publicly visible is not authorization — a key left under a doormat is not an invitation. Researchers have been prosecuted for exactly this.

Finding a key in a public repo is a code-review finding. Testing it is an intrusion. The line between them is the entire distinction between a researcher and a defendant.

### What to do instead

You can establish a complete, reportable finding without ever authenticating:

- **Locate** it precisely: `file:line`, commit SHA, first commit that introduced it (`git log -S'<fragment>' --oneline`).
- **Classify** it by prefix — the shape tells you what it is and how severe without using it. `AKIA` is a long-lived AWS access key; `ASIA` is temporary. `ghp_` is a GitHub PAT. `sk-ant-` is an Anthropic key.
- **Assess reachability**: is it in production code, a test fixture, a dead branch, or a sample config? A dummy value in `test/fixtures/` is not a vulnerability, and reporting it as one is how you earn a reputation for noise.
- **Check whether it is still live in history** even if removed from `HEAD` — `git log --all -S'<fragment>'`. Removal from the current tree does not revoke anything, and maintainers routinely believe it does. Telling them this is often the most valuable part of the report.
- **Report urgently.** Live production credentials in a public repo are an active compromise, not a scheduled disclosure. Skip the normal 90-day cadence, contact the maintainer immediately through their fastest private channel, and tell them plainly: *revoke first, then clean history.* Same order as above.

### Reporting channel

Use the project's private channel — `SECURITY.md`, GitHub Private Vulnerability Reporting, or a security email. Never a public issue: a public issue advertising a live credential is worse than the original mistake.

**Do not include the credential itself in the report.** Reference it by location, a truncated prefix, and a hash — `AKIA…7EXAMPLE at config/settings.py:42, sha256:a1b2c3…`. The maintainer can find it from that. Reports travel through ticketing systems, email, and mirrors; a full credential in a report body just creates a second leak with your name attached.

---

## Quick reference

| Situation | First action |
|---|---|
| You pasted your own token somewhere | Revoke it now, then rotate |
| Hook blocked your commit | Read what it caught; do not `--no-verify` |
| Found a key in a target's source | Document location; **never authenticate** |
| Found a *live production* key in a public repo | Contact maintainer immediately, out of normal cadence |
| Unsure whether something is a real secret | Treat as real until proven otherwise |
