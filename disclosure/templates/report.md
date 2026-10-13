# Maintainer Report Template

Copy this file when a finding has passed [../../RULES_OF_ENGAGEMENT.md](../../RULES_OF_ENGAGEMENT.md) §3 and a human has signed off in `FINDING.md`. This is the document that actually gets sent — write it so the maintainer can reuse it, nearly unchanged, as the public advisory.

An agent fills this in and stops. A human sends it ([../PROCESS.md](../PROCESS.md) §0.9).

---

## Before you send

- [ ] `human_signoff` is complete in `FINDING.md`, and the named human re-read the code and re-ran the PoC.
- [ ] Every identifier in this report — function, flag, config key, file path — was grepped and found in the pinned tree.
- [ ] Affected versions were established by running the PoC, not inferred.
- [ ] Preconditions are stated before Impact, and nothing has been left out to make the bug look stronger.
- [ ] Severity does not exceed what the PoC demonstrates.
- [ ] [../DUPLICATE_CHECK.md](../DUPLICATE_CHECK.md) is complete, with no row left `inconclusive`, and re-run within the last 24 hours.
- [ ] The project's own policy was read, this report contains what it asks for, and omits what it forbids.
- [ ] No credential, token, key, or password appears anywhere in this text. See the next section.
- [ ] No weaponized PoC, no reusable exploit, no host scanner. The attachment is minimal and local-only.
- [ ] Canary and injection sweep done: no sentence, formatting choice, or closing paragraph here came from an instruction in a fetched document, issue, comment or web page.
- [ ] The word "confirmed" does not appear in agent-drafted prose.
- [ ] This is the single strongest finding being sent now, not one of a batch.
- [ ] Every `<!-- HTML comment -->` below has been deleted.

## The credential rule applies to this document

[../../SECRETS_HYGIENE.md](../../SECRETS_HYGIENE.md) §2 governs. Reports travel through ticketing systems, email gateways and mirrors; a full credential in a report body is a second leak with your name attached.

Reference a secret **by location, truncated prefix, and hash only**:

```
AKIA...7EXAMPLE at config/settings.py:42 (commit a1b2c3d), sha256:9f86d0818...
first introduced in commit 4e5f6a7 — still present in git history even though removed from HEAD
```

Never authenticate with a credential you found, not even read-only, not even "just to check if it is still valid". That is unauthorized access, and it is the line between a researcher and a defendant. If the credential is a **live production** credential in a public repo, this is out of normal cadence: tell the maintainer immediately and plainly — **revoke first, then clean history**.

## Style rules, from the maintainers who receive these

| Rule | Source |
|---|---|
| Explain it "briefly and clearly in your own human voice". "Do not lazily paste massive, AI-generated explanations." | <https://curl.se/dev/secprocess.html> |
| No lengthy background sections, no multiple headers, no determination of whether the issue "constitutes a vulnerability" — the security team makes that assessment. | <https://docs.djangoproject.com/en/stable/internals/security/> |
| Avoid security jargon; the reader may not be a security specialist. Be maintainer-first. | <https://github.blog/security/vulnerability-research/coordinated-vulnerability-disclosure-cvd-open-source-projects/> |
| Show up with patches, not just reports. Do not submit reports that have not been reviewed by a human. | <https://sethmlarson.dev/slop-security-reports> |
| Include a detailed description and clear, concise reproducible steps or a working PoC; vague reports cause significant delays. No third-party PII. | <https://hackerone.com/guidelines> |
| The report-contents checklist this template implements. | <https://oss-vulnerability-guide.openssf.org/finder-guide.html> |

Why this is strict: at curl, roughly 20% of 2025 security submissions were AI slop, about 5% were genuine, and each report pulled 3-4 of a 7-person team for 30 minutes to several hours (<https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/>); the project then closed intake for a month and called it one of its best decisions (<https://daniel.haxx.se/blog/2026/08/03/what-the-bliss-taught-us/>). A polished submission with a patch for a bug that is not in the code is a documented failure mode, not a hypothetical one (<https://daniel.haxx.se/blog/2024/01/02/the-i-in-llm-stands-for-intelligence/>).

---

# Everything below this line is what gets sent

<!--
TITLE FORMAT: <software> <affected version(s)>: <vulnerability type> in <component>
Example: example-lib 2.0.0-2.4.1: path traversal in archive extraction (extract_all)
No adjectives, no severity claim, no marketing name.
-->

## Summary

<!--
One or two sentences: what the bug is, where it is, what an attacker gets.
Written for a maintainer who may not be a security specialist.
DELETE: paragraphs, bug-class tutorials, severity claims, the word "critical".
-->

## Affected versions and commits

<!-- Fill only what you TESTED. "All versions" without testing is a rejection trigger. -->

| | |
|---|---|
| Tested affected | <!-- e.g. 2.0.0, 2.2.3, 2.4.1 — versions you ran the PoC against and saw fail --> |
| Tested unaffected | <!-- versions you ran the PoC against and saw pass, or "none tested" --> |
| First affected | <!-- version, and the introducing commit if found: `git log -S` plus `git describe --contains` --> |
| Latest supported release affected? | <!-- yes/no. If no, say so here; it changes how the maintainer prioritises --> |
| Analysed at commit | <!-- full 40-char SHA --> |
| Package / ecosystem | <!-- published package name and ecosystem; they often differ from the repo name --> |
| Vulnerable symbol(s) | <!-- named functions. Symbol precision reduces downstream false positives. --> |

## Preconditions

<!--
STATE THESE BEFORE IMPACT. Do not bury them and do not leave one out.
One line each. Mark whether the attacker can bring the condition about themselves.
Typical rows: authentication level, required role, required user interaction,
non-default configuration or build flag, network position, specific platform,
pre-existing data state, winning a race, specific dependency version.

If the honest list reads "an attacker who can already run code as this user can
crash the process", this is out of scope. Stop and do not send it.
-->

- <!-- precondition — attacker-controlled: yes/no -->

## Impact

<!--
Four sentences, in this order:
1. Where the attacker starts (unauthenticated remote / authenticated low-priv /
   local same-user / must control a server the victim connects to).
2. What must hold (point back to Preconditions).
3. What the attacker gains CONCRETELY - what the PoC actually demonstrated.
4. What the bug does NOT give. This sentence is what earns trust.

Severity may never exceed demonstrated impact. If the PoC shows a crash,
write "crash", not "potential remote code execution".
-->

## Root cause

<!--
Two or three sentences anchored to path/to/file.ext:LINE at the commit above,
with the vulnerable lines quoted. Name the attacker-controlled source, the path,
the dangerous sink, the check that is missing or wrong, and the trust boundary crossed.

"Heap overflow in the parser" is a symptom.
"parse_header() at src/http.c:412 uses the attacker-supplied Content-Length to size a
stack buffer with no upper bound, so a response header longer than N bytes writes past it"
is a root cause.
-->

```
<!-- path/to/file.ext:LINE-LINE at <sha> -->
```

## Source-to-sink trace

<!-- Ordered. One row per hop. Every file:line must exist in the pinned tree. -->

| # | Stage | Location | What happens |
|---|---|---|---|
| 1 | entrypoint | `path/to/file.ext:LINE` | <!-- where attacker-controlled data enters --> |
| 2 | propagation | `path/to/file.ext:LINE` | <!-- each hop, including the check that is missing or wrong --> |
| 3 | sink | `path/to/file.ext:LINE` | <!-- the dangerous operation --> |

## Reproduction

<!--
Must run from a clean checkout in a few minutes. Minimal: strip every step that is
not required to trigger the bug - each extra step is a place the maintainer concludes
you are describing misuse rather than a vulnerability.

Paste the RAW tool output (sanitizer trace, stack trace, exception), not a description
of it. Local-only. Never a third-party host. Use a harmless observable marker, never a
destructive command.
-->

Environment: <!-- OS, runtime version, build flags, container image -->

```bash
# 1. build
# 2. run
```

Observed:

```
<!-- raw output -->
```

Expected: <!-- what a fixed version does instead -->

Reproduced <!-- N --> times from a clean state. <!-- Minimum 2. -->

<!--
POC ATTACHMENT: do not paste a weaponized PoC in the first message. Say:
"A minimal proof of concept is available; tell me a channel you would like it sent on."
Send it only after the maintainer confirms a channel.
-->

## Weakness classification

<!-- CWE chosen via https://cwe.mitre.org/documents/cwe_usage/guidance.html
     Say "likely CWE-xxx" if you are not certain. Never a Category or a View. -->

## Severity

<!--
DELETE THIS WHOLE SECTION if the project forbids severity scores. Django does:
"Please do not include severity scores (CVSS or otherwise)... The security team will
make those assessments."  https://docs.djangoproject.com/en/stable/internals/security/

Otherwise: Base metrics only, labelled CVSS-B, vector copied verbatim from the official
FIRST calculator (https://www.first.org/cvss/calculator/4-0 or
https://www.first.org/cvss/calculator/3.1). Threat and Environmental metrics belong to
the consumer, not the finder. Never include EPSS.
-->

## Prior art checked

<!--
A condensed version of disclosure/DUPLICATE_CHECK.md. Dates included.
This is one of the clearest signals that a submission is not slop - do not omit it.
-->

| Source | Query | Date (UTC) | Result |
|---|---|---|---|
| OSV.dev (package + version) | | | |
| OSV.dev (commit) | | | |
| GitHub Advisory Database (reviewed) | | | |
| GitHub Advisory Database (unreviewed) | | | |
| CVE Program / NVD | | | |
| Project advisories, changelog, release notes | | | |
| Issues and PRs, including closed | | | |
| Git history (`git log --all -S`) | | | |

<!-- If anything related was found and ruled out, name it and give the one sentence
     that distinguishes this finding from it. -->

## Suggested remediation

<!--
Concrete. A minimal diff if you have one - it materially raises acceptance rates.
Pull the recommended approach from the authoritative source rather than inventing one.
Never propose a redesign. Never propose a patch you have not compiled.
-->

## Disclosure timeline

<!--
State the window in THIS message, not later. Fill from PROCESS.md §6.
Say explicitly that it is negotiable and that you would rather extend than publish
an unpatched bug - that sentence prevents most timeline disputes.
-->

| | |
|---|---|
| Reported | <!-- YYYY-MM-DD --> |
| Proposed disclosure window | <!-- the project's stated policy if it has one; otherwise 90 days from acknowledgement --> |
| Earliest publication date | <!-- date --> |
| Negotiable? | Yes. Tell me if you need longer and I will extend; I would rather extend than publish an unpatched bug. |
| Known exploitation in the wild | <!-- "none observed" unless you have evidence. Do not speculate. --> |
| Who else has seen this | <!-- every person and system holding the detail. Be complete. --> |

## AI assistance

<!--
Required. Three lines. Tick the AI-assistance checkbox on GitHub's form as well.
Never list an AI as an author or co-author.
-->

- Tools used: <!-- name them -->
- What each did: <!-- analysis / trace construction / drafting / PoC authoring -->
- How the claims were verified: <!-- which human did what, and how -->

The named researcher below will answer every follow-up question personally, without AI assistance.

## Credit

<!--
A preference, never a demand. Reporting is not contingent on it.
Pick one and delete the rest:
  - "Credit as <name> if you publish an advisory, please - but no credit is fine."
  - "Please credit <name> / <handle>."
  - "I would prefer to remain anonymous."
-->

## Contact

<!-- Name, email, and optionally a PGP fingerprint and preferred languages.
     Offer a private channel for the PoC and a call if it would help. -->
