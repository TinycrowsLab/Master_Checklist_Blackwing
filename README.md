# Master Checklist: Blackwing

An operating playbook that an AI coding agent reads and executes to help a human security researcher audit open-source projects and prepare coordinated disclosures. It is written for an agent as ordered phases with explicit entry conditions, decision criteria and stop conditions, not as advice for a human to skim. Its purpose is to make a small number of defensible findings instead of a large number of plausible ones.

> [!WARNING]
> **This repository is PUBLIC.**
>
> - `findings/` and `evidence/` are **untracked**. Everything in them except their `README.md` is gitignored, and that is deliberate.
> - **Never commit an unpatched finding.** Committing one here is an accidental zero-day disclosure: it exposes every user of the affected software, destroys your standing with the maintainer, and typically voids bounty eligibility.
> - On **every fresh clone**, run `git config core.hooksPath .githooks` or the safety hook is inert. Nothing enforces this for you — `.githooks/` is not active until you point git at it.
> - `git commit --no-verify` bypasses the hook. That flag is for emergencies, not for silencing a complaint you disagree with.

## Non-negotiables

Full text in [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md), which overrides every other file here.

1. **Read public source freely. Test only what you deployed yourself** — your clone, your container, your emulator. Never a third-party production system, absent an explicit written bounty scope naming the asset.
2. **No scanning, enumerating or fingerprinting hosts you do not own. No DoS.** No using a credential you found in a target, not even to check whether it still works ([SECRETS_HYGIENE.md](SECRETS_HYGIENE.md)).
3. **Human sign-off gate.** An agent may analyse, write candidate findings and build local PoCs. An agent may not send, file, submit, publish or otherwise transmit anything to a maintainer or a platform. Those are human actions.
4. **A candidate finding is not a finding.** Reproduced from a clean state, root cause at `file:line`, affected versions determined by testing, impact stated honestly with preconditions, duplicate check completed, human agrees. If a check cannot be completed, it does not ship. When in doubt, do not report.
5. **PoCs are minimal, local-only and not weaponized.** Proving the bug exists is the whole goal.
6. **Severity may never exceed demonstrated impact.**
7. **Uncertainty is a stop condition**, not a problem to think past.

## Repo map

| Path | What it is for | Read by |
|---|---|---|
| [README.md](README.md) | This file: orientation, warnings, repo map, how to start | Human |
| [PLAYBOOK.md](PLAYBOOK.md) | **The spine.** Phases 0-10 with entry conditions, steps, exit criteria and stop conditions | Agent, end to end |
| [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md) | Binding constraints. Overrides every other file, including this one | Both, first |
| [SECRETS_HYGIENE.md](SECRETS_HYGIENE.md) | Your own credentials; credentials found inside a target (never authenticate) | Both |
| [TARGETS.md](TARGETS.md) | The target qualification gate. A gate, not a shopping list | Agent, Phase 1 |
| `setup.sh` | One-shot clone setup: installs the hooks path, checks tooling | Human, once per clone |
| `.githooks/pre-commit` | Blocks commits touching protected paths or carrying credential patterns | Git |
| `.gitignore` | Keeps findings, evidence, target checkouts and scanner output untracked | Git |
| [skills/oss-vuln-audit/SKILL.md](skills/oss-vuln-audit/SKILL.md) | Thin skill entrypoint; routes into the playbook phases | Agent, on trigger |
| [skills/oss-vuln-audit/ATTACK-CLASSES.md](skills/oss-vuln-audit/ATTACK-CLASSES.md) | Router: target shape to attack class to one deep reference file | Agent, Phase 3 |
| [skills/oss-vuln-audit/VERIFICATION.md](skills/oss-vuln-audit/VERIFICATION.md) | Refutation procedure, the three verdicts, clean-state reproduction, PoC limits | Agent, Phases 5-6 |
| `skills/oss-vuln-audit/references/p1-package-ecosystems.md` | P1 deep reference: language package ecosystems | Agent, one of four |
| `skills/oss-vuln-audit/references/p2-web-api-cms.md` | P2 deep reference: web apps, APIs, CMS plugins | Agent, one of four |
| `skills/oss-vuln-audit/references/p3-devops-infra.md` | P3 deep reference: DevOps and infrastructure tooling | Agent, one of four |
| `skills/oss-vuln-audit/references/p4-mobile.md` | P4 deep reference: mobile applications | Agent, one of four |
| [disclosure/PROCESS.md](disclosure/PROCESS.md) | Recipient lookup order, first message, reminder ladder, escalation, timelines | Human, Phase 10 |
| [disclosure/CVE_AND_CNA.md](disclosure/CVE_AND_CNA.md) | CVE eligibility pre-flight and the identifier request routes | Human, Phase 10 |
| [disclosure/DUPLICATE_CHECK.md](disclosure/DUPLICATE_CHECK.md) | The ordered prior-art sweep and silent-fix detection | Agent, Phase 8 |
| [disclosure/templates/](disclosure/templates/) | Report, advisory, AI-use disclosure and email drafts a human fills and sends | Both, Phase 9 |
| [reference/RESOURCES.md](reference/RESOURCES.md) | Annotated external sources with verification status and what each one supports | Both |
| [reference/SEVERITY.md](reference/SEVERITY.md) | Honest impact, CVSS-B scoring and over-scoring traps, CWE selection, exclusion buckets | Agent, Phase 7 |
| [reference/TOOLING.md](reference/TOOLING.md) | Tool inventory, sandbox construction, invocation forms | Agent, Phases 0 and 2 |
| [schemas/finding.schema.json](schemas/finding.schema.json) | Machine-checkable finding contract: verdicts, traces, conditions, severity, sign-off | Agent, Phases 4-9 |
| `findings/` | **Untracked.** Candidates, verdicts, drafts, per-finding timelines | Both |
| `evidence/` | **Untracked.** PoCs, sanitizer output, crash traces, scanner logs | Both |

## How to start a hunt

Fresh clone first:

```bash
git config core.hooksPath .githooks   # required once per clone, or the safety hook is inert
./setup.sh                            # verifies the above and checks tooling
```

Then point an agent at the repo with this, filling in the target:

```
Read RULES_OF_ENGAGEMENT.md, then PLAYBOOK.md. Execute Phase 0 against
<repository URL>. Work the phases in order, record everything in the coverage
ledger, and halt at the Phase 9 human sign-off gate. Do not transmit anything.
```

The agent's reading order, which `PLAYBOOK.md` enforces phase by phase:

1. [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md), then [SECRETS_HYGIENE.md](SECRETS_HYGIENE.md) — before anything else.
2. [PLAYBOOK.md](PLAYBOOK.md) — the whole file, before acting on any phase.
3. [TARGETS.md](TARGETS.md) — Phase 1 gate.
4. [reference/TOOLING.md](reference/TOOLING.md) — Phases 0 and 2.
5. [skills/oss-vuln-audit/ATTACK-CLASSES.md](skills/oss-vuln-audit/ATTACK-CLASSES.md), then **exactly one** P-file — Phase 3.
6. [skills/oss-vuln-audit/VERIFICATION.md](skills/oss-vuln-audit/VERIFICATION.md) — Phases 5 and 6.
7. [reference/SEVERITY.md](reference/SEVERITY.md) — Phase 7.
8. [disclosure/DUPLICATE_CHECK.md](disclosure/DUPLICATE_CHECK.md) — Phase 8.
9. [disclosure/templates/](disclosure/templates/) — Phase 9, then stop.

`disclosure/PROCESS.md` and `disclosure/CVE_AND_CNA.md` are for the human on the far side of the gate.

## Priority order of target classes

| | Class | Why here |
|---|---|---|
| **P1** | Language package ecosystems (npm, PyPI, crates.io, Maven, Go, RubyGems) | The published source *is* the shipped artifact, the whole audit runs offline in a container, one bug fans out to every dependent, and per-package advisory coverage in OSV and GHSA makes duplicate checking cheap and version ranges precise. Best findings per hour, and the lowest chance of straying out of scope. |
| **P2** | Web apps, APIs, CMS plugins | Large surface and well-understood bug classes, but verification needs a running instance — so it must be one you deployed, and the pull toward someone else's install is the single most common way researchers cross the line. |
| **P3** | DevOps and infrastructure tooling | High blast radius, but a large share of candidates land in deployment-and-configuration territory that maintainers correctly reject, so the Phase 1 scope reading matters more here than anywhere else. |
| **P4** | Mobile applications | Slowest loop — unpack, emulator, instrument — findings are usually app-specific rather than library-wide, and much of what looks broken sits inside the platform's documented threat model. |

Priority is about expected value per hour, not about which bugs matter. A qualified P4 target beats an unqualified P1 one; the gate in [TARGETS.md](TARGETS.md) comes first either way.

## What this repo is NOT

- **Not a list of easy targets.** [TARGETS.md](TARGETS.md) is a qualification gate that refuses work. There is no curated list of soft projects here and one will not be added.
- **Not an autonomous reporting bot.** The agent halts at Phase 9, always. Nothing reaches a maintainer without a human who has re-read the code, re-run the PoC, and can defend the finding in a conversation.
- **Not a volume CVE farm.** One strongest finding at a time, then wait for the maintainer's response. Batch submissions are a documented harm, not a throughput strategy.

The quality gates exist because junk reports do measurable damage. Roughly 20% of curl's 2025 security submissions were AI slop at about two per week, only about 5% were genuine, and each one consumed several members of a seven-person security team ([Death by a thousand slops](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/)); curl went on to suspend vulnerability intake for a full month ([What the bliss taught us](https://daniel.haxx.se/blog/2026/08/03/what-the-bliss-taught-us/)). Django now closes reports that look like unverified AI output without responding ([security policy](https://docs.djangoproject.com/en/stable/internals/security/)), and maintainers triaging CPython, pip and urllib3 have asked publicly not to be sent unreviewed AI findings ([New era of slop security reports](https://sethmlarson.dev/slop-security-reports)). When an AI tool handed curl's team five findings it had labelled confirmed, [one survived review](https://daniel.haxx.se/blog/2026/05/11/mythos-finds-a-curl-vulnerability/). A rejected report costs a volunteer their evening and costs you a reputation that does not come back.

## Licence and attribution

Licence: **TBD** — a `LICENSE` file will be added here. Until then, no licence is granted beyond reading.

Third-party material is **cited, not vendored.** No upstream text, ruleset, advisory or target source is copied into this repository. Where another project's wording is load-bearing it is quoted briefly, linked, and recorded with its own licence in [reference/RESOURCES.md](reference/RESOURCES.md) — which matters because some referenced sources are share-alike and would otherwise propagate their terms into this repo's text. Structural debts, chiefly to [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) and [OWASP/secure-agent-playbook](https://github.com/OWASP/secure-agent-playbook), are recorded in the Provenance section of [PLAYBOOK.md](PLAYBOOK.md).
