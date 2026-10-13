# Timeline Template

Copy this file to `findings/<id>/timeline.md` at the moment first contact is sent, and append to it in the same working session as every event. It is the dated record of one finding's disclosure, and it is the only artifact that makes a coordinator escalation or a later timeline dispute defensible.

Procedure that writes to this file: [../PROCESS.md](../PROCESS.md) §5. Lifecycle states: [../../findings/README.md](../../findings/README.md).

---

## Rules

1. **UTC, ISO 8601**, always: `2026-10-13T14:02:00Z`. Local times and "last Tuesday" are not acceptable.
2. **Append in the session the event happened.** Never reconstruct a timeline from memory later; a reconstructed timeline is worthless in an escalation and you will not remember which channel you used.
3. **Append-only.** Correct an error with a new row that says what was wrong. Do not edit history.
4. **Update `Embargo expiry` and `Next action` on every append.** A stale `Next action` is the failure this file exists to prevent.
5. An agent may draft and append rows. **A human performs every outbound action and records who performed it** ([../PROCESS.md](../PROCESS.md) §0.9).
6. `findings/` is gitignored and the pre-commit hook blocks it. That is deliberate. Do not `--no-verify` past it.

---

## Status

<!-- Keep this block at the top of the file and rewrite it on every append. -->

| | |
|---|---|
| Finding ID | <!-- F-YYYY-NNN-<project>-<slug> --> |
| Project / package | |
| Disclosure state | <!-- candidate / verified / reported / acknowledged / patched / published --> |
| Channel used | <!-- which row of PROCESS.md §2, and the exact URL or address --> |
| Stated window | <!-- the project's own policy, or 90 days from acknowledgement --> |
| **Embargo expiry** | <!-- absolute date. Recompute on every extension and record the new date here. --> |
| **Next action** | <!-- one sentence, imperative: "send day-7 reminder on the same channel" --> |
| **Next action due** | <!-- absolute date --> |
| Next action owner | <!-- the named human --> |
| Escalation state | <!-- none / foundation contacted / coordinator filed (VU#…) --> |
| Advisory ID | <!-- GHSA / CVE / PYSEC / RUSTSEC, or "none assigned" --> |

---

## Milestones

One row each. Leave `—` where it has not happened; do not delete the row, because an empty milestone is information.

| Milestone | Date (UTC) | By whom | Channel / reference | Notes |
|---|---|---|---|---|
| Discovered | | | | <!-- first time the candidate was written down --> |
| Duplicate check completed | | | | <!-- DUPLICATE_CHECK.md sweep, no rows left `inconclusive` --> |
| Human sign-off | | | | <!-- who signed, per finding.md §15 --> |
| Reported | | | | <!-- channel, recipient, and who sent it --> |
| Acknowledged | | | | <!-- the embargo clock starts here where no policy exists --> |
| Triaged | | | | <!-- maintainer's verdict: accepted / disputed / out of scope --> |
| Patch committed | | | | <!-- commit SHA --> |
| Patched release shipped | | | | <!-- version and release date --> |
| Advisory published | | | | <!-- GHSA URL; patched version recorded? --> |
| CVE assigned | | | | <!-- ID, and the assigning CNA --> |
| Ecosystem database entry | | | | <!-- PYSEC / RUSTSEC / ruby-advisory-db / Go PR link --> |
| Public writeup | | | | <!-- only after patch and embargo expiry, and only if there is a reason --> |
| Closed | | | | <!-- outcome: fixed / duplicate / rejected / withdrawn --> |

---

## Event log

Every event, including the ones that feel too small to log. Reminders, bounced email, a maintainer's one-line reply, an extension request, a decision not to escalate. The coordination forms ask for contact attempts **with dates** and a summary of communications; this log is that package.

| Timestamp (UTC) | Event | Actor | Channel | Detail | Correspondence file |
|---|---|---|---|---|---|
| | | | | | |

Event vocabulary — use these strings so the log is greppable:

`discovered`, `duplicate_check_completed`, `human_signoff`, `report_sent`, `report_bounced`,
`acknowledged`, `maintainer_reply`, `question_received`, `answer_sent`, `reminder_sent`,
`second_channel_attempted`, `foundation_contacted`, `coordinator_filed`, `triage_verdict`,
`dispute_opened`, `extension_requested`, `extension_granted`, `embargo_recomputed`,
`poc_sent`, `patch_committed`, `release_shipped`, `advisory_drafted`, `cve_requested`,
`cve_assigned`, `advisory_published`, `ecosystem_db_filed`, `writeup_published`,
`public_disclosure_memo_written`, `closed`

Store each exchange verbatim in `findings/<id>/correspondence/<timestamp>-<event>.md` and reference it in the last column. Verbatim means no commentary and no summarising; a paraphrase of a maintainer's words is not evidence.

---

## Extensions

Append a row here for every extension. The decision criteria are in [../PROCESS.md](../PROCESS.md) §6.3 and a human makes the call.

| Timestamp (UTC) | Requested by | Old expiry | New expiry | Reason given | Approved by |
|---|---|---|---|---|---|
| | | | | | |

---

## On close

Fill this in once, at close, then feed it back into the repo's templates ([../PROCESS.md](../PROCESS.md) §13).

| Metric | Value |
|---|---|
| Days to acknowledge | |
| Days to triage | |
| Days to patch | |
| Days to publish | |
| Which channel row from PROCESS.md §2 worked | |
| Which CNA or database assigned the identifier | |
| What in the report caused a follow-up question | |
| Which gate in RULES_OF_ENGAGEMENT.md §3 should have caught something earlier | |
| Credit outcome | |
