# findings/ — UNTRACKED WORKSPACE

**Everything in this directory except this README is gitignored, and that is deliberate.**

This is where in-progress vulnerability findings live: candidate bugs, confirmed bugs awaiting disclosure, draft reports, and disclosure correspondence.

This repository is **public**. A finding committed here before the maintainer ships a patch is an accidental zero-day disclosure — it exposes every user of the affected software, destroys your standing with the maintainer, and typically voids bounty eligibility. The `pre-commit` hook in `.githooks/` blocks commits touching this path. Do not `--no-verify` past it.

## Layout

One directory per finding, named with its local ID:

```
findings/
  F-2026-001-acme-lib-path-traversal/
    FINDING.md        # the finding record — see ../disclosure/templates/
    timeline.md       # dates: discovered, reported, acknowledged, patched, published
    correspondence/   # maintainer emails and advisory threads
```

Keep evidence (PoC inputs, crash dumps, traces) in `../evidence/` under the same finding ID, not here.

## Lifecycle

A finding moves through: `candidate` → `verified` → `reported` → `acknowledged` → `patched` → `published`.

Only at `published` — patch released and embargo expired — may any of it move into a public, tracked location, and only then if there is a reason to publish it at all.

## Retention

Once published, the finding record can be archived publicly as a writeup. Until then, treat this directory as confidential material belonging to the affected project's users, not to you.
