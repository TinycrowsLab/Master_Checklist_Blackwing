# evidence/ — UNTRACKED WORKSPACE

**Everything in this directory except this README is gitignored, and that is deliberate.**

This holds the artifacts that prove a finding: proof-of-concept inputs, crash dumps, stack traces, scanner output, request captures, and screenshots.

Two reasons none of it is tracked, in a public repository:

1. **A PoC for an unpatched bug is an exploit.** Publishing it before a patch exists arms attackers against every user of the software.
2. **Scanner output and captures carry target source and environment detail** that you have no business republishing.

See [../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §4 for PoC discipline — minimal, local-only, not weaponized.

## Layout

Mirror the finding ID used in `../findings/`:

```
evidence/
  F-2026-001-acme-lib-path-traversal/
    repro.sh          # exact steps, runnable from clean state
    input/            # minimal triggering input
    output/           # traces, crash logs, scanner results
    env.md            # versions, OS, commit SHA, container image digest
```

## Reproducibility bar

The gate in `RULES_OF_ENGAGEMENT.md` §3 requires a finding be reproduced from a **clean state**. That means `repro.sh` must work on a fresh container with nothing cached from your earlier attempts — a PoC that only fires on your dirty working copy is not a reproduction, and maintainers will discover that faster than you will.

Record exact versions in `env.md`. "Latest" is not a version; a commit SHA and an image digest are.
