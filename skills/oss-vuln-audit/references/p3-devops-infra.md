# P3 — DevOps, infrastructure, and cloud-native tooling

The deep reference for auditing Kubernetes components, operators and controllers, admission webhooks, CI/CD systems and actions, IaC providers and scanners, container runtimes, and GitOps control planes. Read it in full when [../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §1 routes a target here, before hunting — and work section 2 before section 3, because in this dimension most wasted effort is spent on candidates that were never vulnerabilities in the tool at all.

Nothing here relaxes [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md). Every dynamic step below runs on a cluster, runner, registry, or fork **you deployed in your own account**, in the container discipline of [../SKILL.md](../SKILL.md) §3.

## Contents

1. [Scope, hard rules, and the ordered flow](#1-scope-hard-rules-and-the-ordered-flow)
2. [The central distinction: the tool's code vs someone's deployment](#2-the-central-distinction-the-tools-code-vs-someones-deployment)
3. [CI/CD and pipeline security](#3-cicd-and-pipeline-security)
4. [Where real code vulnerabilities live](#4-where-real-code-vulnerabilities-live)
5. [Configuration and posture scanners](#5-configuration-and-posture-scanners)
6. [Supply chain and provenance — detection and defence only](#6-supply-chain-and-provenance--detection-and-defence-only)
7. [Not a vulnerability in this class](#7-not-a-vulnerability-in-this-class)
8. [Severity, duplicates, and routing](#8-severity-duplicates-and-routing)
9. [Verified sources](#9-verified-sources)

## 1. Scope, hard rules, and the ordered flow

### 1.1 Does this file apply?

| The target is | Read this file | Note |
|---|---|---|
| A Kubernetes operator, controller, CRD-driven tool, or admission webhook | Yes | The core case. Sections 2, 4, 5. |
| A CI/CD system, GitHub Action, reusable workflow, or pipeline plugin | Yes | Section 3 is the whole audit for most of these. |
| An IaC provider, chart renderer, or config/posture scanner | Yes | It parses untrusted manifests and renders templates — section 4, D3 and D5. |
| A container runtime, image builder, or registry client | Yes | Isolation boundary code; section 4, D3 and D4. |
| A GitOps control plane (repo-server, applier, UI) | Yes | Sections 4 D1/D3 and 3. |
| An agent or daemon that holds cloud credentials | Yes | Section 4, D2 and D6. |
| A CLI distributed as an npm/PyPI/Go package | P1 first | Install hooks and dependency resolution are P1. Return here for credential and runner behaviour. |
| An operator with a web dashboard | P3 first, then P2 | The operator's privilege is the impact multiplier. |

**Stop condition.** If the target does not fit a row, do not improvise a file. Say what it is and ask the researcher ([../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §1).

### 1.2 Hard rules specific to this dimension

These are applications of the ROE, not additions to it. Each has a specific way of being broken in this dimension.

1. **No cluster, runner, registry, or API endpoint you do not own, ever.** Not a probe, not a single `curl`, not "just to check the version". A vulnerability in an operator grants nothing regarding a cluster you found (ROE §1).
2. **Never open a pull request against the upstream repository to test a workflow finding.** A PR executes code on the maintainer's runners, in the maintainer's trust context, against the maintainer's secrets. That is a live attack on a third-party system, regardless of intent. Reproduce in a fork inside **your own org** with **your own worthless canary secrets** (section 3.6).
3. **No enumeration or sweeping.** Pipeline tools with org-wide modes get pointed at the single repository you already cloned, never at an org you do not own (section 5.2).
4. **No exposure hunting.** Several sources cited here contain vendor statistics gathered by internet-wide scanning. Cite them for the **code defect and mechanism**; never adopt "find exposed instances" as a step.
5. **PoC ceiling.** A marker file, an injected directive that resolves to a sentinel, an assertion failure, a request arriving at your own listener. No library loading, no credential theft, no chaining past the proof (ROE §4).
6. **Severity ceiling.** What your local reproduction showed, from the privilege you actually started with (ROE §3.4).

### 1.3 The ordered flow

Run in order. Each step names the condition under which you stop and move on.

| # | Step | Do | Stop condition |
|---|---|---|---|
| 0 | Scope attestation | Write into the run notes: clone origin, **commit SHA**, release version under test; the sandbox (throwaway VM + `kind`/`minikube`, your own registry, your own GitHub org); and the sentence "no request will be sent to a cluster, runner, registry, or endpoint we do not own." | Any of the three cannot be written truthfully → **no dynamic work**. Static source reading may continue. |
| 0b | The project's own rules | Collect `SECURITY.md`, the Security tab (is [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) enabled?), `docs/security/`, any threat-model or "security model" page. Record **verbatim**: report channel, stated embargo, declared in/out of scope, and what the project documents as the *operator's* responsibility. | No disclosure channel at all → qualification problem, back to [../../../PLAYBOOK.md](../../../PLAYBOOK.md) Phase 1. |
| 1 | Trust boundary map (one page, before any grep) | Enumerate: every listening port or endpoint **and who can reach it** (anonymous in-cluster pod? only the API server? only localhost?); every input crossing lower→higher trust (CR fields, annotations, Git repo contents, Helm values, webhook payloads, workflow event payloads, image labels, cloud tags); the identity each component runs as (ServiceAccount, cloud role, `GITHUB_TOKEN`). | A candidate that moves neither data nor control **across a line on this map** is not a finding. Delete it. |
| 2 | Classify every candidate | Section 2. Tag `VULN` / `MISCONFIG` / `GREY` in the notes file **before** investing time. | `MISCONFIG` → vuln work stops here. |
| 3 | Audit the repository's own CI/CD | Section 3. Highest yield in this dimension and needs no cluster. | Workflows absent or trivially `pull_request`-only with no secrets → record as covered, move on. |
| 4 | Work the code classes | Section 4, D1 → D8 in order. | A class the target cannot contain (no webhook, no archive handling) is skipped **on a stated reason**, which is coverage; skipped silently, which is not. |
| 5 | Scanner battery on shipped artifacts | Section 5. Expect `MISCONFIG` output and triage it there. | Nothing in the output is evidence for a code-level finding → none of it enters the report. |
| 6 | Posture and supply chain | Section 6, as **context only**. Record in the notes that this layer produced no vulnerability findings. | Always. "Not SLSA L3" and "fails a CIS control" are never reported as vulnerabilities. |
| 7 | Local sandboxed reproduction | `kind` in a throwaway VM, target installed from its own chart/bundle at the pinned version. Reproduce from the **minimum** capability matching the claimed precondition: an unprivileged pod in a non-`kube-system` namespace, a user with no RBAC, or an anonymous network client. Verify the **inverse** too — that it does *not* reproduce on the patched version or with the mitigating setting. | Cannot reproduce from clean state → not a finding ([../VERIFICATION.md](../VERIFICATION.md)). It stays a note. |
| 8 | Severity and write-up | Section 8. | Severity above demonstrated impact → rewrite it. |
| 9 | Route to one channel; **the human sends** | Section 8.3 and [../../../disclosure/PROCESS.md](../../../disclosure/PROCESS.md). | The agent never transmits (ROE §2). |

## 2. The central distinction: the tool's code vs someone's deployment

**A misconfiguration in someone's deployment is not a vulnerability in the tool, and it gets no CVE. A defect in the tool's own code — including in a default it ships — is.**

This single confusion produces a large share of rejected reports in this dimension, because cloud-native tooling is mostly *about* configuration, so configuration findings feel like security findings. They are not the same object:

- A **deployment misconfiguration** is fixed by the person running the software, by editing their own manifest, chart values, or cluster settings. The maintainer cannot patch it and there is nothing to version. Whether it can even become a CVE is governed by the CVE Program's own product-scope and independent-fixability rules ([CNA Operational Rules](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf) — open it before quoting any rule number from it).
- A **vulnerability in the tool** is fixed by the maintainer changing code or a shipped default, and the fix lands in a release. A user who followed the project's documented guidance was still exposed.

### 2.1 The classification gate — run it on every candidate

Do this before reading more code, before writing a PoC, before scoring anything.

1. Write the candidate as one sentence: *who* sends *what* to *which component*, and what happens.
2. Answer three questions in the notes file:
   - **(a) Who fixes it?** If the fix is an edit to the operator's own manifest or cluster settings, it is `MISCONFIG`. If the fix is a patch to code or a shipped default, it is `VULN`.
   - **(b) Is a user who follows the project's documented guidance still exposed?** If yes, that pushes toward `VULN` even when a setting exists to avoid it.
   - **(c) What privilege does the attacker start with?** If it already equals or exceeds what the bug grants — `cluster-admin`, node root, the ability to run privileged pods, write access to the cluster's manifests — there is **no boundary crossing and no finding**.
3. Tag the entry `VULN`, `MISCONFIG`, or `GREY`.
4. **If `MISCONFIG`: stop the vulnerability work.** At most it becomes a hardening or documentation issue on the project's **public** issue tracker, and only if it affects the default installation path (section 5.4). It never goes through the security channel.
5. **If `GREY`: use the protocol in 2.3.**
6. **If `VULN`: continue** to the matching class in section 4 (or section 3 for a pipeline finding) and to the evidence bar in [../VERIFICATION.md](../VERIFICATION.md).
7. **Never promote `MISCONFIG` to `VULN` without new evidence**, and record in the notes what the new evidence was. Re-reading the same code and feeling more strongly is not evidence.

### 2.2 Paired examples

Work the table until the pairs feel obvious. Each left-hand entry is the thing beginners report; each neighbouring entry is the real finding it gets confused with.

| Candidate | Verdict | Why |
|---|---|---|
| A cluster runs privileged pods and a container escapes to the host | **Not a finding** | The operator chose the privilege. The [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) page states the Privileged profile allows for known privilege escalations — that is the documented meaning of the setting. |
| An operator takes a path from a custom resource field and writes outside its volume | **VULN** | Lower-trust input crosses into the operator's filesystem authority ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)). |
| The quickstart manifest binds a ClusterRole with `"*"` verbs | **MISCONFIG** (shipped-artifact hardening, public issue) | The deployer can edit the manifest; no code is defective. See 5.4 for routing. |
| The controller's ClusterRole grants cluster-wide `secrets` `list` and the docs say it needs it | **Not a finding** | Documented requirement; the privilege is the design. Reconsider only if the code reads secrets it has no functional need for (D8). |
| The tool's admission webhook accepts an `AdmissionReview` from any pod, unauthenticated | **VULN** | An unauthenticated in-cluster caller reaches privileged behaviour — the shape at the centre of [IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities). |
| `kube-bench` reports twelve FAILs on your own cluster | **Posture** | A benchmark deviation in a deployment. Not reportable to anyone, including you. |
| The tool's registry client defaults to `InsecureSkipVerify: true` | **VULN / GREY** | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) plus [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html). File privately; let the maintainer and the CNA decide. |
| `values.yaml` exposes `insecureSkipVerify`, default `false`, documented | **MISCONFIG** | The safe path is the default; the consumer declined it. |
| A workflow interpolates `${{ github.event.issue.title }}` into a `run:` block on `issue_comment` | **VULN in that repository** | Attacker-controlled input reaches a shell in a privileged context. It is a defect in code the project ships, not a deployment choice (section 3). |
| The README shows an example Pod with `hostPath: /` | **Not a finding** | An example manifest for documentation. See section 7. |
| A policy engine inspects only `request.object` on UPDATE, so a forbidden value can be introduced by updating an existing object | **VULN** | Policy bypass by request shape alone — [CVE-2021-25735](https://github.com/kubernetes/kubernetes/issues/100096). |
| An attacker with `cluster-admin` can make the operator delete a namespace | **Not a finding** | `cluster-admin` sits above the boundary. Nothing was crossed. |
| A controller dials a URL taken from a CR field with no allowlist, and reflects the response length | **VULN** | SSRF from a control-plane component reaching link-local metadata — [CVE-2020-8555](https://github.com/kubernetes/kubernetes/issues/91542). Score it honestly against IMDSv2 (D6). |

### 2.3 The grey zone: an insecure default that is documented

This is the most contested boundary in this dimension, and the protocol is fixed:

1. The default is **on the production install path** — default chart values, the quickstart manifest, the operator bundle — and a user following the documentation is exposed. Write it up as an **insecure-default finding**, cite [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html), state plainly that the project documents the setting, and file it **privately** anyway. The maintainer and the CNA decide whether it is a CVE; that is their call, not yours.
2. The insecure default exists only in a mode the documentation labels for local development, and the production path differs — that is section 7, not a finding.
3. **Do not argue the classification in public.** No issue comment, no post, no thread. If the maintainer disagrees, the answer is "understood", and the note goes in your own records.
4. One line in every report of this type: *why this is a code-level defect rather than a deployment misconfiguration.* That sentence saves a round trip and is often the difference between triage and dismissal.

## 3. CI/CD and pipeline security

Weight this heavily. It is the highest-yield area in the dimension, it needs no cluster, and the finding classes have names, vendor documentation, and linter rule ids you can cite — which makes reports short and credible.

**Two hats, and you must know which one you are wearing:**

- **The target's workflows are a finding class.** A workflow file is code the project ships and the maintainer patches. An injection in it is a vulnerability **in that repository**, not a misconfiguration (section 2.2).
- **Our own workflows are hygiene.** Findings against this repository's own `.github/workflows/` get fixed here, in a normal commit. They are never written into `findings/` and never reported anywhere.

### 3.1 Trigger and context model

The whole dimension of CI/CD risk is: *does this trigger run in the base repository's context, with its secrets and a write-capable token, while handling input or code the attacker controls?*

| Trigger | Runs with base-repo secrets / write-capable token | Audit weight |
|---|---|---|
| `pull_request` (from a fork) | No — restricted context | Low, unless it checks out and executes untrusted code on a self-hosted runner, or writes a cache a privileged job later restores |
| `pull_request_target` | **Yes** | **Highest.** Combined with checking out the PR head, this is the pwn-request shape |
| `workflow_run` | **Yes** | **Highest.** It consumes artifacts and metadata produced by a lower-trust run |
| `issue_comment`, `issues` | **Yes** | High — comment and title bodies are attacker-controlled |
| `schedule`, `push`, `release` | **Yes** | Medium — look for attacker-influenced refs, branch names, and commit messages |

Confirm the exact context for any trigger you are about to name in a report against the [events reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), and the exact meaning of a context field against the [contexts reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). Reachability is half the report; do not assert it from memory.

### 3.2 Attacker-controllable context fields

Treat every one of these as untrusted input. The enumeration is from [GitHub Security Lab, untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/):

```
github.event.issue.title            github.event.issue.body
github.event.pull_request.title     github.event.pull_request.body
github.event.comment.body           github.event.review.body
github.event.pages.*.page_name      github.event.commits.*.message
github.event.head_commit.message    github.event.head_commit.author.email
github.event.head_commit.author.name
github.event.pull_request.head.ref  github.event.pull_request.head.label
github.event.pull_request.head.repo.default_branch
github.head_ref
```

The vulnerable pattern and its fix are both given verbatim on that page: interpolating one of these directly into a `run:` block is the bug; passing it through an **intermediate environment variable** and referencing `"$VAR"` is the fix. The vendor statement of the same rule, plus the untrusted-checkout, token-permission, action-pinning and self-hosted-runner guidance, is the [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use).

### 3.3 The finding shapes

| Shape | Mechanism | Name it as | Proof obligation |
|---|---|---|---|
| **Template / code injection** | An attacker-controlled context field is interpolated into a `run:` block, an action input, or a `script:` and is evaluated by a shell or interpreter | zizmor `template-injection`; CodeQL `actions/code-injection/{critical,medium}`; Checkov `CKV_GHA_2` | The field, the trigger that carries it, and the interpreter that evaluates it |
| **Pwn request** | `pull_request_target` runs with a write-capable token and secrets; the workflow checks out the fork's head and then executes it (`npm install`, build scripts, test runner) | "pwn request" — [GitHub Security Lab, part 1](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/); CodeQL `actions/untrusted-checkout/{critical,high,medium}` | The privileged trigger, the checkout of `head.sha`/`head.ref`, and the step that executes checked-out code |
| **Checkout TOCTOU** | A gate (label, approval, review) is satisfied, then the attacker pushes a new commit before the privileged job resolves the ref | CodeQL `actions/untrusted-checkout-toctou/*`; the label-gating race is called out in part 1 | That the ref is resolved after the gate rather than pinned to the approved SHA |
| **Cache poisoning** | A lower-trust job writes a cache entry (or its credentials leak) and a privileged workflow restores it | zizmor `cache-poisoning`; CodeQL `actions/cache-poisoning/{code-injection,direct-cache,poisonable-step}`; [Adnan Khan, build cache](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/) | Which job writes the key and which privileged job restores it |
| **`GITHUB_ENV` / `GITHUB_PATH` write** | Attacker-influenced content is appended to these files, which is code execution in later steps | zizmor `github-env` | The write, the content source, and a later step that consumes it |
| **Credential persistence** | `actions/checkout` leaves the token in `.git/config`, where any later step or cached artifact can read it | zizmor `artipacked`; fix is `persist-credentials: false` | A later step or artifact that can read it |
| **Secrets over-exposure** | `secrets: inherit`, `toJSON(secrets)`, secrets in artifacts, unmasked values in logs | zizmor `secrets-inherit`, `overprovisioned-secrets`; CodeQL `actions/secret-exfiltration`, `actions/excessive-secrets-exposure`, `actions/secrets-in-artifacts`, `actions/unmasked-secret-exposure`; Checkov `CKV_GHA_3`, `CKV_GHA_4` | Which secret reaches which lower-trust step, job, or artifact |
| **Unpinned or impostor `uses:`** | `uses:` is code execution with access to `GITHUB_TOKEN` and same-job secrets even when the workflow never references them; a mutable ref lets the action's content change under you | zizmor `unpinned-uses`, `impostor-commit`, `ref-confusion`, `ref-version-mismatch`, `typosquat-uses`, `known-vulnerable-actions`; CodeQL `actions/unpinned-tag`, `actions/unversioned-immutable-action`, `actions/vulnerable-action` (CWE-1395) — mechanism in [part 3](https://securitylab.github.com/resources/github-actions-building-blocks/) | The ref style (branch < tag < short hash < full commit SHA) and what the job holds |
| **Self-hosted runner exposure** | A non-ephemeral self-hosted runner attached to a public repo executes fork code and keeps state between jobs; fork-PR approval only gates a contributor's **first** run | zizmor `self-hosted-runner`; [Adnan Khan, runner images](https://adnanthekhan.com/2023/12/20/one-supply-chain-attack-to-rule-them-all/) | `runs-on:` plus the trigger, plus whether the runner is ephemeral. Describe the precondition exactly using the [fork-approval control](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks) |
| **Insecure commands** | `ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables the deprecated stdout command protocol | zizmor `insecure-commands`; Checkov `CKV_GHA_1` | The env var's scope, and a step whose output an attacker influences |
| **Excessive permissions** | `permissions: write-all` or a missing top-level `permissions` block | zizmor `excessive-permissions`; Checkov `CKV2_GHA_1` | Usually hygiene on its own; it is the **impact multiplier** cited alongside one of the shapes above |
| **Hardcoded container credentials** | Registry credentials literal in the workflow | zizmor `hardcoded-container-credentials` | Scope of the credential; follow [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2 and never authenticate with it |

For the vendor-neutral category label a maintainer will recognise — poisoned pipeline execution, insufficient flow control, dependency-chain abuse, insufficient PBAC — use the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/). For the full query taxonomy, [CodeQL's Actions CWE coverage](https://codeql.github.com/codeql-query-help/actions-cwe/).

### 3.4 The workflow audit procedure

Run all of it. The linters and the hand-read catch different things: linters miss composition across jobs, and a hand-read misses shell-level bugs.

1. **Run the battery, keep the raw output** under `../../../evidence/{ID}/tools/`:
   ```
   actionlint
   zizmor .                      # then: zizmor --persona=auditor .
   poutine analyze_local .
   checkov -d . --framework github_actions
   ```
   Run [`actionlint`](https://github.com/rhysd/actionlint) first: it type-checks expressions, validates action inputs and outputs and reusable-workflow signatures, and runs shellcheck and pyflakes over `run:` scripts, which is a layer the others do not have. Cite a hit as a named check from the [actionlint check list](https://github.com/rhysd/actionlint/blob/main/docs/checks.md). [`zizmor`](https://github.com/zizmorcore/zizmor) carries the security audit set; map each hit to a rule name from the [audit reference](https://docs.zizmor.sh/audits/). [`poutine`](https://github.com/boostsecurityio/poutine) adds GitLab CI coverage and a build-dependency inventory; prefer `analyze_local` on your clone, and if you use a repo mode, point it at the single target repository with a read-only fine-grained token — never an org-wide sweep (1.2.3).
2. **Read every workflow and composite action by hand.** Grep pack:
   ```
   rg -n 'pull_request_target|workflow_run|issue_comment|discussion_comment|^\s*issues:' .github/
   rg -nE '\$\{\{\s*github\.(event|head_ref)' .github/
   rg -n 'persist-credentials|secrets: inherit|toJSON\(secrets|ACTIONS_ALLOW_UNSECURE_COMMANDS' .github/
   rg -n 'runs-on:.*self-hosted' .github/
   rg -n 'actions/cache|GITHUB_ENV|GITHUB_PATH' .github/
   rg -nE 'uses:\s*[^@]+@(main|master|v[0-9.]+)\s*$' .github/
   rg -n 'permissions:' .github/        # note where it is ABSENT at top level
   ```
3. **For each hit, prove the chain end to end.** A hit is not a finding until you can write all four links: **privileged trigger → attacker-controlled field or attacker-controlled code checked out → a sink that executes (`run:` block, build script, action input, cache restore in a later privileged job) → what the executing context holds (token scope, which secrets)**. If any link is missing, record it rejected with the missing link named.
4. **Check composition, which the linters miss.** Does an unprivileged `pull_request` job upload an artifact that a `workflow_run` job unpacks and executes? Does a reusable workflow called with `secrets: inherit` run a step whose input comes from the event? Does a matrix leg run on a self-hosted runner while the others do not?
5. **Classify.** A workflow defect in the **target's** repository is `VULN` against that repository. The same defect in **our** repository is hygiene — fix it here and move on (3.7).
6. **Then stop grepping and reproduce** exactly one or two strongest chains (3.5).

### 3.5 Reproducing a pipeline finding safely

1. Fork the target into **your own org** — or better, build a minimal repository that contains only the vulnerable workflow shape, copied verbatim from the target with the commit SHA recorded.
2. Add a **canary secret with no value** (`CANARY=not-a-real-secret`). Never a real credential, never one found in the target.
3. Trigger it from an account you control, with a benign marker: echo the canary's length, write a marker file, or print a sentinel. Capture the run log.
4. Record: target repo and commit SHA, the workflow file and line, the trigger used, the input, the observed effect, and the token scope the job held.
5. **Never** do any of these: open or push to a PR on the upstream repository; trigger upstream's runners by any means; read, use, or exfiltrate an upstream secret; register a runner anywhere but your own org; publish the reproducer repository while the bug is unfixed.

### 3.6 Reporting a workflow finding

State the trigger and the context explicitly, because that is what the maintainer will check first: *"On `pull_request_target`, step X at `.github/workflows/ci.yml:42` interpolates `github.event.pull_request.title` into a `run:` block; the job holds `contents: write` and `secrets.NPM_TOKEN`."* Then the class name, the rule id, the four-link chain, and the fix shape from the vendor documentation (intermediate environment variable; split into an unprivileged producer plus a privileged `workflow_run` consumer; `persist-credentials: false`; pin to a full-length commit SHA).

### 3.7 Our own repository, as hygiene

Run the same battery against this repository periodically. The output is a to-do list for this repo, not findings. Keep the two apart in writing: nothing from this run is ever described as a vulnerability in anything, and nothing from it goes into `findings/`.

## 4. Where real code vulnerabilities live

Eight classes, in the order to work them. Every block has the same six fields: **Class**, **Lives in**, **Grep**, **Trace**, **Disproved by**, **Confirm with**. Grep finds candidates; findings are made by tracing to an entrypoint on the section 1.3 boundary map. Try the disproof **before** writing anything down.

Examples are Go-first because most cloud-native tooling is Go; JVM and Python equivalents are given where the class differs.

### D1 Control-plane authentication and authorization

**Class.** An endpoint the tool exposes reaches privileged behaviour without authenticating the caller, or an authorization check misses a dimension (a resource kind, a subresource, a verb, an operation). The highest-severity class in this dimension.

**Lives in.** Every listener the tool opens: metrics and health ports that grew features, gRPC services, repo-servers, webhook receivers, agent callbacks, UI and API servers, aggregated API servers.

**Grep.**
```
rg -n 'ListenAndServe|http\.Server\{|grpc\.NewServer|net\.Listen|mux\.NewRouter' --glob '*.go'
rg -n 'SubjectAccessReview|TokenReview|SelfSubjectAccessReview|authorizer\.|Authorize\(|Authenticate\(' --glob '*.go'
rg -n 'AdmissionReview|admission\.Request' --glob '*.go'
rg -ni 'anonymous|system:unauthenticated|insecure[-_]?port|allow[-_]?unauthenticated' --glob '*.go'
rg -n 'ParseUnverified|jwt\.Parse\(|ParseWithClaims|DecodeSegment' --glob '*.go'
```

**Trace.** From each listener to its router, then to the **first** authorization decision on each route. Look for: routes registered outside the authenticated middleware; early `return nil`/`return true` in a decision function; a feature flag that skips verification (the [Argo CD CVE-2022-29165](https://github.com/advisories/GHSA-r642-gv9p-2wjj) shape — anonymous access enabled, so JWT claims were trusted unverified); authorization that enumerates resource kinds and misses one ([CVE-2022-3162](https://github.com/kubernetes/kubernetes/issues/113756)); and a component that trusts data returned by something it is talking to ([CVE-2020-8559](https://github.com/kubernetes/kubernetes/issues/92914)) or proxies with its own credentials ([CVE-2018-1002105](https://github.com/kubernetes/kubernetes/issues/71411)). For Kubernetes-native authz semantics — the `escalate`, `bind` and `impersonate` verbs and the escalation-prevention rules — read the relevant section of the [RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) directly rather than quoting it from memory.

**Disproved by.** Mutual TLS with client-certificate verification actually enabled. Authentication middleware applied at the router root with no per-route opt-out. The token is verified against a key the attacker cannot supply (check the `kid`/issuer handling). The decision function's default branch denies. The listener binds `127.0.0.1` or a unix socket — which reduces the attacker position to the same network namespace, so state that position rather than calling it unreachable.

**Confirm with.** An unauthenticated request from an **unprivileged pod in a separate namespace** on your local `kind` cluster producing the privileged effect, with the request recorded verbatim and the starting privilege named.

### D2 Token, credential, and entropy handling

**Class.** A secret is generated predictably, logged, persisted, surfaced to a lower-privileged reader, or forwarded to a third party.

**Lives in.** OIDC and OAuth flows, session and CSRF handling, bootstrap and join-token issuance, ServiceAccount token use, status subresources and Events, error strings, debug endpoints, cloud SDK credential plumbing.

**Grep.**
```
rg -n 'math/rand' --glob '*.go' | rg -i 'token|nonce|state|secret|session|verifier|password|csrf|key'
rg -ni 'klog\.|log\.(Printf|Println|Info|Error)|fmt\.(Print|Sprintf)' --glob '*.go' | rg -i 'token|secret|password|credential|authorization'
rg -n 'recorder\.Event|\.Status\.|SetCondition|Message:' --glob '*.go' | rg -i 'token|secret|password'
rg -n 'os\.WriteFile|ioutil\.WriteFile|\.Set\("Authorization"|Header\.Add' --glob '*.go'
rg -n 'os\.Environ\(\)|godotenv|viper\.AllSettings' --glob '*.go'
```

**Trace.** For entropy: is the value produced by `math/rand` used as a nonce, `state`, PKCE verifier, session id, or token? That is the [Argo CD CVE-2022-31034](https://github.com/advisories/GHSA-2m7h-86qq-fp4v) shape. For exposure: who can read the destination? A log line on a node a tenant cannot reach is different from a `status` field or an Event in the tenant's own namespace. For propagation: does the tool pass the caller's credential to a third party, or mount a token broader than it needs?

**Disproved by.** `crypto/rand` (or the platform equivalent) on every path that produces the value. The logged value is a non-secret identifier or is truncated/hashed. The secret appears only at an elevated verbosity level the documentation tells operators not to run in production — that is a hardening and documentation finding, not usually a vulnerability. The destination is readable only by subjects who already hold the secret.

**Confirm with.** The predictable value reproduced twice from a known seed state, or the secret read from the destination **by a subject that should not hold it**, on your own cluster, starting from that subject's RBAC only.

### D3 Path handling: volume mounts, archive extraction, repository rendering

**Class.** A path component from a lower-trust source escapes its intended root, or a validated path is swapped for a symlink before it is used (TOCTOU). [CWE-22](https://cwe.mitre.org/data/definitions/22.html).

**Lives in.** `subPath` and volume-mount handling, `tar`/`zip` extraction (image layers, backups, bundles, chart archives), Git clone and render paths, Helm and Kustomize rendering, log and cache path builders, backup/restore, any `--output` style flag reachable from a CR.

**Grep.**
```
rg -n 'filepath\.Join|path\.Join|os\.MkdirAll|os\.OpenFile|os\.Create|os\.Rename|os\.Chown' --glob '*.go'
rg -n 'tar\.NewReader|tar\.Next|zip\.OpenReader|Untar|Extract' --glob '*.go'
rg -n 'EvalSymlinks|os\.Lstat|os\.Readlink|os\.Symlink|SecureJoin|RESOLVE_BENEATH|openat2' --glob '*.go'
rg -n 'subPath|mountPath|hostPath' --glob '*.go' --glob '*.yaml'
rg -n 'go-git|PlainClone|kustomize|helm\.sh/helm' --glob '*.go'
```
Also grep for the **absence** of the defence: a `filepath.Join` with no `filepath.Clean` + resolved-prefix check nearby is the candidate.

**Trace.** Two questions, and they are the two that produced [CVE-2021-25741](https://github.com/kubernetes/kubernetes/issues/104980) and [Argo CD CVE-2022-24904](https://github.com/advisories/GHSA-6gcg-hp2x-q54h):
1. Can **any** component of the path come from a lower-trust source — a CR field, an annotation, a `subPath`, a filename inside a cloned repository, an archive entry name, a chart value?
2. Is there a **gap between validating the path and using it**, during which a symlink could be swapped?

The containment check must be done on the **cleaned, absolute, symlink-resolved** path, compared as a separator-terminated prefix. String matching on the raw input is the bug, not the fix.

**Disproved by.** A `SecureJoin`-style resolution, or `openat2` with `RESOLVE_BENEATH`, performed on every path. An extractor that rejects entries whose cleaned path escapes the root **and** refuses symlink and hardlink entries. The path is an opaque id mapped to a location server-side. Validation and use are the same syscall.

**Confirm with.** A read or write landing outside the intended root **in your own container**, shown by absolute path, with the input recorded verbatim. Read or write a file you planted yourself; do not go looking for `/etc/shadow` to improve the screenshot (ROE §4). For a runtime-isolation claim, read [CVE-2024-21626](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout) and the [vendor write-up](https://access.redhat.com/security/vulnerabilities/RHSB-2024-001) first to see what crossing a real isolation boundary looks like, and check your claim against what the project promises about that boundary — [user namespaces for Pods](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/) is the reference for where the boundary sits.

### D4 TLS verification defaults and skip-verify flags

**Class.** The tool does not verify the identity of the peer it connects to, by default or on a silent fallback path. [CWE-295](https://cwe.mitre.org/data/definitions/295.html), plus [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) when it is the default.

**Lives in.** Registry clients, webhook clients, OIDC discovery, cloud SDK overrides, agent-to-control-plane connections, Git over HTTPS, chart repository clients, and — easy to miss — test helpers that the production path imports.

**Grep.**
```
rg -niE 'InsecureSkipVerify|insecure_skip_verify|insecureSkipTLSVerify|rejectUnauthorized|verify\s*=\s*False|--insecure|--skip-tls|CURLOPT_SSL_VERIFYPEER'
rg -n 'tls\.Config\{' -A4 --glob '*.go'
rg -n 'RootCAs|ClientCAs|ClientAuth|VerifyPeerCertificate|VerifyConnection' --glob '*.go'
```

**Trace.** Classify every hit, because the same string means different things in different places. The semantics of the field itself are in the [Go `crypto/tls` reference](https://pkg.go.dev/crypto/tls) — read what `InsecureSkipVerify` does and does not check before writing about it.

| Hit | Verdict |
|---|---|
| Default is `true` on the production path | `VULN` (CWE-295 + CWE-1188) |
| A code path silently falls back to skipping verification on handshake or CA-load error | `VULN` — and say so plainly; this is the one maintainers most often did not know about |
| The value is plumbed from an input the attacker influences (a CR field, an annotation, a chart value a tenant can set) | `VULN` |
| An explicit, documented flag, default `false`, settable only by the deployer | `MISCONFIG` |
| A test helper or example not reachable from shipped code | Not a finding |

**Disproved by.** Default `false` and only settable by the deployer. A custom CA pool is actually installed (`RootCAs` set) **and** verification stays on. `VerifyPeerCertificate`/`VerifyConnection` implements an equivalent check. The connection is to `localhost` or a unix socket.

**Confirm with.** The default value at `file:line`, plus your own instance accepting a certificate you self-signed for the peer's name — your own listener, your own CA, your own sandbox. That is the whole PoC.

### D5 Deserialization and config/template rendering in operators and controllers

**Class.** Lower-trust structured input reaches a deserializer that can instantiate types or run code, or reaches a template that renders a configuration file or command line. **Config injection is code execution even when no shell is involved**, because the config language itself can load code — nginx `ssl_engine`, systemd units, `sudoers`, `ssh_config`.

**Lives in.** CR reconcilers, annotation handlers, chart/values rendering, generated config files (nginx, HAProxy, Envoy, Prometheus, systemd), job and queue payloads, plugin protocols, state and checkpoint files.

**Grep.**
```
# Go
rg -n 'yaml\.Unmarshal|yaml\.UnmarshalStrict|json\.Unmarshal|gob\.NewDecoder' --glob '*.go'
rg -n 'text/template|html/template|template\.Must|\.Execute\(|fmt\.Sprintf' --glob '*.go'
rg -n 'exec\.Command|exec\.CommandContext' --glob '*.go'
# JVM (CI servers, Java operators)
rg -n 'readObject|ObjectInputStream|XStream|SnakeYAML|new Yaml\(|XMLDecoder'
# Python operators
rg -n 'pickle\.loads|yaml\.load\(|eval\(|exec\(|jinja2|Template\('
```

**Trace.** From each CR field, annotation, or chart value, forward to the renderer or decoder. The [IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) chain is the model to learn: attacker-controlled annotation values and a mirror UID field were inserted unsanitised into an NGINX configuration template, which was then validated with `nginx -t`, and an injected `ssl_engine` directive loaded an attacker-supplied shared library — reported as CVE-2025-1974 (the config-to-RCE step, CVSS 9.8) alongside CVE-2025-24514, CVE-2025-1097, CVE-2025-1098 and CVE-2025-24513, fixed in 1.12.1 and 1.11.5. Two of its teaching points belong in your checklist for any such tool: the admission webhook had no authentication (D1, D7), and the pod could read Secrets in all namespaces (D8). For JVM CI servers, the [Jenkins security advisories](https://www.jenkins.io/security/advisories/) are the calibration corpus for what a maintainer-accepted deserialization or sandbox-bypass report looks like.

**Disproved by.** The templated value comes only from a trusted source (an admin-only field is a different, weaker claim — say which). A strict schema or allowlist regex is applied **before** templating and rejects the injection. The decoder is strict into a typed struct with no polymorphic type resolution (`yaml.UnmarshalStrict` into a concrete type is not a vulnerability on its own). The renderer escapes or quotes for the target config language on every path.

**Confirm with.** A **benign** marker: an injected directive that writes a sentinel file, or a template expression that evaluates to a sentinel string, on your own instance. Do not load a library, do not spawn a shell, do not package it.

### D6 SSRF from a configurable URL, including cloud metadata

**Class.** A destination the attacker influences is dialed by a component whose network position is privileged. [CWE-918](https://cwe.mitre.org/data/definitions/918.html).

**Lives in.** Webhook and notification senders, OIDC/JWKS discovery, chart and Git repository fetchers, image and layer pullers, cloud-provider integrations, volume provisioners, anything with a `url`, `endpoint`, `server`, or `host` field in a CRD.

**Grep.**
```
rg -n 'http\.Get\(|http\.Post\(|http\.NewRequest\(|http\.Client\{|url\.Parse\(|net\.Dial' --glob '*.go'
rg -n '169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254'
rg -n 'CheckRedirect|DisableRedirects|Location' --glob '*.go'
rg -n 'url|endpoint|server|host|webhook' --glob 'api/**/*_types.go' --glob 'config/crd/**'
```

**Trace.** Cross-reference each dialer with the CRD, annotation, and chart fields that can set its destination. Then check four things: is there an allowlist on **scheme and host**, enforced after parsing; are redirects followed without re-validating the new destination; is the component's network position able to reach link-local metadata; and is the response — body, length, status, or error text — reflected back to the caller, which is the "half-blind" variant of [CVE-2020-8555](https://github.com/kubernetes/kubernetes/issues/91542).

**Disproved by.** Scheme and host allowlisted after `url.Parse` **and** re-checked on every redirect. The destination is a fixed in-cluster service address. The dialer resolves and rejects link-local and loopback ranges before connecting. No response content, length, or distinguishable error reaches the caller **and** no state change results.

**Confirm with.** Your own HTTP listener, in your own sandbox, receiving the request, with the CR field that set the destination recorded. **Be honest about impact:** before claiming credential theft, check whether token-required IMDSv2 mode and the response hop limit would already block it — the [AWS instance-metadata options reference](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html) documents `HttpTokens`, the `169.254.169.254` and `fd00:ec2::254` endpoints, and `HttpPutResponseHopLimit` (1–64, with the explicit note that a hop limit of 1 causes problems in container environments). Say in the report which of these you verified and which you did not.

### D7 Admission, webhook, and policy-engine privilege boundaries

**Class.** A control the tool implements as a gate can be bypassed by the shape of a request, or fails open. Audit this as **code**, not as configuration — a policy engine that mis-handles a request is defective software, not a misconfigured cluster. [Kyverno](https://kyverno.io/docs/) is a useful representative of the class, both as a control you may recommend and as an audit target in its own right.

**Lives in.** `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` handlers, policy engines, operators that gate tenant actions, anything implementing its own authorization layer over Kubernetes RBAC.

**Grep.**
```
rg -n 'AdmissionReview|admission\.Request|request\.Operation|request\.OldObject|oldObject' --glob '*.go'
rg -n 'failurePolicy|sideEffects|matchPolicy|namespaceSelector|objectSelector|caBundle|clientConfig' --glob '*.yaml' --glob '*.go'
rg -n 'rules:' -A8 config/webhook/ charts/ deploy/ 2>/dev/null
```

**Trace.** Nine questions, in order. A "no" on any of the first four is a candidate.

1. Does the webhook **authenticate its caller**, or will it accept an `AdmissionReview` from any pod in the cluster? (IngressNightmare.) The [dynamic admission control reference](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) covers `clientConfig`/`caBundle` trust and notes that the example webhook's empty `ClientAuth` defaults to `NoClientCert`, so the webhook does not verify the API server's identity — read that section before quoting it.
2. On UPDATE, does it inspect `request.oldObject` as well as `request.object`? Inspecting only the new object lets a policy be bypassed on update ([CVE-2021-25735](https://github.com/kubernetes/kubernetes/issues/100096)).
3. Is the rule scope complete across `apiGroups`, versions, `resources` **and subresources**, and does it cover the workload controllers as well as Pods? Note the structural gap the [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) reference describes: `enforce` applies to Pod objects, not to the workload resources that create them.
4. Does `failurePolicy` fail open, and can an attacker reach that state by making the webhook slow or unavailable?
5. Can the party being governed set its own `namespaceSelector` or `objectSelector`, or label its own namespace out of scope?
6. Does a mutating step run after validation and reintroduce the forbidden value, or does a decision depend on a field a later mutation can change? The phase split and the extension points are in the [admission controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/).
7. Are read requests in scope at all? `get`, `watch` and `list` do not pass through admission — a design that relies on admission to protect data is relying on the wrong control.
8. Is the exemption mechanism (namespace labels, exempt users) reachable by the governed party?
9. Does the engine fail closed on a malformed or oversized payload, or does it log and allow?

**Disproved by.** The webhook requires and verifies a client certificate. Rules cover all relevant operations, resources and subresources. `failurePolicy: Fail` plus an availability story. Selectors and exemptions live in a namespace or object the governed party cannot write. Decisions are re-evaluated after the final mutation.

**Confirm with.** A crafted request body that gets through on your local cluster, sent by a subject holding **only** the RBAC the documentation expects a tenant to have, with the policy that should have blocked it shown as installed.

### D8 Shipped RBAC and the tool's own identity

**Class.** The tool's own privileges. This block produces fewer vulnerabilities than D1–D7 and more `MISCONFIG` — which is exactly why it is here: to stop over-broad RBAC being written up as a vulnerability by default.

**Lives in.** `config/rbac/`, `charts/`, `deploy/`, the operator bundle, the ServiceAccount the chart creates, cloud IAM roles in the install docs.

**Grep.**
```
rg -n '"\*"|- \*' config/rbac/ charts/ deploy/ 2>/dev/null
rg -n 'secrets|pods/exec|pods/attach|impersonate|escalate|bind|serviceaccounts/token|nodes/proxy' config/rbac/ charts/ deploy/ 2>/dev/null
rg -n 'automountServiceAccountToken|hostPID|hostNetwork|hostPath|privileged|allowPrivilegeEscalation' charts/ deploy/ config/ 2>/dev/null
```
Then, on your own cluster after installing the chart at the pinned version, map what it actually granted with [`kubectl-who-can`](https://github.com/aquasecurity/kubectl-who-can) and [`rbac-tool`](https://github.com/alcideio/rbac-tool).

**Trace.** Decide which of three things you have:

| Observation | Verdict |
|---|---|
| Broad RBAC the tool's documented function requires | **Not a finding.** Note it in the report's context section if it multiplies another finding's impact. |
| Broad RBAC beyond what the function needs, in the default install path | **`MISCONFIG` / hardening.** Public issue tracker, never the security channel. |
| RBAC that is broad **because the code reads something it should not**, or that enables escalation from the tool's ServiceAccount to a privilege the documentation says it does not have (for example, namespace-scoped by the docs but cluster-wide in effect) | **`VULN`.** The defect is in the code or the shipped manifest. |

**Disproved by.** The documentation states the requirement. The privilege is needed by a code path you can point to. The escalation you imagine needs a privilege the attacker does not start with.

**Confirm with.** The escalation performed on your own cluster from the tool's ServiceAccount or from the tenant privilege you claim, with the starting RBAC printed. For reasoning about what a given pod privilege actually buys an attacker, use [Bad Pods](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) and reproduce with the [badPods manifests](https://github.com/BishopFox/badPods) **on your own throwaway cluster only** — and remember that demonstrating what a privilege grants is not a finding unless a boundary was crossed to obtain it (section 2.1, question (c)).

### D9 Exemplar casebook

Read the two or three that match your target before hunting. Each is a real, maintainer-accepted finding in this software class, and each has a grep that would have found it.

| Exemplar | Class it teaches | Found by |
|---|---|---|
| [CVE-2018-1002105](https://github.com/kubernetes/kubernetes/issues/71411) | Proxy/connection handling reaching backends with the control plane's own credentials | D1 — listener and proxy paths |
| [CVE-2020-8559](https://github.com/kubernetes/kubernetes/issues/92914) | Trust-boundary inversion: a higher-trust component trusting what a lower-trust one returns | D1 — redirect and relay handling |
| [CVE-2020-8555](https://github.com/kubernetes/kubernetes/issues/91542) | Half-blind SSRF from a user-supplied field in a volume spec | D6 — dialer cross-referenced with CR fields |
| [CVE-2021-25741](https://github.com/kubernetes/kubernetes/issues/104980) | `subPath` symlink swapped between validation and mount (TOCTOU) | D3 — validate-then-use gap |
| [CVE-2021-25735](https://github.com/kubernetes/kubernetes/issues/100096) | Admission bypass on UPDATE by not observing previous fields | D7 — `oldObject` question |
| [CVE-2022-3162](https://github.com/kubernetes/kubernetes/issues/113756) | Authorization that missed a resource dimension (custom resources) | D1 — authz enumerating kinds |
| [Argo CD CVE-2022-29165](https://github.com/advisories/GHSA-r642-gv9p-2wjj) | Authentication bypass behind a feature flag; JWT claims trusted unverified | D1 — flag-gated verification |
| [Argo CD CVE-2022-24904](https://github.com/advisories/GHSA-6gcg-hp2x-q54h) | Symlink in a Git repository reading files outside its root | D3 — repository rendering |
| [Argo CD CVE-2022-31034](https://github.com/advisories/GHSA-2m7h-86qq-fp4v) | Insecure entropy in PKCE/OAuth2/OIDC parameters | D2 — `math/rand` near token-ish names |
| [IngressNightmare / CVE-2025-1974](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) | Config-template injection to RCE via an unauthenticated admission webhook | D5 + D1 + D7 together |
| [CVE-2024-21626](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout) ([vendor](https://access.redhat.com/security/vulnerabilities/RHSB-2024-001)) | Runtime isolation boundary: leaked file descriptor plus `WORKDIR` ordering | D3 — fd and path handling in runtime code |

## 5. Configuration and posture scanners

**The rule, before the tooling: scanner output about a deployment is not a finding against the tool.** These tools evaluate configuration — manifests, charts, Dockerfiles, Terraform, pipeline files. A `FAIL` means "this configuration deviates from a policy", which is a statement about a deployment, not about the project's code. Trivy's own scanner split makes the distinction concrete: it separates a **Vulnerability** scanner from a **Misconfiguration** scanner precisely because they answer different questions ([Trivy docs](https://trivy.dev/latest/docs/)).

### 5.1 Coverage matrix

| Tool | Scans | Catches | Cite as | Usually yields |
|---|---|---|---|---|
| [actionlint](https://github.com/rhysd/actionlint) | Workflow files | Syntax, expression types, action input/output and reusable-workflow signatures, shellcheck + pyflakes over `run:`, script injection from untrusted input, hard-coded credentials | A named check from [checks.md](https://github.com/rhysd/actionlint/blob/main/docs/checks.md) | `VULN` leads in the target's workflows |
| [zizmor](https://github.com/zizmorcore/zizmor) | Workflows, Dependabot, pre-commit | Template injection, credential persistence and leakage, excessive permissions and credential grants to runners, impostor commits and confusable refs | A rule name from [docs.zizmor.sh/audits](https://docs.zizmor.sh/audits/) | `VULN` leads in the target's workflows |
| [poutine](https://github.com/boostsecurityio/poutine) | GitHub Actions and GitLab CI | Build-pipeline security, build-dependency inventory; SARIF output | The rule id from its output | `VULN` leads, plus pipeline supply-chain context |
| [CodeQL Actions queries](https://codeql.github.com/codeql-query-help/actions-cwe/) | Workflows | The canonical taxonomy for this class | A query id (`actions/code-injection/critical`, …) | The finding-class **name** for a report |
| [Checkov](https://www.checkov.io/5.Policy%20Index/all.html) | Ansible, Argo Workflows, ARM, Azure Pipelines, Bicep, Bitbucket, CircleCI, CloudFormation, Dockerfile, GitHub Actions and configuration, GitLab CI and configuration, Kubernetes, OpenAPI, Secrets, Serverless, Terraform | Broadest on CI/CD-config and VCS-configuration policy. [GitHub Actions policies](https://www.checkov.io/5.Policy%20Index/github_actions.html): `CKV_GHA_1` (`ACTIONS_ALLOW_UNSECURE_COMMANDS`), `CKV_GHA_2` (shell injection in `run`), `CKV_GHA_3` (suspicious curl with secrets), `CKV_GHA_4` (netcat to an IP), `CKV_GHA_5`/`CKV_GHA_6` (cosign signing / SBOM attestation), `CKV_GHA_7` (`workflow_dispatch` inputs), `CKV2_GHA_1` (top-level `write-all`) | `CKV_*` id | Mostly `MISCONFIG`; the GHA policies can be `VULN` leads |
| [Trivy](https://trivy.dev/latest/docs/) | Container Image, Filesystem, Rootfs, Code Repository, VM Image, Kubernetes, SBOM — with separate Vulnerability, Misconfiguration, Secret, License and Cryptographic Asset scanners. Misconfiguration covers Ansible, Azure ARM, CloudFormation, Docker, Helm, Kubernetes, Terraform ([scanner docs](https://trivy.dev/latest/docs/scanner/misconfiguration/)) | Dependency CVEs (vuln scanner) vs config policy (misconfig scanner) — keep the two apart in your notes | An AVD id from the [misconfiguration index](https://avd.aquasec.com/misconfig/) | Both, depending on scanner — label which |
| [KICS](https://kics.io/) | Widest platform breadth: Ansible, ARM, Buildah, CICD (GitHub Actions queries such as Script Block Injection), CloudFormation, Crossplane, Docker Compose, Dockerfile, Google Deployment Manager, gRPC, Knative, Kubernetes, OpenAPI, Pulumi, ServerlessFW, Terraform | Categories include Access Control, Insecure Configurations, Insecure Defaults, Secret Management, Supply-Chain, Build Process | A query id from [all-queries](https://docs.kics.io/latest/queries/all-queries/); custom queries are Rego | Mostly `MISCONFIG` |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Your own cluster, against the CIS Kubernetes Benchmark | Configuration conformance. **Not** a vulnerability scanner | The control id **and the benchmark version** — there is no one-to-one mapping between Kubernetes releases and benchmark releases ([platforms](https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md)) | Posture only |
| [kubescape](https://github.com/kubescape/kubescape) | Your own cluster | Posture against control frameworks | Control id | Posture only; use it as a cross-check so one tool's `FAIL` is not treated as ground truth |
| [Scorecard](https://github.com/ossf/scorecard) | Repository metadata | See section 6.1 | A check name from [checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md) | Context only |

**Superseded — recognise, do not use.** `tfsec` is [folded into Trivy](https://github.com/aquasecurity/tfsec): its README asks users to migrate and new rules land only in Trivy, so use `trivy config` and re-key `AWS001`-style codes to AVD ids. Do not assert a date for the merge. [Terrascan](https://github.com/tenable/terrascan) is archived and carries "This project is no longer maintained" — if older guidance recommends it, note that and move on.

### 5.2 Standard invocations

Keep raw output under `../../../evidence/{ID}/tools/<tool>.{json,sarif,txt}` so a report can be assembled from recorded evidence rather than memory.

```
# pipeline (section 3)
actionlint
zizmor .            # then --persona=auditor for the broader set
poutine analyze_local .
checkov -d . --framework github_actions

# the project's own shipped manifests, charts, Dockerfiles
trivy config .
trivy fs --scanners vuln,secret,misconfig .
checkov -d .
kics scan -p .

# repository posture, once (section 6)
scorecard --repo=<target repo url>

# your own local cluster only
kube-bench
kubescape scan
```

`kube-bench` and `kubescape` run against **your own `kind`/`minikube` cluster**. Pointing either at a cluster you do not own is a ROE §1 violation, not a thorough audit.

### 5.3 Triage procedure

These runs overwhelmingly produce `MISCONFIG`-class results about the project's example manifests, charts and Dockerfiles. Handle them exactly like this:

1. **Group** the output by rule id. Do not read it row by row.
2. **Select only hits that affect the default installation path**: the chart's default `values.yaml`, the quickstart manifest, the operator bundle, the published image.
3. **Route those** to the project's **public** issue tracker as a hardening or documentation issue, with the tool, the rule id, and the file. Not the security channel.
4. **Discard the rest.** Example manifests, test fixtures and documentation snippets are section 7 rows.
5. **Keep all of it out of the vulnerability report** unless a specific hit is *evidence for* a code-level finding — for example, a Trivy secret hit that is a real credential committed in shipped code, or a `CKV_GHA_2` hit that is the injection you traced in section 3.
6. **Never forward a hit you have not run to ground.** A scanner hit is a lead ([../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §4). Each unverified one costs the maintainer the time you saved.

### 5.4 Baselines, for vocabulary only

The [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) are the configuration baselines everything else references; a deviation in someone's cluster is posture, not a CVE. The [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) states its own caveat — that checklists are not sufficient for attaining a good security posture on their own — and that caveat is the reason a checklist delta is not a report. The [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/) gives useful framing vocabulary, but most of its entries are deployment-posture issues rather than code vulnerabilities, so use it for naming and not for classification. For threat-model vocabulary across image, registry, orchestrator, container and host tiers, [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final) is the conceptual reference (2017 — not current tooling advice). The [NSA/CISA Kubernetes Hardening Guide v1.2](https://media.defense.gov/2022/Aug/29/2003066362/1/1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) covers the same ground for hardening; open it in a browser before citing a page number from it.

## 6. Supply chain and provenance — detection and defence only

Everything in this section is **assessment** and **context**. We read posture, describe a release pipeline, and recognise an attack pattern well enough to find its defensive gap. We do not build tooling that finds vulnerable hosts, we do not hunt internet-exposed instances, and we do not package exploits (ROE §4, 1.2.4 above). Where a cited write-up contains exposure statistics gathered by vendor scanning, cite it for the mechanism and the code defect only.

### 6.1 Scorecard, as a pointer

Run [Scorecard](https://github.com/ossf/scorecard) once per target and read exactly three things:

| Check | Why |
|---|---|
| `Dangerous-Workflow` | Points straight back to section 3. Treat each as a lead, then prove the chain by hand. |
| `Token-Permissions` | The impact multiplier for every section 3 finding. |
| `Security-Policy` | Tells you whether a disclosure channel exists — feeds step 0b and, if absent, changes the rest of the run. |

`Pinned-Dependencies` is a useful fourth. **The score itself is never a finding**, and neither is a low check. Definitions and remediation text are in [checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md); quote those rather than the number.

### 6.2 Provenance, assessed not scored

Describe the target's release pipeline against the [SLSA v1.2 tracks](https://slsa.dev/spec/v1.2/tracks) — Build L0 (no guarantees), L1 (provenance exists), L2 (a hosted platform generates and signs provenance that consumers verify), L3 (a hardened platform isolating builds from one another and keeping signing secrets out of user-defined build steps); requirement detail is in [build track basics](https://slsa.dev/spec/v1.2/build-track-basics). Cite v1.2: the v1.0 and v1.1 levels pages are marked retired.

**"Not SLSA L3" is not a vulnerability.** It is one sentence of context in a report whose finding is something else.

One interaction is worth knowing because it defeats a common assumption: signed provenance still validates a build that consumed a **tampered cache entry**, so provenance is not a substitute for cache integrity ([Adnan Khan, build cache](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)). If the target's security claims rest on provenance while its pipeline restores a poisonable cache, that is a real gap — and section 3.3 tells you how to prove it in your own fork.

### 6.3 Pinning, and which hat you are wearing

An unpinned `uses:` is code execution with whatever the job holds ([part 3](https://securitylab.github.com/resources/github-actions-building-blocks/)). In the **target's** repository that is a finding class (section 3.3), because the workflow is code the project ships. In **our** repository it is hygiene: pin it and move on. The vendor rule — pin third-party actions to a full-length commit SHA — is in the [secure use reference](https://docs.github.com/en/actions/reference/security/secure-use).

### 6.4 Community material

[cncf/tag-security](https://github.com/cncf/tag-security) is archived and read-only, and its work has moved to a successor group. It still holds the Cloud Native Security Whitepaper and the project security self-assessment guide, which is a good template for structuring a whole-project audit. Link it as historical, do not guess at a successor repository URL, and do not cite a Kubernetes threat model from it without first finding the file.

## 7. Not a vulnerability in this class

Check every candidate against this table before it is written into `../../../findings/`. Run it **after** the project's own stated exclusions (step 0b), which govern. This is the dimension-specific layer on top of the generic table in [../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §4.

| Not a vulnerability | Why it is rejected | What would change the verdict |
|---|---|---|
| **An insecure-by-default setting that is documented and intended** — a local development mode with authentication off, a demo profile, an "insecure" flag the quickstart tells you to replace | The project told the operator what the setting does and the production path differs. Nothing to patch. | The insecure default is on the **production install path** (default chart values, quickstart manifest, operator bundle) and a user following the documentation is still exposed. Then it is the section 2.3 grey zone: file privately, cite [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html). |
| **Anything requiring `cluster-admin`, in software where `cluster-admin` is the trust boundary** | The attacker starts above the boundary. No crossing occurs. | The `cluster-admin`-equivalent step is itself reachable by an unprivileged subject. Demonstrate that step, and report **it** instead. |
| **A finding against an example, test, or documentation manifest** | It is not the installation path. Nobody runs it; it exists to be read. | It is referenced by the install documentation as the way to deploy, or the chart defaults to it. Then it is a shipped-artifact hardening issue (5.3, public issue) — and a vulnerability only if the code is defective too. |
| **A privileged pod escaping to the host; a `hostPath` mount reading host files; `hostPID` seeing host processes** | Documented behaviour of the setting. The [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) page states the Privileged profile allows for known privilege escalations. | The escape happens **without** the privilege — from a Baseline- or Restricted-equivalent pod, or from a tool that promised isolation (then it is D3, like [CVE-2024-21626](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout)). |
| **A CIS / kube-bench / kubescape `FAIL`, or a Kubernetes security-checklist delta** | A configuration deviation in a deployment. The maintainer cannot patch your cluster. | Nothing. This is never a vulnerability report. At most, if the project's own chart causes it on a default install, a public hardening issue. |
| **A missing hardening control** — no NetworkPolicy shipped, no seccomp profile, no PSA labels in the chart, no resource limits | Defence in depth is good engineering, not a vulnerability. | A primary control is shown to fail; report **that**, and mention the missing layer as context. |
| **A Scorecard score, an unsigned release, "not SLSA L3", an unpinned action in our own repo** | Posture and hygiene, not defects. | Nothing, for the score. An unpinned action in the **target's** shipped workflows is section 3.3. |
| **Scanner output forwarded as-is** | A hit is a lead; each unverified one costs the maintainer the time you saved. | A manual trace, a local reproduction, and a root cause at `file:line`. |
| **"The operator granted the tool cluster-wide `secrets` read"** where the documentation states the requirement | The privilege is the design (D8). | The code reads secrets it has no functional need for, or the documentation claims a narrower scope than the manifest grants. |
| **A CRD field that lets a cluster admin specify an image, a command, or a host path** | Operators run what admins tell them to run. That is the product. | A **tenant** who is not an admin can set that field, or the tool documents the field as safe for tenant use. Then it is D1 or D7. |
| **Requires a malicious container image the operator chose to run, or an already-compromised node** | The attacker already holds more authority than the bug grants. | The tool's stated job is to isolate untrusted images or untenanted workloads — then the isolation failure is the finding (D3). |
| **Resource exhaustion against the API server by a subject with RBAC to create the object** | Authorized use of a resource, and unbounded-in-principle is true of every server. | A specific amplification with both numbers recorded ([../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §C9) — and never demonstrated against anything you do not own (ROE §1). |
| **`:latest` tags, root user, or a missing `USER` in the project's Dockerfile** | Packaging hygiene. Route to the public tracker at most. | The image's identity is also what the tool's security model relies on, and the code depends on it being otherwise. |

**The default verdict is "not a finding."** Promotion requires evidence; rejection requires only the absence of it. A candidate sitting between two rows of this table does not ship.

## 8. Severity, duplicates, and routing

### 8.1 Severity

1. Score CVSS v3.1 from the **verified preconditions only** — the privilege you actually started from in step 7, not the one the sink could be reached from in principle.
2. Sanity-check a control-plane finding against the Kubernetes SRC's [severity-ratings.md](https://github.com/kubernetes/committee-security-response/blob/main/severity-ratings.md): server versus client classification, what Critical means for a remote anonymous user, and the rule that requiring extensive user interaction can drop Critical to High. Use it instead of guessing.
3. Map to a CWE: injection (CWE-74 / CWE-94), [path traversal (CWE-22)](https://cwe.mitre.org/data/definitions/22.html), [certificate validation (CWE-295)](https://cwe.mitre.org/data/definitions/295.html), [SSRF (CWE-918)](https://cwe.mitre.org/data/definitions/918.html), deserialization (CWE-502), privilege management (CWE-269), [insecure default (CWE-1188)](https://cwe.mitre.org/data/definitions/1188.html), vulnerable dependency (CWE-1395).
4. **Do not inflate an SSRF.** If token-required IMDSv2 mode and the response hop limit would already block credential theft, say so in the report (D6). A finding that survives honest scoping is believed; one that does not is discounted entirely.
5. The report must contain: affected component and versions, the **trust boundary crossed**, the attacker's starting privilege, the minimal reproducer, the observed impact, the suggested fix direction, an explicit statement of what is **not** claimed, and one line on why this is a code-level defect rather than a deployment misconfiguration (section 2.3).

### 8.2 Duplicate check

Before anything is drafted: the [GitHub Advisory Database](https://github.com/advisories) (where advisories for tools in this class actually land, with version ranges and CWE mapping), the project's own advisories, its changelog, and its recent commits — silent fixes are common in this ecosystem. For Kubernetes itself, the [official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/) is also the best corpus for calibrating what this ecosystem treats as a CVE at all. For JVM-based CI servers and plugins, the [Jenkins security advisories](https://www.jenkins.io/security/advisories/) stream. Cite nothing you have not opened ([../SKILL.md](../SKILL.md) §5).

### 8.3 Routing — one channel, and the human sends it

Order of preference, stopping at the first that applies:

1. The project's own `SECURITY.md` instructions.
2. GitHub [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on the Security tab, if enabled. It is a separate mechanism from `SECURITY.md` — check both.
3. A security contact named in the repository.
4. A contact solicited by opening a **non-descriptive** issue asking where to send a report. No details in it.

For Kubernetes itself: `security@kubernetes.io` or the HackerOne program, per [Security and Disclosure Information](https://kubernetes.io/docs/reference/issues-security/security/) — acknowledgement within three working days, GPG not required, disclosure typically about seven days from report for a straightforward mitigation, with the Security Response Committee holding final say on the date. That page also states that projects running their own disclosure process should be reported there instead, so check which applies. The committee's [process documents](https://github.com/kubernetes/committee-security-response) are the model for how a mature project runs an embargo. If a bounty program is involved, **read the live program scope** — do not rely on launch-era coverage of what is in or out of scope.

Never cross-post. Never open a public issue with details. Never a PR that fixes the bug while describing it. Then: **the agent prepares the report and the evidence bundle; a human reads all of it, confirms the section 2 classification and the no-third-party-testing attestation, and sends it** (ROE §2, [../../../disclosure/PROCESS.md](../../../disclosure/PROCESS.md)).

### 8.4 The five habits that keep this dimension honest

1. Never report scanner output as a finding.
2. Never report an absent hardening control as a vulnerability.
3. Always state the attacker's starting privilege. If it is `cluster-admin`, node root, or "can already run privileged pods", there is probably no finding.
4. Prefer one proven code-level defect over twenty posture deltas. Maintainer goodwill is the scarce resource.
5. Keep the per-target notes file: commit SHA, the trust boundary map, every candidate tagged `VULN`/`MISCONFIG`/`GREY`, and the exact commands run — so the write-up is assembled from recorded evidence rather than from memory.

## 9. Verified sources

Every URL below was fetched or curl-confirmed during research on 2026-10-13. Re-check before quoting, and read the specific section before quoting its wording.

**Kubernetes primary references**

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — the Privileged/Baseline/Restricted profiles and what each restricts; the source of "Privileged allows known privilege escalations". Read the Restricted control table directly before quoting it.
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) — `enforce`/`audit`/`warn` modes, namespace labels, version pinning, exemptions, and the fact that `enforce` applies to Pods rather than workload resources.
- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) — `escalate`, `bind`, `impersonate`, and the escalation-prevention rules. Read the section before quoting.
- [Admission Control in Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) — the mutating-then-validating split, the four extension points, and that reads bypass admission.
- [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) — `clientConfig`/`caBundle`, timeouts, failure policy, side effects, and the `NoClientCert` default in the example webhook.
- [Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) — section-by-section posture list, including its own "checklists are not sufficient" caveat.
- [User namespaces for Pods](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/) — where the isolation boundary sits.
- [Official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/) — what this ecosystem treats as a CVE.
- [Security and Disclosure Information](https://kubernetes.io/docs/reference/issues-security/security/) — channel, acknowledgement and disclosure timing.
- [committee-security-response](https://github.com/kubernetes/committee-security-response) — release process, severity ratings, CVE requests, CNA handbook. `github.com/kubernetes/security` redirects here.
- [severity-ratings.md](https://github.com/kubernetes/committee-security-response/blob/main/severity-ratings.md) — severity heuristics for control-plane findings.

**CI/CD primary documentation and research**

- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) — the single most important primary source for section 3. The older `security-for-github-actions/security-guides/...` path redirects here.
- [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) — which triggers run in the base-repo context with secrets. Required to prove reachability.
- [Contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) — telling an attacker-controlled field from a trusted one.
- [Approve runs from forks](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks) — the control that pwn-request and self-hosted-runner preconditions depend on.
- [Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) — the canonical pattern description and the fix shape, including the label-gating race.
- [Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) — the attacker-controllable field list and the intermediate-env-var fix.
- [How to trust your building blocks](https://securitylab.github.com/resources/github-actions-building-blocks/) — why `uses:` is code execution, and the ref-style hierarchy.
- [CodeQL CWE coverage for GitHub Actions](https://codeql.github.com/codeql-query-help/actions-cwe/) — the query-id taxonomy to name finding classes with.
- [One Supply Chain Attack to Rule Them All](https://adnanthekhan.com/2023/12/20/one-supply-chain-attack-to-rule-them-all/) — non-ephemeral self-hosted runners on public repos, and why approval gates only the first run.
- [The Monsters in Your Build Cache](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/) — Actions cache poisoning, and provenance validating a poisoned build.
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) — the vendor-neutral category label for a report.

**Linters and scanners**

- [actionlint](https://github.com/rhysd/actionlint) and its [check list](https://github.com/rhysd/actionlint/blob/main/docs/checks.md)
- [zizmor](https://github.com/zizmorcore/zizmor) and its [audit reference](https://docs.zizmor.sh/audits/) — note the org is `zizmorcore`
- [poutine](https://github.com/boostsecurityio/poutine)
- [Checkov policy index](https://www.checkov.io/5.Policy%20Index/all.html) and [GitHub Actions policies](https://www.checkov.io/5.Policy%20Index/github_actions.html)
- [Trivy docs](https://trivy.dev/latest/docs/) and [misconfiguration scanner](https://trivy.dev/latest/docs/scanner/misconfiguration/); rules browsable at [AVD](https://avd.aquasec.com/misconfig/)
- [KICS](https://kics.io/) and [all queries](https://docs.kics.io/latest/queries/all-queries/)
- [tfsec](https://github.com/aquasecurity/tfsec) — superseded by `trivy config`; [Terrascan](https://github.com/tenable/terrascan) — archived
- [kube-bench](https://github.com/aquasecurity/kube-bench) and [supported platforms](https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md); [kubescape](https://github.com/kubescape/kubescape)
- [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can) and [rbac-tool](https://github.com/alcideio/rbac-tool)
- [badPods manifests](https://github.com/BishopFox/badPods) and the [Bad Pods write-up](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) — own throwaway cluster only
- [Kyverno docs](https://kyverno.io/docs/) — representative policy engine, and an audit target in its own right

**Baselines, posture, provenance**

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) · [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/) · [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final) · [NSA/CISA Kubernetes Hardening Guide v1.2](https://media.defense.gov/2022/Aug/29/2003066362/1/1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) (open in a browser before citing a page number) · [cncf/tag-security](https://github.com/cncf/tag-security) (archived)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) and [checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [SLSA v1.2 tracks](https://slsa.dev/spec/v1.2/tracks) and [build track basics](https://slsa.dev/spec/v1.2/build-track-basics) — cite v1.2; v1.0 and v1.1 levels pages are retired

**Classification, CWE, disclosure**

- [CVE Program CNA Operational Rules v4.2.0](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf) — product scope, independent fixability, assignment. Open it before quoting a rule number; `cve.org` returns 200 for every path, so a status code proves nothing there.
- [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) · [CWE-295](https://cwe.mitre.org/data/definitions/295.html) · [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [GitHub Advisory Database](https://github.com/advisories) · [privately reporting a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) · [Jenkins security advisories](https://www.jenkins.io/security/advisories/)
- [AWS instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html) · [Go `crypto/tls`](https://pkg.go.dev/crypto/tls)

**Exemplar advisories** — [CVE-2018-1002105](https://github.com/kubernetes/kubernetes/issues/71411) · [CVE-2020-8559](https://github.com/kubernetes/kubernetes/issues/92914) · [CVE-2020-8555](https://github.com/kubernetes/kubernetes/issues/91542) · [CVE-2021-25741](https://github.com/kubernetes/kubernetes/issues/104980) · [CVE-2021-25735](https://github.com/kubernetes/kubernetes/issues/100096) · [CVE-2022-3162](https://github.com/kubernetes/kubernetes/issues/113756) · [GHSA-r642-gv9p-2wjj](https://github.com/advisories/GHSA-r642-gv9p-2wjj) · [GHSA-6gcg-hp2x-q54h](https://github.com/advisories/GHSA-6gcg-hp2x-q54h) · [GHSA-2m7h-86qq-fp4v](https://github.com/advisories/GHSA-2m7h-86qq-fp4v) · [IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) · [CVE-2024-21626](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout) · [RHSB-2024-001](https://access.redhat.com/security/vulnerabilities/RHSB-2024-001)

**URL shapes that are commonly guessed wrong** — GitHub Security Lab research lives under `/resources/`, not `/research/`. The Actions hardening doc is now "Secure use reference" at `docs.github.com/en/actions/reference/security/secure-use`. zizmor is `github.com/zizmorcore/zizmor`. SLSA's current levels page is `/spec/v1.2/tracks` (`slsa.dev/levels` redirects there). Do not cite an OPA/Gatekeeper URL from memory — it was not verifiable during research, and Kyverno stands in as the policy-engine example here.
