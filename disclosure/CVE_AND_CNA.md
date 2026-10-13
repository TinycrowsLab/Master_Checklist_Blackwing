# CVE Assignment and CNAs

Read this file once a finding has been reported upstream through [PROCESS.md](PROCESS.md) and the question "does this get a CVE, and who issues it?" has come up. It is written for someone who has never requested a CVE ID and needs the real request paths, not a summary of them.

Nothing in this file authorises an agent to file anything. Every request path below ends with an artifact the agent prepares and a human submits — see [PROCESS.md](PROCESS.md) §0.9 and [../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §2.

---

## 1. What a CVE ID is, and what it is not

| A CVE ID **is** | A CVE ID **is not** |
|---|---|
| A unique identifier for one publicly disclosed vulnerability in one product, assigned by a CNA acting within its published scope. | A severity rating. Severity is CVSS, and it is a separate artifact. |
| A coordination handle: it lets distributions, scanners, SBOM tooling and downstream users talk about the same bug. | A verdict that the bug matters, or an endorsement of your report. |
| Something that must be publicly disclosed. CNA Operational Rules §4.2.4-4.2.5: an assigned ID has to be publicly disclosed, and no CNA may assign an ID for something it does not intend to disclose. | Something you can hold privately and indefinitely. |
| Something only a CNA can assign. | Something you assign yourself, or something `oss-security` assigns — it has not done so since 2017 (<https://seclists.org/oss-sec/2026/q2/178>). |
| Optional. Plenty of real vulnerabilities are fixed, advised and never get one. | A prerequisite for disclosure, a measure of a researcher, or a thing worth optimising for. |

Target selection aimed at CVE count is out of scope for this repo. If the reason to pursue an ID is anything other than "downstream users and tooling need a stable handle for this bug", stop.

Use the CVE Program's own vocabulary verbatim in every request — **Vulnerability, Product, Supplier, Scope, Publicly Disclosed, Independently Fixable** are defined terms, and using them correctly removes most triage friction: <https://www.cve.org/ResourcesSupport/Glossary>

---

## 2. Who issues CVE IDs

| Layer | What it does | Who |
|---|---|---|
| CVE Board | Governs the program. | — |
| Top-Level Root | Top of a hierarchy; the appeal destination above a Root. | MITRE for everything general; CISA for industrial control systems and medical devices. |
| Root | Administers a set of CNAs in its hierarchy. | Several. |
| CNA | Assigns IDs within a **published scope**, usually its own products or a defined ecosystem. | ~hundreds; directory in §5.1. |
| CNA of Last Resort (CNA-LR) | Assigns for things no CNA's scope covers. | MITRE CNA-LR (general, including open source); CISA ICS CNA-LR (ICS and medical devices). |

Structure reference: <https://www.cve.org/ProgramOrganization/Structure>

The one official researcher-facing path, in three steps, from the CVE Program itself: <https://www.cve.org/ReportRequest/ReportRequestForNonCNAs>

1. Find the CNA whose scope covers the product, on the List of Partners.
2. Read that CNA's disclosure policy and contact it by the method it specifies.
3. Only if no CNA's scope fits, go to a CNA of Last Resort.

That page also documents the separate "update an existing CVE Record" path, which routes through the record's `Assigning CNA` field.

---

## 3. Eligibility pre-flight — run this before promising anyone an ID

The rulebook is CNA Operational Rules v4.2.0, approved 2026-08-20, effective 2026-08-25. Landing page: <https://www.cve.org/ResourcesSupport/AllResources/CNARules>. The PDF: <https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf>

Answer every row **in writing** in `FINDING.md` before any request is drafted. Any `disqualified` row is a stop: say so plainly in the report and do not request an ID.

| # | Question | Rule | Disqualified if |
|---|---|---|---|
| 3.1 | Is there an actual security impact — increased attacker access, reduced availability, or a violated security policy? | §4.1.2 | There is no security impact. It is a bug, not a vulnerability. |
| 3.2 | Is the insecure state a **default**, or a non-default configuration an authorized user chose? | §4.1.3 (insecure defaults: eligible) / §4.1.3.5 (documented non-default change by an authorized user: not eligible) | The only path requires a documented non-default config change. |
| 3.3 | Is the finding "this project depends on a vulnerable library"? | §4.1.11 | Yes. Updating a dependency is not a new vulnerability. Reference the library's existing CVE instead. |
| 3.4 | Is the complaint that the product is end-of-life or unsupported? | §4.1.12 | Yes, and that is the whole complaint. EOL state alone is not a vulnerability. |
| 3.5 | Does the attack require physical access? | §4.1.4 | Yes. |
| 3.6 | Is it brute-force, resource exhaustion, or volumetric DoS? | §4.1.5 | Yes. |
| 3.7 | Does it merely bypass a mitigation that is inherently imperfect? | §4.1.6 | Yes. |
| 3.8 | Is this deliberately malicious or trojaned code rather than a vulnerability? | §4.1.7-4.1.8 | Yes — route it as malware instead, §6.4. |
| 3.9 | Was the product ever publicly available? | §4.2.10 | No. Never-public products do not get IDs. |
| 3.10 | Will this be publicly disclosed? | §4.2.4-4.2.5 | No. An ID that will never be disclosed cannot be assigned. |
| 3.11 | How many bugs is this? | §4.1.9, §4.2.11-4.2.12 | Not a disqualifier, a counting rule: split into separate IDs when the issues are **Independently Fixable**; merge interdependent conditions into one. |

### 3.2 The beginner time-sinks, restated plainly

These are where new researchers lose the most hours. Each one is a `stop`, not an argument to win.

| Pattern | Verdict |
|---|---|
| Bug only reproduces on an unsupported or EOL branch | Not reportable as a vulnerability. Check whether it reproduces on the newest supported release first. |
| The insecure thing is how a **deployment** was configured, not what the code does | Deployment misconfiguration. Not a code vulnerability, and testing someone's deployment is forbidden ([../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §1). |
| The behaviour is documented and intended | Not a vulnerability. The honest move is a documentation issue. |
| The project's own written scope excludes this class | Not a vulnerability **for that project**. See [PROCESS.md](PROCESS.md) §8 for the four verified exclusion catalogues. |
| The project declines to request CVEs, or its bug bar is higher than yours | Respect it. A dispute path exists (§5.6) but it is for genuine bug-bar disagreements after a real exchange, not for overriding a maintainer. |
| Bug only exists on `main`, never in a release | Frequently not reportable. curl: "Only curl releases are ever considered secure" (<https://curl.se/dev/secprocess.html>). Django and Python both tell reporters to check whether a fix is already on main awaiting backport. |
| The bug is already silently fixed upstream | Not a new vulnerability. Ask the maintainer whether they want an advisory or an ID for the fix they already shipped. Detection procedure: [DUPLICATE_CHECK.md](DUPLICATE_CHECK.md) §9. |

---

## 4. The decision tree

Walk it in order. Each node is a yes/no with an action. Do not skip a node because a later one looks easier.

```
D0  Has the finding passed the gates in RULES_OF_ENGAGEMENT.md §3,
    and has a human reported it upstream per PROCESS.md?
      NO  -> STOP. Go back to PROCESS.md. No ID is requested before upstream contact.
      YES -> D1

D1  Did every row of §3 pass?
      NO  -> STOP. Write the disqualifying rule number into the report. Do not request an ID.
      YES -> D2

D2  Does a CNA's published scope cover this product?
    Check: cve.org List of Partners (search by scope text, org, role),
           and the "Assigning CNA" field on recent CVE Records for this same product.
      YES -> That CNA has FIRST REFUSAL (CNA Rules §4.2.1). Go to §5.1. END.
      NO  -> D3

D3  Is the project hosted on GitHub, and is the maintainer willing to open a
    repository security advisory?
      YES -> GitHub is a CNA. This is the easiest route for GitHub-hosted OSS.
             Go to §5.2. END.
      NO or maintainer unwilling -> D4

D4  Is it open-source software with no product CNA?
      YES -> Check the Red Hat open-source CNA route before defaulting to CNA-LR.
             Go to §5.3. If it does not fit -> D5.
      NO  -> D5

D5  Is the product an industrial control system, OT, or a medical device?
      YES -> CISA ICS CNA-LR. Go to §5.4. END.
      NO  -> D6

D6  MITRE CNA-LR. Read its gates in §5.5 FIRST - two of them stop most
    beginner requests - then follow the request mechanics there. END.
```

Note on D2: GitHub cannot assign an ID if another CNA already covers the project. If an ID was already assigned by another CNA, the advisory records that existing ID instead of requesting a new one.

---

## 5. The routes in detail

### 5.1 A product CNA — First Refusal

1. Open <https://www.cve.org/PartnerInformation/ListofPartners>. It is searchable by scope text, role and organisation type.
2. Find the partner whose scope covers the Product. If uncertain, look at who the `Assigning CNA` was on recent CVE Records for the same product — that is the empirical answer.
3. Open that partner's page and read its **"Steps to Report a Vulnerability"** section. Step 2, the **Contact** field, is the authoritative security contact.
4. Read that CNA's disclosure policy before writing anything.
5. Contact it by the method it specifies. A human sends.

CNA Rules §4.2.1 **First Refusal**: the CNA with the most appropriate scope must be contacted and given the first opportunity to assign. Skipping it to get a faster answer from a CNA-LR is a rules violation, not a shortcut, and it will be bounced back.

### 5.2 GitHub as a CNA — the usual route for a GitHub-hosted project

This is the path most open-source findings should take. Mechanically:

#### What the researcher does

| Step | Action | Notes |
|---|---|---|
| 1 | Report through the repo's **Security** tab → **Report a vulnerability** | Full clickpath in [PROCESS.md](PROCESS.md) §3. Reference: <https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-a-vulnerability/privately-reporting-a-security-vulnerability> |
| 2 | You are added automatically as a **pending credited user** | You do not ask for this. It happens. |
| 3 | Pre-fill the advisory fields in your report so the maintainer only has to confirm | List in the next table. This is the single highest-leverage thing a reporter can do. |
| 4 | If invited, collaborate on the **draft advisory** and the **temporary private fork** | Only the maintainer can merge the fork. |
| 5 | Accept the credit entry when it appears | A preference, never a demand ([PROCESS.md](PROCESS.md) §12). |

#### Fields to pre-fill in your report

The maintainer's advisory form asks for these. Supply every one you can defend. Reference: <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory>

| Advisory field | What you supply |
|---|---|
| Ecosystem | npm, pip, RubyGems, Maven, Go, crates.io, Composer, NuGet, Pub, Swift, Erlang, GitHub Actions |
| Package name | Exactly as published in that ecosystem |
| Affected versions | A tested range, expressed as OSV range events — see §6.1 |
| Patched versions | The release that fixes it, once it exists |
| Vulnerable functions / symbols | Named. Symbol precision measurably reduces downstream false positives. |
| Severity | A CVSS vector string from the official FIRST calculator, with the version the project uses — §5.2.1 |
| CWE identifiers | Chosen by MITRE's procedure: <https://cwe.mitre.org/documents/cwe_usage/guidance.html> |
| Credits | Your name and preferred attribution |
| CVE identifier | Either an existing ID from another CNA, or "request one from GitHub" |

#### What the maintainer does, and what you cannot do for them

| Step | Who | Detail |
|---|---|---|
| Open a **draft** repository security advisory | Maintainer (repo admin) | A researcher without admin cannot open one. Reference: <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories> and <https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/about-repository-security-advisories> |
| Add the researcher as a collaborator on the advisory | Maintainer | This is how you get edit access to the draft. |
| Open a **temporary private fork** to develop the fix | Maintainer | Researcher can be invited; only the maintainer merges. |
| Click **Request CVE** at the bottom of the advisory form | Anyone with admin on the advisory | Typically reviewed within about 72 hours. **Requesting a CVE does not make the advisory public.** |
| Record the **patched version** | Maintainer | Do this before publishing: without it, Dependabot alerts consumers with no safe version to move to. <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/publishing-a-repository-security-advisory> |
| Click **Publish advisory** | Maintainer | The advisory becomes a GHSA in <https://github.com/advisories>. |

The researcher cannot: open a draft advisory on a repo they do not administer, request a CVE on such a repo, publish an advisory, or set the patched version. The researcher **can and should**: pre-fill everything above, write the advisory text so it is publishable nearly unchanged, and offer a patch.

#### 5.2.1 Severity, scored honestly

Severity may never exceed demonstrated impact ([../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §3.4). Publish **Base metrics only** and name it `CVSS-B`: Threat and Environmental metrics belong to the consumer, not the finder.

| Need | URL |
|---|---|
| v4.0 specification | <https://www.first.org/cvss/v4-0/specification-document> |
| v4.0 user guide (CVSS-B / BT / BE / BTE nomenclature, library scoring, VC/VI/VA vs SC/SI/SA) | <https://www.first.org/cvss/v4-0/user-guide> |
| v4.0 worked examples — calibrate your vector against the closest one and explain any divergence | <https://www.first.org/cvss/v4-0/examples> |
| v4.0 calculator (generate the vector; never hand-assemble a vector string) | <https://www.first.org/cvss/calculator/4-0> |
| v3.1 specification — still what many OSS projects and CNAs expect | <https://www.first.org/cvss/v3.1/specification-document> |
| v3.1 user guide — the authoritative over-scoring checklist | <https://www.first.org/cvss/v3.1/user-guide> |
| v3.1 calculator | <https://www.first.org/cvss/calculator/3.1> |

Two rules that come up constantly: do not put **EPSS** in a report — it exists only for published CVEs and is post-publication prioritisation context (<https://www.first.org/epss/>, misuse guidance at <https://www.first.org/epss/using-epss>); and if the project forbids severity scores, omit them (Django: <https://docs.djangoproject.com/en/stable/internals/security/>).

CWE selection, if you include one: <https://cwe.mitre.org/documents/cwe_usage/guidance.html>, the list index <https://cwe.mitre.org/data/index.html>, and a worked example of an ID that is **PROHIBITED** for mapping <https://cwe.mitre.org/data/definitions/699.html>. The 2025 Top 25 (<https://cwe.mitre.org/top25/>, list at <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>) confirms a class is mainstream; it is never a severity argument, because the ranking is derived from CNA mapping volume (<https://cwe.mitre.org/top25/archive/2025/2025_methodology.html>).

### 5.3 Red Hat's open-source CNA

For open-source software with no product CNA, check this before defaulting to a CNA-LR: <https://access.redhat.com/articles/red_hat_cve_program>

### 5.4 CISA ICS CNA-LR — industrial control systems and medical devices

CISA is the Top-Level Root for ICS and medical devices and runs the CNA-LR for that hierarchy. Its coordination process, intake routes and CVE-determination step are documented at <https://www.cisa.gov/coordinated-vulnerability-disclosure-process>. Read the current intake links off that page in a browser; this repo could not verify the portal URL because the host blocks automated clients.

A finding in this category is also a [../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §7 stop condition. Halt and escalate to a human before doing anything else.

### 5.5 MITRE CNA-LR — the gates, then the mechanics

**Read the gates first.** Two of them stop most beginner requests. Policy: <https://mitre.github.io/mitre-cve-roles/CNA-LR/>

| Gate | Consequence |
|---|---|
| MITRE CNA-LR does not publish CVE Records for vulnerabilities that are **not publicly disclosed**. | Reserve the ID during the embargo if you must, but you own the publication plan. There is no "private CVE". |
| It prefers the **Supplier** to request the ID, and accepts a discoverer's request only when the Supplier is unwilling or uncontactable. | Document your contact attempts from `timeline.md` before requesting. A request with no evidence of upstream contact is the wrong shape. |
| Filing a request does **not** make MITRE your coordinator. | Coordination stays between you and the Supplier. If you need a coordinator, that is CERT/CC — [PROCESS.md](PROCESS.md) §9.1. |
| It covers the MITRE Top-Level-Root hierarchy only. | ICS and medical devices go to CISA, §5.4. |

**Mechanics (currency-critical).** `cveform.mitre.org` now redirects to the portal below and the legacy form is being retired. Portal: <https://mitre.github.io/mitre-cve-roles/>. Request form: <https://mitre.github.io/mitre-cve-roles/cve-id-request/>

1. Open the request form and log in with Google or GitLab.
2. Click **Reserve One CAN**. You get a `CAN-YYYY-#######` tracking number.
3. **A CAN is not a public vulnerability ID.** Never cite it in an advisory, a commit message, a writeup, or anywhere public.
4. Open the CAN link and supply at minimum: problem type(s), vendor/project, product name, version, description, and a reference URL.
5. Add a CVSS 4.0 or 3.1 vector if you have one, or dismiss the Metrics block with the red `x`.
6. Submit, then poll the CAN link over the following days for acceptance.
7. Log every one of these steps, with timestamps, in `findings/<id>/timeline.md`.

### 5.6 Disputes

If, after the exchange in [PROCESS.md](PROCESS.md) §8, you and the maintainer still disagree on whether the finding is a vulnerability:

1. You have a documented bug-bar dispute, not a reporting problem. The record of the exchange is the artifact.
2. CNA Operational Rules §4.6 provides a dispute-resolution path. Appeals run up the hierarchy: CNA → Root → Top-Level Root (<https://www.cve.org/ProgramOrganization/Structure>).
3. MITRE's CNA-LR treats a bug-bar dispute the way it treats a product with no Supplier CNA — see the gates in §5.5, which still apply.
4. A human decides whether to pursue it. The realistic answer is usually no: a disputed ID over a maintainer's objection costs goodwill for very little downstream benefit.

---

## 6. Ecosystem advisory databases — a separate, additional destination

These are **not** a CVE route and **not** a substitute for reporting upstream. They are where a fixed vulnerability gets recorded so that scanners, lockfile audits and SBOM tooling warn the ecosystem's users. In almost all cases the sequence is: **report upstream → maintainer ships a fix → then file here.**

### 6.1 The shape of the record

Most of these databases speak the OSV schema. Draft your advisory in that shape and the maintainer can paste it straight in: `affected[].package{ecosystem,name,purl}` and `ranges[].type` (`SEMVER` | `ECOSYSTEM` | `GIT`) with `introduced` / `fixed` / `last_affected` / `limit` events. Specification: <https://ossf.github.io/osv-schema/>

### 6.2 Routes by ecosystem

| Ecosystem | Destination | Submission mechanics | Placeholder / ID format | Upstream first? |
|---|---|---|---|---|
| Python / PyPI | <https://github.com/pypa/advisory-database> | Open a PR adding `vulns/PYSEC-0000-<anything>.yaml`; validate with `check-jsonschema` against the OSV schema. Use `ecosystem_specific.imports` to name the vulnerable modules and attributes — it cuts consumer false positives. | `PYSEC-0000-<anything>`, real ID assigned by the maintainers | Yes. PyPI itself has **no** channel for an ordinary vulnerability in a third-party package. |
| Rust / crates.io | <https://github.com/rustsec/advisory-db> | Report upstream **first**, then open a PR with the placeholder ID. For a soundness or unsafe-block bug that is not a classic CVE, use `informational = "unsound"` — that category exists precisely for this. | `RUSTSEC-0000-0000`, real ID assigned by the maintainers | **Yes, explicitly.** Tooling index: <https://rustsec.org/> |
| Ruby / RubyGems | <https://github.com/rubysec/ruby-advisory-db> | Open a PR with the gem's YAML. Required keys: `gem`, `url`, `title`, `date`, `description`. Optional: `cvss_v2` through `cvss_v4`, `patched_versions`, `unaffected_versions`. Run the repo's lint before opening the PR. | Filename keyed to the gem and advisory | Yes — **and a named human must own the submission.** The maintainers close contributions that look like unreviewed AI output. An agent may draft the YAML; a human submits it and answers the review. |
| PHP / Composer | <https://github.com/FriendsOfPHP/security-advisories> | One directory per Composer package. Filename is the CVE ID, or a date-increment where there is none. Keys: `title`, `link`, `reference` (a `composer://` URI), `branches[]` with `time` and `versions`. Validate with the repo's `validator.php`. | CVE ID or date-increment filename | Yes |
| Go | <https://go.dev/doc/security/vuln/> | That page documents the whole pipeline and links the third-party report form (`go.dev/s/vulndb-report-new` as named on the page), which also covers requesting a CVE. Open the page and follow its link rather than trusting a cached form URL. | Assigned by the Go security team | Yes |
| npm / Node.js | No separate npm advisory database exists to file to. npm advisories flow through the GitHub Advisory Database via a repository advisory (§5.2). | §5.2 | GHSA | Yes |
| Node.js core | Not the Ecosystem Security WG. <https://github.com/nodejs/security-wg> states outright that it is not the channel for reports against Node.js itself; core reports go through the project's own program. | Project's own intake | — | Yes |
| Maven / Java | No community-run equivalent of RustSec or PyPA. The practical path is a repository advisory plus the GitHub Advisory Database. | §5.2 | GHSA | Yes |
| Cross-ecosystem community edits | <https://github.com/github/advisory-database> accepts community PRs for npm, PyPI, Maven, Go and RubyGems, and is clonable in OSV format for offline work. Background on reviewed vs unreviewed: <https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database> | PR against the OSV JSON | GHSA | Yes |

### 6.3 After it lands

Confirm propagation a few days later in <https://osv.dev/> and <https://github.com/advisories>. OSV aggregates GHSA, PyPA, RustSec, Go, distro and OSS-Fuzz data across dozens of ecosystems, so if it is not there, something did not propagate. Who consumes the vulnerable code, for a severity argument you can defend: <https://docs.deps.dev/>

### 6.4 Malicious packages are a different pipeline

A malicious or trojaned package is not a vulnerability (CNA Rules §4.1.7-4.1.8, §3.8 above) and does not go through any of the routes in §6.2.

| Step | Where |
|---|---|
| The ecosystem's abuse channel | PyPI's "Report project as malware" form: <https://pypi.org/security/>. PyPI also asks that suspected issues not be raised in public forums. |
| The cross-ecosystem record, for detection and dedupe | <https://github.com/ossf/malicious-packages> — OSV format, PR-based. |

This repo uses those references for **detection and deduplication only**. It never authors, publishes, or documents how to author a malicious package.

---

## 7. What the researcher can and cannot do, summarised

| Action | Researcher | Maintainer / CNA | Agent |
|---|---|---|---|
| Determine CVE eligibility against §3 and write it down | Yes | — | Drafts it |
| Identify the right CNA and read its policy | Yes | — | Drafts it |
| Submit a private vulnerability report | Yes | — | **Never** |
| Open a draft repository advisory | Only with repo admin | Yes | **Never** |
| Edit a draft advisory | Yes, if added as a collaborator | Yes | Drafts text only |
| Click **Request CVE** | Only with admin on the advisory | Yes | **Never** |
| Assign a CVE ID | No | CNA only | **Never** |
| Publish an advisory | No | Yes | **Never** |
| Set the patched version | No | Yes | Drafts the value |
| Reserve a CAN at MITRE CNA-LR | Yes | — | **Never** |
| File to an ecosystem advisory database | Yes | — | Drafts the YAML/JSON only |
| Report a malicious package | Yes | — | **Never** |
| Answer a triager's follow-up question | Yes, in their own words | — | **Never** |

---

## 8. Currency and verification traps

| Trap | What to do |
|---|---|
| `www.cve.org` is a single-page app that returns HTTP 200 for **any** path. | A 200 does not prove a route exists. Verify a cve.org route in a browser, or against the router in the published site source, before relying on it. |
| `cveform.mitre.org` redirects to <https://mitre.github.io/mitre-cve-roles/> and the legacy form is being retired. | Use <https://mitre.github.io/mitre-cve-roles/cve-id-request/>. Any guidance that still says "fill in the form at cveform.mitre.org" is stale. |
| Government hosts (NVD, CISA portals) return a shell page or a 403 to automated clients. | A human confirms those URLs in a browser. Do not assert their contents from a failed fetch. |
| CVE Program funding and stewardship have been through repeated contract scares, and secondary reporting is noisy. | State the official request path, check <https://www.cve.org/> at the time of filing, and keep GitHub-as-CNA (§5.2) and Red Hat's open-source CNA (§5.3) documented as live alternatives. |
| CNA Rules get revised. | The version this file is written against is v4.2.0, approved 2026-08-20, effective 2026-08-25. Re-check the landing page (<https://www.cve.org/ResourcesSupport/AllResources/CNARules>) before citing a rule number in a request. |
