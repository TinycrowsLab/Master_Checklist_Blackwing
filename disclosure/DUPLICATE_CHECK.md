# Duplicate Check

Read this file before any candidate finding is written up, and again immediately before a human sends anything. It is the prior-art gate from [../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §3.5, expressed as a mechanical procedure with the exact queries to run.

---

## 1. The success criterion, and the stop conditions

**Finding a duplicate is a successful outcome of this phase.** It is the cheapest possible result: it costs an hour of querying and saves a maintainer's hour, your credibility, and a wasted write-up. Do not treat a hit as a failure and do not go looking for a reason your bug is subtly different. If it is subtly different, §12 has a row for that, and it is a different report with a different title.

| Stop condition | Action |
|---|---|
| A published advisory covers the same root cause and includes the version you tested | Stop. Record it. This is a duplicate, not a finding. |
| Any step cannot be completed | Stop. An incomplete duplicate check means the finding does not ship ([../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §3). |
| The bug is already public in an issue, a PR, a changelog entry or a mailing-list post | Stop and re-read [PROCESS.md](PROCESS.md). The route changes: there is no embargo to protect and the maintainer may already be working on it. |
| The latest release no longer reproduces the bug | Go to §9. It is probably already fixed. |

Run the whole sweep twice: once before investing in the write-up, and once in the 24 hours before the human sends. An advisory published mid-audit turns a vulnerability disclosure into, at most, a request that an existing fix be advised.

---

## 2. Step 0 — Pin the facts the queries need

Nothing below works without these. Record each in `FINDING.md` first.

| Fact | How to get it |
|---|---|
| Commit SHA | `git -C <clone> rev-parse HEAD` |
| Release tag you are on | `git -C <clone> describe --tags --exact-match 2>/dev/null \|\| git -C <clone> describe --tags` |
| Package name, exactly as published | The ecosystem's manifest, not the repo name. They differ more often than beginners expect. |
| Ecosystem | `PyPI`, `npm`, `crates.io`, `RubyGems`, `Go`, `Maven`, `Packagist`, `NuGet`, `Pub`, `Hex`, `SwiftURL` — use the OSV spelling: <https://ossf.github.io/osv-schema/> |
| Vulnerable file path and symbol | From the root-cause analysis, at the pinned SHA |
| A distinctive token from the vulnerable line | A literal string, unusual identifier, or constant. This is what git searching keys on. Pick something that will not appear in thousands of lines. |
| Candidate CWE | For filtering advisory databases by class |

---

## 3. Step 1 — OSV.dev

Highest-yield single check. OSV aggregates GHSA, PyPA, RustSec, the Go database, Debian, Alpine, OSS-Fuzz and dozens of other sources, and it is the only major database that can be queried **by commit hash** as well as by package and version — which is exactly what you have after auditing a clone.

Web UI: <https://osv.dev/> . API documentation, which is the authority for these shapes: <https://google.github.io/osv.dev/api/>

### 3.1 By package, ecosystem and version

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
        "package": { "name": "<package>", "ecosystem": "<Ecosystem>" },
        "version": "<version-you-tested>"
      }' | tee evidence/<id>/osv-query-version.json
```

### 3.2 By commit hash

Run this even if 3.1 returned nothing. It catches advisories whose version ranges were recorded as `GIT` ranges rather than semver.

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{ "commit": "<full-40-char-sha>" }' | tee evidence/<id>/osv-query-commit.json
```

### 3.3 Across a version range, in one request

Use `querybatch` to sweep every release you intend to claim as affected. This is how you check a 20-version range without 20 round trips.

```bash
curl -s -X POST https://api.osv.dev/v1/querybatch \
  -H 'Content-Type: application/json' \
  -d '{
        "queries": [
          { "package": { "name": "<package>", "ecosystem": "<Ecosystem>" }, "version": "1.0.0" },
          { "package": { "name": "<package>", "ecosystem": "<Ecosystem>" }, "version": "1.1.0" },
          { "commit": "<sha-of-the-tag-you-tested>" }
        ]
      }' | tee evidence/<id>/osv-querybatch.json
```

`querybatch` returns IDs only. Fetch the full record for each hit:

```bash
curl -s https://api.osv.dev/v1/vulns/<OSV-ID> | tee evidence/<id>/osv-<OSV-ID>.json
```

### 3.4 Vendored C/C++ trees

If the code you audited is a vendored copy and you do not know which upstream version it matches, OSV has an experimental endpoint for that:

```bash
curl -s -X POST https://api.osv.dev/v1experimental/determineversion \
  -H 'Content-Type: application/json' \
  -d '{ "name": "<library>", "file_hashes": [ ... ] }'
```

Read the API docs for the exact `file_hashes` shape before using it. If it cannot be used, say so in the record rather than skipping the vendored case silently; go to §10 instead.

### 3.5 Reading the result

| Result | Means |
|---|---|
| `{}` or an empty `vulns` array | No match **for that query**. It is not a clearance until §4 through §10 are also done. |
| One or more `vulns` entries | Open each one. Compare **root cause**, not title. Two advisories with similar titles are routinely different bugs, and two with different titles are routinely the same bug. |

---

## 4. Step 2 — OSV-Scanner over your own clone

Run it before auditing, so anything already known is off the table before you spend a day on it.

```bash
osv-scanner scan source -r <path-to-your-clone>
```

Tool: <https://github.com/google/osv-scanner> . Documentation: <https://google.github.io/osv-scanner/> . The lockfile and manifest formats it understands, which tells you which file to point it at: <https://google.github.io/osv-scanner/supported-languages-and-lockfiles/>

This is run against a clone the researcher holds. It is not, and must never be turned into, a scanner for finding vulnerable third-party hosts ([../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §1, §4).

---

## 5. Step 3 — GitHub Advisory Database

<https://github.com/advisories>

Search the package name, then the vulnerable symbol, then the bug class. Three partitions exist and they are not equivalent:

| Partition | Query | Why it matters |
|---|---|---|
| Reviewed | `type:reviewed <package>` | GitHub-curated. Strong prior art. |
| Unreviewed | `type:unreviewed <package>` | Roughly ten times larger than the reviewed set, and where CVE-only records hide. **Most beginners skip this and miss the duplicate.** |
| Malware | `type:malware <package>` | Malicious-package records. They carry no fix version, so do not read one as "no fix exists for my bug". |

Narrow with the facets, which are real filters, not decoration: ecosystem (`ecosystem:pip`, `npm`, `Go`, `Maven`, `RubyGems`, `Rust`, `Composer`, `NuGet`, `Pub`, `Swift`, `Erlang`, `actions`), `severity:low|moderate|high|critical`, and the **CWE filter** — searching your candidate CWE within the ecosystem finds same-class duplicates that a package-name search misses.

What reviewed versus unreviewed actually means, so you do not mistake an unreviewed NVD-derived entry for a confirmed duplicate, or dismiss one that is: <https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database>

For offline or scripted grepping over the whole corpus, clone it — it is published in OSV JSON format: <https://github.com/github/advisory-database>

---

## 6. Step 4 — CVE Program and NVD

### 6.1 CVE Program

<https://www.cve.org/>

Use the site's search box. Query the product name, then the vendor or project name, then the weakness term. Two cautions:

1. The site is a JavaScript single-page app. **It returns HTTP 200 for any path**, so a scripted status check proves nothing and this repo cannot verify a search-results URL shape. Open it in a browser and copy the URL you actually used into the record.
2. CVE records are not a complete picture of open-source vulnerabilities. Plenty of real, fixed bugs never got an ID. A clean CVE search is weak evidence on its own.

### 6.2 NVD

NVD is the place to filter by vendor, product, CPE, CVSS severity and publication date window — the one thing cve.org does poorly, and exactly what you need to check whether your finding is already known **for a specific version range**.

This repo deliberately does not print an NVD URL: `nvd.nist.gov` returns only a shell page to automated clients, so none of its URLs could be verified here. A human opens NVD in a browser, runs the vendor/product/version-range search, and pastes the URL they used into the record. Do not let an agent assert NVD's contents from a failed fetch, and do not let an unverified API endpoint into a script.

---

## 7. Step 5 — Snyk and the oss-security archive

| Source | URL | Use |
|---|---|---|
| Snyk Vulnerability Database | <https://security.snyk.io/vuln> | Fourth opinion. Sometimes carries records that never received a CVE. Filterable across Cargo, CocoaPods, Composer, Conan, Go, Hex, Maven, npm, NuGet, PyPI, pub, RubyGems, Swift, C/C++ and OS distributions. |
| oss-security archive | <https://www.openwall.com/lists/oss-security/> | Searchable back to 2008. Last sweep on the project name; catches disclosures and fix notices that never became a database record. |

---

## 8. Step 6 — Ecosystem-native databases and the project's own channels

### 8.1 The ecosystem's own database

Query the database your package's ecosystem actually uses. Routes and formats are in [CVE_AND_CNA.md](CVE_AND_CNA.md) §6; for duplicate-checking, search the repository directly.

| Ecosystem | Search here |
|---|---|
| Python / PyPI | <https://github.com/pypa/advisory-database> |
| Rust / crates.io | <https://github.com/rustsec/advisory-db> (also <https://rustsec.org/>) |
| Ruby / RubyGems | <https://github.com/rubysec/ruby-advisory-db> |
| PHP / Composer | <https://github.com/FriendsOfPHP/security-advisories> |
| Go | <https://go.dev/doc/security/vuln/> |
| Any, malicious packages | <https://github.com/ossf/malicious-packages> |

### 8.2 The project's own channels

The most commonly skipped source and a frequent source of duplicates.

1. The repo's **Security** tab → **Advisories**. Published GHSAs for the project live there.
2. `CHANGELOG`, `NEWS`, `HISTORY`, and the **release notes of every release after the version you tested**. Maintainers routinely describe a security fix in a release note and never file an advisory.
3. The project's own security page, if it has one.
4. Full-text search of **issues and pull requests, including closed ones**:
   ```
   repo:<owner>/<repo> <symbol> OR <distinctive-token>
   repo:<owner>/<repo> is:issue is:closed <bug-class-term>
   repo:<owner>/<repo> is:pr is:closed <symbol>
   ```
5. **Discussions**, if the project uses them.
6. The security-labelled backlog: `repo:<owner>/<repo> label:security`.

---

## 9. Step 7 — Silent-fix detection in git history

A bug quietly fixed without an advisory looks exactly like a new finding. This step is what separates the two. Run every command; record the output.

### 9.1 The decisive test first

```bash
# Build the latest release and re-run the PoC against it.
git -C <clone> fetch --tags
git -C <clone> checkout <latest-release-tag>
# ... build, then run the PoC ...
```

If it no longer reproduces, the bug is **already fixed**. Go to §12 and pick the right row. Do not report a fixed bug as a new vulnerability.

### 9.2 Find the change

```bash
# Every commit that added or removed the distinctive token, across all refs.
git -C <clone> log --all --oneline -S'<distinctive-token>' -- <path/to/file>

# The full history of just the vulnerable function.
git -C <clone> log -L :<function_name>:<path/to/file>

# Commits touching that file whose message mentions a security verb.
git -C <clone> log --all --oneline \
  --grep=security --grep=CVE --grep=overflow --grep=bounds \
  --grep=sanitiz --grep=validat --grep=escape --grep=traversal \
  --grep=injection -i -- <path/to/file>

# A regex search for the token, in case -S is too literal.
git -C <clone> log --all --oneline -G'<regex>' -- <path/to/file>
```

`--all` is not optional. A fix frequently lands on a maintenance branch, or in a fork's branch that was never merged, and a default-branch-only search misses it.

### 9.3 Decide whether the fix shipped

```bash
# Which releases contain the candidate fix commit?
git -C <clone> tag --contains <fix-sha>

# Which release first shipped the commit that INTRODUCED the bug?
git -C <clone> describe --contains <introducing-sha>

# Diff the vulnerable file between your tag and the newest tag.
git -C <clone> diff <your-tag>..<newest-tag> -- <path/to/file>

# Check maintenance branches for backports.
git -C <clone> branch -a --contains <fix-sha>
```

### 9.4 The decision

| Observation | Verdict |
|---|---|
| `tag --contains <fix-sha>` lists a release, and the PoC fails on it | Already fixed and shipped. §12 row 4. |
| The fix exists on `main` but `tag --contains` lists nothing | A **backport question for the maintainer**, not a vulnerability report. Django and Python both tell reporters to check exactly this first. |
| No fix commit anywhere, and the PoC reproduces on the newest supported release | Proceed. This is the normal path. |
| The bug only reproduces on `main`, never in a release | Frequently not reportable. curl: "Only curl releases are ever considered secure" — <https://curl.se/dev/secprocess.html> |
| The bug only reproduces on an EOL branch | Not reportable as a vulnerability. See [CVE_AND_CNA.md](CVE_AND_CNA.md) §3.2. |

---

## 10. Step 8 — Upstream, if the code is vendored or forked

If the audited tree contains a vendored copy, a fork, or a re-packaged library, **repeat §3 through §9 against upstream as well**, under upstream's package name and ecosystem.

1. Identify upstream: the vendor directory's README, `go.mod` replace directives, `package.json` `repository`, `Cargo.toml` source, a copied licence header, or §3.4.
2. Run the whole sweep against upstream's package name.
3. If upstream already fixed it, the finding is "downstream ships a vulnerable vendored copy of X at version Y" — which is a real and useful report, but a different one, with a different root cause sentence and a different remediation.
4. Record both sweeps separately in `duplicate_check`.

---

## 11. Recording the work

Every query gets a row. An unrecorded query did not happen, and the point of recording is that a reviewer can re-run the sweep without asking you anything.

Write the rows into the finding's `duplicate_check` array. The field names, the `source` enum and the `result` enum are defined in [../schemas/finding.schema.json](../schemas/finding.schema.json) and the schema sets `additionalProperties: false`, so an invented field fails validation. If this file and the schema disagree, **the schema wins**; fix this file.

```json
"duplicate_check": [
  {
    "source": "osv_dev",
    "query": "POST https://api.osv.dev/v1/query {\"package\":{\"name\":\"example-lib\",\"ecosystem\":\"PyPI\"},\"version\":\"2.4.1\"}",
    "url": "https://google.github.io/osv.dev/api/",
    "date": "2026-10-13",
    "result": "no_match",
    "note": "Raw response: evidence/F-2026-001-example-lib-path-traversal/osv-query-version.json"
  },
  {
    "source": "github_advisory_unreviewed",
    "query": "type:unreviewed ecosystem:pip example-lib",
    "url": "https://github.com/advisories",
    "date": "2026-10-13",
    "result": "match",
    "match_id": "GHSA-xxxx-xxxx-xxxx",
    "note": "Ruled out: same package, different sink (open() in cli.py); this finding is in parse_config()."
  }
]
```

| Field | Rule |
|---|---|
| `source` | Required. One of the schema's enum values: `osv_dev`, `osv_scanner`, `github_advisory_reviewed`, `github_advisory_unreviewed`, `cve_program`, `nvd`, `snyk`, `project_advisories`, `project_changelog`, `project_issues_and_prs`, `oss_security`, `upstream`, `other`. There is no enum value for an ecosystem-native database — use `other` and name it in `note`. |
| `query` | Required. The literal query string, request body, or command. Not a description of it. Prefix it with the method (`POST <url>`, `git log …`, `web search`) so the row is re-runnable. |
| `url` | The URL actually used. For a browser search, the URL from the address bar. |
| `date` | `YYYY-MM-DD`. |
| `result` | Required. `no_match`, `match`, or `inconclusive`. |
| `match_id` | Required in practice on a `match` row: the CVE/GHSA/PYSEC/RUSTSEC ID. |
| `note` | The evidence path under [../evidence/](../evidence/README.md), and on a ruled-out `match` the one sentence that distinguishes this finding. |

**Minimum rows before a human is asked to sign off:** OSV by version, OSV by commit, OSV-Scanner, GHSA reviewed, GHSA unreviewed, CVE Program, NVD, Snyk, the ecosystem-native database (`other`), the project's advisories, the changelog and release notes, issues and PRs including closed, oss-security, the git silent-fix sweep, and upstream if vendored. The schema requires at least one row on a `confirmed` record; this list is the repo's bar. An unresolved `result: inconclusive` row is a stop ([../RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) §3) — resolve it or hand the finding back.

A documented sweep is also one of the clearest signals that a report is not slop. Include a condensed version of it in the report itself — the destination section is in [templates/report.md](templates/report.md).

---

## 12. The decision table

| # | What the sweep found | Verdict | Action |
|---|---|---|---|
| 1 | Published advisory, same root cause, version range includes what you tested | **Duplicate.** Successful outcome. | Record the ID in `duplicate_check`, set `verdict: rejected` with `rejection_reason.code: duplicate` and the ID as `evidence`, close it. Report nothing. |
| 2 | Published advisory, same root cause, but the range **excludes** the version you tested and it still reproduces | Possible **incomplete fix**. | Different report, different title: "incomplete fix for `<ID>`". Reference the original advisory. A human decides whether to send it. |
| 3 | Published advisory, same package, **different** root cause or sink | Not a duplicate. | Record `result: match` with the `match_id` and the one sentence that distinguishes this finding. Proceed. |
| 4 | Fix exists in git and shipped in a release; no advisory was ever published | **Not a new vulnerability.** | Set `verdict: rejected` with `rejection_reason.code: already_fixed`. The only legitimate move is to ask the maintainer whether they want an advisory or a CVE for the fix they already shipped. Do not frame it as a new finding. |
| 5 | Fix on `main`, not in any release | **Backport question.** | Ask the maintainer about the backport. Not a vulnerability report. |
| 6 | Already discussed publicly in an issue, PR, changelog or mailing list | **Already public.** | Re-read [PROCESS.md](PROCESS.md). No embargo applies; do not treat it as an embargoed finding, and do not add detail to the public thread. |
| 7 | Upstream fixed it; the audited tree vendors a stale copy | Different finding. | Report "vendored copy of X at version Y is affected by `<ID>`" to the downstream project. |
| 8 | Nothing found, every row completed | Clear to proceed. | Attach the record to the finding and continue to [PROCESS.md](PROCESS.md). |
| 9 | Any row left `inconclusive` | **Stop.** | The finding does not ship. Hand back to the human with the unresolved row named. |
