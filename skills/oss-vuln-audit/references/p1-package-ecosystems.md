# Priority 1 — Library and Package Ecosystem Audit

The deep reference for auditing code that ships as a *library* to npm, PyPI, Maven Central, crates.io, RubyGems, the Go module proxy, or Packagist. Read it when the target is a package other projects depend on, and work through it in order: the trust boundary for a library is its own exported API, not an HTTP request, and almost every beginner mistake in this domain comes from forgetting that.

Binding constraints live in [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md) and [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md). Nothing in this file relaxes them. Where a procedure here would cross a line there, the procedure stops.

---

## 1. When to read this file, and the ordered review flow

### 1.1 Applicability

| Target shape | Use this file? |
|---|---|
| Package published to npm / PyPI / Maven / crates.io / RubyGems / Go proxy / Packagist | Yes |
| A monorepo that publishes one or more such packages | Yes, once per published package |
| An application or service that merely *consumes* packages | No — the trust boundary is its request surface, not an exported API |
| A CLI tool distributed through a package registry | Yes for the library surface; its argv surface is a separate target |
| A transitive dependency of the target that you did not pin | No — that is a different target; pin it and start again |

### 1.2 Entry gates — check in order, stop on the first failure

1. Confirm [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md) has been read this session. If not, read it, then return here.
2. Record the target as `ecosystem + package name + git remote + pinned commit SHA`. If you only have "latest", resolve it to a SHA and record the SHA. **If the target cannot be pinned, stop** — affected-version work (§6.1) is impossible without it, and ROE §3.3 requires it.
3. Confirm an analysis container exists with `--network=none`, `--read-only` plus a tmpfs where the runtime allows it, and `ulimit -v` + `timeout` applied to every execution. **If there is no container, stop and build one** — do not "just read the code in place" and then run something.
4. Create one new empty directory per downloaded artifact. Keep your own scripts in a *different* directory. Never run an interpreter or build tool with the artifact directory as cwd: a planted `json.py` executes on `import json`. Run analysis Python as `python -I`.
5. Write the no-go list into the finding record before opening any file: no traffic to any host you do not own; no packaging beyond a minimal in-container proof of the primitive; no detection-evasion work; no publishing to any registry; no target selection driven by CVE-count farming.
6. Confirm every planned step is either (a) read-only local analysis, or (b) a query to a public advisory/registry API, run in the **separate network step** of §2.2. Anything else: stop and ask a human.

### 1.3 Phase order and the gate to advance

| Phase | Output artefact | Gate to advance |
|---|---|---|
| 0 Scope | Target pinned to a SHA; no-go list written | §1.2 all pass |
| 0b Sandbox | Container built, artefact directories created | Container runs with no network |
| 1 Prior art | Prior-art log with dates and databases checked (§2) | No published advisory covers the behaviour you are about to study |
| 2 API inventory | Exported-symbol table (§1.5) | Every public symbol has a trust-level mark |
| 3 Scanner sweep | Lead list, every alert disposed (§4) | Zero undisposed alerts |
| 4 Manual trace | One written source→sink path per surviving lead (§3) | Path has file:line at the pinned SHA for every frame |
| 5 Local verify | Minimal PoC in `../../../evidence/<ID>/` | Reproduced from clean state in the container |
| 6 Reachability | Consumer-precondition sentence per candidate (§5) | Candidate survives the §5.3 decision table |
| 7 Range pinning | OSV range events, vulnerable symbol names (§6.1) | Ranges confirmed by bisect or history, not guessed |
| 8 Package + route | Draft report and OSV JSON (§6) | **Human sign-off. The agent does not send.** |

A phase that cannot complete does not get skipped. It kills the candidate. Record the kill in the lead log (§4.4).

### 1.4 What to open first, per ecosystem

Open left-to-right. The lockfile feeds §2; the manifest feeds the API inventory; the build/install-time code is read **before any install command runs at all**.

| Ecosystem | Resolved lockfiles (prior-art input) | Manifest and API surface, in this order | Code that runs at install or build — read first |
|---|---|---|---|
| npm / Node | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | `package.json` (`exports`, `main`, `module`, `bin`, `files`, `scripts`, `engines`) → the files `exports` actually points at → `lib/` or `src/` → `*.d.ts` | `preinstall`, `install`, `postinstall`, `prepare` in `scripts`; `binding.gyp` and `*.cc`/`*.node` |
| PyPI / Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`, `uv.lock`, `pylock.toml` | `pyproject.toml` (`[project]`, `[project.scripts]`, `[project.entry-points]`, `[build-system].build-backend`) → `src/<pkg>/__init__.py` and `__all__` → re-exported modules → `*.pyi` → `MANIFEST.in` | `setup.py` (executes at build time), the declared build backend, any sdist-only build step, `*.c`/`*.pyx` |
| Maven / Java | `pom.xml`, `gradle.lockfile`, `verification-metadata.xml` | `pom.xml` (packaging, dependencies, shade config) → `module-info.java` → public and protected members → `META-INF/services` → every `Serializable`/`Externalizable` class | Build plugins declared in `pom.xml` — running any `mvn` goal executes them |
| Cargo / Rust | `Cargo.lock` | `Cargo.toml` (`[features]`, which are default, any `*-sys` dependency) → `src/lib.rs` and every `pub` item reachable from it → modules containing `unsafe` | `build.rs` (executes at build time); proc-macro dependencies |
| RubyGems | `Gemfile.lock`, `gems.locked` | `*.gemspec` (`files`, `executables`, `extensions`) → `lib/<gem>.rb` and what it requires → public classes | `ext/**/extconf.rb`, `Rakefile` tasks |
| Go modules | `go.mod` | `go.mod` module path → every exported (capitalised) identifier per package → files with `import "C"` → uses of `unsafe`/`reflect` → `//go:generate` directives | No registry install hook; `import "C"` means a C compiler runs over target-controlled source |
| Composer / PHP | `composer.lock` | `composer.json` (`autoload`, `bin`, `scripts`) → public classes → every magic method (the gadget surface) | `scripts` in `composer.json`; any installed Composer plugin |

File list and the rule that **resolved lockfiles beat manifests** (range-only files such as `requirements.txt` are best-effort): <https://google.github.io/osv-scanner/supported-languages-and-lockfiles/>. npm lifecycle hook names and their trigger conditions: <https://docs.npmjs.com/cli/v11/using-npm/scripts>.

### 1.5 API inventory table — produce this before any grep

| Exported symbol | file:line @ SHA | Parameters | Documented trust level | Notes |
|---|---|---|---|---|
| | | | `trusted-input-only` / `untrusted-safe` / `undocumented` | |

Rules:

1. One row per symbol reachable from the manifest's declared entry points. Not one row per function in the repo.
2. "Documented" means the README, the API docs, the type declarations, or a docstring says something about input trust. Your inference is not documentation. If you are inferring, the mark is `undocumented`.
3. `undocumented` is where the best findings live, because the maintainer cannot fall back on "that API was never meant for untrusted input".
4. A symbol marked `trusted-input-only` by real documentation is a near-certain kill later (§5.3). Mark it now so you do not spend a day on it.

---

## 2. Baseline prior-art scan, per ecosystem, read-only

### 2.1 The rule

Prior art comes before analysis, not after. If the behaviour you are about to study is already published, you have at most a request that an existing fix be advised — not a vulnerability disclosure. Re-run this scan immediately before anything is handed to a human for sending (§6.4); an advisory published mid-audit changes what the report is.

### 2.2 The two-step network split — not optional

| Step | Where it runs | Network | What it may touch |
|---|---|---|---|
| A — Analysis | The `--network=none` container holding the clone | None | The clone, your scripts, the tmpfs |
| B — Prior art | A separate shell or container | Yes | Public advisory APIs and package registries, and nothing else |

Hard rules for step B:

1. Do not resolve, fetch, or request anything the *target's* manifest points at — not its homepage, not its declared download URLs, not its CI endpoints, not the maintainer's infrastructure. Reading published source is allowed (ROE §1); poking the project's hosts is not.
2. Registry and advisory APIs are being used as published, for their documented purpose. That is their intended use, not scanning. Keep it to lookups of the package you pinned.
3. Never run a prior-art tool that needs network **inside** the analysis container. One container, one purpose.

### 2.3 Cross-ecosystem first pass

`osv-scanner` is the first tool on a fresh clone; it covers every ecosystem in this file and reads lockfiles rather than resolving them (<https://google.github.io/osv-scanner/>).

```bash
# Confirm the installed CLI's syntax first — v1 and v2 differ on subcommands.
osv-scanner --help

# v2 syntax:
osv-scanner scan source -r /work/clone
# v1 syntax:
osv-scanner -r /work/clone
```

**Forbidden during an audit: `osv-scanner fix` (guided remediation).** It is a write/remediation path that edits manifests and lockfiles and drives package-manager resolution — `in-place` on an npm `package-lock.json`, `relax` on `package.json`, `override` via Maven `dependencyManagement` (<https://google.github.io/osv-scanner/experimental/guided-remediation/>). Resolution against an unread target is how you end up executing its code. Use it later, if at all, to describe an upgrade path in a report — never against the target tree.

Then query OSV directly for the pinned package. Three endpoints do all the work: `POST /v1/query` for one package+version, `POST /v1/querybatch` for a version sweep, and `GET /v1/vulns/{id}` to read one advisory. Read the API base URL and the exact request body shape from <https://google.github.io/osv.dev/api/> before the first call — do not type a hostname from memory. The query body is a `package` object (`ecosystem`, `name`) plus either a `version` or a `commit`; query by commit when the project does not tag releases.

### 2.4 Per-ecosystem baseline commands

| Ecosystem | Safe baseline | Why it is safe | Forbidden here |
|---|---|---|---|
| npm | `npm audit --json` and `npm audit --audit-level=high` against the committed lockfile; `npm audit signatures --json --include-attestations` for registry signatures and provenance attestations | Reads the lockfile and queries the registry; installs nothing | `npm audit fix`; any `npm install`/`npm ci` without `--ignore-scripts` |
| npm (install needed) | `npm ci --ignore-scripts` | `ignore-scripts` means "npm does not run scripts specified in package.json files" | Installing before the lifecycle hooks have been read |
| PyPI | `pip-audit -r requirements.txt --no-deps --require-hashes`; `-s osv` or `-s pypi` to pick the backend; `--ignore-vuln <id>` for triaged noise | `--no-deps` + `--require-hashes` keep it from resolving or building anything | Bare `pip-audit` inside an unread project tree (it may resolve and build the project); any auto-fix mode |
| PyPI (install needed) | `pip install --only-binary :all: --require-hashes --no-deps -r <locked>` | `--only-binary :all:` refuses sdists and therefore `setup.py` execution; any single `--hash` activates hash-checking mode globally | `pip install .`, `python setup.py <anything>`, installing an sdist from an unread target |
| Maven / Java | `dependency-check.sh --scan /work/clone --format JSON --out /work/out` | Reads files; needs an NVD data download, so it is a step-B command | `mvn <any goal>` on the target — Maven executes the plugins its own `pom.xml` declares |
| Cargo | `cargo audit --file /work/clone/Cargo.lock`, run with cwd **outside** the clone | Parses the lockfile only | **Bare `cargo audit` with no `Cargo.lock`: it runs `cargo update --workspace`** |
| Cargo (extras) | `cargo deny check advisories` once `Cargo.lock` exists; `cargo geiger` only after `build.rs` is read, inside the container | cargo-deny lints the dependency graph for advisories, bans, licenses and sources | Any cargo command that implies resolution or a build before `build.rs` has been read |
| RubyGems | `bundle-audit update` (step B, fetches the DB) then `bundle-audit check` against the committed `Gemfile.lock` | Checks the lockfile against ruby-advisory-db offline; also flags insecure `http://` and `git://` gem sources | `bundle install` / `gem install` before `ext/**/extconf.rb` has been read — those build native extensions |
| Go | `govulncheck ./...` inside the container, after `go.mod` review | Call-graph aware: reports what your code transitively reaches | Running it before reviewing `import "C"` usage, which compiles target-controlled C |
| Go (extras) | `go vet ./...`, `go test -race` | Standard verification recipe | Treating `govulncheck` silence as a clean bill of health — see §2.6 |
| Composer | `composer audit --no-scripts --no-plugins` | Audits against the Packagist API; also surfaces abandoned and malware-flagged packages. Exit 0 clean, 1 on match | **Any `composer` command without `--no-scripts --no-plugins`** |

Sources: <https://docs.npmjs.com/cli/v11/commands/npm-audit>, <https://docs.npmjs.com/cli/v11/using-npm/config>, <https://github.com/pypa/pip-audit>, <https://pip.pypa.io/en/stable/topics/secure-installs/>, <https://jeremylong.github.io/DependencyCheck/>, <https://github.com/rustsec/rustsec/tree/main/cargo-audit>, <https://embarkstudios.github.io/cargo-deny/>, <https://github.com/geiger-rs/cargo-geiger>, <https://github.com/rubysec/bundler-audit>, <https://go.dev/doc/security/best-practices>, <https://getcomposer.org/doc/03-cli.md>, <https://rustsec.org/>.

### 2.5 The code-execution trap table — the most important table in this file

Several baseline tools execute the target's code as a side effect. Memorise this before running anything.

| Command | What executes target code | Safe form | Hard rule |
|---|---|---|---|
| `cargo audit` with no `Cargo.lock` | Runs `cargo update --workspace`, pulling in and resolving dependencies against the target's config | `cargo audit --file /work/clone/Cargo.lock`, cwd outside the tree | Never run bare `cargo audit` inside an unread clone |
| `osv-scanner fix` | Drives package-manager resolution to rewrite manifests and lockfiles | Do not run it against the target | Remediation tooling is out of scope during an audit |
| any `composer` command | Installed Composer plugins activate on boot; `scripts` fire on install/update | Append `--no-scripts --no-plugins` every time | No exceptions, including `composer audit` |
| `npm install` / `npm ci` | `preinstall`, `install`, `postinstall`, `prepare` | `--ignore-scripts`; add `--foreground-scripts` only if you later choose to run them in the container, so their output is visible | Read every hook first; the official Node guidance's worked example of this threat is a `postinstall` that exfiltrates SSH keys |
| `pip install` of an sdist, `python setup.py` | `setup.py` and the declared build backend run at build time | `--only-binary :all:` to refuse sdists; `--require-hashes`; `--no-deps` | Never invoke `setup.py` directly |
| `cargo build` / `cargo test` / `cargo geiger` | `build.rs` and proc macros | Read `build.rs` first, then run inside the `--network=none` container | `cargo geiger` implies a build — it is not a read-only grep |
| `bundle install` / `gem install` | `ext/**/extconf.rb`, Rakefile tasks | Read them first, then build in the container | A gem with `extensions` in its gemspec compiles on install |
| `mvn <goal>` | Every plugin the `pom.xml` declares | Use the standalone `dependency-check` CLI against the files | Prefer file-reading tools over build-system invocations |
| `codeql database create` for `java`, `go`, `cpp` | Invokes the project's build system | Read the build config first; run inside the container | Treat it exactly like `mvn` or `cargo build` (§4.2) |
| `semgrep scan --config=auto` | Nothing in the target, but it resolves rules over the network | Run offline against cloned rules (§4.1); use `--config=auto` only as a step-B command | Never run a network-dependent scan inside the analysis container |

Install-hook enumeration and integrity verification — read the hooks, record whether each one reaches the network, writes outside the package directory, reads credentials or SSH keys, decodes an obfuscated blob, or shells out: <https://docs.npmjs.com/cli/v11/using-npm/scripts>, <https://nodejs.org/en/learn/getting-started/security-best-practices>. Then verify the release rather than trusting it: `npm audit signatures` for registry signatures and Sigstore-backed provenance (<https://docs.npmjs.com/generating-provenance-statements>, <https://docs.sigstore.dev/>), PyPI index-hosted attestations through the PEP 740 verification chain (<https://peps.python.org/pep-0740/>), pip hash-checking mode, and the project's OpenSSF Scorecard (<https://scorecard.dev/>) with Dangerous-Workflow, Token-Permissions, Pinned-Dependencies and Signed-Releases read as release-integrity observations. Record the SLSA build level the provenance actually supports (<https://slsa.dev/spec/v1.1/levels>). State in any report, as npm's own docs do, that provenance links an artifact to a source and build — **it does not prove the code is benign.**

We never author, publish, or describe how to author a malicious package. Suspected malware goes to the abuse channel (§6.3), not into a research write-up: <https://github.com/ossf/malicious-packages>.

### 2.6 Duplicate check — the full procedure

Run every step. Record which databases were checked and on what date; the report must state it.

1. `osv-scanner` over the clone, then direct `/v1/query` and `/v1/querybatch` for the pinned package and version (<https://osv.dev/>).
2. Search <https://github.com/advisories> for the package name, and read the **reviewed**, **unreviewed** and **malware** partitions separately. An unreviewed NVD-derived entry is weak prior art, not automatically a duplicate; a malware advisory has no fix version. Do not mistake either for the other: <https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database>.
3. Check the ecosystem-native database: <https://github.com/pypa/advisory-database>, <https://github.com/rustsec/advisory-db>, <https://github.com/rubysec/ruby-advisory-db>, <https://github.com/FriendsOfPHP/security-advisories>, <https://go.dev/doc/security/vuln/>. Clone <https://github.com/github/advisory-database> for an offline grep and for worked examples of good affected-range and CWE wording.
4. Grep the project's own history for silently fixed issues:

```bash
git log --all -i --grep=security --grep=CVE --grep=sanitiz --grep=traversal --grep=injection
```

Then read closed issues and PRs carrying a security label. **A bug fixed in `main` but never advised is a legitimate finding** — the ask is an advisory with correct ranges, not a patch.

5. For Go specifically: `govulncheck` is call-graph aware, so its silence on a reachable-but-uncalled path is not a clean bill of health (<https://go.dev/doc/security/vuln/>). Say that explicitly rather than quoting a clean run as proof.
6. Use <https://docs.deps.dev/> to enumerate real dependents — needed again in §5 to argue a consumer-side path.

**Stop condition.** If a published advisory already covers the same symbol and the same behaviour at an overlapping version range, kill the candidate and log it. Do not file a "better write-up" of a known bug.

---

## 3. Vulnerability classes

Each class below gives: what it is, which ecosystems it hits, what to grep, how to trace from the **public API** (the source) to the sink, what would **disprove** it, and the evidence required. Read the class section before writing the trace, not after.

Two global rules:

- A candidate is dead the moment any one kill criterion in its "Disproved by" list holds. Log it in the lead log (§4.4) with the criterion named. Do not look for a way around a guard that actually holds.
- The trace record must contain the exported API and parameter that is the source, every intermediate frame with `file:line` at the pinned SHA, the exact sink expression, and **every guard on the path with the reason it is insufficient** — wrong order, wrong encoding layer, normalisation after the check, check applied to a different variable, guard behind an opt-in flag that defaults off, or guard bypassed on a second code path. A finding with no written path is not a finding.

### 3.1 Prototype pollution and unsafe recursive merge, set, clone

**What it is.** A function writes `target[key]` while iterating caller-supplied keys, so a key of `__proto__`, `constructor`, or `prototype` reaches `Object.prototype` and changes behaviour for every object in the process. CWE-1321: <https://cwe.mitre.org/data/definitions/1321.html>. The three vulnerable code shapes come from the original research: recursive merge, path-based property assignment, and object clone (<https://github.com/HoLyVieR/prototype-pollution-nsec18>).

**Ecosystems.** npm/Node overwhelmingly. Watch for the same shape in any JS bundled inside another ecosystem's package.

**Grep.**

```bash
rg -n -e '__proto__' -e "\['constructor'\]" -e '\.prototype\[' -g '!test*' /work/clone
rg -n -e '\b(merge|deepMerge|mergeDeep|extend|defaultsDeep|mixin|assignDeep)\b' \
      -e '\bfunction set\(' -e '\.split\(['"'"'"]\.' -e '\bcloneDeep\b' -e '\bclone\b' /work/clone
```

**Source → sink trace.**

1. Source: the exported `merge(target, source)` / `set(obj, path, value)` / `clone(obj)` parameter from the §1.5 inventory.
2. Follow the key iteration. Note whether the recursion re-enters the same function (so a guard applied only at the top level is bypassed at depth).
3. Sink: the assignment `target[key] = ...` or the final `obj[last] = value`.
4. Record whether the target object came from `{}`/`Object.assign` (pollutable) or `Object.create(null)` (not), and whether the path parser splits on `.` or `[` in a way that reconstructs `__proto__` from pieces.

**Disproved by (any one kills it).**

- Every write target on the path is created with `Object.create(null)`, or the container is a `Map`.
- A key filter rejects `__proto__`, `constructor` and `prototype` **before every write, including inside the recursive call** — check the recursive frame, not just the entry frame.
- Assignment goes through `Object.defineProperty` with an own-property guard, or `Object.hasOwn` gates the copy.
- No public API path passes caller-controlled keys: keys come from a fixed internal allowlist.
- The PoC runs and `({}).polluted` is still `undefined` afterwards.

A consumer running Node with `--disable-proto` is a *consumer* mitigation. Note it as context; it does not kill a library bug.

**Evidence required.** Call the exported function with a `__proto__` or `constructor.prototype` key; show `({}).polluted` observable afterwards; **plus one realistic downstream consequence inside the library's own code** (a changed branch, a bypassed check, a default that now resolves to the attacker's value). Pollution with no demonstrated consequence is a hardening request, not an impact claim.

**Mitigation to recommend,** in CWE-1321's own order of effectiveness: block prototype-resolving attribute names (High), `Object.create(null)` (High), freeze the prototype (High, but discouraged inside a library), `Map` instead of objects (Moderate), schema validation (Limited). Note that <https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html> does **not** cover this class; cite <https://nodejs.org/en/learn/getting-started/security-best-practices> instead, which covers `__proto__`/`constructor`/`prototype`, `Object.create(null)`, `Object.hasOwn()`, `--disable-proto`, and "avoid insecure recursive merges".

### 3.2 ReDoS in exported regexes

**What it is.** A regex whose backtracking is super-linear in input length, reachable through an exported validator. CWE-1333: <https://cwe.mitre.org/data/definitions/1333.html>. The structural definition of an "evil regex" — grouping with repetition, containing repetition or overlapping alternation, with canonical examples `(a+)+$`, `([a-zA-Z]+)*$`, `(a|aa)+$`, `(a|a?)+$` — is at <https://community.owasp.org/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.

**Ecosystems.** npm/Node, Python, Java, Ruby, PHP. See the engine caveat below for Go and Rust.

**Grep.**

```bash
rg -n -e 'new RegExp\(' -e '=\s*/.*[+*]\).*[+*]' /work/clone -g '*.{js,mjs,cjs,ts}'
rg -n -e 're\.(compile|match|search|fullmatch)\(' /work/clone -g '*.py'
rg -n -e 'Pattern\.compile\(' /work/clone -g '*.java'
rg -n -e '=~' -e 'Regexp\.new\(' /work/clone -g '*.rb'
rg -n -e 'preg_(match|replace|split)\(' /work/clone -g '*.php'
```

**Source → sink trace.** Exported validator parameter → the regex object → the match call. Record the maximum input length the API accepts and whether any length cap exists *before* the match.

**Disproved by (any one kills it).**

- `recheck` reports the pattern safe or linear (<https://makenowjust-labs.github.io/recheck/>). Run this **first**; it handles backreferences and lookarounds, so it kills most shape-based suspicions before you spend time on timing.
- A length cap runs before the match and bounds worst-case time acceptably. Quote the cap and the bound.
- The regex is not reachable from any exported API: inputs are literals or a closed enum.
- The measured growth table (below) is linear.
- The engine does not backtrack — see the caveat.

**Engine caveat, and it is a triage rule you must not assert without checking.** Go's `regexp` and Rust's `regex` crate are commonly described as linear-time, non-backtracking engines, which would make classic backtracking ReDoS inapplicable to them; the backtracking surface there is `fancy-regex`, PCRE bindings, and explicit size or complexity limits. **This claim is carried here as an unsourced triage heuristic (Appendix A).** Use it to deprioritise, never to make an assertion in a report, until it has been confirmed against the engine's own documentation.

**Evidence required.** Never claim ReDoS from pattern shape. Run `recheck`, then produce a wall-time table at input lengths n, 2n, 4n, 8n with `timeout` as the backstop, and report the **growth curve**, not "it hangs":

| n | input length | wall time |
|---|---|---|
| n | | |
| 2n | | |
| 4n | | |
| 8n | | |

Note that the official Node security best-practices page has no ReDoS section; <https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html> gives the "stay away from evil regexes" line, and CWE-1333 gives the mitigations: remove nested quantifiers or use a non-backtracking engine (High), engine backtracking limits (Moderate), cap input length (Moderate).

### 3.3 Path traversal and zip slip in archive extraction

**What it is.** Extraction code that joins an archive entry name onto a destination directory without validating the result stays inside it, so `../../evil.sh` writes outside the intended root. Affects zip, tar, jar, war, cpio, apk, rar and 7z; the canonical write-up is <https://security.snyk.io/research/zip-slip-vulnerability>. Symlink and hardlink entries are a **separate** finding from plain traversal: the containment check can be correct and the extractor can still follow a link out of the root. CWE-22 and CWE-29.

**Ecosystems.** All seven. Historically worst in Java, but present everywhere.

**Grep.**

```bash
rg -n -e 'entry\.(fileName|path|name)' -e 'path\.join\(.*entry' -e '\b(decompress|unzip|extract)\b' /work/clone -g '*.{js,ts}'
rg -n -e 'tarfile' -e 'extractall' -e 'ZipFile' -e 'shutil\.unpack_archive' /work/clone -g '*.py'
rg -n -e 'ZipEntry' -e 'TarArchiveEntry' -e 'new File\(.*getName\(\)' /work/clone -g '*.java'
rg -n -e 'filepath\.Join\(.*hdr\.Name' -e 'tar\.Header' -e 'Typeflag' /work/clone -g '*.go'
rg -n -e 'Zip::File' -e 'TarReader' -e 'File\.join\(.*entry' /work/clone -g '*.rb'
rg -n -e 'extractTo' /work/clone -g '*.php'
rg -n -e 'enclosed_name' -e 'use (tar|zip)::' /work/clone -g '*.rs'
```

**Source → sink trace.** The exported `extract(archivePath, destDir)` parameter → the entry iteration → the path construction → the write (`createWriteStream`, `open`, `FileOutputStream`, `os.Create`, `File.open`). Record the entry types the extractor handles and what it does with each.

**Disproved by (any one kills it).**

- A containment check resolves the candidate path to an absolute, canonical form and then compares against `destDir + separator`. Check the separator: comparing against `destDir` alone lets `/tmp/dir2` pass a check intended for `/tmp/dir`.
- Python: `extractall(..., filter='data')` or `filter='tar'` is passed and the runtime supports it. `'tar'` strips leading `/`, refuses absolute paths and escapes, and clears setuid/setgid/sticky; `'data'` adds link and device restrictions (<https://peps.python.org/pep-0706/>). Note the default becomes `'data'` in 3.14 and the documented caveat that even `filter='data'` is "not suited for extracting untrusted files without prior inspection" (<https://docs.python.org/3/library/tarfile.html>) — so a library that extracts untrusted archives still owes its consumers a documented trust boundary.
- Rust: `ZipFile::enclosed_name()` or an equivalent containment check is used.
- Java: `destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator)`.
- Link entries are explicitly rejected or resolved-and-contained (Go: `tar.Header.Typeflag` symlink/hardlink cases handled).
- No public API path reaches the extractor with a caller-supplied archive.

If the containment check holds but link entries are unchecked, **the traversal lead dies and a symlink lead opens.** File it as its own candidate.

**Evidence required.** Build the malicious archive locally with the ecosystem's own writer (never ship a pre-built archive from elsewhere), extract into a fresh empty directory inside the container, and show `find` output before and after with the exact path written outside the intended root. For the symlink variant, show the link target resolution separately. Precedent to cite for an unfiltered `extractall`: CVE-2007-4559, via PEP 706.

### 3.4 Insecure deserialization

**What it is.** Reconstructing attacker-controlled bytes into live objects, where the format itself permits code execution or dangerous object construction. CWE-502: <https://cwe.mitre.org/data/definitions/502.html>. Note CWE-502's own point, which you reuse whenever a maintainer proposes a class allowlist as the whole fix: **allowlisting alone is insufficient, because new gadgets keep appearing.** Per-language clear-box review guidance: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> (no Ruby section — see below).

**Ecosystems and the per-language sink set.**

| Ecosystem | Sinks | Upstream citation to quote |
|---|---|---|
| Python | `pickle.load/loads`, `cPickle`, `dill.load`, `joblib.load`, `torch.load`, `numpy.load(..., allow_pickle=True)`, `pandas.read_pickle`; `yaml.load(` without `Loader=SafeLoader\|CSafeLoader`, `yaml.unsafe_load`, `yaml.full_load` | "It is possible to construct malicious pickle data which will execute arbitrary code during unpickling" (<https://docs.python.org/3/library/pickle.html>); "It is not safe to call yaml.load with any data received from an untrusted source!" (<https://pyyaml.org/wiki/PyYAMLDocumentation>) |
| Java | `readObject`, `readExternal`, `readResolve`, `ObjectInputStream`, `XMLDecoder`, `new Yaml()` without a `SafeConstructor`, XStream without allowlisting | Serialization filtering entry point: <https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html> |
| PHP | `unserialize(` without `['allowed_classes' => ...]`; `Phar`/`PharData`, since phar stream access triggers unserialisation | Untrusted input is unsafe "regardless of the options value of allowed_classes", because "unserialization can result in code being loaded and executed due to object instantiation and autoloading" (<https://www.php.net/manual/en/function.unserialize.php>) |
| Ruby | `Marshal.load`, `YAML.load`, `YAML.unsafe_load`, `Psych.load`, `from_yaml`, MessageVerifier or cookie stores with a Marshal/YAML coder | "You should never unmarshal user supplied input or other untrusted data" (<https://docs.ruby-lang.org/en/master/Marshal.html>) — cite this directly, the OWASP cheat sheet has no Ruby section |
| Node | `node-serialize`, `funcster`, `js-yaml` `load()` on v3 or earlier | — |
| Go | `encoding/gob` on untrusted input; `gopkg.in/yaml.v*` `Unmarshal` vs `UnmarshalStrict`; any custom `UnmarshalJSON` that allocates from a length field | — |

**Source → sink trace.** Exported `load`/`parse`/`fromBytes` parameter → every frame → the deserialise call. For Java and PHP, additionally inventory the **library's own gadget surface**: Java `Serializable` classes whose `readObject`/`readResolve` does I/O, reflection or process execution; PHP `__destruct`, `__wakeup`, `__unserialize`, `__toString`, `__get`, `__call` implementations that touch files, the network, or processes. Describe the chain in prose. **Do not weaponise it.**

**Disproved by (any one kills it).**

- The bytes are authenticated before the deserialise call with an HMAC verified in constant time, and the key is not derivable from the package or from caller-visible data. Check both halves.
- Python: `Loader=SafeLoader`/`CSafeLoader` or `yaml.safe_load` on every path.
- Java: an `ObjectInputFilter`, filter factory, or `jdk.serialFilter` is configured **and** the allowlist excludes every gadget type you inventoried. Absence of any filter is itself the finding.
- PHP: `allowed_classes => false` removes the object-instantiation primitive; the lead survives only if a class still reachable through the allowlist has a dangerous magic method.
- No public API path reaches the call with caller-controlled bytes.

**Evidence required.** Demonstrate that a benign marker object or an attacker-chosen class is instantiated — for example a file written to the container's tmpfs. **Do not build or include a weaponised RCE chain.** Proving the primitive exists is the whole goal (ROE §4).

**Fix wording.** Python: `Unpickler.find_class()` restriction when a pickle format must be kept, otherwise a non-executing format. Java: pattern-based filters or a filter factory — but the exact `jdk.serialFilter` pattern syntax lives on the child pages of the Oracle hub above, which are not verified here, so **do not quote syntax you have not opened.** PHP: JSON plus `hash_hmac()` validation, as the manual itself recommends.

### 3.5 Command injection

**What it is.** A caller-controlled value reaches a shell. CWE-78.

**Ecosystems.** All seven.

**Grep.**

```bash
rg -n -e 'child_process' -e '\bexecSync\(' -e '\bexec\(' -e 'shell:\s*true' -e 'shelljs' /work/clone -g '*.{js,ts}'
rg -n -e 'shell\s*=\s*True' -e 'os\.system\(' -e 'os\.popen\(' -e 'commands\.getoutput' /work/clone -g '*.py'
rg -n -e 'Runtime\.getRuntime\(\)\.exec\(' -e 'new ProcessBuilder' /work/clone -g '*.java'
rg -n -e 'exec\.Command\(' /work/clone -g '*.go'
rg -n -e '`' -e '%x\(' -e '\bsystem\(' -e '\bspawn\(' -e 'Open3' -e 'Kernel\.open\(' -e 'IO\.(read|foreach)\(' /work/clone -g '*.rb'
rg -n -e '\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(' -e 'escapeshellcmd' /work/clone -g '*.php'
rg -n -e 'Command::new\("sh"\)' -e 'Command::new' /work/clone -g '*.rs'
```

**Source → sink trace.** Exported parameter → the string construction (template literal, f-string, `fmt.Sprintf`, `%`/`.format()`, concatenation) → the spawn call. Record whether a shell is actually involved: that is what decides whether the sink is real.

**Disproved by (any one kills it).**

- Node: the sink is `execFile` or `spawn` with an argument array and `shell` not enabled. `exec`/`execSync` always use a shell and carry the upstream warning "Never pass unsanitized user input to this function"; `execFile`/`spawn` carry it only when `shell` is enabled (<https://nodejs.org/api/child_process.html>).
- Python: arguments are passed as a sequence with `shell=False`, or quoted with `shlex.quote()`. **But** the Windows `.bat`/`.cmd` exception (gh-114539) reverses the usual advice — read <https://docs.python.org/3/library/subprocess.html> before claiming a fix, because getting this nuance right is what distinguishes a careful report from a scanner dump.
- Ruby: the multi-argument `system(cmd, *args)` / `spawn(cmd, *args)` form is used, which does not invoke a shell. Backticks and `%x(` always do. For the Ruby-specific trap, the lead dies if the value goes to `File.open`/`File.read` rather than `Kernel.open`/`IO.read`/`IO.foreach` — the latter execute a subshell when the value begins with `|`.
- Java: `ProcessBuilder` with a list and no shell wrapper; no tainted environment entries.
- PHP: `escapeshellarg` applied per argument. `escapeshellcmd` over a whole command line is not equivalent and its presence is not a kill.
- The value is validated against a strict allowlist or a regex anchored at both ends before use.

**Evidence required.** Show the argument reaching the shell using a harmless observable marker — a file created in the container's tmpfs, a distinctive string on stdout. **Never a destructive command.**

### 3.6 SSRF and redirect following in HTTP clients

**What it is.** A library builds and issues a request from a caller-supplied URL, or follows a redirect to a destination that was never validated. CWE-918. Reference for the controls: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>.

**Ecosystems.** All seven, wherever the package wraps an HTTP client.

**Grep.**

```bash
rg -n -e 'http\.request' -e '\bfetch\(' -e 'axios' -e 'maxRedirects' -e 'followRedirect' /work/clone -g '*.{js,ts}'
rg -n -e 'requests\.(get|post)\(' -e 'allow_redirects' -e 'verify\s*=\s*False' /work/clone -g '*.py'
rg -n -e 'setInstanceFollowRedirects' -e 'HttpClient\.Redirect' /work/clone -g '*.java'
rg -n -e 'http\.(Get|Client\{)' -e 'CheckRedirect' /work/clone -g '*.go'
rg -n -e 'file_get_contents\(\$' -e 'CURLOPT_FOLLOWLOCATION' -e 'CURLOPT_SSL_VERIFYPEER' /work/clone -g '*.php'
```

**Source → sink trace.** Exported URL/host parameter → validation, if any → the client call → the redirect handler. Record the default redirect behaviour: Go's `http.Client` with a nil `CheckRedirect` follows up to ten redirects by default, and that default is the finding in a surprising number of wrapper libraries.

**Disproved by (any one kills it).**

- Redirect following is disabled, which the OWASP sheet instructs precisely so validation cannot be bypassed.
- The host is validated **after** resolution and the connection is pinned to the validated IP. Note the two traps: domain allow-listing alone does not prevent DNS rebinding, and a second unchecked lookup between validation and connection re-opens it.
- Authorization headers and credentials are stripped on a cross-origin redirect.
- The URL is not caller-controlled: a fixed base with a path-only parameter.

**Evidence required.** Stand up a listener **inside the container** on localhost and show the request arriving at a destination the caller never authorised. **No request leaves the container.** An SSRF PoC that reaches any external host, including a "harmless" canary service, violates ROE §1 — there is no version of that which is in scope.

`verify=False` / `CURLOPT_SSL_VERIFYPEER => false` in a library's default path is a separate finding (CWE-295), not part of the SSRF one.

### 3.7 XXE and XML parser defaults

**What it is.** An XML parser that resolves external entities or loads external DTDs on data the library accepts from its caller. CWE-611, plus CWE-776 for entity-expansion DoS. The per-parser safe-configuration reference to diff against: <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html>.

**Ecosystems.** Java most of all (factory defaults differ per factory), plus Python, PHP, Ruby, Node. See the Go caveat.

**Grep.**

```bash
rg -n -e 'DocumentBuilderFactory' -e 'SAXParserFactory' -e 'XMLInputFactory' \
      -e 'TransformerFactory' -e 'SchemaFactory' -e 'XPath' -e 'Unmarshaller' \
      -e 'XMLDecoder' /work/clone -g '*.java'
rg -n -e 'xml\.etree' -e 'minidom' -e 'lxml\.etree\.(fromstring|parse)' -e 'defusedxml' /work/clone -g '*.py'
rg -n -e 'simplexml_load_string' -e 'DOMDocument' -e 'LIBXML_NOENT' -e 'libxml_disable_entity_loader' /work/clone -g '*.php'
rg -n -e 'Nokogiri::XML' -e 'Document\.parse' -e 'noent' -e 'DTDLOAD' /work/clone -g '*.rb'
```

**Source → sink trace.** Exported parse parameter → the factory or parser construction → every `setFeature`/`setProperty`/option → the parse call. For Java, diff the configuration **line by line** against the cheat sheet's safe settings; cover `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `XPath`, JAXB `Unmarshaller`, and the wrappers (dom4j, JDOM, Commons Digester). The cheat sheet also warns against `java.beans.XMLDecoder` on untrusted input — if you find it, that is §3.4, not this class.

**Disproved by (any one kills it).**

- `FEATURE_SECURE_PROCESSING` set, `disallow-doctype-decl` set, and `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` emptied, on the factory actually used on the path.
- Python: `defusedxml`, or `lxml` with `resolve_entities=False` and `no_network=True`.
- PHP: entity loading not enabled. Reliance on the removed `libxml_disable_entity_loader` is **not** a kill — it is its own finding.
- Ruby: `Nokogiri` parsed without `NOENT`/`DTDLOAD`.
- The parse call is unreachable from any exported API with caller-supplied XML.

**Go caveat, unsourced.** Go's `encoding/xml` is commonly said not to resolve external entities by default, which would mean XXE findings there need a different argument (entity expansion, or a third-party parser). **This is carried as an unsourced triage heuristic (Appendix A)** — confirm against the package documentation before asserting it either way. There is no Ruby section in the OWASP XXE sheet either; argue Ruby cases from Nokogiri's own option semantics.

**Evidence required.** Use a `file://` entity pointing at a marker file **inside the container** and show its contents appearing in the parse result. **Never an `http://` entity to any host** — that is an out-of-band request to a system you do not own. For expansion DoS, show the growth curve as in §3.2, with `ulimit -v` and `timeout` applied.

### 3.8 Crypto misuse

**What it is.** A cipher mode, IV/nonce, randomness source, or comparison that defeats the guarantee the library claims to provide. Relevant CWEs sit in the CWE-32x range plus CWE-208 (timing) and CWE-338 (non-CSPRNG).

**Ecosystems.** All seven.

**Grep.**

```bash
rg -n -e 'aes-[0-9]+-ecb' -e 'Buffer\.alloc\(16\)' -e 'Math\.random\(\)' -e 'createHmac' /work/clone -g '*.{js,ts}'
rg -n -e 'MODE_ECB' -e 'hashlib\.(md5|sha1)' -e '\brandom\.' -e 'compare_digest' /work/clone -g '*.py'
rg -n -e 'Cipher\.getInstance\("AES"\)' -e '"AES/ECB' -e 'new IvParameterSpec\(new byte\[' \
      -e 'SecureRandom\(\)\.setSeed' -e 'new Random\(' -e 'Arrays\.equals' /work/clone -g '*.java'
rg -n -e 'math/rand' -e 'ConstantTimeCompare' -e 'NewCBCEncrypter' /work/clone -g '*.go'
rg -n -e 'Digest::(MD5|SHA1)' -e 'aes-256-ecb' -e '\brand\b' -e 'secure_compare' /work/clone -g '*.rb'
rg -n -e 'MCRYPT_MODE_ECB' -e 'openssl_encrypt' -e '\b(mt_rand|uniqid)\(' -e 'hash_equals' /work/clone -g '*.php'
```

**Source → sink trace.** The exported encrypt/sign/verify/token API → the key, IV/nonce and comparison it uses → the primitive call. The question is always: what guarantee does the API's name and documentation promise, and which concrete step breaks it?

**Disproved by (any one kills it).**

- Mode is explicit and not ECB. Watch Java's `Cipher.getInstance("AES")`, which defaults to ECB — the absence of a mode string is the bug.
- The IV is generated per message from a CSPRNG and transmitted with the ciphertext; an AEAD nonce is unique per key with a documented uniqueness argument.
- Randomness comes from a CSPRNG: `crypto.randomBytes` (<https://nodejs.org/api/crypto.html>), `secrets`/`os.urandom`, `SecureRandom`, `crypto/rand`, `SecureRandom` (Ruby), `random_bytes` (PHP).
- Comparison is constant-time: `crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `subtle.ConstantTimeCompare`, `OpenSSL.secure_compare` / `ActiveSupport::SecurityUtils.secure_compare`, `hash_equals`.
- The compared value is not a secret — a public checksum compared with `==` is not a timing finding.
- No security decision depends on the weak primitive. "Uses MD5 somewhere" with no security consequence is a low-yield non-finding (§5.4); kill it and log it.

**Evidence required.** Show the concrete consequence, not the pattern: identical ciphertext blocks for identical plaintext blocks under ECB; nonce reuse enabling XOR recovery of a known-plaintext region; a measurable timing differential across many trials with the trial count and distribution stated. A crypto finding with no demonstrated consequence does not ship.

### 3.9 Template injection

**What it is.** A caller-supplied string is used as a *template* rather than as template *data*, so the template engine evaluates it. CWE-1336. Methodology: detect in plaintext versus code context, identify the engine with a payload decision tree, then enumerate accessible objects and dangerous functions — <https://portswigger.net/research/server-side-template-injection>, which also covers the sandbox surface (FreeMarker, Velocity, Smarty secure mode, Twig sandbox, Jade) that a templating library itself owns.

**Ecosystems.** Python (Jinja2), PHP (Twig, Smarty), Ruby (ERB, Liquid), Java (FreeMarker, Velocity), Node.

**Grep.**

```bash
rg -n -e 'jinja2\.Template\(' -e 'Environment\(' -e 'autoescape\s*=\s*False' -e 'SandboxedEnvironment' /work/clone -g '*.py'
rg -n -e 'ERB\.new\(' -e 'Liquid::Template\.parse\(' /work/clone -g '*.rb'
rg -n -e 'createTemplate\(' -e 'new Smarty' -e 'setSandbox' /work/clone -g '*.php'
```

**Source → sink trace.** Exported parameter → whether it becomes the template source or the template context → the render call. These are different findings with different severities; state which one you have.

**Disproved by (any one kills it).**

- The template source is a literal or a compile-time constant and only the *data* is caller-controlled. That is not SSTI. If the data reaches an HTML sink unescaped, that is XSS in the consumer, a separate class.
- A sandbox is in use (Jinja2 `SandboxedEnvironment`, Twig sandbox, Smarty secure mode) **and** its policy does not expose dangerous functions or attributes. If it does, the sandbox escape is the finding, and the PortSwigger methodology is how you characterise it.
- No public API path passes a caller string as template source.

Do not conflate `autoescape` with SSTI control. `autoescape` is an output-encoding control; it does not stop template evaluation.

**Evidence required.** Show evaluation with a harmless arithmetic or string marker, then show the first step of object access that the sandbox was supposed to prevent. Stop there. Do not build a full escape-to-RCE chain.

### 3.10 TOCTOU and symlink issues in temp-file and filesystem helpers

**What it is.** A check and a use separated in time on the same path, or a predictable temp-file name, letting a local attacker swap the target between the two. CWE-367: <https://cwe.mitre.org/data/definitions/367.html>, whose core advice is simply not to perform a check before the use.

**Ecosystems.** All seven, concentrated in "helper" and "utils" modules.

**Grep.**

```bash
rg -n -e 'existsSync' -e 'os\.tmpdir\(\)' -e 'mkdtemp' -e 'lstat' -e 'realpath' /work/clone -g '*.{js,ts}'
rg -n -e 'tempfile\.mktemp' -e 'os\.path\.exists' -e 'os\.chmod' /work/clone -g '*.py'
rg -n -e 'File\.createTempFile' -e 'Files\.createTempFile' /work/clone -g '*.java'
rg -n -e 'os\.OpenFile' -e 'O_EXCL' -e 'ioutil\.TempFile' /work/clone -g '*.go'
rg -n -e 'Dir\.tmpdir' -e 'File\.exist\?' -e 'Tempfile' /work/clone -g '*.rb'
```

**Source → sink trace.** Exported helper → the check (`exists`, `access`, `stat`) → the use (`open`, `write`, `chmod`). Record the window between them and who can write to the containing directory.

**Disproved by (any one kills it).**

- Creation is atomic: `O_EXCL`, `fs.mkdtemp`, `tempfile.NamedTemporaryFile`/`mkdtemp`, `Files.createTempFile` with explicit POSIX permissions, `Tempfile`.
- No check-then-use pair exists on the same path; the code opens and handles the error.
- The mode is passed at creation rather than `chmod`-ed afterwards.
- The path lives inside a directory only this process can write — for example a freshly created `mkdtemp` root. Then the race is not reachable by another local user: say so and **downgrade**, do not file it at full severity.

**Evidence required.** A reproduction in the container showing the swapped target being used, with the local-attacker precondition stated prominently in the impact (ROE §3.4). A TOCTOU finding that requires local code execution on the same host is a real but bounded finding; severity must reflect that.

### 3.11 Unsafe reflection and dynamic require

**What it is.** A name from a parameter or config is resolved to a module, class, or method and then loaded, instantiated, or called. CWE-470.

**Ecosystems.** All seven; most common in plugin loaders, serialiser registries, and "driver" abstractions.

**Grep.**

```bash
rg -n -e 'require\([^'"'"'"]' -e 'import\([^'"'"'"]' -e '\beval\(' -e 'new Function\(' -e 'vm\.runInNewContext' /work/clone -g '*.{js,ts}'
rg -n -e '__import__' -e 'importlib\.import_module' -e 'getattr\(' -e '\bexec\(' -e '\beval\(' /work/clone -g '*.py'
rg -n -e 'Class\.forName' -e 'newInstance' -e 'setAccessible\(true\)' -e 'MethodHandles' /work/clone -g '*.java'
rg -n -e 'instance_eval' -e 'class_eval' -e 'define_method' -e 'const_get' -e 'public_send' -e '\bsend\(' /work/clone -g '*.rb'
rg -n -e 'call_user_func' -e '\$\$' -e '(include|require)(_once)?\s*\(?\$' -e 'create_function' \
      -e 'assert\s*\(\s*\$' -e 'preg_replace\(.*/e' /work/clone -g '*.php'
```

**Source → sink trace.** Exported name/config parameter → the resolution step → the load/instantiate/invoke. Record exactly which part of the name the caller controls: a full dotted path is far worse than a leaf within a fixed namespace.

**Disproved by (any one kills it).**

- The name resolves through a fixed map or an explicit allowlist.
- Resolution is confined to a package-internal namespace prefix **and** the prefix cannot be escaped. Test `../`, absolute paths, and the ecosystem's own resolution quirks before accepting this.
- The argument is a literal or comes from a closed enum on every public path.
- The resolved symbol is only read, never called or instantiated. This weakens the finding to arbitrary-module-load rather than arbitrary-call; it does not always kill it, so state which one you have.

**Evidence required.** Load a benign marker module or class of your choosing and show it was loaded — a printed marker, a file in the tmpfs. Nothing further.

### 3.12 Bounds and integer issues in native addons and unsafe Rust

**What it is.** Memory-safety and arithmetic bugs in code the library ships as native: Node N-API/`node-gyp` addons, Python C/Cython extensions, Ruby C extensions, cgo, and `unsafe` Rust. For Rust specifically, the question is **soundness**: can *safe* code, calling only the public API, violate an invariant an `unsafe` block depends on? Review reference: <https://doc.rust-lang.org/nomicon/>.

**Ecosystems.** Rust, Go (cgo/`unsafe`), and any package with a compiled component.

**Grep.**

```bash
rg -n -e 'unsafe \{' -e 'unsafe fn' -e 'unsafe impl (Send|Sync)' -e 'from_raw_parts' \
      -e 'from_utf8_unchecked' -e 'transmute' -e 'get_unchecked' -e 'set_len' \
      -e 'MaybeUninit' -e 'assume_init' -e 'ptr::copy' -e 'Box::from_raw' \
      -e 'CStr::from_ptr' -e 'mem::zeroed' -e 'extern "C"' /work/clone -g '*.rs'
rg -n -e 'as usize' -e 'as u32' -e 'with_capacity\(' -e 'checked_(add|mul|sub)' /work/clone -g '*.rs'
rg -n -e 'unsafe\.Pointer' -e 'import "C"' /work/clone -g '*.go'
rg -n -e 'napi_' -e 'Napi::' -e 'info\[[0-9]\]' /work/clone -g '*.{cc,cpp,c,h}'
```

Rank the surface before reading it: `cargo geiger` orders a crate and its tree by `unsafe` usage (<https://github.com/geiger-rs/cargo-geiger>). It is statistical input for aiming review, **not a vulnerability verdict** — and it implies a build (§2.5).

**Source → sink trace.** For each `unsafe` block: write down the SAFETY invariant it relies on, then try to construct a call **through the public API, from safe code only**, that breaks it. For FFI: for every `extern "C"` boundary, record who owns each pointer, whether the length is trusted from the other side, and whether a borrowed pointer can outlive its Rust owner.

**Disproved by (any one kills it).**

- The invariant is genuinely enforced by the public API on every path — write the enforcement, with `file:line`.
- The length or capacity comes from the Rust side or from data already read, not from the FFI peer or an untrusted length field.
- `checked_add`/`checked_mul` (or equivalent) guard the arithmetic before an allocation or an index.
- The only way to reach it is by calling an `unsafe fn`. Then the caller owes the invariant and it is **not** a soundness bug. It may still be a documentation bug if the `# Safety` section is missing or wrong — file it as that, honestly.
- Native addon: argument count and types are validated before `info[i]` is read.

**Evidence required.** A safe-code-only reproduction, run under the sanitiser or runtime check that fires (`cargo test` with a debug assertion, ASan, `go test -race`). Report the crash trace or assertion failure — that is usually enough (ROE §4). Do not develop it into a controlled-write or exploitation primitive.

**Where it goes.** Rust soundness bugs that are not classic CVEs belong in RustSec's `informational = "unsound"` category (§6.2), not in a CVE request.

---

## 4. Static analysis: rules, invocation, triage

Scanners are **lead generators**. Nothing from a scanner is reported without a hand-traced path (§3).

### 4.1 Semgrep, offline, reading the rules as a sink inventory

Clone the rule corpus and read it. The point is not only to run it: the rules encode real sink patterns per ecosystem, which is far better than guessing registry ruleset IDs.

```bash
# Step B (network), once:
git clone --depth 1 https://github.com/semgrep/semgrep-rules /work/rules/semgrep-rules
git clone --depth 1 https://github.com/trailofbits/semgrep-rules /work/rules/tob

# Step A (offline), inside the container:
semgrep scan --metrics=off \
  --config /work/rules/semgrep-rules/javascript \
  --config /work/rules/semgrep-rules/python \
  --config /work/rules/tob \
  /work/clone
```

Rule directories worth reading per ecosystem: `python`, `javascript`, `typescript`, `java`, `go`, `ruby`, `php`, `csharp`, `c/lang`, `rust/lang/security`, plus `package_managers` and `problem-based-packs` (<https://github.com/semgrep/semgrep-rules>). The Trail of Bits corpus carries high-signal rules the community pack lacks: pickle-based model loading across PyTorch/NumPy/pandas/Keras/TensorFlow/joblib, `numpy.f2py` compilation, Go concurrency bugs (racy map writes, missing unlocks, `WaitGroup` misuse), insecure transport and disabled certificate validation, Ruby insecure YAML and cookie stores (<https://github.com/trailofbits/semgrep-rules>).

To stack a registry pack with your own rule file, the invocation form is `semgrep scan --config p/<pack> --config PATH/TO/RULE.yaml`, and `--config=auto` selects the default set (<https://docs.semgrep.dev/running-rules>). Both need the network, so they are step-B commands — never inside the analysis container.

### 4.2 CodeQL

```bash
# Step B: fetch the pack.
codeql pack download codeql/javascript-queries     # GITHUB_TOKEN or --github-auth-stdin required

# Step A: build the database.
codeql database create /work/db --language=javascript --source-root=/work/clone

codeql database analyze /work/db codeql/javascript-queries \
  --format=sarif-latest --output=/work/out/js.sarif
```

Mechanics for `codeql pack download <scope>/<pack>` and `codeql database analyze <db> <pack> [query|suite]`, including the container-registry auth requirement: <https://docs.github.com/code-security/codeql-cli/publishing-and-using-codeql-packs/>. The eight standard packs you will actually type — `codeql/cpp-queries`, `codeql/csharp-queries`, `codeql/go-queries`, `codeql/java-queries`, `codeql/javascript-queries`, `codeql/python-queries`, `codeql/ruby-queries`, `codeql/swift-queries` — plus model packs for extending library coverage: <https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-query-packs>. To run the security-extended suite rather than the pack default, pass the suite path inside the pack; confirm the exact suite name against the pack's own contents rather than guessing it.

**Safety.** For `java`, `go` and `cpp`, `codeql database create` invokes the project's build system. Read the build configuration first and run it inside the container, exactly as for `mvn` or `cargo build` (§2.5). For `javascript`, `python` and `ruby`, extraction does not build the project.

### 4.3 The library-input query families — prioritise these

Most security queries assume an application entry point. These model a **library's own parameters** as taint sources, which is what you need here.

| Query | Class | Help index |
|---|---|---|
| `js-prototype-polluting-assignment`, `js-prototype-pollution-utility`, `js-prototype-pollution` (merge call) | §3.1 | <https://codeql.github.com/codeql-query-help/javascript/> |
| `js-polynomial-redos`, `js-redos` | §3.2 | same |
| `js-zipslip`, `js-path-injection` | §3.3 | same |
| `js-unsafe-deserialization` | §3.4 | same |
| `js-shell-command-constructed-from-input`, `js-command-line-injection`, `js-second-order-command-line-injection` | §3.5 | same |
| `py-unsafe-deserialization`, `py-xxe`, `py-xml-bomb` | §3.4, §3.7 | <https://codeql.github.com/codeql-query-help/python/> |
| `py-tarslip` (arbitrary file write during tarfile extraction), `py-path-injection` | §3.3 | same |
| `py-shell-command-constructed-from-input`, `py-command-line-injection`, `py-code-injection` | §3.5, §3.11 | same |
| `py-weak-cryptographic-algorithm`, `py-weak-crypto-key`, `py-insecure-temporary-file` | §3.8, §3.10 | same |
| `java-unsafe-deserialization`, `java-xxe` | §3.4, §3.7 | <https://codeql.github.com/codeql-query-help/java/> |
| `java-zipslip` | §3.3 | same |
| `java-command-line-injection`, `java-concatenated-command-line`, `java-exec-tainted-environment` | §3.5 | same |
| `java-weak-cryptographic-algorithm`, `java-insufficient-key-size`, `java-rsa-without-oaep`, `java-static-initialization-vector` | §3.8 | same |
| `go-zipslip`, `go-unsafe-unzip-symlink` (a distinct class from plain zip slip), `go-path-injection` | §3.3 | <https://codeql.github.com/codeql-query-help/go/> |
| `go-command-injection` | §3.5 | same |
| `go-request-forgery` | §3.6 | same |
| `go-weak-cryptographic-algorithm`, `go-weak-crypto-key`, `go-insecure-randomness` | §3.8 | same |
| `rb-unsafe-deserialization` | §3.4 | <https://codeql.github.com/codeql-query-help/ruby/> |
| `rb-command-line-injection`, `rb-shell-command-constructed-from-input`, `rb-kernel-open`, `rb-non-constant-kernel-open` | §3.5 | same |
| `rb-code-injection`, `rb-unsafe-code-construction` | §3.11 | same |
| `rb-path-injection` | §3.3 | same |
| `rb-weak-cryptographic-algorithm` | §3.8 | same |

### 4.4 Per-language linters

| Tool | Scope | Invocation | What it does not do |
|---|---|---|---|
| Bandit | Python | `bandit -r /work/clone -f json -o /work/out/bandit.json` | AST plugins find dangerous **call sites**, not data flow — hand dataflow to CodeQL/Semgrep (<https://bandit.readthedocs.io/en/latest/>) |
| gosec | Go | `gosec ./...`, `-fmt json -out <f>`, `-include`/`-exclude`, `-no-fail` in CI | Rule families: G1xx general (hardcoded credentials, unsafe usage, HTTP/cookie hardening), G3xx file and path handling (permissions, traversal, temp files, archive extraction), G4xx crypto/TLS (<https://github.com/securego/gosec>) |
| Brakeman | Ruby | `brakeman /work/clone` | The right tool when the "library" is a Rails engine or a gem with Rails integration (<https://brakemanscanner.org/>) |
| cargo-geiger | Rust | See §3.12 | Ranks unsafe surface; not a verdict |
| cargo-vet | Rust | `cargo vet` | Records and shares the audits you perform, so review work is reusable rather than throwaway (<https://mozilla.github.io/cargo-vet/>) |

Stable Bandit IDs worth citing in a finding, from <https://bandit.readthedocs.io/en/latest/plugins/index.html>: `B506` yaml_load, `B602` subprocess_popen_with_shell_equals_true, `B604` any_other_function_with_shell_equals_true, `B603`, `B324` hashlib, `B505` weak_cryptographic_key, `B108` hardcoded_tmp_directory. Note there is no dedicated pickle test ID — do not cite one.

### 4.5 The triage rule — explicit, no third option

Most scanner hits are not findings. Expect to kill the large majority.

1. Every alert gets **exactly one** disposition, recorded in the lead log before the audit advances:
   - **PROMOTED** — a hand-written source→sink path exists with all §3 trace fields filled.
   - **KILLED** — one named kill criterion from the relevant §3 class is satisfied. Record which criterion, and the `file:line` that satisfies it.
2. There is no "maybe", no "revisit later", no silent deletion. An alert left undisposed **blocks Phase 5** (§1.3).
3. A rule ID, alert title, or scanner severity may appear in a report only as *how the lead was found*. It is never the proof. Severity from a scanner is not severity in a report.
4. Duplicate alerts across tools collapse into one lead with one disposition, not three.
5. Keep the kill log in the same file as the confirmed findings. This is what makes the audit auditable, lets a second human re-check judgement calls, stops the same false positive being re-raised on the next version, and is the difference between a review a maintainer trusts and a scanner dump.

Models for what a finished, well-paced write-up looks like: <https://securitylab.github.com/advisories/>.

---

## 5. The reachability question: a library bug needs a consumer

This is where most beginner reports die. A dangerous sink inside a library is not a vulnerability unless a plausible consumer reaches it by doing something reasonable.

### 5.1 The required sentence

For **every** candidate, write exactly one sentence in this form, and put it in the report:

> A consumer is affected if and only if it calls `<exported symbol>` with `<attacker-controlled value>` while `<configuration or option state>`.

If you cannot complete that sentence from the traced path, the candidate is not ready. If completing it requires a clause you are inferring rather than reading, mark the inference explicitly.

### 5.2 The worksheet — answer in writing

| # | Question | Where the answer comes from |
|---|---|---|
| a | Which exported API is the entry point? | §1.5 inventory |
| b | What do the README, docs, or type declarations say about that parameter's trust level? | The project's own text, quoted |
| c | What is a realistic consumer pattern in which untrusted data reaches that parameter? | Ideally a real dependent found via <https://docs.deps.dev/> |
| d | Is the maintainer's plausible counter-argument "that API is documented as trusted-input only"? | (b) |
| e | If so: does the documentation actually say that, or are you inferring it? | Be honest; this answer decides the outcome |
| f | What is the default configuration state, and does the path require a non-default option? | Manifest and option defaults |

### 5.3 Decision table

| Consumer-side precondition | Classification | Severity posture |
|---|---|---|
| API documented as untrusted-safe, reached with default options | Library's own bug | Full demonstrated impact |
| Trust level `undocumented`, reached through a path a reasonable consumer would consider safe | Library's own bug — **say explicitly that this is the case** | Full demonstrated impact, with the precondition stated |
| Requires a non-default option or flag | Library's own bug, reduced | State "requires `<option>`" prominently; cap below the default-config equivalent |
| Requires the consumer to pass attacker-controlled data to an API the documentation says is trusted-input only | Consumer-side misuse or a documentation gap | Do not file as a vulnerability; offer it as a docs improvement |
| Only reachable by calling an internal, underscore-prefixed, or `unsafe fn` symbol | Not a finding | Drop and log |
| Requires the consumer to already be doing something the documentation forbids | Not a finding | Drop and log |
| Requires an already-compromised host or local code execution | Bounded finding at most | State the precondition first, in the summary, not in a footnote |

Then classify every survivor as one of: **library's own bug** / **missing hardening the maintainer may reasonably decline** / **consumer-side misuse that belongs in documentation**. Say which, in the report. A maintainer who sees you have already made that distinction reads the rest of the report differently.

**Severity may never exceed demonstrated impact** (ROE §3.4). "Could lead to RCE" is not an impact statement unless the PoC shows RCE — and if the PoC would have to be weaponised to show it, then the honest finding is the primitive you did demonstrate.

### 5.4 Expected yield — spend time where source review pays

| High yield from reading library source | Low yield or usually out of scope |
|---|---|
| Archive-extraction traversal and symlink writes (§3.3) | "Uses MD5 somewhere" with no security decision depending on it |
| Prototype pollution in merge/set/clone utilities (§3.1) | "Depends on a vulnerable transitive package" — that is the consumer's upgrade, not the library's vulnerability, **unless** the library pins a vulnerable version it controls |
| Unsafe-default deserialization entry points (§3.4) | ReDoS against a non-backtracking engine (§3.2 caveat) |
| `shell=True`-style process spawning in helper APIs (§3.5) | Anything requiring the consumer to pass attacker data to a documented trusted-input-only API |
| ReDoS in exported validation regexes (§3.2) | Findings whose only impact statement is a scanner's severity rating |
| XXE from unconfigured parser factories (§3.7) | |
| Timing-unsafe MAC comparison (§3.8) | |
| Predictable temp-file creation (§3.10) | |

---

## 6. Where a confirmed finding goes

**The gate first.** An agent may analyse, trace, build a local PoC, draft the report, and generate the advisory JSON. An agent may **not** send, file, submit, publish, open an issue or PR, post to a platform, or contact a maintainer by any means (ROE §2). Concretely, in this phase the agent does not run `gh api`, `gh pr create`, `gh issue create`, `git push` to any remote it does not own, or any mail command. It writes files and stops. A human reads the finding, agrees, and acts.

### 6.1 Pin the affected range before routing anything

A vague range is the most common reason a maintainer bounces a report.

1. Find the introducing commit:

```bash
git log -L <start>,<end>:<path/to/file>      # history of the vulnerable function
git log -S '<sink expression>' --oneline     # when the sink appeared
```

2. Confirm with `git bisect` driven by the PoC — not by reading, by running.
3. Map commits to releases: `git tag --contains <sha>`.
4. Check **every maintained branch**, not just the default one.
5. Express the result as OSV range events: `introduced` / `fixed` / `last_affected` / `limit`, with `SEMVER` semantics for npm and crates.io and `ECOSYSTEM` semantics elsewhere (<https://ossf.github.io/osv-schema/>).
6. Name the **vulnerable symbol**, not just the version range. PyPA supports `ecosystem_specific.imports` to name the vulnerable modules and attributes, and the Go database and `govulncheck` are symbol-aware. Symbol precision measurably reduces downstream false positives in consumers; it is worth the extra hour.

### 6.2 Destination table

First contact is **always the project's own private channel**, regardless of ecosystem: GitHub private vulnerability reporting (Security tab → Report a vulnerability) where enabled, otherwise the address in `SECURITY.md`. If neither exists, a public issue may be opened that asks **only** for a security contact and discloses nothing (<https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability>). The ecosystem database comes **after** the maintainer ships a fix.

| Ecosystem | Post-fix destination | Format | Upstream first? | Traps |
|---|---|---|---|---|
| npm / Node | Repository security advisory → <https://github.com/advisories> | GitHub advisory form (§6.3) | Yes | **There is no separate npm advisory database to file to.** <https://github.com/nodejs/security-wg> is explicitly *not* the channel for Node.js core reports (that is the TSC programme) and does not take third-party module reports |
| PyPI / Python | PR to <https://github.com/pypa/advisory-database> | `vulns/<pkg>/PYSEC-0000-<anything>.yaml`, validated with `check-jsonschema` against the OSV schema; use `ecosystem_specific.imports` to name vulnerable modules | Yes | PyPI has **no** channel for an ordinary vulnerability in a third-party package — only "report project as malware" (<https://pypi.org/security/>). `security@python.org` covers CPython and pip only, and explicitly excludes third-party packages and redistributions (<https://www.python.org/dev/security/>) |
| Maven / Java | Repository security advisory → GitHub Advisory Database / OSV | GitHub advisory form | Yes | **No community-run equivalent of RustSec or PyPA exists.** <https://jeremylong.github.io/DependencyCheck/> uses the NVD API, so its coverage differs from OSV — run both and say which you checked |
| crates.io / Rust | PR to <https://github.com/rustsec/advisory-db> with placeholder `RUSTSEC-0000-0000` | RustSec TOML advisory; use `informational = "unsound"` for soundness bugs that are not classic CVEs | **Yes — the process explicitly requires reporting upstream first** | Soundness bugs are a real category here; do not force one into a CVE shape. Toolchain index: <https://rustsec.org/> |
| RubyGems | PR to <https://github.com/rubysec/ruby-advisory-db> | YAML: `gem`, `url`, `title`, `date`, `description` required; `cvss_v2`..`cvss_v4`, `patched_versions`, `unaffected_versions` optional; run the repo's lint command before opening the PR | Yes | Maintainers state they **close contributions that look like unreviewed AI output**. A named human must own the submission — which is exactly ROE §2, enforced by someone else |
| Go modules | Public report form at `go.dev/s/vulndb-report-new`, linked from <https://go.dev/doc/security/vuln/> | The form's fields; it also covers requesting a CVE | Yes | `govulncheck` is call-graph aware, so phrase impact in terms of reachability, and do not present its silence as proof of safety |
| Composer / PHP | PR to <https://github.com/FriendsOfPHP/security-advisories> | One directory per Composer package; filename is the CVE or a date-increment; keys `title`, `link`, `reference` (`composer://<vendor>/<pkg>`), `branches[].time` + `versions`; validated with `validator.php` | Yes | — |
| Any ecosystem, **malicious package** | Abuse channel, not a research write-up: PyPI's "report project as malware" form, npm security, <https://github.com/ossf/malicious-packages> | OSV format, PR-based | n/a | Detection and dedupe only. We never author or describe how to author a malicious package |

CVE assignment and CNA mechanics: see [../../../disclosure/CVE_AND_CNA.md](../../../disclosure/CVE_AND_CNA.md). In practice the request is made through GitHub's CNA flow from the repository advisory, or the ecosystem database routes it (the Go form covers it directly).

### 6.3 OSV as the serialisation target

Write every confirmed finding as OSV JSON **first**, validate it, then transform it into whatever the destination wants. One canonical artefact, many renderings.

- Schema: <https://ossf.github.io/osv-schema/>. The fields that matter: `affected[].package{ecosystem,name,purl}`, `affected[].ranges[].type` (`SEMVER` | `ECOSYSTEM` | `GIT`) with `introduced` / `fixed` / `last_affected` / `limit` events.
- Validate with `check-jsonschema` against the published schema before anything is handed to a human.
- Clone <https://github.com/github/advisory-database> and read real advisories for worked examples of affected-range and CWE wording. Do not invent a house style.
- Pre-fill what the maintainer's own form will ask for, so they can act in one sitting: ecosystem, package name, affected and patched versions, vulnerable functions, CVSS severity, CWE identifiers, credits, and the CVE-identifier choice (existing CVE versus requesting one from GitHub) — <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory>.

CWE identifiers for the classes in §3: CWE-1321 prototype pollution, CWE-1333 ReDoS, CWE-22 / CWE-29 archive traversal, CWE-502 deserialization, CWE-78 command injection, CWE-918 SSRF, CWE-611 XXE, CWE-367 TOCTOU, CWE-470 unsafe reflection, CWE-1336 template injection, plus the relevant CWE-32x entries for crypto misuse.

### 6.4 Report contents, and the last check before handoff

Required sections, in this order:

1. One-sentence summary.
2. Affected package, OSV-style ranges, vulnerable symbols.
3. The full source→sink path with `file:line` at the pinned SHA, including every guard and why each is insufficient. For a PyPI target, cite PyPI Inspector line links to the exact lines inside the published distribution rather than attaching the sdist — that is the tool's stated purpose, it lets the maintainer click straight to the code, and it lets you read an sdist's contents without installing it (<https://github.com/pypi/inspector>).
4. The minimal sandboxed PoC and its exact run command, stored under the finding ID in [../../../evidence/README.md](../../../evidence/README.md) — with a header comment stating it must only be run against a local clone in a sandbox.
5. Impact phrased for a realistic consumer, with the §5.1 sentence stated verbatim. Not "RCE" unless the PoC shows RCE.
6. CWE identifier.
7. CVSS vector **with the environmental assumptions written out**.
8. A concrete suggested fix, ideally a diff. Pull the wording from the authoritative source rather than inventing it: CWE-1321's own mitigation ranking, `filter='data'` per PEP 706, Java `ObjectInputFilter` patterns, `hmac.compare_digest` / `crypto.timingSafeEqual` / `hash_equals` / `subtle.ConstantTimeCompare`, `defusedxml`, `execFile`/argument-array process spawning.
9. The §5.3 classification.
10. The prior-art statement: which databases were checked, and on what date.

Then, immediately before handing it to a human:

1. Re-run §2.6 in full. Re-query OSV, re-search GitHub Advisories including unreviewed entries, re-read the upstream repo's recent commits and open PRs. An advisory or fix published mid-audit changes the report from a vulnerability disclosure into, at most, a request that an existing fix be advised.
2. Confirm nothing in the report body contains a credential found in the target. Reference secrets by location, truncated prefix, and hash only ([../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2).
3. Confirm the PoC is in `evidence/` (gitignored) and nothing about the unpatched bug is staged for commit ([../../../findings/README.md](../../../findings/README.md)).
4. Confirm every ROE §3 anti-slop gate item is satisfied. If any one cannot be completed, **the finding does not ship.**
5. Stop. Hand the paths to a human.

---

## Appendix A — Source coverage gaps and unsourced claims

Do not over-promise a source's coverage, and do not assert the two claims at the bottom without confirming them first.

| Source | Gap |
|---|---|
| <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> | No Ruby section. Argue Ruby cases from <https://docs.ruby-lang.org/en/master/Marshal.html> directly |
| <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html> | No Ruby section |
| <https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html> | Does not cover prototype pollution at all; mentions `child_process.exec` only in passing; dependency advice limited to npm audit / Dependency-Check / Retire.js |
| <https://nodejs.org/en/learn/getting-started/security-best-practices> | No ReDoS section and no path-traversal section. Its "uncontrolled search path element" item is about module resolution, not user-supplied paths |
| <https://bandit.readthedocs.io/en/latest/plugins/index.html> | No dedicated pickle test ID — do not cite one |
| <https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html> | A hub page. The exact `jdk.serialFilter` pattern syntax lives on its "Creating Pattern-Based Filters" and "Allow-Lists and Reject-Lists" child pages, which are not verified here. Do not quote syntax without opening them |
| <https://slsa.dev/spec/v1.1/levels> | This is the retired v1.1 levels page, which itself states v1.2 is current. Navigate from the spec index to pick up v1.2 rather than guessing a URL |

**Two triage claims carried here without a citation.** Both are used above only to *deprioritise* work. Neither may appear as an assertion in a report until it has been confirmed against the relevant engine's own documentation:

1. Go's `regexp` and Rust's `regex` are linear-time, non-backtracking engines, so classic backtracking ReDoS does not apply to them; the backtracking surface is `fancy-regex` and PCRE bindings (§3.2).
2. Go's `encoding/xml` does not resolve external entities by default, so XXE findings there need a different argument (§3.7).
