# Attack classes and routing

Decides what to hunt for in a qualified target. Read this after [../../PLAYBOOK.md](../../PLAYBOOK.md) has put you in a hunting phase, route by target type in section 1, then work the cross-cutting classes in section 3 regardless of type.

Nothing here relaxes [../../RULES_OF_ENGAGEMENT.md](../../RULES_OF_ENGAGEMENT.md). Every "confirm with" step below runs against an instance you deployed yourself, in a container, per [SKILL.md](SKILL.md) section 3.

## Contents

1. [Route by target type](#1-route-by-target-type)
2. [How to use an attack-class block](#2-how-to-use-an-attack-class-block)
3. [Cross-cutting attack classes](#3-cross-cutting-attack-classes)
   - [C1 Injection — command, SQL, template](#c1-injection--command-sql-template)
   - [C2 Path traversal and arbitrary file write](#c2-path-traversal-and-arbitrary-file-write)
   - [C3 Unsafe deserialization](#c3-unsafe-deserialization)
   - [C4 Server-side request forgery](#c4-server-side-request-forgery)
   - [C5 Access control and authorization](#c5-access-control-and-authorization)
   - [C6 Authentication and session management](#c6-authentication-and-session-management)
   - [C7 Cryptographic misuse](#c7-cryptographic-misuse)
   - [C8 Race conditions and TOCTOU](#c8-race-conditions-and-toctou)
   - [C9 Resource exhaustion from untrusted input](#c9-resource-exhaustion-from-untrusted-input)
   - [C10 Hardcoded secrets](#c10-hardcoded-secrets)
   - [C11 Unsafe defaults](#c11-unsafe-defaults)
4. [What is NOT a vulnerability](#4-what-is-not-a-vulnerability)
5. [Sources](#5-sources)

## 1. Route by target type

Identify what the target **is**, then read that one reference file before hunting. Read it fully; do not skim it for keywords.

| Target type | Read | Examples |
|---|---|---|
| Language library or package | [references/p1-package-ecosystems.md](references/p1-package-ecosystems.md) | npm/PyPI/crates/Maven/RubyGems packages, SDKs, parsers, CLI tools distributed as packages, build plugins |
| Web app, API, or CMS plugin | [references/p2-web-api-cms.md](references/p2-web-api-cms.md) | Django/Rails/Express/Laravel apps, REST and GraphQL services, WordPress and Drupal plugins, admin panels |
| DevOps, infra, or CI/CD tooling | [references/p3-devops-infra.md](references/p3-devops-infra.md) | Kubernetes operators and controllers, Terraform providers, GitHub Actions, container tooling, agents and daemons |
| Mobile app | [references/p4-mobile.md](references/p4-mobile.md) | Android APK/AAB, iOS app, React Native or Flutter client, mobile SDK |

### Targets that span several types

**Load exactly one reference file at a time.** Loading all four dilutes the checklist you are actually running and wastes context ([../../PLAYBOOK.md](../../PLAYBOOK.md) Phase 3). Spanning targets are handled by sequencing, not by loading more.

1. Decompose the target into components, then pick the file by **which component holds the trust boundary you are testing** — not by the project's self-description. A "mobile app" whose bug is in its server API is a P2 audit.
2. Audit one component at a time, and finish that reference file's classes before opening the next. Interleaving produces shallow coverage of both.
3. Record which reference files you actually ran. An unopened file is **deferred**, not clean. Never let silence read as coverage.
4. If the researcher scoped the audit to one component, stop after that one file. The orders below are for a full-project audit.

| Spanning target | Order | Reasoning |
|---|---|---|
| Web app with a mobile client | P2 first, then P4 | The server trusts input from the client. Test the boundary the client crosses before testing the client. P4 only if you are testing on-device storage, IPC, or deep links. |
| CLI tool that installs or fetches packages | P1, then P3 | Dependency-resolution and install-hook behaviour is P1; credential handling and runner privileges are P3. |
| CMS plugin | P2, then P1 | The plugin's request handlers first. P1 only if it vendors or fetches its own dependencies. |
| Kubernetes operator with a web dashboard | P3, then P2 | The operator's privileges are the impact multiplier; the dashboard is an entrypoint into them. |
| Mobile SDK published as a package | P1, then P4 | It reaches consumers as a dependency. Supply-chain and API-misuse surface first. |
| A monorepo with several of these | Qualify each separately | Treat each deployable as its own target. One audit, one component, one coverage record. |

**Stop condition.** If you cannot place the target in any row above, do not guess a file. Say what the target is and ask the researcher which reference applies.

## 2. How to use an attack-class block

Every block in section 3 has the same five fields. Work them in order.

| Field | What you do with it |
|---|---|
| **Class** | Decide whether this class can exist in this target at all. If the target has no filesystem access, skip C2. Skipping on a stated reason is coverage; skipping silently is not. |
| **Lives in** | Where to look. Start here rather than grepping the whole tree. |
| **Grep and trace** | Find candidate sinks, then trace **backwards** from each sink to an entrypoint. A sink with no attacker-controlled path is not a candidate. |
| **Disproved by** | Try to kill your own candidate with this first. If one of these holds, the candidate is dead — record it as rejected with the reason and move on. |
| **Confirm with** | The evidence that makes it reportable. Anything less and it stays a candidate. |

**The disproof rule.** If you cannot state what would disprove a candidate, you do not understand it well enough to report it. Write the disproof attempt down even when it fails — a maintainer's first reply is usually exactly that disproof, and the report should have answered it already.

**Direction of travel.** Grep finds sinks; findings are made by tracing to entrypoints. A list of sinks is not a finding, it is a to-do list.

## 3. Cross-cutting attack classes

These apply to every target type. Run them in addition to the reference file for the target's type, not instead of it.

### C1 Injection — command, SQL, template

**Class.** Attacker-controlled data is concatenated into a string that an interpreter then executes — a shell, a SQL engine, or a template engine. CWE-78, CWE-89, CWE-1336.

**Lives in.** Anywhere a string is built and handed to an executor: file-conversion and media wrappers (`ffmpeg`, `convert`, `git`), report and export generators, search and filter endpoints, dynamic `ORDER BY` and `LIKE` clauses, admin tooling, notification and email templating, plugin and webhook systems.

**Grep and trace.**
```
# shell
os.system|os.popen|subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True
child_process\.(exec|execSync)|spawn\(.*shell:\s*true
Runtime\.getRuntime\(\)\.exec|ProcessBuilder
exec\.Command\(\s*"(sh|bash|cmd)"|`[^`]*\$\{|%x\(|Kernel\.(system|open)
shell_exec|passthru|proc_open|popen
# SQL  (look for f-strings, +, %, .format, string interpolation reaching these)
\.(execute|executemany|query|raw|exec_driver_sql)\(|sqlalchemy\.text\(
whereRaw|orderByRaw|\.rawQuery|createStatement|executeQuery
# template
render_template_string|Template\(|env\.from_string|ERB\.new|createTemplate
text/template.*Parse\(|Handlebars\.compile|pug\.compile
```
Then trace each hit backwards: does a request parameter, filename, environment variable, config value, or file the attacker controls reach it?

**Disproved by.** Parameterised query with the value bound, not interpolated. `subprocess` called with an argument **list** and no `shell=True`. The interpolated value is a server-side constant or comes from a fixed allowlist. An escaping function that is correct for the context and applied on every path. A template whose *data* is user-controlled but whose *source* is not — that is not template injection.

**Confirm with.** A trace from entrypoint to sink at `file:line`, and a local run showing the injected effect: a marker file created, a sentinel row returned, a template expression evaluated. One benign marker is enough; do not build a payload chain.

### C2 Path traversal and arbitrary file write

**Class.** An attacker-controlled path component escapes the directory the code intended. CWE-22, CWE-23, CWE-59, and archive-extraction variants.

**Lives in.** Static-file handlers, upload and download endpoints, archive extraction, template and plugin loaders, log and cache path builders, backup and restore, `--output` style CLI flags, anything joining a base directory with a name from outside.

**Grep and trace.**
```
os\.path\.join\(|pathlib\.Path\(.*\)\s*/|path\.join\(|filepath\.Join\(
open\(|readFile|sendFile|createReadStream|File\(|FileInputStream
extractall|tarfile\.open|shutil\.unpack_archive|ZipFile|ZipEntry|getName\(\)
```
Also grep for the defence and note where it is **absent**: `realpath`, `os.path.abspath`, `filepath.EvalSymlinks`, `path.resolve`, `startsWith`, `normalize`, `commonpath`.

**Disproved by.** Canonicalisation (`realpath`) followed by a prefix check that includes the trailing separator, performed **after** symlink resolution and on the final path. A strict allowlist or an opaque ID that is mapped to a path server-side. The path never reaches a filesystem call. Note: stripping `../` once, rejecting `..` before URL-decoding, or blocklisting characters are **not** disproofs — they are the bug.

**Confirm with.** A read or write landing outside the intended root, shown by absolute path in your own container, with the traversal input recorded verbatim. For archives, a crafted entry whose extracted path is outside the target directory. Read a file you planted yourself; do not go looking for `/etc/shadow` to make the screenshot better.

### C3 Unsafe deserialization

**Class.** Untrusted bytes are fed to a deserializer that can instantiate arbitrary types or invoke code during reconstruction. CWE-502.

**Lives in.** Session and cookie stores, caches, job and message queues, inter-process and plugin protocols, config and state files, model and checkpoint loaders, import/restore features.

**Grep and trace.**
```
pickle\.(load|loads)|marshal\.loads|dill\.load|jsonpickle|shelve\.open
yaml\.load\((?!.*SafeLoader)|numpy\.load\(.*allow_pickle\s*=\s*True|torch\.load\(
ObjectInputStream|readObject\(|XMLDecoder|new\s+Yaml\(\)|enableDefaultTyping|@JsonTypeInfo
unserialize\(|Marshal\.load|YAML\.load|Psych\.load
BinaryFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling
node-serialize|funcster
```

**Disproved by.** The deserializer is the safe variant (`yaml.safe_load`, `SafeLoader`, `json`, `weights_only=True`, a schema-bound decoder). The bytes are authenticated before deserialization — a signature or MAC verified with a constant-time compare, over the exact bytes deserialized. The input is not attacker-reachable. Note: "no gadget exists in this classpath" is a **weak** disproof — dependencies change. Prefer unreachability or safe-loader as the disproof.

**Confirm with.** The trace from entrypoint to the deserializer at `file:line`, plus a local run where a crafted object causes an observable, benign side effect — a marker file, a log line. State the preconditions honestly: many of these need a specific library on the path.

### C4 Server-side request forgery

**Class.** The target makes a network request to a destination the attacker influences, borrowing the server's network position and credentials. CWE-918.

**Lives in.** Webhook registration and delivery, URL preview and unfurl, avatar and remote-image fetch, HTML-to-PDF and screenshot renderers, feed and sitemap importers, OIDC/SAML metadata and JWKS fetchers, "import from URL", proxy endpoints, XML parsers resolving external entities, `git clone` of a user-supplied remote.

**Grep and trace.**
```
requests\.(get|post)\(|urllib\.request\.urlopen|httpx\.|aiohttp\.
axios\.|fetch\(|got\(|request\(|http\.(Get|Post)|net/http
curl_(init|exec)|HttpClient|WebClient|Net::HTTP|open-uri|URL\(.*\)\.openStream
resolveEntity|XMLInputFactory|DocumentBuilderFactory|libxml_disable_entity_loader
```

**Disproved by.** The destination is a compile-time constant or chosen from a server-side allowlist. Resolution is pinned and the **resolved IP** is checked against a deny set, with redirects either disabled or re-checked at every hop. The request goes through an egress proxy that enforces the policy. Note: a hostname-only allowlist, a check performed before DNS resolution, or blocklisting `169.254.169.254` alone are **not** disproofs — DNS rebinding and redirects defeat all three.

**Confirm with.** A listener **you** run on loopback inside your own container receiving the request, with the full request line and headers captured. Never point the target at a cloud metadata endpoint on infrastructure you do not own, and never use a public SSRF canary or collaborator service — that is a request to a third-party system and it leaks the target's identity. If the impact claim depends on a metadata service or an internal host, you have not demonstrated it; say so and cap severity accordingly.

### C5 Access control and authorization

**Class.** An authenticated principal reaches an object or action belonging to another principal, or a privilege tier above its own. CWE-285, CWE-639 (IDOR), CWE-862/863, CWE-915 (mass assignment).

**Lives in.** Any handler taking an object ID from the request; multi-tenant query layers; GraphQL field resolvers; bulk and batch endpoints; export, invite and sharing flows; admin routes; the second step of a multi-step flow; webhook and callback handlers.

**Grep and trace.**
1. Enumerate every route or resolver into a list. This is the work; there is no shortcut.
2. For each, record the authentication check, the authorization check, and the ownership predicate in the query.
3. The findings are in the **gaps** — a route whose siblings all carry a decorator that it lacks.
```
# missing ownership predicate
findById|get_object_or_404|findOne\(|\.find\(|where\(\s*\{?\s*id
# tenant scoping present elsewhere but absent here
tenant_id|org_id|account_id|workspace_id|user_id\s*=
# decorators and guards  (diff presence across routes)
@login_required|@require_permission|@admin|IsAuthenticated|before_action|canActivate
# mass assignment
Model\(\*\*|update\(\*\*|Object\.assign\(|permit!|attr_accessible|\.save\(req\.body
```

**Disproved by.** A single policy enforcement point every route provably passes through, demonstrated by enumerating routes and showing none bypass it. The identifier is an unguessable capability token with no other authority, and that is the documented design. The "other" object is public by design.

**Confirm with.** Two accounts **you created** in your own instance. Show account A reading or modifying account B's object, with both principals and the exact request recorded. Name the authorization decision that should have happened and the `file:line` where it is missing. Stop at the proof — do not enumerate further objects, and if the finding reaches beyond the target, do not walk through the door (ROE §1).

### C6 Authentication and session management

**Class.** Identity can be forged, borrowed, or retained past revocation. CWE-287, CWE-384 (fixation), CWE-613, CWE-640 (reset flow), CWE-347 (signature verification).

**Lives in.** Login, logout, registration, password reset, email change, token issuance and refresh, "remember me", SSO callbacks, API-key and service-account handling, impersonation features, 2FA enrolment and verification.

**Grep and trace.**
```
jwt\.decode\(.*verify\w*\s*=\s*(False|false)|verify_signature|algorithms\s*=\s*\[?\s*['"]?none
decode\(.*complete:\s*true|jwt\.sign\(.*algorithm:\s*['"]none
random\.|Math\.random|rand\(\)|uuid1\(|time\(\)       # token generation
==\s*(password|token|signature|hmac|digest)|password\s*==    # non-constant-time compare
session\[|session_regenerate_id|reset_session|rotate|regenerate   # presence on login path
```
Check the order of operations in the login handler: is the session issued **before** or **after** the 2FA check? Is the reset token single-use, expiring, and invalidated on password change?

**Disproved by.** A maintained library performs the check and the version in use is not affected (verify the version, do not assume). The weak path is unreachable because configuration forces the strong one. The token is generated by a CSPRNG with adequate entropy. Constant-time comparison is used (`hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`).

**Confirm with.** A local run showing the concrete failure: a token you forged accepted; a session valid after logout; a reset link reused; a pre-2FA session with post-2FA authority. Record the exact token or session value you used — yours, never a real one.

### C7 Cryptographic misuse

**Class.** A primitive is used in a way that does not provide the property the code depends on. CWE-327, CWE-328, CWE-330, CWE-295, CWE-916.

**Lives in.** Password storage, token and nonce generation, cookie and license signing, at-rest encryption, TLS client configuration, inter-service authentication, anything with "sign", "encrypt", or "hash" in the name.

**Grep and trace.**
```
md5|sha1|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|hashlib\.(md5|sha1)
MODE_ECB|AES/ECB|DES|RC4|Blowfish
IV\s*=\s*(b?["']|bytes\(|new byte\[)|iv\s*=\s*0|static.*(iv|nonce)
verify\s*=\s*False|InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|TrustManager|checkServerTrusted\(\)\s*\{\s*\}
rejectUnauthorized:\s*false|CURLOPT_SSL_VERIFYPEER.*(0|false)
```

**Disproved by.** The primitive is used for a non-security purpose — a cache key, an ETag, a content checksum, a published test vector — and nothing downstream treats it as a security property. The weak option exists only behind an explicitly documented dangerous flag that is off by default. A stronger construction wraps it (encrypt-then-MAC with the MAC verified first).

**Confirm with.** Name the property the code relies on and show it does not hold: a forged MAC accepted, two ciphertexts revealing a pattern under ECB, a reset token predicted from an observed earlier one, a connection accepted against a certificate you self-signed. "MD5 is weak" with no dependent security property is a hardening note, not a finding. Severity is capped by what you predicted or forged, not by the algorithm's reputation.

### C8 Race conditions and TOCTOU

**Class.** An invariant holds when checked and not when used, because something changes in between. CWE-362, CWE-367, CWE-377 (insecure temp file).

**Lives in.** Filesystem check-then-open sequences, temp-file creation, lockfile and pidfile handling, privilege-dropping sequences, and at the application level any read-modify-write over shared state: balances, quotas, credits, invite and coupon redemption, one-time tokens, idempotency handling, concurrent job claiming.

**Grep and trace.**
```
# filesystem TOCTOU
(os\.path\.exists|os\.access|stat\(|fs\.exists)[\s\S]{0,200}(open\(|fs\.(read|write))
chmod|chown|umask            # applied after creation rather than at creation
/tmp/|tempfile\.mktemp|NamedTemporaryFile\(.*delete\s*=\s*False|os\.getpid\(\)
# application-level
SELECT[\s\S]{0,300}UPDATE|\.save\(\)|increment|decrement|balance|credits|quota
redeem|claim|consume|used\s*=\s*True|one.?time
```
For each, ask: what stops two requests from passing the check simultaneously? Name the mechanism or you have a candidate.

**Disproved by.** A unique database constraint, a row-level lock (`SELECT ... FOR UPDATE`), a transaction at an isolation level that serialises the conflict, a compare-and-swap, or an atomic filesystem primitive (`O_EXCL`, `mkstemp`, `renameat2`) that makes the window unobservable. A single-process single-threaded design where concurrency cannot occur — verify, do not assume.

**Confirm with.** A **reproducible** demonstration against your own instance: N concurrent requests, the invariant broken, and the observed rate across repeated runs ("18 of 20 runs redeemed a single-use token twice, N=50 concurrent"). A single lucky flake is not a confirmation. Keep N small and local; concurrency testing against anything you do not own is a denial-of-service attempt (ROE §1).

### C9 Resource exhaustion from untrusted input

**Class.** A small, cheap input causes disproportionate CPU, memory, or disk consumption. CWE-400, CWE-770, CWE-1333 (ReDoS), CWE-409 (decompression bomb), CWE-776 (entity expansion), CWE-674 (uncontrolled recursion).

**This class has the highest junk rate in the corpus.** Resource exhaustion, DoS and rate-limiting concerns are on the published default-exclusion list of [claude-code-security-review](https://github.com/anthropics/claude-code-security-review). It is reportable only as a **specific amplification with a measured ratio**, never as "there is no rate limiting".

| Reportable | Not reportable |
|---|---|
| Catastrophic backtracking in a regex applied to a request field | "The login endpoint has no rate limit" |
| Decompression bomb with no size or ratio cap on extraction | "An admin can upload a very large file" |
| XML entity expansion (billion laughs) in a parser reachable from input | "Enough concurrent requests will exhaust the server" |
| Unbounded allocation from an attacker-supplied length field | "The process can run out of memory" |
| Recursive parser with no depth limit, reachable from input | "There is no connection limit" |
| Quadratic or worse algorithm on an attacker-sized collection | Anything needing a botnet or sustained flooding |

**Lives in.** Regexes applied to request data (especially nested quantifiers), archive and image handling, XML/YAML/JSON parsers, protocol framing that trusts a length prefix, recursive descent parsers, pagination without a maximum.

**Grep and trace.**
```
# nested quantifiers and alternation under repetition
\(\.?\*\+?\)[\*\+]|\([^)]*[\*\+][^)]*\)[\*\+]|re\.(match|search|sub)\(.*\+.*\+
extractall|decompress|gzip\.open|zlib\.decompress|lzma|Inflater
resolveEntity|DocumentBuilderFactory|XMLReader|yaml\.load
malloc\(|make\(\[\]byte,|new byte\[|Buffer\.alloc\(|read\(.*length
limit|max_|MAX_|timeout        # grep for the cap and note its absence
```

**Disproved by.** A size, depth, count, ratio or timeout cap applied before the expensive operation. A linear-time engine (RE2, Go `regexp`, Rust `regex`) that cannot backtrack. The input is bounded upstream by a framework default you can point to. The expensive path requires privileges that already permit worse.

**Confirm with.** One input, its exact byte count, and the measured effect — CPU seconds, peak RSS, or bytes written — against your own instance, next to the baseline for a normal input. **The ratio is the finding.** Record both numbers. If the ratio is not dramatic, drop it.

### C10 Hardcoded secrets

**Class.** A credential, key, or token with real authority is committed to source. CWE-798, CWE-259, CWE-321.

**Lives in.** Config defaults and `settings` modules, CI workflow files, Dockerfiles and compose files, migration and seed scripts, mobile app resources and strings, client bundles, and **git history** after removal from `HEAD`.

**Grep and trace.** Classify by prefix — the shape tells you what it is without using it.
```
ghp_|github_pat_|gho_|ghs_|AKIA|ASIA|sk-ant-|xox[baprs]-|AIza|glpat-|npm_|pypi-
-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
(password|passwd|secret|token|api_?key|private_?key)\s*[=:]\s*['"][^'"]{8,}
```
Then, for each hit, in this order:
1. Locate precisely — `file:line` and commit SHA.
2. Find the introducing commit — `git log -S'{fragment}' --oneline --all`.
3. Check whether it survives in history after removal from `HEAD` — `git log --all -S'{fragment}'`. Maintainers routinely believe deletion revoked it. Telling them otherwise is often the most valuable line in the report.
4. Assess reachability: is it referenced by a shipped code path, or only by tests, examples, or docs?

**Disproved by.** The value is a documented dummy or a published test vector. It lives in a fixtures, examples, or docs path **and** no shipped code path references it. It is public by design — a Firebase web config, a Stripe publishable key, a Sentry DSN, a Google Maps browser key, an OAuth `client_id`, any public key. It was already rotated, which the project's own history or changelog states.

**Confirm with.** Location, introducing commit, history status, prefix classification, and the reachability answer. **Never authenticate with it** — not to check validity, not read-only, not once. That is unauthorized access regardless of how the credential was obtained ([../../SECRETS_HYGIENE.md](../../SECRETS_HYGIENE.md) §2). Report it by location, truncated prefix and hash, never by value. A live production credential in a public repository is an active compromise, not a scheduled disclosure — escalate to the human immediately and out of normal cadence.

### C11 Unsafe defaults

**Class.** The state a user gets **without making a choice** is insecure, so following the project's own quickstart produces an exposed deployment. CWE-1188, CWE-453, CWE-276, CWE-1392 (default credentials).

**Lives in.** Default config files and config-schema defaults, `docker-compose.yml` and Helm values shipped by the project, the README quickstart, first-run and installer code, framework-level defaults the project sets on its users' behalf.

**Grep and trace.**
```
0\.0\.0\.0|::\b|listen.*0\.0\.0\.0|host\s*=\s*['"]0\.0\.0\.0
DEBUG\s*=\s*True|debug:\s*true|development|NODE_ENV.*development
(auth|authentication|tls|ssl|csrf|verify)\w*\s*[=:]\s*(False|false|off|none|disabled)
Access-Control-Allow-Origin.*\*|allow_origins.*\*|cors.*true
admin.*(admin|password|changeme)|default_password|SECRET_KEY\s*=\s*['"]
chmod\s+0?7[0-7][0-7]|0o?666|0o?777|umask\(0\)
```
Then answer one question: **is the insecure state what you get by default, or does it require an explicit opt-in?**

**Disproved by.** The default is the safe value and the insecure state requires a flag documented as dangerous. The binding or permission is appropriate for the artifact's purpose (a container entrypoint binding `0.0.0.0` inside a container is normal). The value is a development-only config file that the project's own documentation excludes from production, and production config is separate.

**Confirm with.** The default value at `file:line`, the exact documented command that produces the exposed state, and the observed exposure on your own instance. Severity depends entirely on the opt-in question: default-insecure is a finding, opt-in-insecure is a hardening note, and "the user could configure it badly" is neither. If the project's docs tell users to change it and the finding is only that they might not, say so plainly and expect it to be closed as intended behaviour.

## 4. What is NOT a vulnerability

Check every candidate against this table before it is written into `../../findings/`. Run it **after** the project's own stated non-vulnerability list ([../../PLAYBOOK.md](../../PLAYBOOK.md) Phase 1 collects it), not instead of it — the project's own exclusions govern, and this table is the generic backstop. Most rejected reports fail on one of these rows. Rejecting here costs you minutes; failing here costs a maintainer's trust.

| Not a vulnerability | Why it is rejected | What would change the verdict |
|---|---|---|
| **Deployment misconfiguration** — someone's nginx, S3 bucket, Kubernetes manifest, or exposed admin panel | The fix belongs in a deployment, not in the project's source. The maintainer cannot patch it. | The project **ships** that manifest or config as its recommended deployment and the default is exploitable. Then it is C11 against the shipped artifact, with the shipped file at `file:line`. |
| **Intended behaviour** — a template engine executing templates, a plugin system running plugins, a CLI running the command you gave it | The documented purpose of the feature is the thing being reported. | An untrusted-input path reaches it where the documentation promises it cannot. Quote the documentation and show the path. |
| **Requires an already-compromised host** — "if the attacker can edit the config", "if the attacker is root", "if the attacker has the private key" | No trust boundary is crossed. The attacker already holds more authority than the bug grants. | The precondition is itself reachable by an unprivileged attacker. Demonstrate that step too, or report it as the finding instead. |
| **Theoretical with no reachable path** — the dangerous sink exists but no attacker input arrives at it | Unreachable code is not exploitable. This is the single most common AI-generated false positive. | A written trace from a named entrypoint to the sink, every hop at `file:line`. No trace, no finding. |
| **Self-inflicted configuration** — the user set `verify=False`, passed `--insecure`, disabled CSRF in their own app | The library offered the safe path; the consumer declined it. | The insecure value is the **default** (C11), or the safe setting is silently ignored. |
| **Unsupported or already-fixed version** | A duplicate, or a report against code nobody runs. Silent fixes are common. | It reproduces on the latest supported release. Check the changelog, recent commits, OSV.dev, and the [GitHub Advisory Database](https://github.com/github/advisory-database) before writing — and the ecosystem DB where one exists, e.g. [rustsec/advisory-db](https://github.com/rustsec/advisory-db). |
| **Missing redundant defence behind a working control** — no CSP although output is correctly encoded, no rate limit although the token is unguessable | Defence in depth is good engineering, not a vulnerability. The primary control works. | The primary control is shown to fail. Then report *that*, and mention the missing layer as context. |
| **Generic input validation with no demonstrated sink** | "This parameter is not validated" describes code, not impact. On the published exclusion list of [claude-code-security-review](https://github.com/anthropics/claude-code-security-review). | A sink is identified and reached. |
| **DoS, rate limiting, and resource exhaustion without a measured ratio** | Same exclusion list. Unbounded in principle is true of every server. | A specific amplification with both numbers recorded — see C9. |
| **Open redirect with nothing leaked** | Exclusion list. Low impact absent a credential in the request. | A token, session, or credential demonstrably travels to the attacker's destination. |
| **Scanner output not run to ground** — a Semgrep, CodeQL, or Trivy hit forwarded as-is | A scanner hit is a lead. Each unverified one costs the maintainer the time you saved. | Manual trace, local reproduction, and a root cause at `file:line`. |
| **A dependency CVE the target never calls** | The vulnerability is the dependency's, and the affected function may be unreachable. | Reachability is demonstrated from the target's own code. Otherwise report it to the dependency's maintainer, or raise it as an upgrade request, clearly labelled as not a flaw in this project. |
| **Secrets in test fixtures, examples, or public-by-design keys** | Noise, and it marks you as a pattern-matcher. | Reachability from a shipped code path, plus the C10 classification. |
| **Self-XSS, version disclosure, missing headers on a library, directory listing on a demo instance** | No cross-principal impact, or not the project's responsibility to set. | A path to another user's context. Then it is C5 or stored XSS, not this. |
| **"The code looks wrong but I could not reproduce it"** | ROE §3 — a failed reproduction is a note to yourself. | Reproduce it. Until then it stays in your notes and does not enter `findings/`. |

**The default verdict is "not a finding."** Promotion requires evidence; rejection requires only the absence of it. When a candidate sits between two rows of this table, it does not ship.

## 5. Sources

- [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) — MIT. The routing-hub pattern this file uses (target type to a companion deep file, plus self-contained attack-class blocks) is adapted from its [ATTACK-CLASSES.md](https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/skills/security-audit/ATTACK-CLASSES.md), and the evidence bar in section 2 from its [VALIDATION-AND-REPORTING.md](https://raw.githubusercontent.com/cloudflare/security-audit-skill/main/skills/security-audit/VALIDATION-AND-REPORTING.md).
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) — MIT. Section 4 and the C9 table follow its published default-exclusion list, applied as a filtering stage separate from finding generation.
- [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg) and its [checklists directory](https://github.com/OWASP/wstg/tree/master/checklists) — the stable-test-ID and machine-readable-checklist conventions the class IDs here anticipate.
- [OWASP/ASVS](https://github.com/OWASP/ASVS) — requirement IDs to cite in a finding instead of prose.
- [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) and the [rule contribution conventions](https://docs.semgrep.dev/contributing/contributing-to-semgrep-rules-repository) — the per-class metadata vocabulary (CWE, OWASP, confidence, likelihood, impact, vulnerability class) and the true-positive/true-negative fixture pairing; see [python/flask/security](https://github.com/semgrep/semgrep-rules/tree/develop/python/flask/security) for the pairing in a real tree.
- [CodeQL query metadata reference](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/) — precision and severity vocabulary.
- [OpenSSF Scorecard docs/checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md) — the per-entry documentation shape (risk level with a one-line reason, what is detected, remediation, stated detection limits) that the blocks above follow.
