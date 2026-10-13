# P2 — Open-Source Web Apps, APIs, and CMS Plugins

Execution reference for auditing open-source web applications, HTTP APIs, and CMS plugins/modules/extensions: source review first, then verification on a local instance the researcher deployed. Read this file before the first grep against a P2 target; execute §1 in order and do not skip ahead.

**Binding constraints live in [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md). It overrides this file.** Two of its rules bite on almost every step here:

1. **Dynamic verification runs only against an instance you stood up yourself.** A vendor's hosted demo, a SaaS trial, a staging box you found, or any site running the target is a third-party production system. Out of bounds, including for "one request to confirm".
2. **You may analyse, write candidate findings, and build local PoCs. You may not send, file, submit, publish, or contact anyone.** Those are human actions.

Credentials found inside a target are governed by [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2: locate, classify, never authenticate.

---

## 1. When to read this file, and the ordered review flow

Read this file when the target is any of: a web application served over HTTP, a REST/GraphQL/RPC API, a WordPress plugin or theme, a Drupal module, a Joomla extension, or a library whose primary consumers are request handlers. For native code, kernel, mobile, or dependency-supply-chain targets, use the matching P-dimension reference instead — see [../SKILL.md](../SKILL.md).

### 1.1 The flow

Execute in this order. Each phase has an artifact and a gate; if the gate fails, stop at that phase instead of advancing.

| # | Phase | Artifact produced | Gate before advancing |
|---|---|---|---|
| 0 | Scope and provenance (§1.2) | Target notes: repo URL, commit SHA, released version, license, security contact | A security contact exists, or it is recorded as "to be established" |
| 0b | Duplicate check (§1.3) | Prior-art list | Prior advisories for this component have been read, not just counted |
| 0c | Local lab up (§2) | Running local instance + recorded config | Instance reachable on loopback; no third-party host touched |
| 1 | Entrypoint map (§3) | Entrypoint inventory table, complete | Every externally reachable handler has a row |
| 2 | Auth boundary matrix (§4) | Per-entrypoint authn / authz / CSRF matrix | Every state-changing row names the enforcing function or says "none" |
| 3 | Taint trace (§5, §6) | Written `source -> transforms -> sink` chain per candidate | Chain is complete with `file:line` at both ends |
| 4 | Static analysis + triage (§7) | Scanner output + triage log + committed custom rules | Every surviving finding has the four-part chain from §7.4 |
| 5 | Local verification (§8) | Reproduction from clean state, evidence bundle, version range | Reproduced at the **lowest** privilege the claim requires |
| 6 | Classification (§8.3) | CWE + OWASP + ASVS IDs, WSTG coverage ledger | IDs come from the current editions, not memory |
| 7 | Report draft + **human sign-off** | Draft report in `findings/` | A human has read it and agrees. Nothing is sent by an agent. |
| 8 | Close the loop (§8.5) | Re-run of the rule and the repro against the patched version | Fix is real, not a block-list patch the original chain bypasses |

### 1.2 Step 0 — scope and provenance

Record before reading code, in the target's notes file:

1. Exact repository URL and the commit SHA you are reviewing.
2. The released version string that commit corresponds to, and whether it is the newest public release.
3. License, and whether it permits the analysis (ROE §7 stop condition).
4. Stated security contact: `SECURITY.md`, GitHub private vulnerability reporting ([flow](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)), a vendor security page, the Drupal Security Team, or a Joomla extension publisher.
5. If no contact exists: write "report path unestablished" in the notes. The finding can still be researched; the human establishes the channel before anything is written up.

### 1.3 Step 0b — duplicate check first, not last

Searching for prior art after a week of work is how a week gets wasted. Before tracing anything:

1. Search the [GitHub Advisory Database](https://github.com/advisories) filtered by ecosystem (Composer, npm, pip, Maven, RubyGems, Go, NuGet) for the component name.
2. Search the [Patchstack database](https://patchstack.com/database/) for WordPress plugins/themes — per-plugin version ranges and vuln type.
3. **Read** the prior advisories, do not merely count them. A prior advisory tells you which code paths were already hardened and which sinks the maintainer now guards.
4. Check the project's issue tracker, changelog, and recent commits for silently-fixed bugs (ROE §3.5).
5. Pull the **newest public release tag** before reviewing. [Patchstack's intake rules](https://patchstack.com/articles/bug-bounty-guidelines-rules/) accept findings only against the newest publicly available release, so reviewing last month's clone can invalidate the work outright.

**STOP condition:** if a published advisory covers the same sink in the same file for the version under test, this is a duplicate. Record it as prior art and move to the next entrypoint.

---

## 2. Standing up a local instance

Do this in Step 0c, before any hypothesis exists, so verification is never the thing that blocks a finding.

### 2.1 The rule that is not negotiable

Verification happens **only** against an instance you deployed. Per [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md) §1, the software being open source grants rights over the code, not over anyone's deployment of it. A vendor demo site is a third-party production system. `docker compose up` is always available and always legal — use it.

Bind every lab service to loopback. A lab reachable from the network is an invitation to test something you do not own by accident.

### 2.2 WordPress — `wp-env`

[`@wordpress/env`](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-env/) is the sanctioned disposable local WordPress. It requires Docker, or `--runtime=playground` for a Docker-free run.

```bash
npm -g i @wordpress/env
cd /path/to/plugin-under-review      # cwd is auto-mapped as a plugin
wp-env start                         # site: http://localhost:8888  admin / password
wp-env status
wp-env logs
wp-env run cli wp plugin list        # any WP-CLI command goes through `run cli`
wp-env stop
wp-env destroy                       # full teardown between version tests
```

To map a plugin explicitly, or to review several at once, write `.wp-env.json` in the lab directory:

```json
{ "plugins": ["."] }
```

Pin the core version with the `core` field when a finding is version-dependent; read the wp-env page for the accepted value forms rather than guessing one.

**Provision one user per role immediately.** Verifying as Administrator proves nothing about a claim that says "Subscriber":

```bash
wp-env run cli wp user create sub sub@example.test --role=subscriber
wp-env run cli wp user create con con@example.test --role=contributor
wp-env run cli wp user create ed  ed@example.test  --role=editor
```

### 2.3 Everything else — Docker Compose

Write a [Compose file](https://docs.docker.com/reference/compose-file/) pinned to the exact released version or image digest, driven with the standard [Compose lifecycle](https://docs.docker.com/compose/) (`up`, `logs`, `exec`, `down`):

```yaml
services:
  app:
    image: example/target@sha256:<digest>   # digest, never :latest — "latest" is not a version
    ports:
      - "127.0.0.1:8080:8080"               # loopback only
    environment:
      APP_ENV: production                   # review the shipped default config, not a hardened one
  db:
    image: mysql@sha256:<digest>
    # no `ports:` — the database is not published at all
```

Review the project's **own** shipped default configuration. A bug that only appears after you harden the config is not the bug users have; a bug that only appears after you weaken it is a deployment misconfiguration, not a code flaw (ROE §3.6).

### 2.4 Record what is under test

Into `../../../evidence/README.md`'s `env.md` convention, per finding: image digests, app version and commit SHA, PHP/Node/Python version, database version, the lab config file itself, and which role each attempt ran as. "Latest" is not a version.

### 2.5 Dynamic tooling, scoped to localhost

[ZAP's Docker images](https://www.zaproxy.org/docs/docker/about/) are appropriate as *confirmation*, pointed at your own container only:

| Scan | Use when |
|---|---|
| `zap-baseline.py` | Quick passive sweep of your local instance; short spider, passive rules only |
| `zap-full-scan.py` | Active scanning — **own instance only**, never anything else |
| `zap-api-scan.py` | You have an OpenAPI or GraphQL definition for the local API |

Never point a scanner at a hosted instance, a vendor demo, or a site found in the wild — that is the prohibited scanning in ROE §1. To rehearse an unfamiliar class before reviewing code, use the [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs, which exist for exactly this, instead of someone else's deployment.

---

## 3. Entrypoint mapping per framework family

**An unmapped entrypoint is an unreviewed one, and it is the single most common reason a real bug is missed.** Produce the inventory table first. Do not grep for sinks until it exists.

### 3.1 The inventory table

One row per externally reachable handler:

| Field | Content |
|---|---|
| id | `E-01`, stable for the rest of the audit |
| location | `file:line` of the registration |
| method | GET / POST / CLI / cron / webhook |
| mechanism | How it is registered (hook name, route decorator, routing YAML key, controller task) |
| reachable by | anonymous / authenticated-low / specific role / admin |
| parameters read | Every request value the handler touches |
| state-changing | yes / no — decides whether CSRF is in scope at all |

**Completion test — all four must hold before advancing:**
1. Every route-registration mechanism for the framework has been grepped, not just the obvious one.
2. Every file directly requestable by URL has a row or a documented guard.
3. Every cron/queue/webhook/CLI handler that reads request-shaped input has a row.
4. Routes present in code but absent from the project's own docs/OpenAPI have a row and are flagged (§6.4).

### 3.2 WordPress

Run over the plugin or theme tree. Highest priority first.

```bash
rg -n "add_action\(\s*['\"]wp_ajax_nopriv_"   # UNAUTHENTICATED admin-ajax — review these first
rg -n "add_action\(\s*['\"]wp_ajax_"          # authenticated admin-ajax (any logged-in user, incl. Subscriber)
rg -n "admin_post_nopriv_|admin_post_"        # admin-post.php handlers
rg -n "register_rest_route\("                 # REST routes — check permission_callback (§5.7)
rg -n "add_shortcode\("                       # attribute values are attacker-influenced on any post
rg -n "add_menu_page|add_submenu_page"        # note the capability argument, then compare it to the handler's own check
rg -n "add_filter\(\s*['\"]the_content"       # runs on public page render
rg -n "template_redirect|parse_request|init\b|admin_init"   # callbacks reading superglobals
rg -n "\\\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)\b"       # every raw source, with its file:line
rg -n "wp_schedule_event|wp_cron|upload_mimes|wp_handle_upload"
rg -n "\\\$_SERVER\['HTTP_"                   # header-driven logic (host, referer, x-forwarded-for)

# Directly requestable PHP files with no bootstrap guard — each one is an entrypoint:
rg --files-without-match "defined\(\s*'ABSPATH'\s*\)" -g '*.php' .
```

Facts that shape the table: all WordPress AJAX goes to `wp-admin/admin-ajax.php`, and the request's `action` value builds the hook tag ([handbook](https://developer.wordpress.org/plugins/javascript/ajax/)). The `_nopriv_` suffix means anonymous-reachable; the un-suffixed form means *any* logged-in user, which on an open-registration site means anyone who signs up.

### 3.3 Drupal

Read, for every module in scope:

1. Every `*.routing.yml`: `path`, `defaults._controller` / `defaults._form`, `requirements._permission` / `_access` / `_csrf_token`, `options._admin_route`.
2. `*.links.task.yml`, `*.links.action.yml`, `*.services.yml` (event subscribers reached on every request).
3. REST / JSON:API resource plugins (`@RestResource` annotations) and controllers returning raw responses.
4. Any `hook_menu`-era remnant in legacy code.

Current API guidance is [Writing secure code for Drupal](https://www.drupal.org/writing-secure-code) (maintained, updated March 2025). The [develop/security index](https://www.drupal.org/docs/develop/security) also lists "Handle user input with care" — treat that page as historical: its examples are Drupal 7 era (`db_query`, `check_plain`) and it is flagged as needing work.

### 3.4 Joomla

Map: the controller `task=` dispatch surface, `com_ajax` plugin handlers, views reachable with `format=raw|json`, CLI and scheduled tasks (`onExecuteTask`), and every input read through `Factory::getApplication()->getInput()->get()`.

Record the **filter type argument** on each input read: `'cmd'`, `'int'`, `'string'`, `'raw'`. `'raw'` is a red flag and belongs in the parameters column verbatim.

Joomla's [extension security page](https://manual.joomla.org/docs/next/building-extensions/security/) is almost entirely coordinated-disclosure process and names SQLi/XSS/CSRF only as examples; it carries no code-level guidance. Derive Joomla code-level expectations from the framework API itself (`Session::checkToken`, `$user->authorise`, `quote`/`quoteName`/`bind`) and do not cite sandbox doc mirrors.

### 3.5 APIs and web frameworks

Derive the route table from the router, **not** from documentation:

| Family | Where routes are declared | Where middleware/filters sit |
|---|---|---|
| Express / Fastify / Koa / hapi / Restify | `app.<verb>()` / plugin route options, mounted routers | `app.use()` order; per-route middleware arrays; auth applied per-router is easy to miss on one route |
| NestJS | `@Controller` + `@Get`/`@Post` decorators | Guards (`@UseGuards`), interceptors, pipes; a global guard with one `@Public()` override is a common gap |
| Django / DRF | `urls.py`, DRF routers and viewsets | `MIDDLEWARE`, DRF `permission_classes` (and `DEFAULT_PERMISSION_CLASSES`), `@login_required`, object-level `has_object_permission` |
| Flask / FastAPI | `@app.route` / `@router.<verb>` decorators, blueprints | `before_request`, FastAPI `dependencies=`; a dependency declared on the router but absent on one route |
| Spring MVC / JAX-RS / Struts | `@RequestMapping` / `@GetMapping`, JAX-RS `@Path` | Security filter chains, `@PreAuthorize`, interceptors; `permitAll()` patterns and wildcard matchers |
| Rails | `config/routes.rb` | `before_action` chains and their `only:`/`except:` lists; `skip_before_action` is where authentication disappears |

Then diff the code-derived route table against any published OpenAPI/GraphQL schema. Routes in code but absent from the spec are [API9:2023 Improper Inventory Management](https://api-security.owasp.org/editions/2023/en/0x11-t10/) and are where undocumented admin and debug endpoints live.

---

## 4. Auth boundaries: three independent controls

For every row in the §3 inventory, record which of these three is present and **which function enforces it**:

| Control | Question | Failure mode when assumed |
|---|---|---|
| Authentication | Is the caller identified at all? | Anonymous-reachable handler assumed to be admin-only |
| Authorization | Is *this* caller permitted *this* action on *this* object? | Logged-in treated as authorized; row existence treated as ownership |
| CSRF / request intent | Did the caller intend this request? | Token check treated as an authorization check |

**The classic CMS plugin CVE is an entrypoint that has one of the three and is assumed to have all three.** Fill the matrix mechanically before judging anything.

### 4.1 Object-level and property-level authorization

1. For every entrypoint that accepts an identifier (`id`, `post_id`, `user_id`, `order_id`, `uuid`, `file`, `nid`, `cid`), find the line that ties that identifier to the **current actor**.
2. If the only check is "is the caller logged in" or "does the row exist", that is a Broken Object Level Authorization candidate ([API1:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/), CWE-639). Record it.
3. Repeat **per field** on every write path: can a low-privilege caller set `role`, `is_admin`, `price`, `status`, `owner_id`, `verified`? That is API3:2023 / mass assignment (CWE-915).
4. The authoritative test-case set for this work is [WSTG Authorization Testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/) (directory traversal/file include, bypassing authorization schema, privilege escalation, insecure direct object references).

---

## 5. Per-class review

Each class below gives: **Grep** (source patterns), **Taint path**, **Disproved if** (what kills the candidate — check this *before* writing it up), and **Evidence** (what the report needs). Trace one entrypoint at a time and write the chain as `source (file:line) -> transforms -> sink (file:line) -> required privilege -> impact`. A chain that is not written down is a hypothesis, not a finding.

Stable classification per class (use the CWE as the primary ID; OWASP category *names* shift between editions, CWE IDs do not):

| Class | CWE | OWASP Top 10:2025 | API Top 10:2023 | WSTG category |
|---|---|---|---|---|
| SQL injection | CWE-89 | A05 Injection | API8 | INJT |
| Stored / reflected XSS | CWE-79 | A05 Injection | API8 | INJT |
| DOM XSS | CWE-79 | A05 Injection | — | CLNT |
| CSRF | CWE-352 | A01 Broken Access Control | API5 | SESS |
| IDOR / broken access control | CWE-639, CWE-862, CWE-863 | A01 Broken Access Control | API1, API5 | ATHZ |
| SSRF | CWE-918 | confirm on the 2025 list | API7 | INJT |
| SSTI | CWE-1336, CWE-94 | A05 Injection | API8 | INJT |
| Unrestricted file upload | CWE-434 | confirm on the 2025 list | API8 | BUSL |
| Authentication / session flaws | CWE-287, CWE-384 | A07 Authentication Failures | API2 | ATHN, SESS |
| Mass assignment | CWE-915 | A01 Broken Access Control | API3 | APIT |
| Open redirect | CWE-601 | A01 Broken Access Control | — | CLNT |
| Insecure deserialization | CWE-502 | A08 Software or Data Integrity Failures | API8 | INJT |
| Path traversal | CWE-22 | A01 Broken Access Control | API1 | ATHZ |

Resolve exact WSTG test IDs from the checklist copy in `../../../checklists/` (source: [OWASP/wstg checklists](https://github.com/OWASP/wstg/tree/master/checklists)); pick the OWASP category from the [2025 list](https://top10.owasp.org/2025/) rather than quoting a 2021 name from memory.

### 5.1 SQL injection

- **Grep (PHP/CMS):** `$wpdb->(query|get_results|get_var|get_row|get_col)\(` with `$` interpolation or `.` concatenation; `$wpdb->prepare` where the placeholder is already quoted (`'%s'`) or where a variable is interpolated into the *template string*; `esc_sql` used as though it were a bind; `ORDER BY` without `sanitize_sql_orderby`; `\Drupal::database()->query()` with concatenation; Joomla queries without `quote()`/`quoteName()`/`bind()`.
- **Grep (other):** string building around `query(`, `raw(`, `execute(`, `find_by_sql`, `where("...#{}")`, f-strings and `%`-formatting inside `cursor.execute`, JPQL/HQL concatenation.
- **Taint path:** request parameter -> optional cast/sanitize -> query string assembly -> driver execution. Identifiers (table/column names, `ORDER BY`, `LIMIT` direction) are the common survivors because placeholders cannot bind them in most drivers.
- **Disproved if:** the value is bound as a parameter; it is cast to int before concatenation *on every path* including the error path; the query is only reachable with a privilege that already implies database access; the input is drawn from a fixed server-side allow-list rather than the request.
- **Evidence:** the interpolated expression at `file:line`, the entrypoint that reaches it, the minimum privilege, and a local request producing an observable difference (an error, a row count change, a boolean difference). Prove injection, do not dump data.
- **Fix to quote:** [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) ordering — prepared statements/parameterized queries first, correctly built stored procedures second, allow-list validation third, escaping explicitly *strongly discouraged*.

### 5.2 Stored and reflected XSS

- **Grep:** `echo`, `print`, `printf`, `_e(`, `wp_die(` reaching a request value with no `esc_*` / `wp_kses*`; values placed inside HTML attributes or inline `<script>`; `|raw` in Twig; `#markup` where `#plain_text` belongs; template interpolation marked safe/unescaped.
- **Taint path:** request value -> (storage) -> template/echo at a specific output context (element text, attribute, URL attribute, JS literal, CSS). The context decides whether the escaper present is the right one.
- **Disproved if:** the correct context escaper runs on every path; the sink output is consumed as data (JSON with correct `Content-Type` and no sniffing-exploitable path); the only actor who can store the value already has HTML-posting privileges by design (§9); the value is rendered inside a text-only node by a framework that autoescapes and the template does not opt out.
- **Evidence:** the unescaped sink at `file:line`, the storing entrypoint and its privilege, the rendering page, and a local screenshot or DOM excerpt showing script execution in a *different* user's session context — not your own pasted payload (that is self-XSS, §9).

### 5.3 DOM XSS

- **Grep sinks:** `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `v-html`, `$.html()`, `eval`, `new Function`, `setTimeout` with a string.
- **Grep sources:** `location`, `location.hash`, `location.search`, `document.URL`, `document.referrer`, `postMessage` handlers (check the `origin` test), `localStorage` values written from a request.
- **Taint path:** browser-controlled source -> JS string handling -> HTML-parsing sink, entirely client-side; the server may never see the payload (fragment-only).
- **Disproved if:** the sink receives a value from a server-rendered constant; a sanitizer (DOMPurify or equivalent) runs with a configuration that blocks the vector; the `postMessage` handler validates `event.origin` against an allow-list.
- **Evidence:** source and sink at `file:line`, the URL shape that triggers it on the local instance, and the executing payload captured in the local browser.

### 5.4 CSRF

- **Grep:** state-changing handlers with no token verification. WordPress: `wp_verify_nonce`, `check_admin_referer`, `check_ajax_referer` absent. Drupal: `_csrf_token: 'TRUE'` missing on a state-changing GET route. Joomla: `Session::checkToken()` / `checkToken('post')` absent from a `task`. Frameworks: `csrf_exempt`, `@csrf.exempt`, `skip_before_action :verify_authenticity_token`, global CSRF middleware disabled or bypassed for a route.
- **Taint path:** attacker-hosted page -> victim's authenticated browser -> state-changing request with ambient credentials -> server performs the action.
- **Disproved if:** the endpoint is not state-changing (§9); the request requires a custom header that triggers CORS preflight and no permissive CORS policy allows it; the framework's global protection applies and you simply did not send the token; the token is verified somewhere earlier in the call chain (read the chain, do not assume).
- **Evidence:** the handler with no token check at `file:line`, the state change it performs, the minimum role that can perform it, and a minimal local HTML form (≤10 lines) demonstrating the action from a different origin against your own instance.

### 5.5 IDOR and broken access control

- **Grep:** identifier parameters reaching a fetch/update/delete with no ownership predicate; `findById(req.params.id)` followed directly by a mutation; `get_post($_GET['id'])` with no author comparison; Drupal entity loads without `->access('update'|'delete', $account)` or a `hook_entity_access`; Joomla operations without `$user->authorise('core.edit'|'core.delete', $asset)`.
- **Taint path:** attacker-supplied identifier -> object load -> privileged operation, with the authorization decision made on authentication alone.
- **Disproved if:** an ownership or capability predicate exists on the query (`WHERE user_id = :current`) or immediately after the load on every path; the identifier is server-derived; the object is public by design; the operation is permitted to that role by the product's documented model.
- **Evidence:** the missing check at `file:line`, two local accounts, and a captured request where account A reads or modifies account B's object. Stop at proof — do not enumerate, do not harvest (ROE §1).

### 5.6 SSRF

- **Grep:** `wp_remote_get`, `wp_remote_post`, `curl_exec`, `file_get_contents` on a request-supplied URL; `requests.get`, `urllib.request`, `axios`, `fetch`, `http.Get`, `URLConnection`, `RestTemplate` with an input URL; webhook/callback/avatar-import/preview/oEmbed features; PDF and image generators that fetch remote resources.
- **Taint path:** request-supplied URL or host -> HTTP client -> internal network, cloud metadata, or a `file://`/`gopher://` scheme handler. Check redirect following and retry paths separately — they are frequently unvalidated even when the first hop is checked.
- **Disproved if:** the destination comes from a fixed allow-list of hosts; the code resolves the host, validates the IP, and connects to the **validated IP**; client redirects are disabled; the schemes are restricted to http/https; the feature already proxies arbitrary URLs as its documented purpose and reaches nothing internal.
- **Evidence:** sink at `file:line`, the parameter, the minimum privilege, and a local demonstration against a listener you control inside your own lab (for example a second container). Never a third-party host, never a public SSRF-canary service — that is an outbound request to someone else's system.
- **Fix to quote:** [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — Case 1 (fixed destinations: allow-list) vs Case 2 (arbitrary destinations: block internal ranges plus a request-authenticity token), never accept a full URL, validate then connect to the validated IP, disable redirects, apply the checks to retries, reject on parser disagreement (DNS rebinding).

### 5.7 SSTI

- **Grep:** `render_template_string`, `Template(...)` on input, `Twig_Environment::createTemplate`, `compile`/`render` on a request value, user-editable email/notification/label templates, admin-supplied "custom format" strings.
- **Taint path:** request value -> template *source* (not template *data*) -> engine compile -> expression evaluation.
- **Disproved if:** the input lands in the template's variable context rather than its source; the engine is a logic-less formatter (no expression evaluation); a sandbox policy blocks attribute and callable access and you cannot escape it with a minimal expression.
- **Evidence:** the compile call at `file:line` and an arithmetic or string-builtin evaluation result from the local instance. Demonstrate evaluation; do not build an RCE chain (ROE §4).

### 5.8 Unrestricted file upload

- **Grep:** `move_uploaded_file`, `wp_handle_upload` without `wp_check_filetype_and_ext`, `upload_mimes` filters that *widen* the allowed set, extension checks by block-list, `$_FILES` name used in the destination path, archive extraction loops (path traversal via entry names), image libraries invoked on unvalidated content.
- **Taint path:** uploaded filename/content/MIME -> validation (or its absence) -> destination path under a web-served directory -> request for the stored file -> interpretation by the server.
- **Disproved if:** the extension is drawn from a server-side allow-list and the stored name is regenerated; the storage directory is non-executable and outside the document root, or blocked by a shipped `.htaccess`/web-server rule; the MIME and extension are cross-checked; execution requires a privilege that already includes file management.
- **Evidence:** the validation gap at `file:line`, the minimum role, the stored path, and one local request showing the file is served with an interpreted content type or an unexpected location. A single marker file is enough — no web shells (ROE §4).
- **Fix to quote:** the OWASP `File_Upload` cheat sheet, reached from the [cheat sheet index](https://cheatsheetseries.owasp.org/).

### 5.9 Authentication and session flaws

- **Grep:** password reset token generation (`rand`, `mt_rand`, `uniqid`, time-seeded values), token comparison with `==` instead of a constant-time compare, session identifier not regenerated after privilege change (session fixation, CWE-384), "remember me" cookies containing user-controlled or guessable material, JWT verification with `algorithm: none` accepted or the signature unverified, email-change and password-change flows that do not require the current password, OAuth `state` parameter unchecked, account lockout logic keyed on a client-supplied value.
- **Taint path:** depends on the flaw; always write the chain from the request that starts the flow to the moment identity is granted.
- **Disproved if:** the token comes from a CSPRNG and is single-use and expiring; the session ID rotates on login and on privilege change; signature verification is enforced with a pinned algorithm; the flow requires a secret the attacker does not have.
- **Evidence:** the generation or comparison line at `file:line`, and a local demonstration of the identity boundary being crossed (one account acting as another) — never against a real account on a real service.
- **Fix to quote:** the OWASP `Authentication` and `Session_Management` cheat sheets from the [index](https://cheatsheetseries.owasp.org/).

### 5.10 Mass assignment

- **Grep:** request body bound straight to a domain object: `Object.assign(user, req.body)`, `Model(**request.data)`, `update_attributes(params[:user])`, `$model->fill($request->all())`, lodash `merge` on a request body, Spring `setDisallowedFields` (block-list) where `setAllowedFields` (allow-list) belongs, Laravel `$guarded` instead of `$fillable`, mongoose `protect` instead of a picked subset, and binding through nested objects or constructors.
- **Taint path:** request body field -> ORM/entity binder -> column write the UI never exposes (`role`, `is_admin`, `status`, `price`, `owner_id`, `email_verified`).
- **Disproved if:** binding uses an explicit allow-list; the sensitive column is not writable at the persistence layer; a server-side assignment overwrites the field after binding on every path; the field has no security meaning.
- **Evidence:** the binder call at `file:line`, the writable sensitive field, the minimum privilege, and a local before/after database row showing the field changed.
- **Fix to quote:** [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) — allow-list, never block-list.

### 5.11 Open redirect

- **Grep:** `wp_redirect(` where `wp_safe_redirect(` belongs, `header('Location: ' . $input)`, `res.redirect(req.query.next)`, `return redirect(request.GET['next'])`, `redirect_to params[:url]`, and any `redirect_uri` / `next` / `return_to` / `continue` parameter.
- **Taint path:** request parameter -> redirect response `Location` header or client-side `location` assignment, with no host validation.
- **Disproved if:** the destination is validated against an allow-list or forced relative; the framework's safe-redirect helper is used; the parameter is signed.
- **Evidence:** the redirect call at `file:line` and a local request returning a `Location` to an off-site origin. **Severity ceiling:** on its own this is low. It rises only with a demonstrated consequence — a token or credential forwarded to the attacker origin, or an OAuth/SSO `redirect_uri` that leaks a code. Do not claim the consequence without demonstrating it (ROE §3.4).

### 5.12 Insecure deserialization in a request path

- **Grep:** `unserialize`, `maybe_unserialize` on input, cookies, or options rows an attacker can write; `pickle.loads`; `yaml.load` without `SafeLoader`; `ObjectInputStream.readObject`; `Marshal.load`; `JSON.parse` feeding a prototype-polluting merge; PHAR-aware filesystem functions on attacker-named paths.
- **Taint path:** attacker-controlled serialized blob -> deserializer -> magic method / gadget chain / prototype chain -> side effect.
- **Disproved if:** the format is data-only and no object instantiation occurs; a safe loader is used; the blob is integrity-protected with a server-side key (and the key is not in the repo — see [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md)); the input is not attacker-reachable.
- **Evidence:** the deserialization call at `file:line`, the path by which input reaches it, and a minimal local proof that object instantiation occurs — a benign gadget that writes a marker or triggers an observable side effect. Not a full RCE chain.
- **Fix to quote:** the OWASP `Deserialization` cheat sheet from the [index](https://cheatsheetseries.owasp.org/).

### 5.13 Sanitizer-context mismatch — the highest-yield read in mature code

In a project that has had prior advisories, the productive finding is rarely "no sanitizer". It is a sanitizer that does not match its sink. For each traced path, name the sanitizer and judge it against the **sink context**, not against its own existence:

| Pattern seen | Why it fails |
|---|---|
| `sanitize_text_field()` before a SQL sink | It strips tags; it does not quote. Not a bind. |
| `esc_html()` inside an HTML attribute or `<script>` | Wrong context escaper; attribute and JS contexts need `esc_attr` / `esc_js` |
| `intval()` on two of three parameters | The third one carries the injection |
| Allow-list applied before a second decode | Decoding after validation reintroduces the payload |
| Block-list of field names for mass assignment | New fields are writable by default |
| Validation on the first hop, skipped on redirect or retry | The SSRF/redirect check never runs on the path that matters |

This is also where a reviewer most often cries wolf, so the "Disproved if" step is mandatory before writing anything up.

---

## 6. CMS plugin review

A large share of real advisories in this dimension are CMS plugins/modules/extensions. Give this section the most time.

### 6.1 WordPress — the per-endpoint checklist

**For EVERY registered endpoint in the plugin (every `wp_ajax_*`, `wp_ajax_nopriv_*`, `admin_post*`, `register_rest_route`, shortcode, form handler, and unguarded PHP file), answer four questions:**

| | Question | Enforcing API | Verdict rule |
|---|---|---|---|
| **(a)** | Does it verify a **capability**? | `current_user_can( $cap )` inside the handler | Missing on a state-changing endpoint → privilege escalation candidate |
| **(b)** | Does it verify a **nonce**? | `check_admin_referer()`, `check_ajax_referer()`, `wp_verify_nonce()` | Missing on a state-changing endpoint → CSRF candidate |
| **(c)** | Is input **sanitised/validated** for its use? | `sanitize_*`, `wp_kses*`, `absint`, `$wpdb->prepare` | Wrong-for-context control → injection candidate (§5.13) |
| **(d)** | Is output **escaped** for its context? | `esc_html`, `esc_attr`, `esc_url`, `esc_js`, `esc_textarea`, `wp_kses_post` | Missing or wrong escaper → XSS candidate |

**Missing (a) or (b) on a state-changing endpoint is the single most common real finding in this class.** Record the answer for every endpoint even when it is "yes" — the table is the evidence that the audit was complete.

### 6.2 Capabilities — what `current_user_can()` does and does not do

Reference: [Checking User Capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/).

1. A capability check must run **inside the handler**, on the execution path, before the side effect.
2. A capability check at **hook-registration time only** does not gate execution. The handbook's own "secure" example gates at registration, accepts GET, and uses no nonce — useful teaching material, not a complete secure pattern. Treat registration-time-only gating as missing (a).
3. Compare the capability to the **effect**. `current_user_can('read')`, or any Subscriber-reachable capability, guarding an option write, a user-meta write, or a file operation is a capability-too-low finding even though a check exists.
4. Compare the `add_menu_page` / `add_submenu_page` capability argument against the capability the form handler itself checks. A mismatch means the menu is the only gate, and the handler is reachable directly.
5. A capability check and a nonce check are **independent controls**. Having one is not having the other.

### 6.3 Nonces — what they prove

Reference: [Nonces](https://developer.wordpress.org/apis/security/nonces/).

| Function | Role | Note |
|---|---|---|
| `wp_create_nonce`, `wp_nonce_field`, `wp_nonce_url` | Issue | Issuing side only; presence proves nothing about verification |
| `wp_verify_nonce` | Verify | Returns a value — **check the return**; an unchecked call is not a control |
| `check_admin_referer` | Verify nonce **and** referrer | Dies with 403 on failure |
| `check_ajax_referer` | Verify nonce only | No referrer check |

A nonce is **not** an authorization check. It proves the request came from your UI. Any handler with a nonce check and no `current_user_can()` is a candidate privilege-escalation finding, not a secure handler. Conversely, `current_user_can()` with no nonce on a state-changing request is a CSRF candidate. AJAX nonces arrive as `_ajax_nonce` ([handbook](https://developer.wordpress.org/plugins/javascript/ajax/)).

### 6.4 Sanitise vs validate vs escape

Order of preference, per [Sanitizing Data](https://developer.wordpress.org/apis/security/sanitizing/): **validate** if the field has a known shape; **sanitise** only when the field is too general to validate. Escape at output, not at input — the "escape late" principle in [Escaping Data](https://developer.wordpress.org/apis/security/escaping/) tells you *where* in the file to expect the call.

| Output context | Correct escaper |
|---|---|
| Element content | `esc_html()` |
| HTML attribute value | `esc_attr()` |
| `src` / `href` | `esc_url()` (`esc_url_raw()` for storage and redirects, not for output) |
| Inline JavaScript string | `esc_js()` |
| `<textarea>` content | `esc_textarea()` |
| Untrusted HTML that must stay HTML | `wp_kses()` with an explicit allow-list, or `wp_kses_post()` |
| XML | `esc_xml()` |

Input sanitisation does not substitute for output escaping, and output escaping does not substitute for a bind in SQL. Reference hub: [WordPress Security APIs](https://developer.wordpress.org/apis/security/). (Note: the old `/plugins/security/{data-validation,securing-input,securing-output,nonces}/` paths have moved to `/apis/security/` — do not link the old ones.)

### 6.5 Prepared statements — `$wpdb->prepare()` rules

Reference: [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/).

1. Placeholders: `%d` (integer), `%f` (float), `%s` (string), `%i` (identifier, WP 6.2+), `%%` (literal percent).
2. **Placeholders must be unquoted.** `prepare( "... WHERE x = '%s'", $v )` is a bug — the function adds the quotes. A pre-quoted placeholder is reviewable as SQL injection.
3. A variable interpolated into the **template string** is not protected: `prepare( "... WHERE col = {$col} AND x = %s", $v )` leaves `$col` raw.
4. Numbered or formatted placeholders such as `%1$s` are **not** auto-quoted.
5. `esc_sql()` is not a bind. Table and column names need `%i` (6.2+) or a server-side allow-list; `ORDER BY` needs `sanitize_sql_orderby` or an allow-list.

### 6.6 AJAX endpoints

1. All WordPress AJAX reaches `wp-admin/admin-ajax.php`; the request's `action` value builds the hook tag.
2. `add_action( 'wp_ajax_nopriv_<action>', ... )` is **anonymous-reachable**. Any privileged effect there is unauthenticated by design — review these first.
3. `add_action( 'wp_ajax_<action>', ... )` is reachable by **any logged-in user**, including Subscriber. "Logged in" is not "admin".
4. Apply the §6.1 four questions to each. A handler registered on both the `_nopriv_` and the privileged hook must still check capability inside the handler.

### 6.7 REST routes — `permission_callback`

The requirement is stated on [Adding Custom Endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/): *"You must also register a permissions callback for the endpoint."* WordPress 5.5+ emits a `_doing_it_wrong` notice when `permission_callback` is absent, and `__return_true` is the documented marker for a deliberately public endpoint. (The [Routes and Endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/) page describes it as optional — cite the former for the requirement.)

Review rules:

1. `register_rest_route` with **no** `permission_callback` → finding candidate; confirm the route is reachable and state-changing.
2. `permission_callback => '__return_true'` on a route that writes state, reads private data, or triggers an outbound request → finding candidate regardless of the `_doing_it_wrong` notice being silenced.
3. `permission_callback` that checks only `is_user_logged_in()` on a privileged route → function-level authorization gap (API5:2023).
4. In the `args` schema, `validate_callback` runs **before** `sanitize_callback` (WP 4.6+). A `sanitize_callback` that assumes validation already happened is only correct if `validate_callback` is actually present.
5. REST routes are registered on `rest_api_init`; grep that hook as well as the function.

### 6.8 Settings and options

[`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/) takes `sanitize_callback`, `type`, and `show_in_rest`. Two facts the reference page does not state and that you must apply yourself:

1. **A missing `sanitize_callback` stores raw input.** If that option is later echoed into a page or interpolated into SQL, the option write is the injection point.
2. **`type` constrains the REST API only.** An admin-form save of a mismatched type goes through.

Also check: options written from an endpoint whose capability is lower than `manage_options`; `update_option` calls reached from a `_nopriv_` handler; option values rendered in the admin UI without escaping (admin-side stored XSS still crosses a boundary when a lower role can write the option).

### 6.9 Other WordPress specifics

| Check | What to look for |
|---|---|
| Direct file access | Any plugin `.php` file without `defined( 'ABSPATH' ) \|\| exit;` is directly requestable |
| Upload surface | `upload_mimes` filters that widen the allowed set; `wp_handle_upload` without `wp_check_filetype_and_ext` |
| Redirects | `wp_redirect()` where `wp_safe_redirect()` belongs |
| Deserialization | `maybe_unserialize` / `unserialize` on request input, cookies, or options a lower role can write |
| Shortcodes | Attribute values reaching an unescaped sink — shortcodes run wherever a Contributor can place them |
| Cron | `wp_schedule_event` callbacks that read stored request data without re-validating it |
| Header-driven logic | `$_SERVER['HTTP_*']` used for authorization, host building, or cache keys |

### 6.10 WordPress verdict and expectations

- Fast first pass with the tools the review team itself uses: [Plugin Check](https://wordpress.org/plugins/plugin-check/) (`wp plugin check <plugin>`) covers insecure `wp_verify_nonce()` use, direct database calls, direct file access, and missing input sanitisation. It is a first pass, not a finding.
- The [WordPress.org plugin guidelines](https://developer.wordpress.org/plugins/wordpress-org/detailed-plugin-guidelines/) state that all directory code should be as secure as possible, that a plugin with security issues is closed until fixed, and that the security team may force-update it. Useful for expectation-setting. **It is not a vulnerability-reporting channel.**
- Intake constraints that change research decisions: [Patchstack](https://patchstack.com/articles/bug-bounty-guidelines-rules/) accepts reports only via its official form, only against the newest public release, credits the first valid report, generally requires the exploit to be reachable unauthenticated or as Subscriber/Customer, and **bans reporters for untested AI-generated assumptions**. [WPScan's policy](https://wpscan.com/vulnerability-disclosure-policy/) runs a 30-day patch window (extendable to 120 for highly complex cases) with escalation to the hosting marketplace on vendor silence, and holds PoC write-ups for at least a week after disclosure. Submission surfaces: [WPScan submit](https://wpscan.com/submit/) for plugins/themes; WordPress **core** goes to the HackerOne WordPress program, not the plugin channels. All of this is executed by the human, not by an agent (ROE §2).

### 6.11 Drupal equivalents

Guidance: [Writing secure code for Drupal](https://www.drupal.org/writing-secure-code).

| Control | Check |
|---|---|
| Route access | `requirements: _access: 'TRUE'` on a route with any effect; `_permission` too broad for the effect |
| CSRF | `_csrf_token: 'TRUE'` missing on a state-changing GET route |
| Entity authorization | Entity load/update/delete without `->access('update'\|'delete', $account)` or a `hook_entity_access` implementation |
| Output | Twig `{{ }}` autoescapes — the `raw` filter opts out; `#markup` where `#plain_text` belongs; `Html::escape()` for plain text, `Xss::filter()` for untrusted HTML, `Xss::filterAdmin()` only for admin-trusted HTML |
| URLs | `UrlHelper::stripDangerousProtocols()` / `filterBadProtocol()` on user-supplied URLs |
| Translation | `t()` / `formatPlural()` placeholders: `@` escapes, `%` escapes and themes, `:` is for URLs — a concatenated string with no placeholder is the bug |
| SQL | `Database::query()` with **named placeholders**, `select()->condition()`, `escapeLike()` on LIKE patterns |
| JS | `Drupal.checkPlain()` on the client side |

**Reportability gate — read before writing a Drupal finding** ([Security Team policy](https://www.drupal.org/drupal-security-team/security-advisory-process-and-permissions-policy)): coverage requires an opt-in contrib project (grey shield) and a stable release in a supported branch; sandboxes, externally hosted projects, and externally required libraries are not covered; and bugs that require *Administer users*, *Administer permissions*, or *Administer site configuration* are explicitly **not** treated as vulnerabilities. Report to the Security Team regardless and let them triage — but do not expect an advisory for an admin-permission bug, and do not inflate one.

### 6.12 Joomla equivalents

| Control | Check |
|---|---|
| CSRF | `Session::checkToken()` / `checkToken('post')` missing from a controller `task` |
| Authorization | `$user->authorise('core.edit'\|'core.delete', $asset)` missing on an asset operation |
| Input filtering | `getInput()->get()` filter type: `'raw'` is a red flag; `'cmd'`/`'int'` are constrained |
| SQL | Queries without `quote()` / `quoteName()` / `bind()` |
| Reachability | `format=raw\|json` views, `com_ajax` handlers, `onExecuteTask` scheduled tasks |

Process expectations from [Joomla's extension security page](https://manual.joomla.org/docs/next/building-extensions/security/): report to the publisher's security contact, confidentiality until an agreed date, acknowledgement within 1 business day, assessment in 3–5, CVSS 4.0 scoring, private fix plus regression test, CVE via Joomla's CNA before disclosure, advisory with affected/fixed versions and reporter credit, no exploit detail that raises user risk — plus explicit no-access-to-others-data and no-destructive-testing limits, which match ROE §1. The [Vulnerable Extensions List](https://extensions.joomla.org/vulnerable-extensions/about/) is a **listing** mechanism, not a coordinated-disclosure process: it states it does not promise to test or validate reports and gives no embargo timeline. The maintainer remains the primary path.

---

## 7. API-specific review

Taxonomy: [OWASP API Security Top 10 — 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/). Work the route table from §3.5 row by row.

| Item | Source-review question | Candidate when |
|---|---|---|
| API1 Broken Object Level Authorization | For each `id` parameter, which line ties the object to the caller? | Only "is logged in" or "row exists" |
| API2 Broken Authentication | Where is identity established, and can it be forged or replayed? | Unverified JWT signature, guessable reset token, no session rotation |
| API3 Broken Object Property Level Authorization | Which **fields** can this caller write, and which can it read back? | Binder accepts `role`/`status`/`price`; response serializer returns fields the role should not see |
| API4 Unrestricted Resource Consumption | Does any endpoint allow unbounded work per request? | Establish it from **source** — the missing bound at `file:line`. ROE §1 forbids load testing anything you do not own; a cost measurement on your own lab instance is permitted but proves little, so report the unbounded code path, not a benchmark |
| API5 Broken Function Level Authorization | Do admin/debug routes enforce role, or only hide from the UI? | Admin handler gated by UI visibility, a client-side role flag, or `is_logged_in` alone |
| API6 Unrestricted Access to Sensitive Business Flows | Can a scripted caller abuse a flow the UI rate-paces? | Flow has value (purchase, invite, vote) and no server-side pacing or atomicity |
| API7 SSRF | §5.6 | Request-supplied URL reaches an HTTP client |
| API8 Security Misconfiguration | Shipped defaults: CORS, debug endpoints, verbose errors, permissive auth defaults | A default in the project's own config is insecure, and the impact is demonstrated |
| API9 Improper Inventory Management | Route table vs OpenAPI diff; old versioned paths still mounted | A route exists in code with no spec entry and no authorization |
| API10 Unsafe Consumption of APIs | Does the app trust an upstream response as data? | Upstream JSON/redirect/HTML flows into a sink unvalidated |

### 7.1 The highest-yield API finding

**Enumerable identifier + missing ownership check.** Sequential integer IDs (or ordered UUIDv1/ULIDs) tell an attacker which objects exist; the missing predicate lets them have those objects. The combination needs no injection, no payload, no race, and no unusual client — which is exactly why it survives in code that has had a security review, and why it accounts for a large share of valid API reports.

Review procedure per route:

1. List every parameter that names an object.
2. For each, find the ownership predicate. Write its `file:line`, or write "none".
3. Where there is none, confirm the route is reachable at a lower privilege than the object's owner.
4. Verify locally with two accounts you created (§8). Prove exactly one cross-account access. **Stop there** — no enumeration, no bulk retrieval, no other person's data (ROE §1 and §7).
5. Check the response body for fields beyond what the role should see; that is a separate API3 finding with its own evidence.

---

## 8. Static analysis, triage, verification, and the handoff

### 8.1 Tool selection by language

Run static analysis **after** the manual map — the map is what makes triage possible.

| Language | Tools | Why |
|---|---|---|
| PHP (WordPress, Drupal, Joomla, Laravel, Symfony) | Semgrep, [Psalm `--taint-analysis`](https://psalm.dev/docs/security_analysis/), WPCS, Plugin Check | **[CodeQL does not support PHP](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)** — this is the defining tooling constraint of this dimension |
| JS / TS | CodeQL (`javascript-typescript`) + Semgrep | CodeQL models Express, Fastify, hapi, Koa, NestJS, Restify, Sails, Angular/React/Vue, EJS/Handlebars/Nunjucks |
| Python | CodeQL (`python`) + Semgrep | Models Django, DRF, Flask, FastAPI, aiohttp.web, Tornado, Twisted, Starlette |
| Java / Kotlin | CodeQL (`java-kotlin`) + Semgrep | Models Spring MVC, Struts, JAX-RS |
| Ruby | CodeQL (`ruby`) + Semgrep | Models Rails |

```bash
# PHP / CMS plugin first pass
semgrep scan --config p/php --config p/owasp-top-ten --config p/phpcs-security-audit .
psalm --taint-analysis                  # add --dump-taint-graph when a chain is unclear
composer require --dev wp-coding-standards/wpcs:"^3.0"   # Composer-only since 3.0
vendor/bin/phpcs -ps . --standard=WordPress-Extra
wp plugin check <slug>

# Compiled/typed languages, on your own clone
codeql database create db --language=javascript-typescript --source-root .
# then analyze with the `default`, `security-extended`, or `security-and-quality` suite
```

Tool facts worth knowing before you trust the output:

- Semgrep invocation is `semgrep scan --config="RULESET-ID" PATH`; `--config` repeats to stack registry rulesets with local YAML, and `--config=auto` uses the curated default ([docs](https://docs.semgrep.dev/running-rules/)). Browse ruleset IDs at [Semgrep explore](https://semgrep.dev/explore) and **pin the exact IDs you used** in the audit notes. A large share of [p/php](https://semgrep.dev/p/php) and [p/owasp-top-ten](https://semgrep.dev/p/owasp-top-ten) rules are Pro-tier, so an unauthenticated community run covers less than the advertised count — do not read a quiet scan as a clean one.
- There is **no WordPress ruleset** in the official [semgrep-rules](https://github.com/semgrep/semgrep-rules) repo (no top-level `wordpress/` directory). WordPress-specific coverage is yours to write (§8.2).
- Psalm's default taint sources are `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST`, `php://input` and `php://stdin` reads, and `STDIN`; built-in sinks include `echo`, `include`, `header`. Declare the project's real sanitisers (`esc_*`, `wp_kses*`, `$wpdb->prepare`, `sanitize_*`) and its real sources (admin-ajax and REST handlers) or every result will be noise.
- CodeQL suite names are `default` (high precision), `security-extended` (adds lower-precision/severity queries), and `security-and-quality` (advanced setup only). There is no `code-quality` suite ([suites](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/codeql-query-suites)). Database creation, language IDs, `--db-cluster` for multi-language repos, and `database init --begin-tracing` are documented in [preparing your code for analysis](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/preparing-your-code-for-codeql-analysis); resolve `.qls` pack paths with `codeql resolve qlpacks` locally rather than hardcoding a remembered string.
- WPCS ships the `WordPress`, `WordPress-Core`, `WordPress-Extra`, and `WordPress-Docs` rulesets ([repo](https://github.com/WordPress/WordPress-Coding-Standards)). Read sniff IDs out of the shipped ruleset XML before quoting one in a report.

### 8.2 Encode each hypothesis as a rule

For every manual hypothesis, write a [taint-mode](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/) rule and commit it:

1. `mode: taint`, with `pattern-sources` (the *specific* entrypoint's `$_POST['x']` / `req.body.x`), `pattern-sinks` (the *specific* sink call), `pattern-sanitizers` (the project's real sanitisers).
2. `pattern-propagators` is Pro-only — write community-compatible rules.
3. Re-run the rule against the patched version (§8.5) and across the same author's other components. The same missing `permission_callback` or unprepared query is usually repeated, and that is how the second and third instance get found.

### 8.3 Triage rules

Unreviewed scanner output is what gets a researcher banned from an intake program. Execute in order and keep the log:

1. Sort by **sink**, not by rule. Collapse duplicates.
2. Drop anything in test fixtures, vendored dependencies, or build output, and anything in dead code with no entrypoint in the §3 table.
3. For each survivor, require all four: **named source**, **named sink**, **reachable entrypoint**, **minimum privilege**. If you cannot name all four, discard it. No exceptions, no "probably reachable".
4. Read the rule's own YAML in [semgrep-rules](https://github.com/semgrep/semgrep-rules) to see which sanitisers it models. "The rule did not model this project's escaper" is the most common false positive, and claiming a finding the rule misread is how credibility goes.
5. Record every dismissal with a reason from [Semgrep's triage vocabulary](https://docs.semgrep.dev/semgrep-code/triage-remediation/) — *False positive*, *Acceptable risk*, *Duplicate*, or *ignored via `nosemgrep`* — so the next scan is quieter and the judgement is auditable.
6. **Standing rule: nothing that only a scanner has seen is reported.** A human must have read the code path.

### 8.4 Local verification

On your own instance only, at the lowest privilege the chain claims:

1. Record the exact version and commit under test, plus the lab config.
2. Snapshot the relevant database and filesystem state.
3. Create the minimum-privilege actor the chain requires — anonymous, Subscriber, Contributor, authenticated-user. **Verifying as Administrator proves nothing if the claim is "Subscriber can do X."**
4. Send the single smallest request that demonstrates the impact.
5. Capture the full request and response, the database/filesystem delta, and the logs (`wp-env logs`, `docker compose logs`).
6. Re-run as anonymous and as each lower role to establish the true privilege boundary — that boundary is the finding's severity.
7. Re-run against the previous and next released versions to pin the affected version range the advisory needs. ROE §3.3 requires this to be determined, not guessed.
8. Re-run from a **clean** container, per [../../../evidence/README.md](../../../evidence/README.md). A PoC that fires only on your dirty working copy is not a reproduction.

PoC discipline (ROE §4): a curl request or a ten-line HTML form is the deliverable. Demonstrate the *primitive* — a value reaching an unescaped sink, a file written to a controlled path, one cross-account read — not a full payload. No chaining, no packaging, no evasion, no reusable scanner, nothing run outside your own container.

### 8.5 Classify, then hand to the human

Per finding, record:

1. A **CWE ID** (stable across editions; see the [CWE Top 25](https://cwe.mitre.org/top25/index.html) for the common set).
2. The **OWASP Top 10:2025** category, taken from [the 2025 list](https://top10.owasp.org/2025/) — not a 2021 name from memory.
3. The **API Security Top 10 2023** item for API findings.
4. The **ASVS 5.0.0** requirement ID the code fails, pulled from the v5.0.0 CSV in the [ASVS repo](https://github.com/OWASP/ASVS) rather than paraphrased ([project page](https://owasp.org/www-project-application-security-verification-standard/)).
5. Coverage in a copy of the [WSTG v4.2 checklist](https://github.com/OWASP/wstg/blob/master/checklists/checklist.md) (~114 test IDs across INFO, CONF, IDNT, ATHN, ATHZ, SESS, INJT, ERRH, CRYP, BUSL, CLNT, APIT), marked Pass/Fail/N-A per ID so completeness is evidence, not assertion. WSTG stable is v4.2 with v5.0 in development ([project page](https://owasp.org/www-project-web-security-testing-guide/)); the test corpus is at [wstg.owasp.org/v4.2](https://wstg.owasp.org/v4.2/).

Then draft into `../../../findings/` with: component and exact affected version range, class + CWE, privilege required, the source-to-sink chain with `file:line` against a named commit, the minimal reproduction **stated as having been run against a locally deployed instance**, honest impact with preconditions, and remediation quoting the framework's own API (`$wpdb->prepare` with unquoted `%s`/`%i`; `current_user_can()` *and* `check_admin_referer()` as two controls; a real `permission_callback`; a `sanitize_callback` on `register_setting`; context-correct `esc_attr`/`esc_url`/`wp_kses_post`; `Html::escape`/`Xss::filter` or `#plain_text` for Drupal; allow-list binding for mass assignment).

Disclose AI assistance — GitHub's private report form has a checkbox for it, and Patchstack bans untested AI-derived reports outright.

**Then stop.** Per [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md) §2, an agent does not send, file, submit, publish, or contact anyone. The human reads the finding, agrees with it, and acts.

### 8.6 Close the loop

When a fix ships: re-run the committed taint rule and the §8.4 reproduction against the patched version on your local instance. If the original chain still works — a block-list patch, a check added on one path of three — that is a follow-up on the same private thread, not a publication. Then re-run the rule across the same author's other components and start each new candidate at §1.2.

---

## 9. Not a vulnerability in this class

Report none of these on their own. Each row states what would have to be demonstrated to turn it into a finding — and "demonstrated" means §8.4, locally, not argued.

| Claim | Why it is not a finding | What would make it one |
|---|---|---|
| **Self-XSS** | The victim must paste the payload into their own browser or console. No boundary is crossed. | The payload is delivered by a URL, a stored value, or another user's action |
| **Missing security headers** (CSP, X-Frame-Options, HSTS, `X-Content-Type-Options`) | A hardening gap, not an exploit. Also usually the deployer's responsibility, not the code's. | A concrete attack the header would have blocked, demonstrated — e.g. clickjacking a specific state-changing action, or a CSP-dependent XSS sink you actually reached |
| **CSRF on a non-state-changing endpoint** | A cross-origin GET that returns data the attacker cannot read changes nothing. | The endpoint changes state, or the response is readable cross-origin via a permissive CORS policy |
| **Logout CSRF** | Nuisance, no security boundary crossed. | It is chained into a demonstrated login-CSRF or session-fixation impact |
| **Absence of rate limiting, alone** | API4 requires demonstrated resource consumption, and ROE §1 forbids proving it by load against anything you do not own. | An unbounded operation shown in source *and* a reproducible disproportionate cost on your own instance — plus honest framing that it is a design gap |
| **Admin-only issues where admin is fully trusted** | In software where an administrator can already install code, edit templates, or run SQL, an admin-reachable sink is not a privilege boundary. Drupal's Security Team says so explicitly for *Administer users / permissions / site configuration*. | A role **below** full trust reaches the sink — Contributor, Subscriber, Editor, or anonymous |
| **WordPress stored XSS by a role that already has `unfiltered_html`** | Posting HTML is that role's documented capability on a standard single-site install. | The storing role lacks `unfiltered_html` (Contributor/Subscriber), or the install is multisite where only Super Admin has it. Confirm the boundary on your own instance before claiming it |
| **Version disclosure, `readme.txt`, generator tags, directory listing with nothing sensitive** | Information, not impact. | The listing exposes credentials, backups, or private user data |
| **Error messages and stack traces in the shipped debug mode** | Enabling debug is a deployment choice; the default config is what matters. | The default shipped configuration leaks the trace, and the trace contains something that enables a demonstrated attack |
| **Username enumeration where the platform publishes authors anyway** | WordPress exposes author names through author archives and the users REST route by design. | Enumeration reveals identities the product deliberately hides, or the endpoint leaks emails or password hashes |
| **Weak password policy, no MFA, no password-history** | Product decisions, not code flaws. | An authentication bypass or a credential-reset flaw with a working chain |
| **A dependency CVE with no reachable call path** | The advisory belongs to the dependency, and the target may never call the affected function. | A traced path from a target entrypoint to the vulnerable function — then it is a supply-chain finding with its own evidence |
| **Scanner output with no manual chain** | §8.3 rule 6. | A human has read the path and can name source, sink, entrypoint, and privilege |
| **Open redirect with no demonstrated consequence** | Real but low. Severity may never exceed demonstrated impact (ROE §3.4). | A token, credential, or OAuth code is shown to reach the attacker origin |
| **Anything observed on a hosted demo, staging box, or a site found in the wild** | Not merely invalid — **prohibited**. ROE §1. | Nothing. Re-do it on an instance you deployed, or drop it |

If an item is borderline, the ROE answer applies: **when in doubt, do not report.** A missed finding costs a delay. A wrong finding costs a maintainer's trust, which does not come back.

---

## 10. Verified sources

Standards and taxonomies

- [OWASP Web Security Testing Guide — project page](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/) · [Authorization Testing chapter](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [WSTG checklists directory](https://github.com/OWASP/wstg/tree/master/checklists) · [checklist.md](https://github.com/OWASP/wstg/blob/master/checklists/checklist.md)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/) — current edition; do not cite 2021 as current
- [OWASP API Security Top 10 — 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
- [OWASP ASVS — project page](https://owasp.org/www-project-application-security-verification-standard/) · [repository (v5.0.0 artifacts)](https://github.com/OWASP/ASVS)
- [CWE Top 25](https://cwe.mitre.org/top25/index.html)
- [OWASP Cheat Sheet Series index](https://cheatsheetseries.owasp.org/) · [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

WordPress

- [Security APIs hub](https://developer.wordpress.org/apis/security/) · [Escaping Data](https://developer.wordpress.org/apis/security/escaping/) · [Sanitizing Data](https://developer.wordpress.org/apis/security/sanitizing/) · [Nonces](https://developer.wordpress.org/apis/security/nonces/)
- [Checking User Capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/)
- [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/) · [`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/)
- [REST API: Adding Custom Endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/) · [Routes and Endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/) · [Plugin Handbook: AJAX](https://developer.wordpress.org/plugins/javascript/ajax/)
- [`@wordpress/env`](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-env/) · [Plugin Check](https://wordpress.org/plugins/plugin-check/) · [WPCS](https://github.com/WordPress/WordPress-Coding-Standards)
- [Detailed Plugin Guidelines](https://developer.wordpress.org/plugins/wordpress-org/detailed-plugin-guidelines/)

Drupal and Joomla

- [Writing secure code for Drupal](https://www.drupal.org/writing-secure-code) · [develop/security index](https://www.drupal.org/docs/develop/security) · [Security advisory process and permissions policy](https://www.drupal.org/drupal-security-team/security-advisory-process-and-permissions-policy)
- [Joomla extension security (coordinated disclosure)](https://manual.joomla.org/docs/next/building-extensions/security/) · [Vulnerable Extensions List](https://extensions.joomla.org/vulnerable-extensions/about/)

Tooling

- [Semgrep: Running rules](https://docs.semgrep.dev/running-rules/) · [taint mode](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/) · [triage and remediate](https://docs.semgrep.dev/semgrep-code/triage-remediation/) · [semgrep-rules](https://github.com/semgrep/semgrep-rules) · [explore](https://semgrep.dev/explore) · [p/php](https://semgrep.dev/p/php) · [p/owasp-top-ten](https://semgrep.dev/p/owasp-top-ten)
- [CodeQL supported languages and frameworks](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) · [query suites](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/codeql-query-suites) · [preparing your code](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/preparing-your-code-for-codeql-analysis)
- [Psalm security (taint) analysis](https://psalm.dev/docs/security_analysis/)
- [Docker Compose](https://docs.docker.com/compose/) · [Compose file reference](https://docs.docker.com/reference/compose-file/)
- [ZAP Docker user guide](https://www.zaproxy.org/docs/docker/about/) · [PortSwigger Web Security Academy](https://portswigger.net/web-security)

Duplicate checking and disclosure channels (executed by the human)

- [GitHub Advisory Database](https://github.com/advisories) · [Privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
- [Patchstack database](https://patchstack.com/database/) · [Patchstack bug bounty guidelines and rules](https://patchstack.com/articles/bug-bounty-guidelines-rules/)
- [WPScan: Submit a Vulnerability](https://wpscan.com/submit/) · [WPScan Vulnerability Disclosure Policy](https://wpscan.com/vulnerability-disclosure-policy/)

Link hygiene: `owasp.org/Top10` redirects to `top10.owasp.org`, `owasp.org/API-Security/...` to `api-security.owasp.org`, and `owasp.org/www-project-web-security-testing-guide/v42` to `wstg.owasp.org/v4.2`. Cite the destination hosts. The old `developer.wordpress.org/plugins/security/{data-validation,securing-input,securing-output,nonces}/` paths have moved to `/apis/security/`; `www.drupal.org/docs/develop/security/writing-secure-code` is dead. Do not cite sandbox doc mirrors (`docs.sandbox.joomla.org`), and do not cite third-party "WSTG checklist" repos — many track the 2014 OTG-* IDs, not WSTG v4.2.
