# P4 — Open-Source Mobile Apps (Android First, iOS Second)

Execution reference for auditing open-source mobile applications: static review from the project's own source, with dynamic verification **only** on the researcher's own emulator or own device running the researcher's own build. Read this file before the first grep against a P4 target; execute §1.3 in order and do not skip ahead.

**Binding constraints live in [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md). It overrides this file.** Three of its rules decide most of what follows:

1. **An app's login screen is somebody else's server.** Sending it a request, replaying its traffic, or enumerating its endpoints is testing a third-party production system (ROE §1) — out of bounds, including "one request to confirm what the client sends". Every dynamic step in this file runs against an emulator or device the researcher owns, with a build the researcher produced.
2. **You may analyse, write candidate findings, and build local PoCs. You may not send, file, submit, publish, or contact anyone** (ROE §2). Those are human actions, including filing to a bug-bounty platform.
3. **PoC discipline (ROE §4): minimal, local, non-destructive, not packaged for distribution.** No vulnerable-app scanner, no exploit app published to a store or a gist, and — specific to this dimension — **no root-detection or anti-instrumentation evasion research** (§5.5). MASVS-RESILIENCE invites it; this repository does not do it.

Credentials found inside an APK, an IPA, or a source tree are governed by [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2: locate, classify, **never authenticate**.

---

## 1. When to read this file, and the ordered flow

### 1.1 When

Read this file when the trust boundary under test is **on the device**: Android app shipped as source, APK or AAB; iOS app shipped as source; a React Native or Flutter client; or a mobile SDK whose consumers are apps.

Route elsewhere when:

| Situation | Read instead |
|---|---|
| The bug is in the app's server API or web backend | `references/p2-web-api-cms.md` — a "mobile app" whose bug is in its API is a P2 audit |
| The target reaches consumers as a published package or dependency | `references/p1-package-ecosystems.md` first, then return here |
| The target is a build pipeline, signing service, or CI that produces the app | `references/p3-devops-infra.md` |
| You cannot place the target | Stop. State what it is and ask the researcher ([../ATTACK-CLASSES.md](../ATTACK-CLASSES.md) §1) |

### 1.2 The standard this file is anchored to

Findings in this dimension are named with three ids: a **MASVS control** (what requirement failed), a **MASWE weakness** (the class), and a **MASTG-TEST** (the procedure actually followed). Resolve all three before writing anything up (§6.1).

| Layer | What it gives you | Source |
|---|---|---|
| MASVS controls | The requirement a finding fails. Groups: `MASVS-STORAGE` (1–2), `MASVS-CRYPTO` (1–2), `MASVS-AUTH` (1–3), `MASVS-NETWORK` (1–2), `MASVS-PLATFORM` (1–3), `MASVS-CODE` (1–4), `MASVS-RESILIENCE` (1–4), `MASVS-PRIVACY` (1–4) | [MASVS](https://mas.owasp.org/MASVS/) |
| MASWE weaknesses | The weakness class, between control and test — e.g. `MASWE-0032` Insecure Intents for implicit-intent hijacking and intent redirection | [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/) |
| MASTG | Per-platform procedure. In v2 the content is split into `MASTG-KNOW-xxxx` (knowledge), `MASTG-TEST-xxxx` (tests), `MASTG-TECH-xxxx` (techniques), `MASTG-DEMO-xxxx`, `MASTG-BEST-xxxx`, `MASTG-TOOL-xxxx` | [MASTG](https://mas.owasp.org/MASTG/) |

Almost every Android IPC finding lands in [MASVS-PLATFORM](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM): PLATFORM-1 (IPC mechanisms are secure), PLATFORM-2 (WebViews do not expose sensitive data or functionality), PLATFORM-3 (no accidental on-screen exposure).

**Three currency traps. Get these wrong and the report reads as dated:**

1. **The OWASP MAS Checklist no longer exists.** It was removed in MASTG v2.0.0; `mas.owasp.org/checklists/` now redirects to the [removal notice](https://mas.owasp.org/news/2026/07/14/checklists-removal/). Search engines still index the old pages, so an agent will "find" one and get a redirect. **§6.1 of this file is the checklist.** Do not link the dead one.
2. **MASVS verification levels L1/L2/R left MASVS in v2.0.0.** They are now [MAS Testing Profiles](https://mas.owasp.org/Profiles/) (the legacy `/MASTG/0x03b-Testing-Profiles/` path redirects there).
3. **MASTG test ids were renumbered in v2.** `MASTG-TEST-0028` "Testing Deep Links" is deprecated in favour of [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/) (unverified App Links) and `MASTG-TEST-0394` (custom URL scheme input validation); `MASTG-TEST-0027` and `-0031` are superseded. Resolve any id you cite from the [MASTG repository](https://github.com/OWASP/mastg) — the rendered site is 130–155k characters of nav-heavy HTML and a fetch often returns only the sidebar, so clone it and grep `tests/`, `tests-beta/`, `knowledge/`, `techniques/`, `best-practices/` and `rules/` offline.

### 1.3 The flow

Execute in order. Each phase has an artifact and a gate; if the gate fails, stop at that phase instead of advancing.

| # | Phase | Artifact produced | Gate before advancing |
|---|---|---|---|
| 0 | Scope gate (§2.1) | Three written statements: open source, lawful copy, own-emulator-only | All three written down in the target notes. No statement, no audit. |
| 0b | Profile set (§1.4) | `MAS-L1` / `MAS-L2` (+ `MAS-R` only if the project claims anti-tampering) | Profile recorded — it decides what counts as a finding |
| 0c | Duplicate check | Prior-art list | Advisories **read**, not counted (ROE §3.5) |
| 1 | Review artifacts built (§3.1) | `src/` at a pinned SHA, `apk/`, `work/` with the manifest, apktool and jadx views | `minSdkVersion` **and** `targetSdkVersion` recorded |
| 2 | Manifest inventory (A1) | Component table, complete | Every component has a row; every `exported` cell says `true`, `false`, or `ABSENT` |
| 3 | Exported triage (A2) | Reachable-entrypoint list **and** a "reviewed, not reachable" list | Every exported row has either a written source→sink path or a stated reason it is unreachable |
| 4 | Per-class passes (A3–A13) | One candidate block per hit, with its "Disproved if" checked | No candidate advances with an unchecked "Disproved if" |
| 5 | iOS pass (§4), if applicable | Same block shape | — |
| 6 | Scanners + triage (§5.3) | SARIF/JSON output + triage log + rule provenance | Every surviving hit confirmed by hand against the §A1 inventory |
| 7 | Local verification (§5.4) | Reproduction on own AVD with own build, from clean state | Reproduced at the **lowest** precondition the claim requires |
| 8 | Mapping and severity (§6.1, §6.2) | MASVS + MASWE + MASTG-TEST + CWE + SDK range + preconditions | Ids resolved from the current sources, not from memory |
| 9 | Report draft + **human sign-off** | Draft in [../../../findings/](../../../findings/README.md) | A human has read it and agrees. Nothing is sent by an agent. |

### 1.4 Pick the profile before reading code

The [MAS Testing Profiles](https://mas.owasp.org/Profiles/) set review depth and the reporting bar. Record the choice; it is the answer to "why is missing pinning a finding here and not there".

| Profile | Applies to | Consequence for this audit |
|---|---|---|
| `MAS-L1` | A low-stakes utility — note taker, reader, offline tool | Storage and crypto gaps are findings only where a real secret is at stake. Missing pinning is **not** reportable. |
| `MAS-L2` | Anything handling money, credentials, messages, health or location data | Storage, crypto, network and auth controls are all in scope. Missing pinning is a **hardening gap** (§6.2), still never "TLS broken". |
| `MAS-R` | Add **only** if the project itself claims anti-tampering or obfuscation as a feature | Even then: this repository does not do evasion research (§5.5). Limit to observing that a claimed control is absent. |

---

## 2. Scope: an open-source source audit, not a reversing exercise

### 2.1 The three statements (phase 0)

Write these at the top of the target notes before opening a single file. If any one cannot be written honestly, **stop and ask the human.**

1. **The project is open source and the researcher holds a legitimate copy** — their own clone at a pinned commit, their own build, or an APK/IPA they may lawfully analyse.
2. **All dynamic work will run on the researcher's own emulator or own device, with the researcher's own build.** Never a third party's device, never the project's production backend, never an account other than the researcher's own test account.
3. **The profile is recorded** (§1.4).

### 2.2 Source beats binary, always

1. **Review `src/` as the primary evidence.** The whole point of this dimension being open source is that root cause is available as `file:line` in the upstream tree, which is exactly what the anti-slop gate requires (ROE §3.2). A finding traced in decompiled Java and never matched to upstream source is a candidate, not a finding.
2. **Decompile only to answer a question the source cannot** — what the shipped manifest actually declares after manifest merging, what a release build's `BuildConfig` contains, whether a dependency was shaded in, whether the release is v1-signed.
3. **jadx cannot decompile everything** — its own README says so. When the Java output looks wrong, incomplete, or too convenient, confirm against the apktool smali and against the upstream source before writing a word.
4. **A shipped artifact must be one the researcher may lawfully analyse.** If the only artifact available is a published binary of software that is not open source, this is not the playbook for it — that is a different scope question and goes to the human.

### 2.3 Decompiled output is never committed

[../../../.gitignore](../../../.gitignore) carries a P4 block — `*.apk`, `*.aab`, `*.ipa`, `*.dex`, `unpacked/`, `jadx-out/`, `apktool-out/` — plus `work/`, `clones/`, `sandbox/`, `*.sarif` and the `evidence/` tree. That is a **second** line of defence. The primary rule is [../SKILL.md](../SKILL.md) §3.4: build the lab **outside this repository** and never vendor a target into it. Do not `git add -f` a decompiled tree "just to show the diff".

### 2.4 Out of scope for this dimension

Not grey areas. Do none of these, and do not write them up:

| Excluded | Why |
|---|---|
| Mass scanning of apps or app stores | Picking targets by volume is not research; it is the behaviour the anti-slop gate exists to stop |
| Weaponization or packaging of a PoC | ROE §4. A crash, a log line, or a screenshot of the leaked value is the deliverable |
| Root-detection, emulator-detection or anti-instrumentation evasion | §5.5. If the app blocks instrumentation, fall back to source review and say so in the notes |
| Picking targets by popularity to farm CVE volume | Produces noise and burns maintainer trust ([../SKILL.md](../SKILL.md) §5) |
| Fetching `/.well-known/assetlinks.json` for any domain other than one the audited project itself publishes | Everything else is probing a host you do not own (ROE §1) |
| Testing a credential found in the app | [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2. Tell the maintainer to rotate it; never use it |

---

## 3. Android static review

Work A1 → A13 in order. A1 and A2 are not optional preliminaries: **an unmapped component is an unreviewed one**, and the inventory is what makes every later scanner hit triageable.

| # | Pass | Primary MASVS group |
|---|---|---|
| A1 | Manifest inventory (§3.2) | — (input to everything) |
| A2 | Exported-component triage | MASVS-PLATFORM-1 |
| A3 | Deep links and App Links verification | MASVS-PLATFORM-1 |
| A4 | Intent redirection | MASVS-PLATFORM-1 |
| A5 | Implicit intent leakage | MASVS-PLATFORM-1 / PRIVACY |
| A6 | PendingIntent mutability and broadcasts | MASVS-PLATFORM-1 |
| A7 | ContentProviders | MASVS-PLATFORM-1 / STORAGE |
| A8 | WebView configuration | MASVS-PLATFORM-2 |
| A9 | Local storage, logs, clipboard | MASVS-STORAGE-1/2, PRIVACY |
| A10 | Cleartext, network security config, pinning | MASVS-NETWORK-1/2 |
| A11 | Hardcoded secrets and keys | MASVS-STORAGE-1 / CRYPTO |
| A12 | Cryptographic misuse | MASVS-CRYPTO-1/2 |
| A13 | Build and signing hygiene | MASVS-CODE-1/2, RESILIENCE |

Each block below gives **Grep**, **Trace**, **Disproved if** (check this *before* writing anything up), and **Evidence**. Write the chain as `source (file:line) -> transforms -> sink (file:line) -> preconditions -> impact`. A chain that is not written down is a hypothesis.

### 3.1 Build the three views first

Build the lab outside this repository. Record `git rev-parse HEAD` for `src/`.

```bash
# (a) the manifest in plain XML, without unpacking anything
apkanalyzer manifest print   app.apk > work/manifest.xml
apkanalyzer manifest permissions app.apk
apkanalyzer manifest debuggable  app.apk
apkanalyzer manifest min-sdk     app.apk
apkanalyzer manifest target-sdk  app.apk

# (b) ground truth: decoded resources and smali
apktool d app.apk -o work/apktool

# (c) readable Java for tracing
jadx -d work/jadx app.apk
```

**Record `minSdkVersion` and `targetSdkVersion` now, in the notes, before any grep.** Nearly every Android platform default a finding depends on — `exported`, cleartext permitted, PendingIntent mutability, WebView file access, `RECEIVER_NOT_EXPORTED` — is keyed to one of them. A finding that is wrong about the target SDK is a wrong finding, and `apkanalyzer manifest target-sdk` settles it in one command ([apkanalyzer](https://developer.android.com/tools/apkanalyzer)).

Do not run build tools or interpreters from inside a downloaded or extracted directory; pass paths as arguments.

### 3.2 A1 — Manifest inventory (the mandatory first artifact)

Read `work/manifest.xml` top to bottom before any other file. Emit one row per component:

| Field | Content |
|---|---|
| id | `C-01`, stable for the rest of the audit |
| name | Fully qualified class name |
| type | activity / activity-alias / service / receiver / provider |
| exported | `true` / `false` / **`ABSENT`** — record which, never normalise |
| permission | `android:permission`, **plus its `protectionLevel`** from the defining `<permission>` element |
| intent filters | action / category / data (scheme, host, port, path, pathPrefix, pathPattern), and `android:autoVerify` |
| provider extras | `android:authorities`, `readPermission`, `writePermission`, `grantUriPermissions`, every `<path-permission>` |

In the same pass record the application block: `android:debuggable`, `android:allowBackup`, `android:usesCleartextTraffic`, `android:networkSecurityConfig`, `android:dataExtractionRules`, and every `<permission>` the app defines with its `protectionLevel`.

**Mark ABSENT-and-suspicious:**

1. A component **with** intent filters and **no** explicit `android:exported`. On `targetSdk` 31+ such an app cannot install, so an absent value tells you the target is old — record the target SDK next to it.
2. A custom `<permission>` with `protectionLevel="normal"` or `"dangerous"` guarding an internal interface. `normal` is granted on request; `dangerous` is one user tap. Neither is a trust boundary between apps. Only `signature` is.
3. **A provider with no permissions at all.** Google's own guide states providers are open by default: "all applications can read from or write to your provider … because by default your provider doesn't have permissions set" ([Create a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating)).

**Completion test — all four before advancing:** every `<activity>`, `<activity-alias>`, `<service>`, `<receiver>` and `<provider>` has a row; every custom permission's `protectionLevel` is resolved; the application-flags block is filled; `minSdk`/`targetSdk` are recorded.

### 3.3 A2 — Triage exported components into reachable entrypoints

For every row where `exported` is `true`, or is absent while intent filters are present, open the class in jadx and answer one question: **what attacker-controlled data reaches what sink?**

- **Grep (taint sources):**

```bash
rg -n "getIntent\(\)|getIntent\(\)\.getData\(\)" work/jadx
rg -n "get(String|Int|Boolean|Parcelable|ParcelableArrayList|Serializable|Bundle|Extras)Extra\(" work/jadx
rg -n "onStartCommand|onBind|onReceive|onNewIntent|onCreate\(Bundle" work/jadx
rg -n "public (Cursor query|Uri insert|int (update|delete)|ParcelFileDescriptor openFile|Bundle call)" work/jadx
```

- **Trace:** source → transforms → sink, with `file:line` at both ends. For providers the sources are the `Uri` and the `selection` / `selectionArgs` / `sortOrder` arguments.
- **Disproved if:** the component requires a **signature**-level permission — then it is not reachable cross-app and belongs in the "reviewed, not reachable" list, not the findings list. Also disproved if the component is exported but every path drops the input before any sink, or if the only reachable effect is already available to any app by design (a share target that opens a viewer).
- **Pre-empt two maintainer rebuttals** from Google's own text ([Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection)): `getCallingActivity()` being non-null does **not** prove the caller is trusted, and `checkCallingPermission()` **returns an int rather than throwing** — so "we check the permission" code that ignores the return value is not checking anything.
- **Evidence:** the component row id, the source→sink path, and the minimum precondition (does a second app have to be installed? does the user have to tap?).

**Write the "reviewed, not reachable" list explicitly.** It is how a maintainer sees that the audit was complete rather than lucky, and it is the artifact that stops the same component being re-reported later.

A note to keep in the back pocket for the pushback "the intent filter is the boundary": [Intents and intent filters](https://developer.android.com/guide/components/intents-filters) states another app can still start a component with an **explicit** intent if it knows the name. `android:exported="false"` is the control; the filter is not. The same page carries the API 31+ rule that a filtered component without an explicit `android:exported` cannot install, and that `bindService()` with an implicit intent has thrown since API 21.

### 3.4 A3 — Deep links and App Links

- **Grep:** pull from the A1 inventory every filter with `action.VIEW` + `category.BROWSABLE`, then:

```bash
rg -n "autoVerify|android:scheme|android:host|android:pathPrefix|android:pathPattern" work/apktool/AndroidManifest.xml
rg -n "getData\(\)|getQueryParameter|getLastPathSegment|getPathSegments|Uri\.parse" work/jadx
```

- **Trace:** three sub-checks, then the handler.
  1. **`http`/`https` scheme without `android:autoVerify="true"`** → unverified App Link ([MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/)). Impact to state: any other installed app may declare the same host and be offered as a handler.
  2. **Custom scheme (`myapp://`)** → unverifiable by design; any app can claim it. The finding is about **what the handler does with the data**, not the scheme's existence.
  3. **Each declared host** → does `https://<host>/.well-known/assetlinks.json` exist and name the app's package and signing cert? Fetch this **only** for a domain the audited project itself publishes (§2.4).
  4. Then trace scheme/host/path/query into sinks: a `WebView` load, a file path, a SQL selection, a nested `Intent`, an auth token, a redirect. **The classic high-impact chain is deep link → unvalidated `url` parameter → `WebView.loadUrl`** (chain this with A8).
- **Enumerate reproducibly** with [MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/) — manifest inspection, cross-check with `dumpsys`, then a verification test — and confirm state on your own device with the sequence in [verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks):

```bash
adb shell pm set-app-links --package <PKG> 0 all
adb shell pm verify-app-links --re-verify <PKG>
adb shell pm get-app-links <PKG>     # states: verified / approved / none / denied / legacy_failure
```

- **Disproved if:** `autoVerify="true"` is present **and** the `assetlinks.json` the project publishes names this package and cert; or the handler treats the link as untrusted input and validates it against a server-side allow-list before any sink; or the deep link reaches only a read-only view of already-public content.
- **Evidence:** the manifest filter with line number, the handler at `file:line`, the `pm get-app-links` state before and after re-verification, and the single `am start` that reaches the sink. Real impact worth quoting from the same Google page: on Android 11 and lower **one** bad host breaks the whole verification set, and only one app can hold a domain.

### 3.5 A4 — Intent redirection

- **Grep:**

```bash
rg -n "getParcelableExtra\(.*Intent\.class|getParcelableExtra\(.*\"(intent|extra_intent)\"" work/jadx
rg -n "Intent\.parseUri|Intent\.getIntent\(|getBundleExtra" work/jadx
rg -n "startActivity(ForResult)?\(|startService\(|bindService\(|sendBroadcast\(" work/jadx
rg -n "FLAG_GRANT_(READ|WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION|IntentSanitizer" work/jadx
```

The pattern is an inner `Intent` recovered from extras (or parsed from a string) and then launched. In an **exported** component that is a confused deputy: the attacker supplies the inner intent and the app launches it **with its own identity**, reaching the app's own non-exported components.

- **Trace:** exported entrypoint → `getParcelableExtra`/`parseUri` → `startActivity`/`startService`/`sendBroadcast`, naming the non-exported component or provider the redirect can now reach.
- **Disproved if:** the code validates the resolved `ComponentName`'s **package AND class** (package alone is not enough); or it uses `androidx` `IntentSanitizer`; or it strips `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` and `FLAG_GRANT_PREFIX_URI_PERMISSION`; or the component is signature-permission-guarded (A2); or the redirect target set is a fixed internal allow-list.
- **Severity modifier you must record:** Android 16 applies a default launch-security protection, and an app can opt out with `removeLaunchSecurityProtection()`; API 31+ raises a StrictMode violation that detects the pattern. Note the `minSdk`/`targetSdk` range in which the finding actually bites. Unchecked grant flags turn a redirection into **provider data theft** — say so only if you demonstrated it.
- **Evidence:** both ends at `file:line`, the SDK range, the local `am start` with the nested intent, and the observed effect (the private activity started, the private file read). Cite [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection) in remediation.

### 3.6 A5 — Implicit intent leakage of sensitive data

The mirror image of A4: data going out rather than in.

- **Grep:**

```bash
rg -n "new Intent\(" -A6 work/jadx | rg -n "putExtra" 
rg -n "sendBroadcast\(|sendOrderedBroadcast\(|startActivity\(" work/jadx
rg -n "setPackage\(|setComponent\(|setClassName\(|createChooser\(" work/jadx
```

- **Trace:** a sensitive value (token, session cookie, PII, file URI, location) into `putExtra`, on an intent with **no** `setPackage`, `setComponent` or `setClassName`. Any installed app with a matching filter receives it.
- **Disproved if:** the intent is explicit (`setPackage`/`setComponent`/`setClassName`); or it goes through `Intent.createChooser()` and the payload is what the user chose to share; or the extras carry nothing sensitive; or a `receiverPermission` is supplied on the broadcast.
- **Evidence:** the construction site at `file:line`, the sensitive field name, and a minimal local receiver app in the lab that logs the extra it received. Remediation references: `Intent.createChooser()` for sensitive implicit intents, per [Android app security best practices](https://developer.android.com/privacy-and-security/security-best-practices), and the matching article in the [risks catalog](https://developer.android.com/privacy-and-security/risks) (`/implicit-intent-hijacking`).

### 3.7 A6 — PendingIntent mutability, and exported components that leak via broadcast

- **Grep:**

```bash
rg -n "PendingIntent\.get(Activity|Broadcast|Service|ForegroundService)\(" work/jadx
rg -n "FLAG_MUTABLE|FLAG_IMMUTABLE|FLAG_UPDATE_CURRENT" work/jadx
rg -n "registerReceiver\(|RECEIVER_NOT_EXPORTED|RECEIVER_EXPORTED" work/jadx
rg -n "sendStickyBroadcast|sendBroadcast\(.*,\s*\"" work/jadx
```

- **Trace (PendingIntent):** flag any `PendingIntent` whose wrapped `Intent` is **implicit** (no component, no package) and which is created with `FLAG_MUTABLE`, or — on `targetSdk` below 31 — with neither `FLAG_IMMUTABLE` nor `FLAG_MUTABLE`. The receiver can fill in the blanks with `Intent.fillIn()` and have it executed **with the sending app's identity and permissions**. Check the inverse too: code that trusts an incoming `PendingIntent`'s creator.
- **Trace (broadcasts):** `registerReceiver()` without `RECEIVER_NOT_EXPORTED` on API 33+; manifest receivers exported with no permission; `sendBroadcast` carrying sensitive extras with no `receiverPermission`; sticky broadcasts, which **cannot be access-controlled at all**.
- **Disproved if:** the wrapped intent is explicit (then mutability cannot be abused into an arbitrary launch); `FLAG_IMMUTABLE` is set; the `PendingIntent` never leaves the app; the receiver is registered `RECEIVER_NOT_EXPORTED`; the broadcast extras carry nothing sensitive; the receiver requires a signature-level permission.
- **Evidence:** the creation site at `file:line`, the wrapped intent's emptiness, the `targetSdk`, and a local demonstration of the filled-in intent executing. Remediation: the `/pending-intent`, `/sender-of-pending-intents`, `/insecure-broadcast-receiver` and `/sticky-broadcast` articles in the [risks catalog](https://developer.android.com/privacy-and-security/risks).

### 3.8 A7 — ContentProviders

For every provider in the A1 inventory that is exported or lacks permissions, read `query` / `insert` / `update` / `delete` / `openFile` / `call`.

- **Grep:**

```bash
rg -n "openFile|openAssetFile|ParcelFileDescriptor\.open|new File\(" work/jadx
rg -n "getCanonicalPath|getCanonicalFile|startsWith\(" work/jadx
rg -n "rawQuery\(|execSQL\(|SQLiteQueryBuilder|selection\s*\+|getLastPathSegment\(\)" work/jadx
rg -n "UriMatcher|addURI\(" work/jadx
rg -n "grantUriPermissions|FileProvider|xml/.*paths" work/apktool
```

- **Trace, five checks:**
  1. **`openFile`/`openAssetFile` building a `File` from a Uri path segment** without `getCanonicalPath()` plus a prefix check → path traversal. The attacker reads or overwrites app-private files through a public authority. The mitigation text to quote is [Path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal): canonicalise, then prefix-check — **and the prefix needs a trailing separator**, or a sibling directory (`/data/files2` vs `/data/files`) defeats it.
  2. **`query()` concatenating a Uri segment or a caller-supplied string into `selection` or `sortOrder`** → SQL injection into the app's own database. Note that Google's own provider guide ships a `query()` sample doing exactly this (`selection + "_ID = " + uri.getLastPathSegment()`), so the pattern is common in real code and **first-party docs are not automatically safe reference code** ([Create a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating)).
  3. **A `UriMatcher` whose default branch falls through** instead of throwing.
  4. **`grantUriPermissions="true"` at provider scope** — that grants temporary access to the whole provider rather than a path. Check the `<grant-uri-permission>` and `<path-permission>` precedence rules on the same page.
  5. **`FileProvider` `<paths>` whose root is external storage** or a directory wider than intended.
- **Always cross-check** whether the same data is also reachable on **external storage**, where provider permissions do not apply at all.
- **Disproved if:** `readPermission`/`writePermission` are signature-level; the path is canonicalised and prefix-checked with a trailing separator; the selection is bound through `selectionArgs`; the authority is not exported and no `grantUriPermissions` is set; the files served are already public content.
- **Evidence:** the sink at `file:line`, the authority from the manifest, and one local command proving reachability:

```bash
adb shell content query --uri content://<authority>/<path>
adb shell content read  --uri content://<authority>/../../databases/app.db > /dev/null
```

Prove the traversal resolves; **do not exfiltrate a database.** One error, one file descriptor, or one path echoed back is the finding.

### 3.9 A8 — WebView configuration

- **Grep:**

```bash
rg -n "new WebView|WebSettings|getSettings\(\)" work/jadx
rg -n "setJavaScriptEnabled|addJavascriptInterface|@JavascriptInterface" work/jadx
rg -n "setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowContentAccess" work/jadx
rg -n "setMixedContentMode|setDomStorageEnabled|setSavePassword" work/jadx
rg -n "loadUrl\(|loadDataWithBaseURL\(|shouldOverrideUrlLoading|shouldInterceptRequest|onReceivedSslError" work/jadx
```

- **Build a per-WebView matrix** (one row per WebView construction site) across those settings plus the source of the loaded URL. **The reportable combinations:**

| Combination | Finding class | What to trace |
|---|---|---|
| `javaScriptEnabled` **AND** `addJavascriptInterface` reachable from content the app does not control | Exposed native bridge | Follow each bridge method into native capability — file read, token return, intent launch. A bridge that returns a session token is the impact, not the annotation |
| `javaScriptEnabled` **AND** file access (`setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs`) **AND** an attacker-influenced `file://` or `content://` URL | Local file theft / cross-app scripting | The URL's origin, and what the page can then read |
| `loadUrl` / `loadDataWithBaseURL` fed from an intent extra, a deep-link parameter, or a server response with no allow-list | Unsafe URI loading | **Check BOTH scheme and host** — checking only the host is the common bug |
| `onReceivedSslError` calling `proceed()` | TLS bypass in the WebView | Whether the WebView loads anything over the network at all |

- **Disproved if:** JavaScript is disabled (it is **off by default**; it is turned on by `settings.javaScriptEnabled`); the bridge is only reachable from an asset bundled in the APK and the WebView cannot navigate away (`shouldOverrideUrlLoading` blocks off-origin navigation); the loaded URL comes from a compile-time constant; file access flags are default-off for the declared `minSdk`; the bridge methods expose nothing but presentational data.
- **State the SDK range.** WebView defaults depend on `minSdkVersion`; a finding that bites only below API 16 needs to say so.
- **Evidence:** the construction site and every setter at `file:line`, the URL source, and a local page in the lab that calls the bridge method and shows what it returns. Remediation citations: [Build web apps in WebView](https://developer.android.com/develop/ui/views/layout/webapps/webview) — `addJavascriptInterface` "lets JavaScript control your Android app" and "can also be a dangerous security issue", the `targetSdk` 17+ `@JavascriptInterface` annotation rule — and [security best practices](https://developer.android.com/privacy-and-security/security-best-practices), which says not to enable a JavaScript interface unless you control the content and points to `createWebMessageChannel()` as the API 23+ replacement. The matching risk articles are `/insecure-webview-native-bridges`, `/unsafe-uri-loading`, `/webview-unsafe-file-inclusion` and `/cross-app-scripting`.

### 3.10 A9 — Local storage, logs and clipboard

- **Grep:**

```bash
rg -n "getSharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|openFileOutput" work/jadx src
rg -n "getExternalFilesDir|getExternalStorageDirectory|getExternalCacheDir|MediaStore" work/jadx src
rg -n "SQLiteOpenHelper|Room|RoomDatabase|Realm" work/jadx src
rg -n "android\.util\.Log|Log\.(v|d|i|w|e)\(|printStackTrace\(" work/jadx src
rg -n "ClipboardManager|setPrimaryClip" work/jadx src
rg -n "allowBackup|dataExtractionRules|fullBackupContent" work/apktool/AndroidManifest.xml
```

- **Flag:** credentials, tokens, session cookies, PII or crypto keys written to `SharedPreferences` or an unencrypted SQLite database in an app whose profile is `MAS-L2`; anything sensitive on **external storage** (no enforced access control, and on API 29 and below the external cache is readable by apps holding `WRITE_EXTERNAL_STORAGE`); sensitive values passed to `Log` at **any** level, since logs are collectible on-device; `allowBackup="true"` with no rules excluding the secret stores; secrets copied to the clipboard.
- **Disproved if:** the value is stored in `MODE_PRIVATE` internal storage **and** the profile is `MAS-L1` **and** the value is not a credential; the key is Keystore-backed and the stored blob is ciphertext; the log call is behind a `BuildConfig.DEBUG` guard that is actually false in release (check the release build, not the source constant); backup rules exclude the file; the clipboard write is the user's own explicit copy action.
- **Evidence:** the write site at `file:line`, and the artefact on your own emulator — `adb shell run-as <pkg> cat shared_prefs/<file>.xml` with the secret **redacted**, or a `logcat` excerpt. Redact every real-looking value, including your own test token.

### 3.11 A10 — Cleartext traffic, network security config, pinning

Read `res/xml/network_security_config.xml` **together with** the manifest attributes; neither alone tells you the answer.

- **Grep:**

```bash
rg -n "usesCleartextTraffic|networkSecurityConfig" work/apktool/AndroidManifest.xml
rg -n "cleartextTrafficPermitted|trust-anchors|certificates src=|pin-set|expiration|debug-overrides" work/apktool/res/xml
rg -n "X509TrustManager|checkServerTrusted|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier" work/jadx src
rg -n "onReceivedSslError|SSLSocketFactory|CertificatePinner|setSSLSocketFactory" work/jadx src
rg -n "\"http://" work/jadx src
```

- **Flag, per [Network security configuration](https://developer.android.com/privacy-and-security/security-config):** `cleartextTrafficPermitted="true"` in `base-config` or `android:usesCleartextTraffic="true"`; a `domain-config` that re-permits cleartext for a production host; `trust-anchors` including `src="user"` **outside** `debug-overrides`; a `pin-set` whose `expiration` has passed or is near — after it, **pinning silently stops**, which is an attacker-usable window. Remember the precedence rule (longest matching domain wins), that `cleartextTrafficPermitted` defaults to **false** for `targetSdk` 28+, and that `debug-overrides` is ignored in non-debuggable builds.
- **In code, flag:** a custom `X509TrustManager` with an empty `checkServerTrusted`, a `HostnameVerifier` returning `true`, `ALLOW_ALL_HOSTNAME_VERIFIER`, and `onReceivedSslError` → `proceed()`.
- **Disproved if:** cleartext is permitted only for a loopback or `.local` development host in a `debug-overrides` block; the trust-manager override is inside a `debug`-only source set that is not in the release APK (confirm against the release artifact, not the source tree); the "cleartext" URL is a non-network identifier (an XML namespace, a schema URL, a documentation link).
- **Severity discipline — this is where mobile reports most often inflate.** **Missing certificate pinning is a hardening recommendation, not a vulnerability, for most apps.** Report it as `MASVS-NETWORK-2 not met for a high-assurance profile` at `MAS-L2`, in the hardening-gap bucket (§6.2). It is never "TLS broken". A disabled trust manager or a hostname verifier that always returns true **is** a vulnerability, because TLS verification actually fails.
- **Evidence:** the config file and line, or the override at `file:line`, the profile, and — if dynamic — the request observed in **your own lab**, on your own emulator, against a server you control. Never the project's production backend.

### 3.12 A11 — Hardcoded secrets and keys

- **Grep, then tools:**

```bash
rg -n "(?i)(api[_-]?key|secret|passwd|password|token|bearer|private[_-]?key|client[_-]?secret)" src work/jadx
rg -n "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" src work/jadx work/apktool
rg -n "" work/apktool/res/values/strings.xml | rg -n "(?i)key|token|secret"
rg -n "BuildConfig\.[A-Z_]+" work/jadx
# then: gitleaks over src/, apkleaks over the APK, mobsfscan over src/
```

Cover `src/`, `res/values/strings.xml`, `BuildConfig`, `gradle.properties`, `assets/`, and native libraries.

- **Before reporting one, run all four checks:**
  1. **Is it actually a secret?** Firebase config values, Google Maps keys, Stripe *publishable* keys, Sentry DSNs and OAuth *client ids* ship publicly by design. Reporting one is how a researcher becomes known as a scanner forwarder ([../SKILL.md](../SKILL.md) §5).
  2. **Is it a test fixture?** A dummy value under `test/`, `androidTest/`, `src/test/`, `fixtures/` or `sample/` is not a vulnerability. Check the path before the value.
  3. **Is it reachable from shipped code?** A constant in a dead branch is a code-quality note.
  4. **Was it ever live?** `git log --all -S'<fragment>' --oneline` in `src/`. Removal from `HEAD` does not revoke anything, and maintainers routinely believe it does — telling them that is often the most valuable line in the report.
- **Disproved if:** any of checks 1–3 fails.
- **The hard rule: never authenticate with it.** [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2 — not to confirm the finding, not "just a read-only call", not "only to check if it's still valid". Authenticating with a credential you found is unauthorized access regardless of how it was found. Locate it (`file:line` + commit SHA), classify it by prefix shape, assess reachability, check history — then **tell the maintainer to rotate it**, urgently and out of the normal 90-day cadence, and **do not put the credential itself in the report** (reference it by location, truncated prefix and hash).
- **Note for routing:** the [Google Mobile VRP rules](https://bughunters.google.com/about/rules/6618732618186752/google-mobile-vulnerability-reward-program-rules) explicitly exclude hardcoded API keys. If the app is in that program's scope, read the live rules before spending time on this class.

### 3.13 A12 — Cryptographic misuse

- **Grep:**

```bash
rg -n "Cipher\.getInstance\(" work/jadx src
rg -n "\"AES\"|ECB|DES|DESede|RC4|Blowfish|RC2" work/jadx src
rg -n "IvParameterSpec|GCMParameterSpec|new byte\[\s*16\s*\]" work/jadx src
rg -n "MessageDigest\.getInstance\(\"(MD5|SHA-?1)\"" work/jadx src
rg -n "PBEKeySpec|SecretKeyFactory|iterationCount|getBytes\(\)" work/jadx src
rg -n "new Random\(|SecureRandom\(.+\)|setSeed\(" work/jadx src
rg -n "OAEPPadding|OAEPParameterSpec|getInstance\(\"RSA" work/jadx src
rg -n "KeyStore\.getInstance\(\"AndroidKeyStore\"\)|KeyGenParameterSpec|security-crypto" work/jadx src
```

- **Flag, against [Android cryptography](https://developer.android.com/privacy-and-security/cryptography):** `Cipher.getInstance("AES")` alone (resolves to ECB) or an explicit `ECB`; DES/3DES/RC4/Blowfish; CBC with no MAC and no authenticated mode; a hardcoded or all-zero IV, or an IV derived from the key — **a missing IV is treated as all-zero**; `MD5`/`SHA-1` for a security purpose; PBE with a static salt or a low iteration count; `new Random()` or a seeded `SecureRandom` where unpredictability matters; `RSA/ECB/OAEPPadding` **without** an explicit `OAEPParameterSpec` (Keystore then uses SHA-1 for MGF1); the deprecated Bouncy Castle `"BC"` provider; the `"Crypto"` provider, removed in API 28.
- **Disproved if:** the primitive is not protecting anything (a hash used as a cache key or an ETag is not a crypto finding); the key is single-use and random per message; the mode is GCM or CBC-with-HMAC; the "weak" call is in a vendored library's test code; the data encrypted is already public.
- **Remediation to quote:** AES-256 in GCM or CBC, SHA-2 digests, `HMACSHA256`, `SHA256withECDSA`, and **Keystore-backed keys**. Do **not** recommend `androidx.security:security-crypto` — it is deprecated as of 1.1.0.
- **Evidence:** the `Cipher.getInstance` string at `file:line`, what the key protects, and the demonstrated consequence. "ECB mode" with no statement of what is encrypted and who can read it is an informational finding, not a vulnerability.

### 3.14 A13 — Build and signing hygiene

- **Grep / commands:**

```bash
apkanalyzer manifest debuggable app.apk
apksigner verify --verbose --print-certs app.apk      # which signature schemes are present
rg -n "DexClassLoader|PathClassLoader|BaseDexClassLoader|loadLibrary|System\.load\(" work/jadx
rg -n "(?i)staging|\.test\.|debug.*endpoint|10\.0\.2\.2|localhost" work/jadx
```

- **Flag:** `android:debuggable="true"` in a **release** manifest; test or debug endpoints and feature flags compiled into release; dynamic code loading (`DexClassLoader`, a dex loaded from external storage or the network); and **v1-only (JAR) signing**.
- **The v1-signing finding, stated without building anything:** per [AOSP application signing](https://source.android.com/docs/security/features/apksigning), v1 (JAR) signing "doesn't protect some parts of the APK, such as ZIP metadata" and forces the verifier to process large amounts of unverified data, whereas v2+ (Android 7.0+) treats the APK as a blob so any change outside the signing block invalidates it, and v3 (Android 9) extends v2. A v1-only release is reportable as a signing-integrity weakness **cited to that page**. Do not construct a tampered APK; there is no need, and a tampered APK is a weaponized artifact (ROE §4).
- **Disproved if:** `debuggable` is true only in the debug variant and absent from the release manifest in the shipped artifact; the dynamically loaded code is bundled in the APK and integrity-checked; the "staging" string is a build-time constant swapped by the release flavour; `apksigner` reports v2 or v3 present.
- **Evidence:** the `apkanalyzer manifest debuggable` / `apksigner verify` output verbatim, the released version it came from, and the download source of the artifact.

---

## 4. iOS static review (second pass, same structure)

Same block shape: Grep, Trace, Disproved if, Evidence. Keep this second to Android unless the project is iOS-only.

**Honesty note that governs this whole section:** Apple's documentation pages are JavaScript-rendered, so the sources below were verified by page identity, not by reading their bodies. **Resolve every key name, constant and accessibility-value list against the live Apple page before writing it into a report.** Third-party pages get these wrong — for example `NSAllowsArbitraryLoadsInMedia` instead of Apple's `NSAllowsArbitraryLoadsForMedia`. For MASTG-side detail, read the iOS tests and knowledge articles out of the cloned [MASTG repository](https://github.com/OWASP/mastg) rather than the rendered site.

### 4.1 I1 — `Info.plist`: usage descriptions and App Transport Security

- **Grep:** `rg -n "NS.*UsageDescription|NSAppTransportSecurity|NSExceptionDomains" --glob '*.plist' src`
- **Trace, two parts:**
  1. **Usage descriptions.** List every `NS*UsageDescription` the app declares and match each to a real feature. An unused `NSCameraUsageDescription` or `NSLocationAlwaysUsageDescription` is an over-permission finding (`MASVS-PRIVACY`).
  2. **ATS.** `NSAllowsArbitraryLoads = true` is a blanket ATS kill. `NSAllowsArbitraryLoadsInWebContent` disables ATS for web-view content and is **easy to miss if you only check the top-level flag** — check it explicitly. Every `NSExceptionDomains` entry needs its `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion` and `NSExceptionRequiresForwardSecrecy` values justified against a named host.
- **Disproved if:** the exception is scoped to a loopback or a documented local development host; the key is present in a debug-only plist not shipped in the release; the usage description backs a feature you can point to in source.
- **Cite:** [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) for the "fix the server, do not add the exception" framing, and [NSAppTransportSecurity](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) for the authoritative key list.

### 4.2 I2 — Custom URL schemes

- **Grep:**

```bash
rg -n "CFBundleURLTypes|CFBundleURLSchemes" --glob '*.plist' src
rg -n "application\(_:open:options:\)|open url|scene\(_:openURLContexts:\)|onOpenURL|LSApplicationQueriesSchemes" src
rg -n "URLComponents|queryItems|host ==|path ==|absoluteString" src
```

- **Trace:** for each registered scheme, read the handler — `application(_:open:options:)`, `scene(_:openURLContexts:)`, SwiftUI `.onOpenURL` — and trace scheme/host/path/query to sinks exactly as in A3. **Custom schemes are claimable by any app**, so authentication, token exchange, or any state-changing action behind one is reportable. Apple's own page says to validate parameters and reject malformed links, and prefers universal links.
- **Disproved if:** the handler validates against a server-side allow-list and performs no state change without a separate authenticated call; the scheme reaches only a read-only view; the action requires a secret the caller does not have.
- **Cite:** [Defining a custom URL scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app) and [MASTG-KNOW-0079](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/) (which also tells you where registration lives in the Xcode target's Info pane — i.e. what to look for in a source checkout).

### 4.3 I3 — Keychain accessibility attributes

- **Grep:** `rg -n "SecItemAdd|SecItemUpdate|SecItemCopyMatching|kSecAttrAccessible" src`
- **Trace:** for every `SecItemAdd` / `SecItemUpdate`, compare the `kSecAttrAccessible` value against the item's sensitivity, and decide whether a `…ThisDeviceOnly` variant is needed to keep the item out of backups and iCloud sync. **A missing attribute means the platform default** — record which default applies rather than assuming.
- **Disproved if:** the accessibility class matches the item's sensitivity; the item is not a secret; the value is additionally encrypted with a key that is itself protected.
- **Cite:** [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility), and read its live "Accessibility Values" topic for the current constant list rather than trusting a remembered one.

### 4.4 I4 — Pasteboard leakage

- **Grep:** `rg -n "UIPasteboard\.general|setItems|localOnly|expirationDate" src`
- **Trace:** writes of tokens, passwords, recovery phrases or PII to `UIPasteboard.general` with **neither** `localOnly` **nor** an `expirationDate`. The general pasteboard is system-wide and persists until replaced.
- **Disproved if:** the write is the user's own explicit copy action on data they typed; `localOnly` or an `expirationDate` is set; the value is not sensitive.
- **Cite:** [UIPasteboard](https://developer.apple.com/documentation/uikit/uipasteboard).

### 4.5 I5 — Local data protection classes

- **Grep:** `rg -n "FileManager|\.protectionKey|NSFileProtection|write\(to:|Data\(contentsOf:" src`
- **Trace:** files holding sensitive data written with **no** explicit protection class, or with `none`, where the profile demands Complete or Complete Unless Open. The class vocabulary is Complete / Complete Unless Open / Complete Until First User Authentication / None.
- **Disproved if:** the file holds no sensitive data; the class is set at the container level and inherited; the content is already encrypted at the application layer.
- **Cite:** [Encrypting your app's files](https://developer.apple.com/documentation/uikit/encrypting-your-app-s-files).

### 4.6 I6 — The code sweep

```bash
rg -n "NSLog\(|print\(" src                               # sensitive values in logs
rg -n "UserDefaults\.standard\.set|NSUserDefaults" src     # UserDefaults as a secret store
rg -n "urlSession\(_:didReceive:|SecTrustEvaluate|serverTrust|\.useCredential" src   # trust overrides
rg -n "CCCrypt|kCCOptionECBMode|CCCryptorCreate" src       # CommonCrypto ECB / static IV
```

Same disproof discipline as A9, A10 and A12. A `URLSession` delegate that accepts any server trust is a vulnerability; `UserDefaults` holding a non-secret preference is not.

---

## 5. Tooling

### 5.1 The tool set, with the ids a maintainer can reproduce from

Cite the MASTG tool id alongside the tool so the maintainer knows exactly what produced the evidence. Ids below are from the [MASTG tools index](https://mas.owasp.org/MASTG/tools): `MASTG-TOOL-0018` jadx, `0011` Apktool, `0010` APKLab, `0004` adb, `0123` apksigner, `0124` aapt2, `0009` APKiD, `0099` FlowDroid, `0125` Apkleaks, `0002`/`0035` MobSF, `0110` semgrep, `0031` Frida, `0038` objection, `0015` drozer, `0144` gitleaks.

| Tool | Use | Caveat to record |
|---|---|---|
| [apkanalyzer](https://developer.android.com/tools/apkanalyzer) | First pass before decompiling: `manifest print`, `manifest permissions\|debuggable\|min-sdk\|target-sdk`, `files list`, `dex packages --defined-only`, `dex code --class`, `apk compare` | Gives the manifest in plain XML without unpacking. Run it before anything else |
| [jadx](https://github.com/skylot/jadx) ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) | Readable Java from apk/dex/aab/jar/class/aar; decodes manifest and `resources.arsc`; jadx-gui gives jump-to-declaration, find-usage, full-text search. Apache-2.0 | Its README says it "can't decompile 100% of the code" — **confirm every finding against smali or upstream source** |
| [Apktool](https://apktool.org/) | Ground truth for resources, manifest and baksmali'd classes when jadx output is wrong or incomplete | Use `-m` for a resources/manifest view without rebuilding |
| [mobsfscan](https://github.com/MobSF/mobsfscan) | **Best fit for an open-source audit**: MobSF's rules over Java, Kotlin, Android XML, Swift, Objective-C and `Info.plist` via Semgrep plus libsast. No APK needed. `pip install mobsfscan`, then `mobsfscan <path>`; SARIF/JSON output for the evidence trail | `.mobsf` config and `// mobsf-ignore` suppress noise — record any suppression you add |
| [mobsfscan rule tree](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep) | Read the rule source (`best_practices/`, `java/`, `kotlin/`, `swift/`) when deciding whether a hit is real | Cite the specific rule file behind each automated finding |
| [semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security) | Semgrep rules derived from MASTG Android static tests, with a documented decompile-then-scan workflow. GPL-3.0 | **Targets MASTG v1.5.0 test ids**, omits the resilience category, and jadx output is Java so **Kotlin-only code is weakly covered** — pair with mobsfscan's Kotlin rules |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Breadth report over an APK/IPA or source tree, with REST API/CLI for repeatable runs. GPL-3.0 | Run locally in Docker. **Default `mobsf`/`mobsf` credentials mean it must never be network-exposed.** Its output is leads, not findings |
| [Android Emulator](https://developer.android.com/studio/run/emulator) | The sanctioned verification surface: each AVD is an independent device with private storage | Use a **Google APIs / AOSP** image, not a Play image, so `adb root` works |
| [Frida on Android](https://frida.re/docs/android/) | Observing the app's own behaviour on **your own** device/emulator with **your own** build | §5.5. Never pointed at anyone else's device or any production service |
| [objection](https://github.com/sensepost/objection) | Frida-powered runtime exploration: app container filesystem, keychain dump (iOS), memory inspection, pinning bypass **to watch your own lab traffic**. `pip3 install objection` | §5.5 |
| [MASTG repository](https://github.com/OWASP/mastg) | Grep tests and techniques offline; diff test ids across MASTG versions; `apps/`, `Samples/Android` and `Crackmes` for practising on intentionally vulnerable code the researcher legitimately holds | Far faster than the JS-heavy site |

### 5.2 Setup

```bash
# SDK command-line tools: apkanalyzer, apksigner, aapt2, adb
# jadx and apktool from their releases
pip install mobsfscan
mobsfscan --sarif -o work/mobsfscan.sarif src/

# MASTG-derived Semgrep rules: run from the rules checkout so its .semgrepignore applies
jadx -d work/jadx app.apk
cd /path/to/semgrep-rules-android-security/semgrep_for_android/ && semgrep -c ./rules/ /path/to/work/jadx/

# MobSF, local only — never bind it to a routable interface
docker run -it --rm -p 127.0.0.1:8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Treat every extracted APK/IPA directory as untrusted data: keep your own scripts in a different directory, pass paths as arguments, and never run an interpreter or build tool from inside it.

### 5.3 Scanner triage — run the scanners **after** the manual manifest pass

**Order matters.** The A1 inventory is what tells you which scanner hits are reachable. Running the scanners first produces a pile you cannot triage.

1. Run mobsfscan over `src/` (SARIF), the MASTG-derived Semgrep rules over `work/jadx/`, then MobSF over the binary for breadth.
2. For **every** candidate, do all four in order, then keep or delete: **open the file**; **confirm the sink is real**; **confirm the component is reachable** per the A1 inventory; **confirm the SDK range**. If any one fails, delete the hit. No "probably reachable".
3. **Record the rule file behind each surviving finding.** "A scanner said so" is not provenance; `rules/java/<file>.yaml` is.
4. **Exclude bundled third-party libraries from the findings list.** A genuine library issue goes to the library's own project, with the app maintainer told which version is affected (§6.3).
5. **Standing rule: nothing that only a scanner has seen is reported** ([../VERIFICATION.md](../VERIFICATION.md)).
6. Record the documented coverage gaps in the audit notes so silence is not read as coverage: the MASTG-derived Semgrep rules target v1.5.0 ids, skip resilience, and under-cover Kotlin; jadx cannot decompile everything.

### 5.4 Local verification lab — own device or emulator, own build only

1. Create an AVD on a **Google APIs / AOSP** system image so `adb root` works ([Android Emulator](https://developer.android.com/studio/run/emulator)). Each AVD has private storage, which is what keeps the PoC off any real phone.
2. Install **the researcher's own build** of the target. Not a store download of someone else's signed release where the build can be produced from source.
3. Write the **smallest** possible PoC: a one-liner, or a throwaway app in the lab's `work/poc/` that sends the crafted intent or queries the authority.

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://host/path?x=1" -n <pkg>/<cls>
adb shell am start -n <pkg>/<cls> --es key value
adb shell content query --uri content://<authority>/<path>
adb shell am broadcast -a <action> --es key value
```

4. Capture evidence as **command + output + a screenshot or logcat excerpt**, redacting anything that looks like real data. Store it under [../../../evidence/](../../../evidence/README.md) with the env record: device/AVD image, app version and commit SHA, `minSdk`/`targetSdk`, and how the build was produced.
5. Reproduce **from clean state** — fresh AVD snapshot or `adb uninstall` then reinstall. A PoC that only fires on a dirty device is not a reproduction (ROE §3.1).
6. Pin the affected range by re-running against the previous and next released versions, or by reading history. ROE §3.3 requires it determined, not guessed.

**Hard limits:** no traffic to the project's production backend; no account other than the researcher's own test account; no testing on a device belonging to anyone else; no packaging of the PoC for distribution.

### 5.5 Dynamic instrumentation: the constraint, stated once and binding

[Frida](https://frida.re/docs/android/) and [objection](https://github.com/sensepost/objection) run **only** on the researcher's own device or emulator, with the researcher's own build. The official Frida setup is exactly that shape: root the device or use a Google-provided emulator image, `adb shell getprop ro.product.cpu.abilist`, push the matching `frida-server` to `/data/local/tmp/`, run it as root, then `frida-ps -U`.

What they are for: **observing the app's own behaviour** — confirming a value lands unencrypted on disk, that a bridge method is callable, that a request leaves in cleartext. The pinning-bypass features are used **only** to watch the researcher's own lab traffic.

What they are not for, and what this repository does not do:

1. **No instrumentation of anyone else's device or any production service.** ROE §1.
2. **No root-detection, emulator-detection or anti-instrumentation evasion research.** If the app blocks instrumentation, fall back to source review and **say so in the notes**. "The app detected Frida" is a line in the notes, not a research direction.
3. **A dynamic observation is not a finding by itself.** It confirms a chain you already traced in source to `file:line`. A Frida hook with no source-level root cause fails ROE §3.2.

---

## 6. Mapping, severity, and reporting routes

### 6.1 The mapping table — this is the checklist

The OWASP MAS Checklist was removed in MASTG v2.0.0 (§1.2). **This table is its replacement for this repository.** Fill one row per surviving finding. Resolve the `MASTG-TEST` id from the cloned [MASTG repository](https://github.com/OWASP/mastg) — do not cite a v1 id.

| Finding class | MASVS control | MASWE | CWE | First-party remediation source |
|---|---|---|---|---|
| Exported component with no / weak permission | MASVS-PLATFORM-1 | MASWE-0032 | CWE-926 | [security best practices](https://developer.android.com/privacy-and-security/security-best-practices) · [intents and filters](https://developer.android.com/guide/components/intents-filters) |
| Intent redirection | MASVS-PLATFORM-1 | MASWE-0032 | CWE-441 | [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection) |
| Implicit intent leaking sensitive extras | MASVS-PLATFORM-1 / PRIVACY | MASWE-0032 | CWE-927 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/implicit-intent-hijacking` |
| Unverified App Link (`autoVerify` absent) | MASVS-PLATFORM-1 | — | CWE-939 | [verify App Links](https://developer.android.com/training/app-links/verify-android-applinks) · [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/) |
| Mutable PendingIntent wrapping an implicit intent | MASVS-PLATFORM-1 | — | CWE-927 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/pending-intent` |
| Provider `openFile` path traversal | MASVS-PLATFORM-1 / STORAGE-2 | — | CWE-22 | [Path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal) |
| Provider SQL injection via `selection` | MASVS-PLATFORM-1 | — | CWE-89 | [Create a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating) |
| WebView JavaScript bridge exposure | MASVS-PLATFORM-2 | — | CWE-749 | [WebView guide](https://developer.android.com/develop/ui/views/layout/webapps/webview) |
| WebView loading an attacker-influenced URL | MASVS-PLATFORM-2 | — | CWE-601 / CWE-79 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/unsafe-uri-loading` |
| Sensitive data in SharedPreferences / external storage / logs | MASVS-STORAGE-1/2 | — | CWE-312 / CWE-532 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/sensitive-data-external-storage`, `/log-info-disclosure` |
| Cleartext traffic permitted | MASVS-NETWORK-1 | — | CWE-319 | [Network security configuration](https://developer.android.com/privacy-and-security/security-config) |
| Broken TLS validation (trust manager / hostname verifier) | MASVS-NETWORK-1 | — | CWE-295 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/unsafe-trustmanager`, `/unsafe-hostname` |
| Missing pinning (**hardening gap**, MAS-L2 only) | MASVS-NETWORK-2 | — | — | [Network security configuration](https://developer.android.com/privacy-and-security/security-config) |
| Hardcoded secret or key | MASVS-STORAGE-1 / CRYPTO-1 | — | CWE-798 | [../../../SECRETS_HYGIENE.md](../../../SECRETS_HYGIENE.md) §2 |
| Crypto misuse (ECB, static IV, weak digest, weak PRNG) | MASVS-CRYPTO-1/2 | — | CWE-327 / CWE-329 / CWE-338 | [Android cryptography](https://developer.android.com/privacy-and-security/cryptography) |
| `debuggable` release build | MASVS-RESILIENCE | — | CWE-489 | [risks catalog](https://developer.android.com/privacy-and-security/risks) `/android-debuggable` |
| v1-only APK signing (**hardening gap**) | MASVS-RESILIENCE | — | CWE-347 | [AOSP app signing](https://source.android.com/docs/security/features/apksigning) |
| iOS blanket ATS exception | MASVS-NETWORK-1 | — | CWE-319 | [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) · [NSAppTransportSecurity](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) |
| iOS custom URL scheme handler | MASVS-PLATFORM-1 | — | CWE-939 | [custom URL scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app) · [MASTG-KNOW-0079](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/) |
| iOS keychain accessibility too weak | MASVS-STORAGE-1 | — | CWE-922 | [keychain accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility) |
| iOS file written without a protection class | MASVS-STORAGE-2 | — | CWE-311 | [Encrypting your app's files](https://developer.apple.com/documentation/uikit/encrypting-your-app-s-files) |
| iOS pasteboard leakage | MASVS-PRIVACY | — | CWE-200 | [UIPasteboard](https://developer.apple.com/documentation/uikit/uipasteboard) |

An empty MASWE cell means **resolve it from the [MASWE catalog](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/)'s own navigation**, not that none exists. Do not invent an id.

### 6.2 Severity: preconditions decide it, not the sink

**Preconditions are usually what decides severity for a mobile finding.** Record them explicitly, in the first paragraph of the report, for every finding:

| Precondition | Effect on severity |
|---|---|
| Reachable by any installed app, no user interaction | Highest in this dimension. Still state which permission the attacker app needs, if any |
| Requires a second malicious app already installed | **Valid** — that is the whole Android IPC threat model — but **not critical.** Claiming otherwise is the fastest way to lose a maintainer's trust |
| Requires the victim to tap a link or a notification | Lower. State the exact user action |
| Requires a network position (same Wi-Fi, hostile proxy) | Lower, and it must be a position an attacker plausibly holds |
| Requires physical access to an unlocked device | **Not a finding** (§7) |
| Requires a rooted or jailbroken device | **Not a finding** (§7) |

Then assign the finding to exactly one of three buckets, and let the **human** confirm both bucket and severity:

1. **Vulnerability** — reachable, with a demonstrated impact on your own emulator.
2. **Hardening gap** — missing pinning, no anti-tampering, v1 signing, `allowBackup="true"`. Real, worth saying, **not a vulnerability**, and never scored as one.
3. **Informational** — observations with no demonstrated reachability or impact.

**Severity may never exceed demonstrated impact** (ROE §3.4). Not what the sink could do in principle, not what a chain might reach — what your reproduction actually showed.

### 6.3 Channel routing: app, platform, or library

Decide before writing a word of the report. Then report **once**, through **one** channel, and let the **human** send it (ROE §2).

| Root cause | Channel | Notes |
|---|---|---|
| **The app's own code** | The project's own private channel: `SECURITY.md`, GitHub private vulnerability reporting, or the documented security contact | **Never a public issue.** Default route for this dimension. Process and timelines: [../../../disclosure/PROCESS.md](../../../disclosure/PROCESS.md) |
| **An app built or maintained by Google or a listed affiliate publisher** | [Google Mobile VRP rules](https://bughunters.google.com/about/rules/6618732618186752/google-mobile-vulnerability-reward-program-rules) | **Read the live page first** for the current in-scope publisher and Tier 1 lists, and for the exclusions — StrandHogg-style variants and hardcoded API keys are explicitly excluded, as are attacks needing heavy user interaction or social engineering. Settling scope first prevents a wasted report |
| **The Android platform or AOSP, not the app** | [Android and Google Devices Security Reward Program rules](https://bughunters.google.com/about/rules/6171833274204160/android-and-google-devices-security-reward-program-rules) | Check the [Android Security Bulletins](https://source.android.com/docs/security/bulletin) **first** — if it is a known, fixed platform bug, there is no report to make. Bulletins also set the disclosure cadence to expect |
| **A bundled third-party library** | The library's own project | Tell the app maintainer which version is affected; do not file the library's bug against the app |

**How to tell app from platform.** Ask: would the behaviour change if the app's code changed? If yes, it is the app's. If the same code is safe on one Android version and unsafe on another with no app change, the platform default is doing the work — record the SDK range and consider the platform route. A WebView bridge the app declares is the app's. A platform API that grants more than it documents is the platform's.

**Two routing traps:**

1. [`source.android.com/docs/security/overview/reports`](https://source.android.com/docs/security/overview/reports) **is not a reporting channel** despite the slug. It is a security-papers index with no address, timeline, or intake form. Background reading only.
2. The Google Play Security Reward Program was retired in 2024. **Do not list it as an option.** No primary source remains to cite for it.

**Cite no reward amounts.** Figures for the Mobile VRP differ wildly across sources; tell the researcher to read the live rules.

### 6.4 What the report must contain

Draft into [../../../findings/](../../../findings/README.md):

1. Affected version **and** commit SHA, plus how the artifact under test was produced.
2. The manifest line or source path, with **line numbers**, in the upstream tree.
3. The source-to-sink path, written out.
4. The `minSdk`/`targetSdk` range in which the finding is actually exploitable.
5. Preconditions, prominently (§6.2).
6. The local reproduction, **stated as having been run on the researcher's own emulator with the researcher's own build**.
7. Observed impact — only what you saw.
8. The MASVS + MASWE + MASTG-TEST + CWE mapping from §6.1, with the tool ids that produced any automated evidence.
9. A concrete patch suggestion quoting the first-party remediation: `android:exported="false"`; `IntentSanitizer`; `FLAG_IMMUTABLE`; `getCanonicalPath()` plus a prefix check **with a trailing separator**; parameterised `selectionArgs`; a scheme-**and**-host allow-list before `loadUrl`; `autoVerify` plus a correct `assetlinks.json`; `cleartextTrafficPermitted="false"`; Keystore-backed keys (**not** the deprecated `androidx.security:security-crypto`).
10. AI assistance disclosed. GitHub's private report form has a checkbox for it.

If the finding needs a CVE, the eligibility pre-flight and route selection are in [../../../disclosure/CVE_AND_CNA.md](../../../disclosure/CVE_AND_CNA.md) — run its decision tree rather than promising an id. A GitHub-hosted open-source app normally takes the GitHub-as-CNA route (CVE_AND_CNA §5.2); a platform root cause is Google's to assign, not the researcher's to request.

**Then stop.** Per [../../../RULES_OF_ENGAGEMENT.md](../../../RULES_OF_ENGAGEMENT.md) §2, an agent does not send, file, submit, publish, post to a bounty platform, or contact a maintainer. The human reads it, agrees with it, and acts.

---

## 7. Not a vulnerability in this class

Report none of these on their own. Each row says what would have to be **demonstrated** — locally, on your own emulator, per §5.4 — to turn it into a finding.

| Claim | Why it is not a finding | What would make it one |
|---|---|---|
| **Anything requiring a rooted or jailbroken device** | Root breaks the platform's own sandbox. Every app's private storage is readable; that is root working as designed, not the app failing | The same data is reachable **without** root — through an exported component, a provider, external storage, a backup, or a log |
| **Anything requiring physical access to an unlocked device** | The attacker already has the user's session. The device lock screen is the control, and it already failed | The data is reachable from another **app** on the device, or over the network, with the screen locked |
| **A `debuggable` build that is not shipped to users** | A debug variant is a development artifact. `debuggable` in `src/debug/` is correct | `android:debuggable="true"` in the **released** artifact — show the `apkanalyzer manifest debuggable` output for the release APK |
| **A local-only issue with no cross-app or remote reachability** | If no other app and no remote party can reach it, no boundary is crossed | A reachable entrypoint per the A1 inventory, named, with the calling app's required permissions stated |
| **Exported component guarded by a `signature`-level permission** | Only an app signed with the same key can call it. That is the intended same-developer sharing mechanism | The permission is `normal` or `dangerous`, or the guard is on the manifest but not checked on the code path that matters |
| **"Intent filter present, therefore attackable"** | Filters describe matching, not access. Any app that knows the class name can send an explicit intent regardless | A written source→sink path from the received intent to a real sink (A2) |
| **Missing certificate pinning** | A hardening gap, not a broken control. TLS still validates | A trust manager, hostname verifier, or `onReceivedSslError` that actually accepts an invalid certificate — that is CWE-295 and a real finding |
| **Absence of obfuscation, RASP, root detection or emulator detection** | Not security controls against the platform threat model, and this repository does not do evasion research (§5.5) | Nothing. Report it as informational at most, and only if the project itself claims the control |
| **A hardcoded value that ships publicly by design** | Firebase config, Google Maps keys, Stripe publishable keys, Sentry DSNs, OAuth client ids | A credential class that grants server-side authority, with path, reachability and history checked (A11) — and still never tested |
| **A secret in a test fixture** | `test/`, `androidTest/`, `fixtures/`, `sample/` values are not shipped credentials | The value is reachable from shipped code, or git history shows it was once live in production code |
| **"ECB mode" with no statement of what is encrypted** | A cipher mode is not an impact | The data protected, who can read it, and what they learn — shown, not asserted |
| **`allowBackup="true"` alone** | A platform default on older targets, and exploiting it needs adb plus an unlocked device | Backup actually extracts a credential, demonstrated on your own emulator, with the preconditions stated honestly as a hardening gap |
| **A platform bug reported to the app maintainer** | Wastes a maintainer's time on code they do not own | The app's own code is the root cause. Otherwise route per §6.3 |
| **A finding in a bundled third-party library, filed against the app** | The app maintainer cannot fix someone else's library | A traced path from the app's own entrypoint into the vulnerable function — then it is a supply-chain finding with its own evidence, and the library still gets the report |
| **Scanner output with no manual chain** | §5.3 rule 5 | A human has read the path and can name source, sink, reachable component and SDK range |
| **Anything observed against a production backend, a store build on someone else's phone, or a third party's device** | Not merely invalid — **prohibited**. ROE §1 | Nothing. Redo it on your own emulator with your own build, or drop it |

If an item is borderline, the ROE answer applies: **when in doubt, do not report.** A missed finding costs a delay. A wrong finding costs a maintainer's trust, which does not come back.

---

## 8. Verified sources

Standards and taxonomies

- [OWASP MASVS](https://mas.owasp.org/MASVS/) · [MASVS-PLATFORM group](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM)
- [OWASP MASTG](https://mas.owasp.org/MASTG/) · [MASTG repository](https://github.com/OWASP/mastg) (clone it; the site is nav-heavy and often returns only the sidebar)
- [MASWE-0032 Insecure Intents](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/)
- [MAS Testing Profiles](https://mas.owasp.org/Profiles/) — replaces the removed MASVS L1/L2/R levels
- [MASTG v2.0.0 Removes MAS Checklists](https://mas.owasp.org/news/2026/07/14/checklists-removal/) — read this before citing any checklist URL
- [MASTG-TEST-0393 Use of Unverified App Links](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/) · [MASTG-TECH-0172 Listing Deep Links](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/) · [MASTG-KNOW-0079 Custom URL Schemes (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/)

Android, first-party

- [Android app security risks catalog](https://developer.android.com/privacy-and-security/risks) — 45 risk articles grouped by MASVS category; the highest-value index for this dimension, and vendor-authoritative when a maintainer pushes back
- [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection) · [Path traversal](https://developer.android.com/privacy-and-security/risks/path-traversal)
- [Security best practices](https://developer.android.com/privacy-and-security/security-best-practices) · [Network security configuration](https://developer.android.com/privacy-and-security/security-config) · [Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Intents and intent filters](https://developer.android.com/guide/components/intents-filters) · [Create a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating) · [Build web apps in WebView](https://developer.android.com/develop/ui/views/layout/webapps/webview) · [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks)
- [apkanalyzer](https://developer.android.com/tools/apkanalyzer) · [Android Emulator](https://developer.android.com/studio/run/emulator)
- [AOSP application signing](https://source.android.com/docs/security/features/apksigning) · [Android Security Bulletins](https://source.android.com/docs/security/bulletin)

Apple, first-party (page identity verified; **bodies not read** — resolve exact key names and constants live before quoting them)

- [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) · [NSAppTransportSecurity](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity)
- [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility) · [Encrypting your app's files](https://developer.apple.com/documentation/uikit/encrypting-your-app-s-files)
- [Defining a custom URL scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app) · [UIPasteboard](https://developer.apple.com/documentation/uikit/uipasteboard)

Tooling

- [MASTG tools index](https://mas.owasp.org/MASTG/tools) · [MASTG-TOOL-0018 jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [jadx](https://github.com/skylot/jadx) · [Apktool](https://apktool.org/)
- [mobsfscan](https://github.com/MobSF/mobsfscan) · [mobsfscan Semgrep rule tree](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep) · [semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security) · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida on Android](https://frida.re/docs/android/) · [objection](https://github.com/sensepost/objection)

Reporting channels (executed by the human, never by an agent)

- [Google Mobile VRP rules](https://bughunters.google.com/about/rules/6618732618186752/google-mobile-vulnerability-reward-program-rules)
- [Android and Google Devices Security Reward Program rules](https://bughunters.google.com/about/rules/6171833274204160/android-and-google-devices-security-reward-program-rules)

Dead ends — recorded so nobody re-adds a broken link

| URL or claim | Status |
|---|---|
| `mas.owasp.org/checklists/` and `/checklists/MASVS-PLATFORM` | **Removed** in MASTG v2.0.0; both redirect to the [removal notice](https://mas.owasp.org/news/2026/07/14/checklists-removal/). §6.1 is the checklist |
| `mas.owasp.org/MASVS/05-MASVS-PLATFORM/` | **404.** The group page is [`/MASVS/09-MASVS-PLATFORM`](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM) |
| `mas.owasp.org/MASTG/0x03b-Testing-Profiles/` | Redirects to [`/Profiles/`](https://mas.owasp.org/Profiles/) |
| [`source.android.com/docs/security/overview/reports`](https://source.android.com/docs/security/overview/reports) | Exists, but is a **security-papers index**, not a reporting channel. No address, no timeline, no intake |
| A Semgrep registry ruleset for mobsfscan | **Unconfirmed** — no registry page content returned on fetch or targeted search. Use the [mobsfscan CLI](https://github.com/MobSF/mobsfscan) or its [rule tree](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep) instead. Do not publish the registry URL |
| Google Play Security Reward Program (GPSRP) | **Retired in 2024.** Not a channel. No primary source to cite |
| Mobile VRP reward figures | Inconsistent across sources. Cite none; read the live rules |
| `MASTG-TEST-0028`, `-0027`, `-0031` | Deprecated or superseded in MASTG v2. Resolve current ids from the [cloned repo](https://github.com/OWASP/mastg) before citing |

Risk-catalog slugs differ from the obvious guesses: it is `/implicit-intent-hijacking`, `/insecure-webview-native-bridges`, `/unsafe-uri-loading` and `/broken-cryptographic-algorithm` — there is no `/webview-javascript-interface`, no `/content-provider-path-traversal`, and no `/unsafe-cipher-mode`. And a standing caution: Google's own [Create a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating) guide ships a `query()` sample that concatenates `uri.getLastPathSegment()` into a selection string. **First-party documentation is not automatically safe reference code.**
