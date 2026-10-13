#!/usr/bin/env bash
# Run once per clone. Without this, the pre-commit safety hook is inert, because
# git does not transfer hooks and does not honour .githooks/ by default.
#
#   ./setup.sh

set -uo pipefail

cd "$(dirname "$0")" || exit 1

pass=0; warn=0; crit=0
ok()   { printf '  [ ok ]  %s\n' "$*"; pass=$((pass+1)); }
miss() { printf '  [WARN]  %s\n' "$*"; warn=$((warn+1)); }
bad()  { printf '  [FAIL]  %s\n' "$*"; crit=$((crit+1)); }

echo
echo "Master_Checklist_Blackwing — setup"
echo "=================================="

# --- 1. the safety hook (the only step that must not fail) -------------------
echo
echo "Safety hook"
if [ ! -d .git ]; then
    bad "not a git repository — run this from inside the clone"
else
    git config core.hooksPath .githooks
    chmod +x .githooks/pre-commit 2>/dev/null
    if [ "$(git config --get core.hooksPath)" = ".githooks" ] && [ -x .githooks/pre-commit ]; then
        ok "pre-commit hook installed (blocks findings/evidence and credential commits)"
    else
        bad "could not install pre-commit hook — do NOT commit until this is fixed"
    fi
fi

# --- 2. local-only workspaces -----------------------------------------------
echo
echo "Workspaces"
for d in findings evidence targets/private; do
    mkdir -p "$d"
    if git check-ignore -q "$d/probe" 2>/dev/null; then
        ok "$d/ exists and is gitignored"
    else
        bad "$d/ is NOT gitignored — fix .gitignore before doing any work"
    fi
done

# --- 3. tooling -------------------------------------------------------------
echo
echo "Core tooling"
need() { command -v "$1" >/dev/null 2>&1 && ok "$1 — $2" || bad "$1 missing — $2"; }
want() { command -v "$1" >/dev/null 2>&1 && ok "$1 — $2" || miss "$1 missing — $2 ($3)"; }

need git    "version control"
need curl   "fetching advisories and verifying links"
need jq     "parsing OSV and advisory JSON"
need docker "sandboxed verification — REQUIRED, targets are never run on the host"

echo
echo "Static analysis"
want semgrep   "multi-language taint and pattern analysis" "pipx install semgrep"
want gitleaks  "secret scanning, including git history"    "https://github.com/gitleaks/gitleaks"

echo
echo "Prior-art and dependency scanners (install per ecosystem as needed)"
want osv-scanner "cross-ecosystem prior-art scan (P1)"        "https://google.github.io/osv-scanner/"
want gh          "GitHub advisories and Private Vuln Reporting" "https://cli.github.com"
want pip-audit   "Python prior-art scan (P1)"                  "pipx install pip-audit"
want npm         "Node prior-art scan (P1)"                    "nodejs"
want govulncheck "Go prior-art scan with reachability (P1)"    "go install golang.org/x/vuln/cmd/govulncheck@latest"
want cargo       "Rust toolchain, for cargo-audit (P1)"        "rustup"
want trivy       "container and IaC scanning (P3)"             "https://trivy.dev"
want actionlint  "GitHub Actions workflow auditing (P3)"       "https://github.com/rhysd/actionlint"
want jadx        "Android APK decompilation (P4)"              "https://github.com/skylot/jadx"

# --- 4. summary -------------------------------------------------------------
echo
echo "=================================="
printf 'ready: %d   optional missing: %d   blocking: %d\n' "$pass" "$warn" "$crit"
echo

if [ "$crit" -gt 0 ]; then
    echo "BLOCKING ISSUES ABOVE. Resolve them before starting any audit work."
    echo "A missing pre-commit hook or an untracked-workspace failure risks publishing"
    echo "an unpatched finding from this public repository."
    echo
    exit 1
fi

cat <<'NEXT'
Setup complete. Optional tools can be installed per target as needed.

Read in this order:
  1. RULES_OF_ENGAGEMENT.md   non-negotiable boundaries
  2. PLAYBOOK.md              the ordered process
  3. TARGETS.md               qualify a target before touching it

Reminder: this repository is PUBLIC. Findings and evidence stay local.
NEXT
