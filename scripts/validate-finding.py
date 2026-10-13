#!/usr/bin/env python3
"""Validate finding records against schemas/finding.schema.json, plus the rules
JSON Schema cannot express.

    scripts/validate-finding.py findings/F-2026-001-acme-lib-zip-slip/finding.json
    scripts/validate-finding.py findings/          # walk a directory
    scripts/validate-finding.py --self-test        # check the checker

Exit status is 0 only when every record passes. Wire it into CI and into the
Phase 5 verification loop; a record that does not validate is not a finding.

Why this file exists: JSON Schema cannot compare two sibling property values, so
it cannot express "the verifier may not be the finder" or "reported severity may
not exceed demonstrated impact". Those are the two rules most likely to be bent
under pressure, so they get enforced in code.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema is required:  pipx install jsonschema  (or pip install jsonschema)")

REPO = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "schemas" / "finding.schema.json"

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# From the schema's duplicate_check description: the floor for a confirmed record.
REQUIRED_DUPE_SOURCES = {
    "osv_dev",
    "osv_scanner",
    "github_advisory_reviewed",
    "github_advisory_unreviewed",
    "cve_program",
    "snyk",
    "project_advisories",
    "project_changelog",
    "project_issues_and_prs",
    "oss_security",
}

POST_SIGNOFF_STATES = {"reported", "acknowledged", "patched", "published"}

# A fingerprint must survive re-runs. These substrings mean it will not.
FINGERPRINT_SMELLS = [
    (re.compile(r"(?:^|[^a-z])l(?:ine)?[-_:]?\d+", re.I), "encodes a line number"),
    (re.compile(r"\b(?:run|wave|round|pass|iter(?:ation)?)[-_:]?\d+", re.I), "encodes a run/wave number"),
    (re.compile(r"\bagent[-_:]?\w*", re.I), "encodes an agent name"),
    (re.compile(r"\b(?:informational|low|medium|high|critical)\b", re.I), "encodes a severity"),
    (re.compile(r"\b(?:confirmed|rejected|needs[-_]validation)\b", re.I), "encodes a verdict"),
]


class Problems:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, rule: str, msg: str) -> None:
        self.errors.append(f"[{rule}] {msg}")

    def warn(self, rule: str, msg: str) -> None:
        self.warnings.append(f"[{rule}] {msg}")


def check_cross_field(rec: dict, p: Problems) -> None:
    verdict = rec.get("verdict")
    confirmed = verdict == "confirmed"

    # --- the verifier may not be the finder --------------------------------
    found_by = (rec.get("found_by") or "").strip()
    verified_by = (rec.get("verified_by") or "").strip()
    if found_by and verified_by and found_by.casefold() == verified_by.casefold():
        p.err("verifier-independence",
              f"found_by and verified_by are both {found_by!r}. A verifier may not verify its "
              "own candidate — the whole point is an independent attempt to refute it.")

    # --- reported severity may not exceed demonstrated impact --------------
    sev = rec.get("severity") or {}
    overall, impact = sev.get("overall"), sev.get("impact")
    if overall in SEVERITY_ORDER and impact in SEVERITY_ORDER:
        if SEVERITY_ORDER.index(overall) > SEVERITY_ORDER.index(impact):
            p.err("severity-ceiling",
                  f"overall severity {overall!r} exceeds demonstrated impact {impact!r}. "
                  "Severity is capped by what the PoC actually showed, not by what the bug "
                  "could do in theory.")

    # --- a confirmed record must have done the prior-art work --------------
    if confirmed:
        done = {e.get("source") for e in rec.get("duplicate_check") or []}
        missing = REQUIRED_DUPE_SOURCES - done
        if missing:
            p.err("duplicate-check-floor",
                  "confirmed record has not queried: " + ", ".join(sorted(missing)) +
                  ". A duplicate found here is a success, not a failure.")
        inconclusive = [e.get("source") for e in rec.get("duplicate_check") or []
                        if e.get("result") == "inconclusive"]
        if inconclusive:
            p.warn("duplicate-check-inconclusive",
                   "inconclusive result from: " + ", ".join(sorted(filter(None, inconclusive))) +
                   ". Resolve before reporting, or the maintainer will.")
        if any(e.get("result") == "match" for e in rec.get("duplicate_check") or []):
            p.err("duplicate-found",
                  "a duplicate_check entry reports result='match'. This is already known — "
                  "it does not get reported again as new.")

    # --- reproduction quality ---------------------------------------------
    rep = rec.get("reproduction") or {}
    if confirmed:
        runs = rep.get("runs")
        if isinstance(runs, int) and runs < 2:
            p.err("flaky-repro", f"reproduction.runs={runs}; a single successful run does not "
                                 "distinguish a bug from a coincidence.")
        if rep.get("negative_control_passed") is False:
            p.err("negative-control",
                  "negative_control_passed is false: the PoC also 'succeeds' where the bug should "
                  "be absent, so it is not testing what you think it is.")
        elif "negative_control_passed" not in rep:
            p.warn("negative-control",
                   "no negative control recorded. Confirm the PoC FAILS on a patched or "
                   "unaffected version before believing it.")
        poc = rep.get("poc_path")
        if poc and not str(poc).replace("\\", "/").lstrip("./").startswith("evidence/"):
            p.err("poc-location",
                  f"poc_path {poc!r} is outside evidence/. PoCs live in the untracked workspace, "
                  "never anywhere this public repo tracks.")

    # --- nothing leaves without a human -----------------------------------
    state = rec.get("state")
    signed = ((rec.get("human_signoff") or {}).get("signed_off")) is True
    if state in POST_SIGNOFF_STATES and not signed:
        p.err("human-signoff-gate",
              f"state={state!r} without human_signoff.signed_off. No agent advances a record past "
              "verified; a person does, after re-reading the code and re-running the PoC.")

    # --- fingerprint stability --------------------------------------------
    fp = rec.get("fingerprint")
    if fp:
        for pattern, why in FINGERPRINT_SMELLS:
            if pattern.search(fp):
                p.err("fingerprint-unstable",
                      f"fingerprint {fp!r} {why}; it will not match the same defect on a later "
                      "run, which silently breaks deduplication.")
                break

    # --- reachability honesty ---------------------------------------------
    reach = rec.get("reachability") or {}
    if confirmed and reach.get("reachable_from_untrusted_entrypoint") is False:
        p.err("unreachable-confirmed",
              "confirmed, but not reachable from an untrusted entrypoint. With no reachable path "
              "this is a hardening note at most, not a vulnerability.")
    if confirmed and reach.get("default_configuration") is False and not rec.get("conditions"):
        p.warn("undeclared-precondition",
               "not reachable in the shipped default configuration, but conditions[] is empty. "
               "The required non-default config is a precondition and belongs in the report.")


def validate_one(path: Path, validator: Draft202012Validator) -> Problems:
    p = Problems()
    try:
        rec = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        p.err("json", f"does not parse: {e}")
        return p
    for e in sorted(validator.iter_errors(rec), key=lambda x: list(x.path)):
        loc = "/".join(str(x) for x in e.path) or "(root)"
        p.err("schema", f"{loc}: {e.message}")
    check_cross_field(rec, p)
    return p


def self_test() -> int:
    """The checker is a safety control, so it gets tested too."""
    cases = [
        ("verifier verifying its own candidate",
         {"found_by": "agent-7", "verified_by": "Agent-7"}, "verifier-independence"),
        ("severity above demonstrated impact",
         {"severity": {"overall": "critical", "impact": "medium"}}, "severity-ceiling"),
        ("reported without human sign-off",
         {"state": "reported", "human_signoff": {"signed_off": False}}, "human-signoff-gate"),
        ("fingerprint with a line number",
         {"fingerprint": "acme-lib/path-join/traversal-line42"}, "fingerprint-unstable"),
        ("fingerprint naming an agent",
         {"fingerprint": "agent3/acme-lib/traversal"}, "fingerprint-unstable"),
        ("PoC stored outside evidence/",
         {"verdict": "confirmed", "reproduction": {"poc_path": "findings/x/poc.sh"}},
         "poc-location"),
        ("confirmed but unreachable",
         {"verdict": "confirmed",
          "reachability": {"reachable_from_untrusted_entrypoint": False}},
         "unreachable-confirmed"),
        ("known duplicate reported as new",
         {"verdict": "confirmed",
          "duplicate_check": [{"source": "osv_dev", "query": "q", "result": "match"}]},
         "duplicate-found"),
        ("single repro run",
         {"verdict": "confirmed", "reproduction": {"runs": 1}}, "flaky-repro"),
    ]
    bad = 0
    width = max(len(n) for n, _, _ in cases)
    for name, rec, expect in cases:
        p = Problems()
        check_cross_field(rec, p)
        hit = any(e.startswith(f"[{expect}]") for e in p.errors)
        print(f"  {name:<{width}}  {'caught' if hit else 'MISSED'}  ({expect})")
        bad += 0 if hit else 1

    clean = {
        "verdict": "confirmed", "state": "verified",
        "found_by": "hunter-a", "verified_by": "verifier-b",
        "fingerprint": "acme-lib/path-join/traversal",
        "severity": {"overall": "high", "impact": "high"},
        "reachability": {"reachable_from_untrusted_entrypoint": True,
                         "default_configuration": True},
        "reproduction": {"runs": 3, "negative_control_passed": True,
                         "poc_path": "evidence/F-2026-001/repro.sh"},
        "duplicate_check": [{"source": s, "query": "q", "result": "no_match"}
                            for s in REQUIRED_DUPE_SOURCES],
    }
    p = Problems()
    check_cross_field(clean, p)
    ok = not p.errors
    print(f"  {'a clean confirmed record':<{width}}  {'passes' if ok else 'FALSE POSITIVE'}")
    if not ok:
        for e in p.errors:
            print(f"      {e}")
    bad += 0 if ok else 1

    print()
    print("self-test: " + ("all checks behave correctly" if not bad else f"{bad} problem(s)"))
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--self-test", action="store_true", help="test the checker itself")
    ap.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.paths:
        ap.error("give at least one finding.json or a directory to walk")

    schema = json.loads(args.schema.read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    targets: list[Path] = []
    for pth in args.paths:
        if pth.is_dir():
            targets += sorted(pth.rglob("*.json"))
        else:
            targets.append(pth)
    if not targets:
        print("no finding records found")
        return 0

    failed = 0
    for t in targets:
        p = validate_one(t, validator)
        full = t.resolve()
        rel = full.relative_to(REPO) if REPO in full.parents else t
        if p.errors:
            failed += 1
            print(f"FAIL  {rel}")
            for e in p.errors:
                print(f"        {e}")
        else:
            print(f"ok    {rel}")
        for w in p.warnings:
            print(f"        warn {w}")

    print()
    print(f"{len(targets) - failed}/{len(targets)} records valid")
    if failed:
        print("A record that does not validate is not a finding. Fix it or drop it.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
