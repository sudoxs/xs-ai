#!/usr/bin/env python3
"""
xs-ai benchmark — measure the QUALITY of the research/analysis logic, not how
convincing a model sounds.

The core suite is deterministic and offline: it scores the engine's own logic
(service identification, CVE applicability, auth classification, source parsing,
hypothesis generation, attack-chain linking, report accuracy) against known
inputs with expected outcomes. It runs with no model and no network, so it works
in CI and as a regression gate.

Cases live in benchmark/cases.json and are data, not code — new cases need no
changes to this runner, and the suite is provider/model-agnostic. A later,
optional live mode can score a configured model against the same fixtures.

Usage:
    python3 benchmark.py                 # run the offline suite, print a scorecard
    python3 benchmark.py --cases FILE    # use a different case file
    python3 benchmark.py --json          # machine-readable results
Exit code is non-zero if any case fails.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import research as R

try:
    import client  # only needed for the report-accuracy handler
except Exception:  # pragma: no cover
    client = None


# ---------------------------------------------------------------------------
# Handlers: each returns a result dict; the runner compares it to case["expect"]
# ---------------------------------------------------------------------------

def h_fingerprint(inp: dict) -> dict:
    fps = R.parse_fingerprints(inp["nmap"])
    fp = next((f for f in fps if f.port == str(inp["port"])), R.ServiceFingerprint(port=str(inp["port"])))
    return {"service": fp.service, "version": fp.version,
            "product_id": fp.product_id, "reliability": fp.reliability}


def h_applicability(inp: dict) -> dict:
    fp = R.ServiceFingerprint(port="0", service=inp.get("service", ""), version=inp.get("version", ""))
    status, confidence, _ = R.assess_cve_applicability(fp, inp.get("affected", {}))
    return {"status": status, "confidence": confidence}


def h_classify(inp: dict) -> dict:
    status, confidence, auth_state, _ = R.classify_validation(
        inp["kind"], inp.get("service", ""), inp.get("exit_code", 0), inp.get("output", ""))
    return {"status": status, "confidence": confidence, "auth_state": auth_state}


def h_nvd_parse(inp: dict) -> dict:
    fp = R.ServiceFingerprint(port="0", service=inp.get("service", ""),
                              product=inp.get("product", ""), version=inp.get("version", ""))
    leads = R.NVDSource.parse(inp["response"], fp)
    kept = sorted({c for l in leads for c in l["cves"]})
    return {"kept_cves": kept}


def h_kb_lookup(inp: dict, kb_dir: str) -> dict:
    kb = R.LocalKnowledgeBase(kb_dir=kb_dir)
    fp = R.ServiceFingerprint(port=str(inp.get("port", "")), service=inp.get("service", ""))
    leads = kb.query(fp, online=False)
    titles = " || ".join(l["title"].lower() for l in leads)
    cats = sorted({l["category"] for l in leads})
    sev = sorted({l["severity"] for l in leads})
    return {"lead_count": len(leads), "titles": titles, "categories": cats, "severities": sev}


def h_hypotheses(inp: dict, kb_dir: str) -> dict:
    eng = R.ResearchEngine(sources=R.default_sources(kb_dir), online=False)
    fp = R.fingerprint_for_port(str(inp.get("port", "")), inp.get("nmap", ""))
    hyps = eng.investigate(fp, inp.get("asset", "10.0.0.1"), client=None)
    cats = sorted({h.category for h in hyps})
    top_sev = hyps[0].severity if hyps else "none"
    # quality: every hypothesis keeps confidence and severity as distinct fields
    well_formed = all(h.confidence in R.CONFIDENCE_ORDER and h.severity in R.SEVERITY_ORDER for h in hyps)
    return {"count": len(hyps), "top_severity": top_sev, "categories": cats,
            "well_formed": well_formed}


def h_cve_discipline(inp: dict, kb_dir: str) -> dict:
    """Guard: the model must never introduce a CVE. Run investigate with a stub
    model that fabricates CVEs and check none leak into the hypotheses."""
    class _FabricatingModel:
        def run_phase(self, phase, prompt, system="", want_json=False):
            return inp["model_json"]
    eng = R.ResearchEngine(sources=R.default_sources(kb_dir, tech_dir="techniques"), online=False)
    fp = R.fingerprint_for_port(str(inp.get("port", "")), inp.get("nmap", ""))
    hyps = eng.investigate(fp, "10.0.0.1", client=_FabricatingModel(),
                           evidence_text=inp.get("nmap", ""))
    leaked = sorted({c for h in hyps for c in h.cves})
    nvd_links = any("nvd.nist.gov" in r for h in hyps for r in h.references)
    cve_in_text = any("CVE-" in h.observation for h in hyps)
    return {"leaked_cves": leaked, "nvd_links": nvd_links, "cve_in_text": cve_in_text}


def h_chains(inp: dict) -> dict:
    chains = R.analyze_attack_chains(inp.get("asset", "10.0.0.1"), inp["hypotheses"],
                                     inp.get("findings", []), client=None)
    linked = sorted({i for c in chains for i in c.hypothesis_ids})
    return {"chain_count": len(chains), "linked_ids": linked}


def h_report(inp: dict) -> dict:
    if client is None:
        return {"error": "client import unavailable"}
    import tempfile
    s = client.Session(target=inp.get("target", "10.0.0.1"))
    s.findings = inp.get("findings", [])
    s.hypotheses = inp.get("hypotheses", [])
    s.attack_chains = inp.get("attack_chains", [])
    path = client.generate_report(s, tempfile.mkdtemp())
    text = open(path, encoding="utf-8").read()
    return {"has_sections": [sec for sec in inp.get("want_sections", []) if sec in text]}


HANDLERS = {
    "fingerprint": lambda inp, kb: h_fingerprint(inp),
    "applicability": lambda inp, kb: h_applicability(inp),
    "classify": lambda inp, kb: h_classify(inp),
    "nvd_parse": lambda inp, kb: h_nvd_parse(inp),
    "kb_lookup": lambda inp, kb: h_kb_lookup(inp, kb),
    "hypotheses": lambda inp, kb: h_hypotheses(inp, kb),
    "chains": lambda inp, kb: h_chains(inp),
    "report": lambda inp, kb: h_report(inp),
    "cve_discipline": h_cve_discipline,
}


def _matches(result: dict, expect: dict) -> tuple[bool, str]:
    for key, want in expect.items():
        got = result.get(key)
        if isinstance(want, dict) and want.get("__contains__") is not None:
            needle = want["__contains__"]
            if needle not in (got or ""):
                return False, f"{key}: expected to contain {needle!r}, got {got!r}"
        elif isinstance(want, list) and isinstance(got, list):
            # subset / set-equality: every wanted item must be present
            missing = [w for w in want if w not in got]
            if missing:
                return False, f"{key}: missing {missing} in {got}"
        elif got != want:
            return False, f"{key}: expected {want!r}, got {got!r}"
    return True, "ok"


def run(cases: list[dict], kb_dir: str) -> dict:
    results = []
    cat_tally: dict[str, list[int]] = {}
    fp_count = fn_count = 0
    t0 = time.monotonic()
    for case in cases:
        kind = case.get("kind")
        cat = case.get("category", kind)
        handler = HANDLERS.get(kind)
        if handler is None:
            results.append({"id": case.get("id"), "ok": False, "why": f"unknown kind {kind}"})
            continue
        try:
            res = handler(case.get("input", {}), kb_dir)
            ok, why = _matches(res, case.get("expect", {}))
        except Exception as exc:
            ok, why, res = False, f"exception: {exc}", {}
        results.append({"id": case.get("id"), "category": cat, "ok": ok, "why": why})
        tally = cat_tally.setdefault(cat, [0, 0])
        tally[0] += 1
        tally[1] += 1 if ok else 0
        # false-positive / false-negative accounting (negative = should NOT flag)
        if not ok:
            if case.get("negative"):
                fp_count += 1
            else:
                fn_count += 1
    elapsed = time.monotonic() - t0
    passed = sum(1 for r in results if r["ok"])
    return {
        "total": len(results), "passed": passed, "failed": len(results) - passed,
        "false_positives": fp_count, "false_negatives": fn_count,
        "by_category": cat_tally, "elapsed_sec": round(elapsed, 3), "results": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="xs-ai research-engine benchmark")
    ap.add_argument("--cases", default=os.path.join("benchmark", "cases.json"))
    ap.add_argument("--kb", default="knowledge")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not os.path.isfile(args.cases):
        print(f"[FAIL] cases file not found: {args.cases}")
        return 2
    with open(args.cases, encoding="utf-8") as f:
        cases = json.load(f).get("cases", [])

    summary = run(cases, args.kb)

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0 if summary["failed"] == 0 else 1

    print("=" * 56)
    print(" xs-ai benchmark — research/analysis quality")
    print("=" * 56)
    for r in summary["results"]:
        mark = "PASS" if r["ok"] else "FAIL"
        line = f"  [{mark}] {r['id']}"
        if not r["ok"]:
            line += f"  — {r['why']}"
        print(line)
    print("-" * 56)
    print("  by category:")
    for cat, (tot, ok) in sorted(summary["by_category"].items()):
        print(f"    {cat:22s} {ok}/{tot}")
    print("-" * 56)
    print(f"  total: {summary['passed']}/{summary['total']} passed  "
          f"| false-positives: {summary['false_positives']}  "
          f"| false-negatives: {summary['false_negatives']}")
    print(f"  elapsed: {summary['elapsed_sec']}s")
    print("=" * 56)
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
