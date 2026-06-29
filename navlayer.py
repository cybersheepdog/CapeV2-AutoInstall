#!/usr/bin/env python3
"""
navlayer.py — build a MITRE ATT&CK Navigator layer from a CAPE analysis.

Harvests technique IDs from (a) a CAPE report's signatures and (b) generated
Sigma rules' `attack.*` tags, and writes a Navigator layer JSON you can load at
https://mitre-attack.github.io/attack-navigator/ to visualise coverage.

Usage:
  ./navlayer.py --task 42 --sigma-dir ./rules/sigma -o coverage.json
  ./navlayer.py --report-file report.json -o coverage.json
  ./navlayer.py selftest
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from capelib import family_slug, load_report, ok, warn

# T1059, T1059.001 etc.
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
SIGMA_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def harvest_report(report: dict):
    """Technique IDs from the report's signatures (format-agnostic)."""
    techs = {}
    sigs = report.get("signatures", []) or []
    for s in sigs:
        blob = json.dumps(s)
        name = s.get("name", "signature") if isinstance(s, dict) else "signature"
        for tid in TECH_RE.findall(blob):
            techs.setdefault(tid.upper(), set()).add(f"sig:{name}")
    return techs


def harvest_sigma_dir(path: str):
    techs = {}
    d = Path(path)
    if not d.is_dir():
        return techs
    for yml in d.rglob("*.yml"):
        text = yml.read_text(errors="ignore")
        for m in SIGMA_TAG_RE.findall(text):
            techs.setdefault(m.upper(), set()).add(f"sigma:{yml.name}")
    return techs


def merge(*sources):
    out = {}
    for src in sources:
        for tid, why in src.items():
            out.setdefault(tid, set()).update(why)
    return out


def build_layer(techs: dict, name: str, desc: str) -> dict:
    techniques = []
    maxscore = max((len(v) for v in techs.values()), default=1)
    for tid, why in sorted(techs.items()):
        techniques.append({
            "techniqueID": tid,
            "score": len(why),
            "color": "",
            "comment": "; ".join(sorted(why)),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": "." in tid,
        })
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": desc,
        "sorting": 3,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe6e6", "#ff6666", "#990000"],
            "minValue": 0, "maxValue": max(1, maxscore),
        },
        "legendItems": [], "metadata": [], "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def selftest():
    from capelib import SAMPLE_REPORT
    rep = harvest_report(SAMPLE_REPORT)
    assert "T1056.001" in rep and "T1547.001" in rep, rep
    sigma = {"T1059.003": {"sigma:x.yml"}}
    merged = merge(rep, sigma)
    layer = build_layer(merged, "test", "desc")
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1056.001", "T1547.001", "T1059.003"} <= ids
    json.dumps(layer)  # serialisable
    ok(f"selftest passed ({len(ids)} techniques)")


def main(argv=None):
    p = argparse.ArgumentParser(description="Build an ATT&CK Navigator layer from CAPE.")
    p.add_argument("command", nargs="?", default="build",
                   choices=["build", "selftest"])
    p.add_argument("--task", type=int)
    p.add_argument("--report-file")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--token", default="")
    p.add_argument("--sigma-dir", help="directory of generated Sigma rules to harvest")
    p.add_argument("-o", "--out", default="attack-layer.json")
    args = p.parse_args(argv)

    if args.command == "selftest":
        selftest(); return

    techs = {}
    family = "unknown"
    tid = "report"
    if args.report_file or args.task is not None:
        report = load_report(args.report_file, args.task, args.url, args.token)
        techs = merge(techs, harvest_report(report))
        info = report.get("info", {}) or {}
        tid = info.get("id", "report")
        family = info.get("category") or (report.get("malfamily") or "unknown")
    if args.sigma_dir:
        techs = merge(techs, harvest_sigma_dir(args.sigma_dir))

    if not techs:
        warn("No ATT&CK techniques found in the report signatures or Sigma rules.")
        return

    name = f"CAPE {family_slug(family)} task {tid}"
    layer = build_layer(techs, name, "Auto-generated detection coverage from CAPE.")
    Path(args.out).write_text(json.dumps(layer, indent=2))
    ok(f"Wrote ATT&CK Navigator layer ({len(techs)} techniques) -> {args.out}")
    ok("Load it at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer).")


if __name__ == "__main__":
    main()
