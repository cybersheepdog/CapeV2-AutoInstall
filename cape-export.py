#!/usr/bin/env python3
"""
cape-export.py — turn a finished CAPE analysis into threat intel.

Pulls a CAPE report (apiv2 or local file), extracts IOCs + extracted config via
capelib, and emits a MISP event (pushed or written) and a STIX 2.1 bundle (for
OpenCTI). Standard library only.

Usage:
  ./cape-export.py --task 42 --misp-url https://misp.local --misp-key KEY
  ./cape-export.py --report-file report.json --outdir ./export
  ./cape-export.py selftest

Review before disseminating: auto-extracted IOCs can include sandbox noise.
Tune capelib's safelist for your environment.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
import uuid
from pathlib import Path

from capelib import (IOCSet, SAMPLE_REPORT, extract, load_report, now_z, ok, warn)


# --------------------------------------------------------------------------- #
# MISP event
# --------------------------------------------------------------------------- #
def build_misp_event(iocs: IOCSet) -> dict:
    attrs = []

    def add(type_, category, value, to_ids=True):
        attrs.append({"type": type_, "category": category,
                      "value": value, "to_ids": to_ids})

    for v in sorted(iocs.ipv4):
        add("ip-dst", "Network activity", v)
    for v in sorted(iocs.domain):
        add("domain", "Network activity", v)
    for v in sorted(iocs.url):
        add("url", "Network activity", v)
    for v in sorted(iocs.sha256):
        add("sha256", "Payload delivery", v)
    for v in sorted(iocs.md5):
        add("md5", "Payload delivery", v)
    for v in sorted(iocs.ja3):
        add("ja3-fingerprint-md5", "Network activity", v)
    for v in sorted(iocs.filename):
        add("filename", "Payload delivery", v, to_ids=False)
    for v in sorted(iocs.regkey):
        add("regkey", "Persistence mechanism", v, to_ids=False)
    for v in sorted(iocs.mutex):
        add("mutex", "Artifacts dropped", v, to_ids=False)

    tags = []
    if iocs.family:
        tags.append({"name": f"malware:{iocs.family}"})
    for d in sorted(iocs.detections):
        tags.append({"name": f'cape:detection="{d}"'})
    tags.append({"name": "tlp:amber"})

    fam = iocs.family or "unknown"
    info_str = f"CAPE sandbox: {fam} (task {iocs.meta.get('task_id')})"
    return {"Event": {"info": info_str, "distribution": "0", "analysis": "2",
                      "threat_level_id": "2", "Attribute": attrs, "Tag": tags}}


def push_misp(event: dict, url: str, key: str) -> None:
    body = json.dumps(event).encode()
    req = urllib.request.Request(url.rstrip("/") + "/events/add", data=body,
                                 method="POST")
    req.add_header("Authorization", key)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
        resp = json.loads(r.read())
    eid = (resp.get("Event", {}) or {}).get("id", "?")
    ok(f"MISP event created (id {eid}).")


# --------------------------------------------------------------------------- #
# STIX 2.1 bundle
# --------------------------------------------------------------------------- #
def _ind(pattern: str, name: str, labels=("malicious-activity",)) -> dict:
    now = now_z()
    return {"type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid4()),
            "created": now, "modified": now, "name": name,
            "pattern_type": "stix", "pattern": pattern,
            "valid_from": now, "labels": list(labels)}


def build_stix_bundle(iocs: IOCSet) -> dict:
    objs = []
    malware_id = None
    if iocs.family:
        now = now_z()
        malware_id = "malware--" + str(uuid.uuid4())
        objs.append({"type": "malware", "spec_version": "2.1", "id": malware_id,
                     "created": now, "modified": now, "name": iocs.family,
                     "is_family": True, "labels": ["trojan"]})

    def esc(v):
        return v.replace("'", "\\'")

    patterns = []
    for v in sorted(iocs.ipv4):
        patterns.append((f"[ipv4-addr:value = '{esc(v)}']", f"IP {v}"))
    for v in sorted(iocs.domain):
        patterns.append((f"[domain-name:value = '{esc(v)}']", f"domain {v}"))
    for v in sorted(iocs.url):
        patterns.append((f"[url:value = '{esc(v)}']", f"URL {v}"))
    for v in sorted(iocs.sha256):
        patterns.append((f"[file:hashes.'SHA-256' = '{esc(v)}']", f"file {v[:12]}"))
    for v in sorted(iocs.md5):
        patterns.append((f"[file:hashes.MD5 = '{esc(v)}']", f"file md5 {v[:12]}"))

    for pattern, name in patterns:
        ind = _ind(pattern, name)
        objs.append(ind)
        if malware_id:
            now = now_z()
            objs.append({"type": "relationship", "spec_version": "2.1",
                         "id": "relationship--" + str(uuid.uuid4()),
                         "created": now, "modified": now,
                         "relationship_type": "indicates",
                         "source_ref": ind["id"], "target_ref": malware_id})

    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}


# --------------------------------------------------------------------------- #
def selftest():
    iocs = extract(SAMPLE_REPORT)
    assert iocs.family == "AgentTesla"
    assert "203.0.113.10" in iocs.ipv4 and "8.8.8.8" not in iocs.ipv4
    assert "evil-c2.example" in iocs.domain and "microsoft.com" not in iocs.domain
    assert "http://evil-c2.example/panel" in iocs.url
    misp = build_misp_event(iocs)
    assert misp["Event"]["Attribute"]
    stix = build_stix_bundle(iocs)
    assert any(o["type"] == "malware" for o in stix["objects"])
    assert any(o["type"] == "indicator" for o in stix["objects"])
    json.dumps(misp); json.dumps(stix)
    ok("selftest passed")
    print("  IOC summary:", iocs.summary(), "| family:", iocs.family)


def main(argv=None):
    p = argparse.ArgumentParser(description="Export a CAPE analysis to MISP + STIX.")
    p.add_argument("command", nargs="?", default="export",
                   choices=["export", "selftest"])
    p.add_argument("--task", type=int)
    p.add_argument("--report-file")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--token", default="")
    p.add_argument("--misp-url"); p.add_argument("--misp-key")
    p.add_argument("--outdir", default="./export")
    args = p.parse_args(argv)

    if args.command == "selftest":
        selftest(); return

    report = load_report(args.report_file, args.task, args.url, args.token)
    iocs = extract(report)
    ok(f"Extracted IOCs: {iocs.summary()} | family: {iocs.family}")

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    tid = iocs.meta.get("task_id") or "report"

    misp_event = build_misp_event(iocs)
    if args.misp_url and args.misp_key:
        try:
            push_misp(misp_event, args.misp_url, args.misp_key)
        except Exception as e:  # noqa: BLE001
            warn(f"MISP push failed ({e}); writing JSON instead.")
            (outdir / f"task-{tid}-misp.json").write_text(json.dumps(misp_event, indent=2))
    else:
        mp = outdir / f"task-{tid}-misp.json"
        mp.write_text(json.dumps(misp_event, indent=2))
        ok(f"MISP event JSON -> {mp}")

    stix = build_stix_bundle(iocs)
    sp = outdir / f"task-{tid}-stix.json"
    sp.write_text(json.dumps(stix, indent=2))
    ok(f"STIX 2.1 bundle -> {sp}  (import into OpenCTI)")


if __name__ == "__main__":
    main()
