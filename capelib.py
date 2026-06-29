#!/usr/bin/env python3
"""capelib.py — shared helpers for the CAPE tooling.

Report loading (apiv2 or local file), IOC extraction, classification, and the
safelist live here so cape-export.py and rulegen.py share one implementation.
Importable (no hyphen in the name).
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

# Obvious sandbox/OS noise. Extend for your environment.
SAFELIST_DOMAINS = {
    "microsoft.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com",
    "windows.com", "office.com", "bing.com", "live.com", "digicert.com",
    "verisign.com", "google.com", "gstatic.com", "ubuntu.com", "canonical.com",
}
SAFELIST_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "8.8.4.4"}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def warn(m): print(f"[!] {m}", file=sys.stderr)
def ok(m): print(f"[+] {m}")
def die(m): print(f"[-] {m}", file=sys.stderr); sys.exit(1)


# --------------------------------------------------------------------------- #
def http_get(url: str, token: str = "") -> bytes:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Token {token}")
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (trusted local)
        return r.read()


def load_report(report_file: str | None = None, task: int | None = None,
                url: str = "http://127.0.0.1:8000", token: str = "") -> dict:
    if report_file:
        return json.loads(Path(report_file).read_text())
    if task is None:
        die("provide --task <id> or --report-file <path>")
    u = f"{url.rstrip('/')}/apiv2/tasks/get/report/{task}/?format=json"
    raw = json.loads(http_get(u, token))
    return raw.get("data", raw)


def classify(value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    if v.startswith(("http://", "https://")):
        return "url"
    if IPV4_RE.match(v):
        return "ipv4"
    if DOMAIN_RE.match(v):
        return "domain"
    return None


def domain_safelisted(d: str) -> bool:
    d = (d or "").lower()
    return any(d == s or d.endswith("." + s) for s in SAFELIST_DOMAINS)


def ip_safelisted(ip: str) -> bool:
    return ip in SAFELIST_IPS


# --------------------------------------------------------------------------- #
class IOCSet:
    def __init__(self):
        self.ipv4, self.domain, self.url = set(), set(), set()
        self.sha256, self.md5, self.filename = set(), set(), set()
        self.regkey, self.mutex, self.ja3 = set(), set(), set()
        self.family = None
        self.detections = set()
        self.signatures = set()
        self.meta = {}

    def add_value(self, value: str):
        kind = classify(value)
        if kind == "ipv4" and not ip_safelisted(value):
            self.ipv4.add(value)
        elif kind == "domain" and not domain_safelisted(value):
            self.domain.add(value)
        elif kind == "url":
            self.url.add(value)

    def summary(self) -> dict:
        return {k: len(getattr(self, k)) for k in
                ("ipv4", "domain", "url", "sha256", "md5", "filename",
                 "regkey", "mutex", "ja3")}


def _walk_config(obj, iocs: IOCSet):
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_config(v, iocs)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_config(v, iocs)
    elif isinstance(obj, str):
        iocs.add_value(obj)


def extract(report: dict) -> IOCSet:
    iocs = IOCSet()
    info = report.get("info", {}) or {}
    iocs.meta = {
        "task_id": info.get("id"),
        "score": info.get("score"),
        "package": info.get("package"),
        "started": info.get("started"),
    }

    tgt = (report.get("target", {}) or {}).get("file", {}) or {}
    if tgt.get("sha256"):
        iocs.sha256.add(tgt["sha256"])
    if tgt.get("md5"):
        iocs.md5.add(tgt["md5"])
    if tgt.get("name"):
        iocs.filename.add(tgt["name"])

    net = report.get("network", {}) or {}
    for host in net.get("hosts", []) or []:
        iocs.add_value(host if isinstance(host, str) else host.get("ip", ""))
    for d in net.get("domains", []) or []:
        if isinstance(d, dict):
            iocs.add_value(d.get("domain", ""))
            iocs.add_value(d.get("ip", ""))
    for q in net.get("dns", []) or []:
        if isinstance(q, dict):
            iocs.add_value(q.get("request", ""))
            for a in q.get("answers", []) or []:
                iocs.add_value(a.get("data", "") if isinstance(a, dict) else a)
    for h in (net.get("http", []) or []) + (net.get("http_ex", []) or []):
        if not isinstance(h, dict):
            continue
        host = h.get("host", "")
        iocs.add_value(host)
        uri = h.get("uri", "") or h.get("path", "")
        if host and uri:
            scheme = "https" if str(h.get("port")) == "443" else "http"
            iocs.url.add(f"{scheme}://{host}{uri}")
    for t in net.get("tls", []) or []:
        if isinstance(t, dict) and t.get("ja3"):
            iocs.ja3.add(t["ja3"])

    for d in report.get("dropped", []) or []:
        if not isinstance(d, dict):
            continue
        if d.get("sha256"):
            iocs.sha256.add(d["sha256"])
        if d.get("md5"):
            iocs.md5.add(d["md5"])
        if d.get("name"):
            iocs.filename.add(d["name"])
    cape = report.get("CAPE", {}) or {}
    for p in (cape.get("payloads", []) if isinstance(cape, dict) else []) or []:
        if isinstance(p, dict) and p.get("sha256"):
            iocs.sha256.add(p["sha256"])

    beh = (report.get("behavior", {}) or {}).get("summary", {}) or {}
    for k in beh.get("keys", []) or []:
        iocs.regkey.add(k)
    for m in beh.get("mutexes", []) or []:
        iocs.mutex.add(m)

    configs = []
    if isinstance(cape, dict):
        configs = cape.get("configs", []) or cape.get("config", []) or []
    configs = configs or report.get("malconf", []) or []
    for c in configs if isinstance(configs, list) else [configs]:
        if isinstance(c, dict):
            for fam in c.keys():
                if fam and not iocs.family:
                    iocs.family = fam
        _walk_config(c, iocs)

    iocs.family = iocs.family or report.get("malfamily") or info.get("category")
    det = report.get("detections")
    if isinstance(det, str):
        iocs.detections.add(det)
    elif isinstance(det, list):
        for d in det:
            iocs.detections.add(d.get("family") if isinstance(d, dict) else str(d))
    for s in report.get("signatures", []) or []:
        if isinstance(s, dict) and s.get("name"):
            iocs.signatures.add(s["name"])
    iocs.detections.discard(None)
    return iocs


def family_slug(name: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", (name or "unknown")).strip("_") or "unknown"


# Shared synthetic report for selftests.
SAMPLE_REPORT = {
    "info": {"id": 42, "score": 9.2, "package": "exe", "category": "AgentTesla"},
    "target": {"file": {"name": "invoice.exe", "sha256": "a" * 64, "md5": "b" * 32}},
    "network": {
        "hosts": ["203.0.113.10", "8.8.8.8"],
        "domains": [{"domain": "evil-c2.example", "ip": "203.0.113.10"},
                    {"domain": "microsoft.com", "ip": "20.1.2.3"}],
        "dns": [{"request": "evil-c2.example", "type": "A"},
                {"request": "windowsupdate.com", "type": "A"}],
        "http": [{"host": "evil-c2.example", "uri": "/gate.php", "method": "POST",
                  "user-agent": "Mozilla/4.0 (compatible; MSIE)", "port": 80},
                 {"host": "evil-c2.example",
                  "uri": "/a8f3c1d9e0b7a6f5c4d3e2b1/upload", "method": "GET",
                  "port": 80}],
        "tls": [{"ja3": "771,4865-4866,0-23,29-23,0", "sni": "evil-c2.example"}],
    },
    "dropped": [{"name": "payload.dll", "sha256": "c" * 64, "md5": "d" * 32}],
    "CAPE": {"configs": [{"AgentTesla": {"c2": ["http://evil-c2.example/panel"],
                                         "key": "deadbeef"}}],
             "payloads": [{"sha256": "e" * 64}]},
    "behavior": {"summary": {"mutexes": ["Global\\xyz"],
                             "keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"],
                             "executed_commands": [
                                 "\"C:\\Users\\admin\\AppData\\Roaming\\evil.exe\"",
                                 "schtasks /create /tn Updater /tr C:\\evil.exe /sc onlogon /f",
                                 "C:\\Windows\\System32\\svchost.exe -k netsvcs"]}},
    "signatures": [{"name": "stealer_behavior", "ttp": ["T1056.001", "T1547.001"]}],
}
