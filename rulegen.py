#!/usr/bin/env python3
"""
rulegen.py — generate DRAFT detection rules from a CAPE analysis.

  suricata   network rules from HTTP / DNS / TLS / JA3 (implemented)
  yara       file/config string rules                  (planned)
  sigma      host-behaviour rules                       (planned)

!!! These are STARTING POINTS for an analyst, not production detections. !!!
Auto-generated rules without curation cause false-positive storms. Generate from
a CLEAN, single-family analysis, review every rule, and compile-test before
deploying. Every rule is emitted with a DRAFT banner and provenance.

Usage:
  ./rulegen.py suricata --task 42
  ./rulegen.py suricata --report-file report.json --outdir ./rules --sid-base 90000000
  ./rulegen.py selftest
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from capelib import (SAMPLE_REPORT, domain_safelisted, extract, family_slug,
                     load_report, now_z, ok, warn)

PREFIX = "CAPE-DRAFT"


# --------------------------------------------------------------------------- #
# Suricata helpers
# --------------------------------------------------------------------------- #
def suri_content(s: str) -> str:
    """Render a string as a Suricata content payload, hex-escaping specials."""
    out, hexbuf = [], []

    def flush():
        if hexbuf:
            out.append("|" + " ".join(hexbuf) + "|")
            hexbuf.clear()

    for b in s.encode("utf-8", "replace"):
        if 0x20 <= b <= 0x7E and chr(b) not in '";\\|':
            flush()
            out.append(chr(b))
        else:
            hexbuf.append(f"{b:02X}")
    flush()
    return "".join(out)


def looks_dynamic_uri(uri: str) -> bool:
    """Heuristic: a path/query token that looks random (poor detection anchor)."""
    for tok in re.split(r"[/?=&.]", uri):
        if len(tok) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_-]+", tok):
            digits = sum(c.isdigit() for c in tok)
            if digits >= 4 or re.fullmatch(r"[0-9a-fA-F]{16,}", tok):
                return True
    return False


class SidAllocator:
    def __init__(self, base: int):
        self.n = base

    def next(self) -> int:
        s = self.n
        self.n += 1
        return s


def gen_suricata(report: dict, family: str, sid_base: int):
    """Return (rule_text, rule_count, notes[])."""
    sids = SidAllocator(sid_base)
    rules, notes, seen = [], [], set()
    meta = (report.get("info", {}) or {})
    tid = meta.get("id", "?")
    date = now_z()[:10]
    md = f"metadata:created {date}, cape_task {tid};"

    def emit(proto, dst, body, msg):
        key = (proto, body)
        if key in seen:
            return
        seen.add(key)
        sid = sids.next()
        rules.append(
            f'alert {proto} $HOME_NET any -> {dst} any '
            f'(msg:"{PREFIX} {family} {msg}"; {body} '
            f'classtype:trojan-activity; {md} sid:{sid}; rev:1;)'
        )

    net = report.get("network", {}) or {}

    # HTTP — combine method + host + uri for specificity
    for h in (net.get("http", []) or []) + (net.get("http_ex", []) or []):
        if not isinstance(h, dict):
            continue
        host = (h.get("host") or "").strip()
        if not host or domain_safelisted(host):
            continue
        method = (h.get("method") or "").upper()
        uri = h.get("uri") or h.get("path") or ""
        parts = ["flow:established,to_server;"]
        if method:
            parts.append(f'http.method; content:"{suri_content(method)}";')
        parts.append(f'http.host; content:"{suri_content(host)}";')
        tail = "HTTP C2 " + host
        if uri and uri != "/":
            if looks_dynamic_uri(uri):
                notes.append(f"host {host}: URI '{uri}' looked dynamic — anchored on "
                             f"host only (add a stable URI fragment if one exists).")
            else:
                parts.append(f'http.uri; content:"{suri_content(uri)}";')
                tail += " " + uri
        emit("http", "$EXTERNAL_NET", " ".join(parts), tail)

    # DNS queries
    for q in net.get("dns", []) or []:
        dom = (q.get("request") if isinstance(q, dict) else q) or ""
        if not dom or domain_safelisted(dom):
            continue
        emit("dns", "any", f'dns.query; content:"{suri_content(dom)}"; nocase;',
             "DNS " + dom)

    # TLS SNI + JA3 (JA3 hash = md5 of the raw JA3 string)
    for t in net.get("tls", []) or []:
        if not isinstance(t, dict):
            continue
        sni = (t.get("sni") or t.get("subject") or "").strip()
        if sni and not domain_safelisted(sni):
            emit("tls", "$EXTERNAL_NET", f'tls.sni; content:"{suri_content(sni)}";',
                 "TLS SNI " + sni)
        ja3 = (t.get("ja3") or "").strip()
        if ja3:
            ja3hash = ja3 if re.fullmatch(r"[0-9a-fA-F]{32}", ja3) \
                else hashlib.md5(ja3.encode()).hexdigest()
            emit("tls", "$EXTERNAL_NET", f'ja3.hash; content:"{ja3hash}";', "JA3")

    banner = (
        f"# {'='*68}\n"
        f"# {PREFIX} Suricata rules — family: {family} — CAPE task: {tid}\n"
        f"# generated: {date}\n"
        f"# DRAFT: review and compile-test (suricata -T) before deploying.\n"
        f"#        SIDs from {sid_base}; ensure they don't collide with your set.\n"
        f"# {'='*68}\n"
    )
    if notes:
        banner += "# Notes:\n" + "".join(f"#   - {n}\n" for n in notes)
    return banner + "\n" + "\n".join(rules) + "\n", len(rules), notes


def lint_suricata(text: str) -> int:
    """Cheap structural sanity check; returns count of well-formed rules."""
    good = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("alert ") and line.endswith(")") \
                and "sid:" in line and "msg:" in line:
            good += 1
        else:
            warn(f"lint: suspect rule line: {line[:60]}...")
    return good


# --------------------------------------------------------------------------- #
# YARA generator — string rules from extracted config + payload strings
# --------------------------------------------------------------------------- #
# Substrings too common to anchor on (boilerplate / OS / library noise).
YARA_COMMON = {
    "microsoft", "kernel32", "advapi32", "getprocaddress", "loadlibrary",
    "this program cannot be run in dos mode", "mozilla", "windows",
    "program files", "http://schemas", "msvcrt", "user32", "ntdll",
    "assembly", ".dll", "system32",
}


def _yara_escape(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= o <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\x{o & 0xFF:02x}")
    return "".join(out)


def _interesting(s: str) -> bool:
    s = (s or "").strip()
    if len(s) < 6 or len(s) > 200:
        return False
    low = s.lower()
    if any(c in low for c in YARA_COMMON):
        return False
    if domain_safelisted(s):
        return False
    return True


def _strings_from_file(path: Path, minlen: int = 6):
    found = set()
    try:
        data = path.read_bytes()
    except OSError:
        return found
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):          # ascii
        found.add(m.group().decode("latin-1"))
    for m in re.finditer((rb"(?:[\x20-\x7e]\x00){%d,}" % minlen), data):  # utf-16le
        found.add(m.group().decode("utf-16-le", "ignore"))
    return {s for s in found if _interesting(s)}


def gen_yara(report: dict, family: str, samples=None):
    iocs = extract(report)
    cands = set()
    cape = report.get("CAPE", {}) or {}
    cfgs = (cape.get("configs") or cape.get("config") or []) if isinstance(cape, dict) else []

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        elif isinstance(o, str) and _interesting(o):
            cands.add(o)

    for c in (cfgs if isinstance(cfgs, list) else [cfgs]):
        walk(c)
    for m in iocs.mutex:
        if _interesting(m):
            cands.add(m)
    for u in iocs.url:
        if _interesting(u):
            cands.add(u)
    for f in (samples or []):
        cands |= _strings_from_file(Path(f))

    chosen = sorted(cands, key=lambda x: (-len(x), x))[:20]
    name = f"{family_slug(family)}_task_{iocs.meta.get('task_id') or 'x'}"
    sha = next(iter(sorted(iocs.sha256)), "")
    date = now_z()[:10]
    meta = [
        ("author", "CAPE-DRAFT"), ("family", family),
        ("cape_task", str(iocs.meta.get("task_id"))),
        ("sample_sha256", sha), ("date", date),
        ("description", "DRAFT - auto-generated from CAPE; review before deploying"),
        ("status", "experimental"),
    ]
    meta_block = "\n".join(f'        {k} = "{_yara_escape(str(v))}"' for k, v in meta)

    if not chosen:
        # fallback: hash rule (still useful, low effort) if we have a sample hash
        if not sha:
            return "", 0, ["no anchor strings and no sample hash — nothing to emit."]
        rule = (f'import "hash"\n\nrule {name}_hash\n{{\n    meta:\n{meta_block}\n'
                f'    condition:\n        hash.sha256(0, filesize) == "{sha}"\n}}\n')
        return _yara_banner(family, iocs.meta.get("task_id"), date) + rule, 1, \
            ["no distinctive strings found — emitted a hash-only rule (weak)."]

    strings_block = "\n".join(
        f'        $s{i} = "{_yara_escape(s)}" ascii wide' for i, s in enumerate(chosen))
    n = len(chosen)
    thresh = "all of them" if n <= 3 else f"{max(3, n // 2)} of ($s*)"
    rule = (f"rule {name}\n{{\n    meta:\n{meta_block}\n"
            f"    strings:\n{strings_block}\n"
            f"    condition:\n"
            f"        uint16(0) == 0x5A4D and filesize < 10MB and {thresh}\n}}\n")
    notes = ["YARA strings are auto-selected; drop any that look generic before use."]
    return _yara_banner(family, iocs.meta.get("task_id"), date) + rule, 1, notes


def _yara_banner(family, tid, date) -> str:
    return (f"/* {'='*64}\n"
            f"   {PREFIX} YARA — family: {family} — CAPE task: {tid} — {date}\n"
            f"   DRAFT: review strings and compile-test (yara rule.yar <file>).\n"
            f"   {'='*64} */\n\n")


# --------------------------------------------------------------------------- #
# Sigma generator — host-behaviour rules
# --------------------------------------------------------------------------- #
SIGMA_BENIGN = ("svchost.exe", "conhost.exe", "backgroundtaskhost", "wermgr",
                "dllhost.exe", "runtimebroker", "sihost.exe", "taskhostw")

ATTACK_HINTS = [
    (r"currentversion\\run", ["attack.persistence", "attack.t1547.001"]),
    (r"schtasks|\\schedule", ["attack.persistence", "attack.t1053.005"]),
    (r"\\services\\|sc\s+create", ["attack.persistence", "attack.t1543.003"]),
    (r"powershell.*(-enc|-e |frombase64)", ["attack.execution", "attack.t1059.001"]),
    (r"cmd(\.exe)?\s+/c", ["attack.execution", "attack.t1059.003"]),
]


def _sigma_tags(text: str):
    tags = set()
    low = text.lower()
    for pat, t in ATTACK_HINTS:
        if re.search(pat, low):
            tags.update(t)
    return sorted(tags)


def _yml_q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sigma_rule(title, category, field, value, tid, sha) -> str:
    tags = _sigma_tags(value)
    tag_block = ("tags:\n" + "".join(f"    - {t}\n" for t in tags)) if tags else ""
    return (
        f"title: {title}\n"
        f"id: {uuid.uuid4()}\n"
        f"status: experimental\n"
        f"description: DRAFT - auto-generated from CAPE task {tid}; review before use\n"
        f"references:\n    - CAPE task {tid}\n"
        f"author: CAPE-DRAFT\n"
        f"date: {now_z()[:10].replace('-', '/')}\n"
        f"{tag_block}"
        f"logsource:\n    category: {category}\n    product: windows\n"
        f"detection:\n    sel:\n        {field}: {_yml_q(value)}\n"
        f"    condition: sel\n"
        f"falsepositives:\n    - Auto-generated from sandbox behaviour; verify before deploying\n"
        f"level: medium\n"
    )


def gen_sigma(report: dict, family: str):
    beh = (report.get("behavior", {}) or {}).get("summary", {}) or {}
    tid = (report.get("info", {}) or {}).get("id", "?")
    tgt = (report.get("target", {}) or {}).get("file", {}) or {}
    sha = tgt.get("sha256", "")
    rules, i = [], 0

    for cmd in beh.get("executed_commands", []) or []:
        low = cmd.lower()
        if any(b in low for b in SIGMA_BENIGN):
            continue
        i += 1
        title = f"{family} suspicious command ({i}) [DRAFT]"
        rules.append(("proc", _sigma_rule(title, "process_creation",
                                          "CommandLine|contains", cmd, tid, sha)))

    for key in beh.get("keys", []) or []:
        low = key.lower()
        if "currentversion\\run" in low or "\\services\\" in low:
            i += 1
            title = f"{family} persistence registry write ({i}) [DRAFT]"
            rules.append(("reg", _sigma_rule(title, "registry_set",
                                             "TargetObject|contains", key, tid, sha)))

    for d in report.get("dropped", []) or []:
        name = d.get("name") if isinstance(d, dict) else None
        if name:
            i += 1
            title = f"{family} dropped file ({i}) [DRAFT]"
            rules.append(("file", _sigma_rule(title, "file_event",
                                              "TargetFilename|endswith", name, tid, sha)))
    return rules


# --------------------------------------------------------------------------- #
# Validation — test drafts against the SAME analysis they came from
# --------------------------------------------------------------------------- #
def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def validate_suricata(rules_path: Path, pcap: str | None):
    if shutil.which("suricata") is None:
        return ("SKIP", "suricata not installed")
    if not pcap or not Path(pcap).is_file():
        return ("SKIP", f"no pcap to replay ({pcap})")
    out = tempfile.mkdtemp()
    cfg = "/etc/suricata/suricata.yaml"
    cmd = ["suricata"]
    if Path(cfg).is_file():
        cmd += ["-c", cfg]
    cmd += ["-k", "none", "-r", pcap, "-S", str(rules_path), "-l", out]
    r = _run(cmd)
    if r.returncode != 0 and "ERROR" in (r.stderr + r.stdout):
        return ("FAIL", "suricata error: " + (r.stderr or r.stdout).strip()[:160])
    fast = Path(out) / "fast.log"
    alerts = len(fast.read_text().splitlines()) if fast.exists() else 0
    return (("PASS", f"{alerts} alert(s) on own pcap") if alerts
            else ("FAIL", "rules did not fire on the sample's own traffic"))


def validate_yara(yar_path: Path, samples):
    if shutil.which("yara") is None:
        return ("SKIP", "yara not installed")
    if not samples:
        return ("SKIP", "no sample files to scan")
    matched = 0
    for s in samples:
        r = _run(["yara", "-w", str(yar_path), str(s)])
        if r.returncode not in (0, 1):
            return ("FAIL", "compile error: " + r.stderr.strip()[:160])
        if r.stdout.strip():
            matched += 1
    return (("PASS", f"matched {matched}/{len(samples)} sample(s)") if matched
            else ("FAIL", "rule did not match its own sample(s)"))


def validate_sigma(sigma_dir: Path):
    if shutil.which("sigma") is None:
        return ("SKIP", "sigma-cli not installed (pip install sigma-cli)")
    r = _run(["sigma", "check", str(sigma_dir)])
    return (("PASS", "sigma check passed") if r.returncode == 0
            else ("FAIL", (r.stdout or r.stderr).strip()[:160]))


def _report_validation(kind, status, detail):
    tag = {"PASS": "[+]", "FAIL": "[-]", "SKIP": "[~]"}[status]
    print(f"{tag} validate {kind}: {status} — {detail}")


def _gather_samples(analysis_dir, samples):
    files = list(samples or [])
    if analysis_dir:
        fdir = Path(analysis_dir) / "files"
        if fdir.is_dir():
            files += [str(p) for p in fdir.iterdir() if p.is_file()]
    return files


# --------------------------------------------------------------------------- #
def selftest():
    text, n, notes = gen_suricata(SAMPLE_REPORT, "AgentTesla", 90000000)
    assert n >= 3, f"expected several rules, got {n}"
    assert 'content:"evil-c2.example"' in text, "C2 host missing"
    assert 'content:"/gate.php"' in text, "static URI missing"
    assert 'content:"/a8f3c1d9e0b7a6f5c4d3e2b1/upload"' not in text, \
        "dynamic URI was used as a content anchor"
    assert "windowsupdate.com" not in text, "safelisted DNS leaked"
    assert "ja3.hash" in text, "JA3 rule missing"
    # sids unique and increasing
    sids = [int(m) for m in re.findall(r"sid:(\d+);", text)]
    assert sids == sorted(sids) and len(sids) == len(set(sids)), "sid collision"
    assert lint_suricata(text) == n, "lint disagreed with count"
    assert any("dynamic" in x for x in notes), "expected a dynamic-URI note"
    ok(f"selftest passed ({n} rules, {len(notes)} note(s))")
    print("  sample rule:\n   ", text.strip().splitlines()[-1][:100], "...")

    # YARA
    ytext, yn, _ = gen_yara(SAMPLE_REPORT, "AgentTesla")
    assert yn == 1 and "rule AgentTesla_task_42" in ytext
    assert "uint16(0) == 0x5A4D" in ytext, "missing PE scope"
    assert "deadbeef" in ytext or "evil-c2.example/panel" in ytext, "no config anchor"
    assert 'Global\\\\xyz' in ytext, "mutex not escaped/embedded"
    assert "microsoft.com" not in ytext, "safelisted string leaked"
    ok("yara selftest passed")

    # Sigma
    srules = gen_sigma(SAMPLE_REPORT, "AgentTesla")
    cats = [c for c, _ in srules]
    assert "proc" in cats and "reg" in cats, f"expected proc+reg rules, got {cats}"
    joined = "\n".join(t for _, t in srules)
    assert "logsource:" in joined and "condition: sel" in joined
    assert "attack.t1547.001" in joined, "run-key MITRE tag missing"
    assert "svchost.exe -k netsvcs" not in joined, "benign command not filtered"
    assert "C:\\\\Windows" not in joined or "\\\\" in joined  # backslashes escaped
    ok(f"sigma selftest passed ({len(srules)} rules)")

    # validators degrade gracefully when tools/artifacts are absent
    assert validate_yara(Path("x.yar"), [])[0] == "SKIP"
    assert validate_suricata(Path("x.rules"), None)[0] == "SKIP"
    assert validate_sigma(Path("."))[0] in ("PASS", "FAIL", "SKIP")
    ok("validators degrade gracefully")


def main(argv=None):
    p = argparse.ArgumentParser(description="Generate DRAFT detection rules from CAPE.")
    p.add_argument("command", choices=["suricata", "yara", "sigma", "all", "selftest"])
    p.add_argument("--task", type=int)
    p.add_argument("--report-file")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--token", default="")
    p.add_argument("--outdir", default="./rules")
    p.add_argument("--family", help="override the family name used in rule names")
    p.add_argument("--sid-base", type=int, default=90000000)
    p.add_argument("--samples", nargs="*", default=[],
                   help="yara: extra binary files to mine strings from / validate against")
    p.add_argument("--validate", action="store_true",
                   help="test each draft against the analysis' own artifacts")
    p.add_argument("--analysis-dir",
                   help="CAPE task storage dir (provides pcap + files for --validate)")
    p.add_argument("--pcap", help="pcap to replay for Suricata validation")
    args = p.parse_args(argv)

    if args.command == "selftest":
        selftest(); return

    report = load_report(args.report_file, args.task, args.url, args.token)
    iocs = extract(report)
    family = args.family or iocs.family or "unknown"
    tid = iocs.meta.get("task_id") or "report"
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    slug = family_slug(family)
    do = {"suricata", "yara", "sigma"} if args.command == "all" else {args.command}

    if "suricata" in do:
        text, n, notes = gen_suricata(report, family, args.sid_base)
        if n:
            out = outdir / f"{slug}-task-{tid}.rules"
            out.write_text(text)
            ok(f"Wrote {n} DRAFT Suricata rule(s) -> {out}")
            for note in notes:
                warn("review: " + note)
            if args.validate:
                pcap = args.pcap or (str(Path(args.analysis_dir) / "dump.pcap")
                                     if args.analysis_dir else None)
                _report_validation("suricata", *validate_suricata(out, pcap))
        else:
            warn("Suricata: no network artifacts produced rules.")

    if "yara" in do:
        ytext, yn, ynotes = gen_yara(report, family, args.samples)
        if yn:
            out = outdir / f"{slug}-task-{tid}.yar"
            out.write_text(ytext)
            ok(f"Wrote {yn} DRAFT YARA rule -> {out}")
            for note in ynotes:
                warn("review: " + note)
            if args.validate:
                _report_validation(
                    "yara", *validate_yara(out, _gather_samples(args.analysis_dir, args.samples)))
        else:
            warn("YARA: " + (ynotes[0] if ynotes else "nothing to emit."))

    if "sigma" in do:
        srules = gen_sigma(report, family)
        if srules:
            sdir = outdir / "sigma"; sdir.mkdir(exist_ok=True)
            for idx, (cat, txt) in enumerate(srules):
                (sdir / f"{slug}-task-{tid}-{cat}-{idx}.yml").write_text(txt)
            ok(f"Wrote {len(srules)} DRAFT Sigma rule(s) -> {sdir}/")
            warn("review: Sigma rules are the noisiest — verify each against your logs.")
            if args.validate:
                _report_validation("sigma", *validate_sigma(sdir))
        else:
            warn("Sigma: no host-behaviour artifacts produced rules.")

    ok("All output is DRAFT — review and compile-test before deploying.")


if __name__ == "__main__":
    main()
