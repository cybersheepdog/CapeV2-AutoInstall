# SandBox Roadmap

Planned additions to the CAPEv2 deployment + `capevm` pipeline, ordered by
priority. Status legend: ✅ done · 🔨 in progress · ⬜ planned.

---

## Phase 1 — Safety & correctness (do first)

### ✅ 1. Network isolation — `netiso.sh`
The scripts warn "you own egress control" but don't enforce it. An analysis VM
that can reach the LAN or open internet is how a sandbox becomes an incident.
Fail-closed nftables enforcement on the analysis bridge, with switchable modes:
- **isolated** — guests reach only the result server on the host; everything else
  dropped (incl. guest-to-guest).
- **simulated** — guest traffic redirected to a fake-internet service
  (INetSim/FakeNet) on the host; no real egress.
- **gateway** — controlled egress through a VPN/Tor uplink with a kill-switch
  (egress drops if the tunnel is down).
*Done. Wired into cape-deploy.sh as the `netiso` stage (applied before services).*

### ✅ 2. End-to-end smoke test — `smoketest.sh`
`verify` proves the infrastructure is up; it does not prove the pipeline
*analyzes*. Submit a known-benign sample, wait, and assert a report came back
with the expected processing stages. Turns "services running" into "chain works."
*Done. Wired in as the `smoketest` stage (non-fatal in `all`).*

---

## Phase 2 — Operational hygiene

### ✅ 3. Shared config — `sandbox.conf`
Settings currently live at the top of each script and are duplicated. A single
sourced config (read by the bash scripts and `capevm.py`) removes drift and the
"edited the wrong copy" failure mode.
*Done. All scripts source it; precedence is default → sandbox.conf → CLI flag.*

### ✅ 4. Watchdog + retention — `watchdog.sh`
Catch stuck analyses, dead VMs, and disk pressure; prune old results on a
schedule. The hygiene that keeps a long-running sandbox from silently degrading.
*Done. `check` (read-only) / `reap` (acts) / `install-timer` (systemd, every 30m).*

---

## Phase 3 — Threat-intel value

### ✅ 5. IOC + config exporter — `cape-export.py`
Pull finished analyses, extracted configs, and IOCs from CAPE and push to
OpenCTI / MISP. Converts the sandbox from a detonation box into a feed that wires
into the rest of the tooling (email monitoring, IOC feeds).
*Done. Extracts IOCs+config, pushes a MISP event, emits a STIX 2.1 bundle. Stdlib-only.*

---

## Phase 4 — Detonation coverage

### ✅ 6. Linux guest support in `capevm`
Add Linux guest provisioning (agent + static IP + snapshot) for ELF/script analysis.
*Done. `--platform linux` builds from a `--cloud-image` via a NoCloud cloud-init seed.*

### ✅ 7. Guest matrix
Office/browser/runtime variants for better coverage and to defeat
target-specific evasion.
*Inventory now carries an optional platform field; Linux guests build from a cloud image via cloud-init. Software variants ride on capevm's extra-installer hooks.*

---

## Cross-cutting (applies to everything above)

- **Network isolation precedes "live C2" work.** Never enable `gateway` mode
  without the kill-switch verified.
- **Keep CAPE/Cuckoo3 pieces behind adapters, not deep-merged**, so upstream
  changes don't become merge conflicts. (Ties into the separate architectural
  track below.)
- **Licensing:** Cuckoo3 is EUPL-1.2, CAPE is copyleft from the Cuckoo line.
  Verify obligations before shipping any combined distribution.

---

## Phase 5 — Detection rule generation (`rulegen.py`)

Generate **draft** detections from a clean, single-family analysis. All output is
analyst-review material with provenance + DRAFT banners, never auto-deployed.

### ✅ Suricata generator
Network rules from HTTP (method+host+uri combined), DNS, TLS SNI, and JA3 (hash
computed from the raw string). Safelisted infra excluded; dynamic-looking URIs
flagged and anchored on host only; SIDs allocated from a configurable local range.

### ✅ YARA generator
String/byte rules from CAPE's dumped payloads + extracted config strings, with
goodware filtering and a PE-header/size scope. Anchor on config markers.
*Done. Config + payload strings, hash-rule fallback, `N of` threshold.*

### ✅ Sigma generator
Host-behaviour rules (process_creation / registry_set / file_event) from the
behaviour summary, preferring field combinations and mapping signatures to
MITRE ATT&CK. Needs the heaviest safelisting.
*Done. process_creation/registry_set/file_event, benign-cmd filter, ATT&CK tags.*

Shared plumbing (`capelib.py`) already factored out and used by `cape-export.py`
and `rulegen.py`.

### ✅ Validation + visualisation
`rulegen.py --validate` replays drafts against the analysis' own pcap/files (suricata -r, yara) and runs `sigma check`. `navlayer.py` emits a MITRE ATT&CK Navigator layer from report signatures + Sigma tags for coverage heatmaps.

---

## Separate architectural track — "expand Cuckoo3 with CAPE capabilities"

Larger effort, tracked apart from the deployment tooling above:
1. Port CAPE **config extraction** into Cuckoo3 post-processing (best value/effort).
2. Port **YARA payload classification** + a signature-compat shim.
3. **Dump-based unpacking** (partial, host-side).
4. **capemon + debugger** — either merge into the Cuckoo3 guest, or (preferred)
   federate via a dedicated **"CAPE analysis node"** using Cuckoo3's node model.
5. Wire in **Volatility3 / Suricata** and surface CAPE-style results in the
   Cuckoo3 schema + UI.
