# CAPEv2 Deployment — Step-by-Step

A linear walkthrough for standing up the sandbox with this toolkit. Stages run in
this order: `preflight → host → cape → community → dmi → buildvm → register →
netiso → services → (tls) → verify → smoketest`.

> ⚠️ This executes **live malware**. Deploy only on a dedicated, disposable,
> network-isolated host with no routable access to anything you care about.

---

## Phase 0 — Host prerequisites

1. Install a dedicated host on **Ubuntu 24.04 LTS** (only officially supported OS).
2. Confirm CPU virtualization: `egrep -c '(vmx|svm)' /proc/cpuinfo` > 0. If the host
   is itself a VM, enable **nested** virtualization.
3. Check AVX: `grep -o avx /proc/cpuinfo | head -1`. No AVX → Mongo falls back to
   4.4 automatically (fine, just be aware).
4. Ensure **≥ 200 GB free disk** (plan 500 GB–1 TB for sustained use).
5. Gather build artifacts and note paths:
   - Windows install ISO (e.g. `win10x64.iso`).
   - A **32-bit (x86) Python 3 installer `.exe`** (required for in-guest hooks).
   - *(Optional)* a `dmidecode` dump from a real machine you own.

## Phase 1 — Stage the files

6. Put all scripts in one directory and make them executable:
   ```bash
   chmod +x cape-deploy.sh capevm.py netiso.sh smoketest.sh watchdog.sh
   ```
   Keep `capevm.py` next to `cape-deploy.sh` (or set `CAPEVM=/path/to/capevm.py`).

## Phase 2 — Configure `sandbox.conf` (edit this, not the scripts)

7. Must-change / key settings:
   - **`DB_PASSWORD`** — change from default.
   - **Networking, keep consistent** (#1 cause of failed analyses): `NETWORK_IFACE`
     / `VM_BRIDGE` (`virbr0`), `RESULTSERVER_IP` (`192.168.122.1`, must be on the
     bridge), `ANALYSIS_SUBNET` (`192.168.122.0/24`).
   - **`INSTALL_ISO`**, **`PYTHON_INSTALLER`** → Phase 0 paths.
   - **`VM_LIST`** → guest inventory `name|ip|snapshot|tags`.
   - Guest specs `VM_CPUS=4` / `VM_RAM_MB=8192` / `VM_DISK_GB=120` (keep generous —
     tiny VMs are a sandbox tell).
   - `ISO_MODE`: `isolated` (default) | `simulated` | `gateway`.
   - *(Optional)* `REALISTIC_HW=1`, `SMBIOS_PROFILE`, `REFERENCE_DMI`, `ENABLE_TLS=1`.

## Phase 3 — (Optional) Real hardware identity

8. On a machine you own: `sudo dmidecode > reference-dmi.txt`, copy to the host, set
   `REFERENCE_DMI` to its path. Skip to use the `dell`/`lenovo` preset.

## Phase 4 — Run the deployment

9. Full build (recommended to watch first guest over VNC):
   ```bash
   sudo ./cape-deploy.sh all          # add --tls for HTTPS on the UI
   ```
   Or stage by stage:
   ```bash
   sudo ./cape-deploy.sh host cape community
   sudo ./cape-deploy.sh dmi buildvm verify
   ```

Stage roles:
- **host** — clone CAPEv2 + run `kvm-qemu.sh` (recompiles QEMU/SeaBIOS for
  host-layer stealth). The long one.
- **cape** — CAPE `cape2.sh` base installer (DB, Mongo, agent, web).
- **community** — signatures/parsers.
- **dmi** — *(optional)* clone SMBIOS identity to JSON.
- **buildvm** — per VM: unattended install → agent + x86 Python → stealth → live
  snapshot. **Watch the first build over VNC (`127.0.0.1`)**; check `C:\provision.log`.
- **register** — write `conf/kvm.conf`, set `machinery=kvm`.
- **netiso** — fail-closed nftables isolation.
- **services** — restart `cape`, `cape-processor`, `cape-web`, `cape-rooter`.

## Phase 5 — Verify

10. `verify` (read-only health: result server `2042`, web `8000`, snapshot present).
11. `sudo ./cape-deploy.sh smoketest` — submit benign sample, assert a report returns.
    Missing snapshot → agent didn't answer post-reboot; fix provisioning, then
    `capevm.py snapshot --name <vm>`.

## Phase 6 — Post-deploy & upkeep

12. *(Optional)* `sudo ./cape-deploy.sh tls` — self-signed UI TLS (isolated host only).
13. Install `watchdog.sh` as a systemd timer (disk, dead services, stuck VMs, retention).
14. Ongoing: `cd /opt/CAPEv2 && git pull` + restart services; `sudo ./cape-deploy.sh
    community` for sigs; rebuild a guest via `capevm.py destroy --name <vm>` then `buildvm`.

---

**Two things that bite people:** run the first `buildvm` attended over VNC before
trusting unattended builds, and confirm `kvm-qemu.sh` actually completed during
`host` — without that patch, guest-layer stealth alone won't hold up.
