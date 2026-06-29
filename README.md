# CAPEv2 Automated Deployment + `capevm` Guest Builder

Handoff documentation for the two-file pipeline that stands up a CAPEv2 malware
sandbox on KVM and builds stealth-hardened Windows analysis guests.

> ⚠️ **Safety.** This builds infrastructure that **executes live malware**. Deploy
> only on a dedicated, network-isolated, disposable host. You are responsible for
> egress control and isolation of the analysis VMs. Do not run on a workstation or
> anything with routable access to assets you care about.

---

## What's in the box

| File | Role |
| --- | --- |
| `cape-deploy.sh` | Orchestrates the whole host build in idempotent stages. Drives CAPE's **official** installers and `capevm.py`. |
| `capevm.py` | libvirt-native Windows guest builder: unattended install, CAPE agent, anti-detection hardening, snapshot, `kvm.conf` emission. A focused alternative to VMCloak for the KVM path. |
| `netiso.sh` | Fail-closed network isolation for the analysis bridge (nftables). Modes: isolated / simulated / gateway. |
| `smoketest.sh` | End-to-end pipeline check: submits a benign sample and asserts a report comes back. |
| `sandbox.conf` | **Single source of truth** for shared settings. Sourced by the shell scripts, read by `capevm.py`. Edit this instead of each script. |
| `watchdog.sh` | Operational hygiene: disk pressure, dead services, stuck VMs, retention pruning. Install as a systemd timer. |
| `cape-export.py` | Turn a finished analysis into threat intel: extract IOCs + config, push a MISP event, emit a STIX 2.1 bundle for OpenCTI. |
| `capelib.py` | Shared library: CAPE report loading, IOC extraction, safelists. Imported by `cape-export.py` and `rulegen.py`. |
| `rulegen.py` | Generate **draft** detection rules from an analysis — Suricata, YARA, and Sigma. `--validate` tests each draft against the analysis' own pcap/files. Review before deploying. |
| `navlayer.py` | Build a MITRE ATT&CK Navigator layer (JSON) from report signatures + Sigma `attack.*` tags to visualise detection coverage. |

Keep both files in the same directory (or set `CAPEVM=/path/to/capevm.py`).

---

## How it fits together

```
cape-deploy.sh  (host orchestration)
   ├── host       → git clone CAPEv2 + installer/kvm-qemu.sh   (KVM + anti-VM source patches)
   ├── cape       → cape-config.sh override + installer/cape2.sh base
   ├── community  → utils/community.py -waf   (signatures/parsers)
   ├── dmi        → capevm.py clone-dmi        (optional: clone a real machine's SMBIOS)
   ├── buildvm    → capevm.py build (per VM)   (install → agent → stealth → snapshot)
   ├── register   → write conf/kvm.conf + cuckoo.conf machinery=kvm
   ├── netiso     → fail-closed network isolation on the analysis bridge
   ├── services   → restart cape / cape-processor / cape-web / cape-rooter
   ├── verify     → read-only health check
   └── smoketest  → submit a benign sample, assert a report returns
```

The two anti-detection layers are complementary and you want **both**:

- **Host layer** — CAPE's `kvm-qemu.sh` patches QEMU/SeaBIOS *source* to strip
  firmware/ACPI strings (`BOCHS`, `QEMU`, etc.). Run during the `host` stage.
- **Guest/domain layer** — `capevm.py` hides the hypervisor CPUID bit, the KVM
  signature and Hyper-V leaks, spoofs SMBIOS/DMI, uses a real-vendor MAC OUI and
  disk serial, avoids virtio driver tells, and ejects install media before
  snapshot. Applied during `buildvm`.

Neither layer alone is sufficient; stealth raises detection cost, it is not
invisibility.

---

## Prerequisites

- **Ubuntu 24.04 LTS** host (CAPE's officially supported platform).
- CPU virtualization (VT-x/AMD-V). If the host is itself a VM, enable **nested**
  virtualization.
- ~200 GB+ free disk (images, memory dumps, PCAPs grow fast).
- A **Windows install ISO** (e.g. Win10 x64).
- A **32-bit (x86) Python 3 installer** `.exe` — CAPE's in-guest monitor hooks
  require x86 Python in the guest.
- (Optional) A `dmidecode` dump from a **reference machine you own**, to clone a
  realistic hardware identity.

---

## Quick start

```bash
# 1. Put both files together and make them executable
chmod +x cape-deploy.sh capevm.py

# 2. Edit the CONFIG block at the top of cape-deploy.sh (see table below)

# 3. (optional) Capture a reference identity on a machine you own
sudo dmidecode > reference-dmi.txt    # copy this file to the CAPE host

# 4. Run everything
sudo ./cape-deploy.sh all

# …or run individual stages
sudo ./cape-deploy.sh dmi buildvm verify
```

The first full run is **long**: `kvm-qemu.sh` recompiles QEMU/SeaBIOS, and each
VM does a full unattended Windows install. Watch the first guest over VNC
(`virt-viewer`/VNC on `127.0.0.1`) to confirm the answer file and provisioning
land correctly.

---

## Configuration reference

> **Edit `sandbox.conf`, not the scripts.** Every script keeps built-in defaults
> and sources `sandbox.conf` (if present) to override them, so one file drives the
> whole toolkit. Precedence is: script default → `sandbox.conf` → explicit CLI
> flag. If `sandbox.conf` is absent, everything still runs on its defaults.

### `cape-deploy.sh` (top-of-file block)

| Variable | Meaning |
| --- | --- |
| `CAPE_USER` / `CAPE_ROOT` | Service account and install dir (`cape` / `/opt/CAPEv2`). |
| `DB_PASSWORD` | PostgreSQL password for the CAPE DB. **Change it.** |
| `MONGO_ENABLE` | `1` to enable the Mongo-backed web UI. |
| `NETWORK_IFACE` / `RESULTSERVER_IP` | libvirt network the guests use + the host IP they call back to. **Keep these consistent** — mismatch is the #1 cause of failed analyses. |
| `RESULTSERVER_PORT` / `WEB_PORT` | Ports the `verify` stage checks (default `2042` / `8000`). |
| `CAPEVM` | Path to `capevm.py` (defaults to alongside the script). |
| `INSTALL_ISO` | Windows install ISO. |
| `PYTHON_INSTALLER` | 32-bit Python `.exe` injected into the guest. |
| `AGENT_PY` | CAPE agent (`$CAPE_ROOT/agent/agent.py`, present after `cape`). |
| `VM_BRIDGE` | Bridge the guests attach to (defaults to `NETWORK_IFACE`). |
| `VM_CPUS` / `VM_RAM_MB` / `VM_DISK_GB` | Guest specs. Defaults are deliberately realistic (tiny VMs are a sandbox tell). |
| `BUILD_TIMEOUT_MIN` | How long to wait for the agent before giving up. |
| `SMBIOS_PROFILE` | `dell` or `lenovo` preset (used when no DMI clone). |
| `REFERENCE_DMI` | Path to a saved `dmidecode` dump to clone. Empty = use preset. |
| `DMI_PROFILE` | Where the clone is written / read. |
| `DMI_KEEP_SERIALS` | `1` clones exact serials/UUID; else regenerated per VM. |
| `VM_LIST` | Inventory: `name|ip|snapshot|tags` per line. `name` == libvirt domain == CAPE label. |

### `capevm.py` (CLI)

```
capevm.py <command> [options]

commands:
  build       install + provision + stealth + snapshot (end to end)
  install     just the unattended install
  stealth     re-define an existing domain with the hardened XML
  eject       remove CD-ROM media from a domain
  wait        block until the agent answers
  snapshot    take the named live snapshot
  genconf     print the kvm.conf stanza
  clone-dmi   read a machine's SMBIOS into a reusable JSON profile
  selftest    validate the XML transform + DMI parser (no host needed)
  destroy     tear down a domain + disk

key options:
  --name --ip --snapshot --tags --bridge --resultserver-ip
  --install-iso --agent-py --python-installer
  --cpus --ram-mb --disk-gb --timeout-min
  --smbios-profile {dell,lenovo}
  --dmi-profile FILE  --keep-dmi-serials      (identity spoofing)
  --from-file FILE  --out FILE                (clone-dmi I/O)
```

---

## Presenting more CPU / RAM (and making it look real)

Tiny VMs are a sandbox tell, so you generally want to show generous specs. Two
separate things are going on — assigning resources, and making them look like
real hardware:

- **Amount.** KVM lets you *overcommit*: assign more vCPUs/RAM than the host
  physically has (`--cpus 8`, `--ram-mb 16384`, or `VM_CPUS` / `VM_RAM_MB`). From
  inside the guest these numbers are genuinely real — `NUMBER_OF_PROCESSORS`,
  `Win32_Processor`, and `GlobalMemoryStatusEx` all report the assigned values,
  which is exactly what survives malware checks. To afford large RAM beyond host
  free memory, back it with **swap** and enable **KSM** (`ksmtuned`) so identical
  pages across guests dedup.
  > You can't cleanly report *more than you assigned* — `/proc/meminfo` and the
  > memory APIs reflect the allocation, and any mismatch is itself a detectable
  > tell. So you assign more (overcommit); you don't fake-report more.

- **Realism — `--realistic-hw` (or `REALISTIC_HW=1`).** Beyond the raw count,
  this makes the specs look like a real machine:
  - a believable **CPU topology** derived from `--cpus` (e.g. 8 vCPUs become
    1 socket × 4 cores × 2 threads, instead of 8 flat sockets — a classic VM
    giveaway). Native libvirt `<topology>`, always applied.
  - realistic **DIMM vendor strings** via SMBIOS Type 17 (manufacturer, part,
    speed, serial) so `Win32_PhysicalMemory` shows e.g. a Samsung/Hynix DDR4
    module rather than a QEMU placeholder. This sets vendor strings only — **not
    size**, so the hardware view stays consistent with assigned RAM.
  - a realistic **disk/optical model** (e.g. `Samsung SSD 870 EVO` instead of
    `QEMU HARDDISK`) via `-global` overrides, and the GPU switched off the
    `Red Hat QXL` vendor tell to a generic **VGA** adapter.

  The qemu bits (DIMM + disk/optical model) go in through `qemu:commandline`
  (libvirt's `<sysinfo>` only covers SMBIOS blocks 0–2, no memory device). If a
  given libvirt rejects that, `capevm` automatically redefines with the CPU
  topology + VGA only — the build never breaks. Enable per-build with
  `--realistic-hw`, or for the whole fleet with `REALISTIC_HW="1"`.

  > **Chassis consistency:** the built-in profiles are desktops (Dell OptiPlex,
  > Lenovo ThinkCentre), so no battery is expected. Avoid laptop DMI profiles —
  > x86 QEMU can't cleanly emulate an ACPI battery, and a laptop with no battery
  > is itself a tell. (A fake battery needs a custom SSDT table, which is out of
  > scope here.)

## Looking lived-in (decoy profile)

A pristine guest is a tell — evasive families check for recent documents, file
counts, installed-program lists, browser artifacts, and a non-default owner.
Windows builds seed a **lived-in profile** by default (`--decoy`, disable with
`--no-decoy` or `DECOY=0`):

- a populated user profile (`C:\Users\<name>` with Documents / Desktop /
  Downloads / Pictures and realistically-sized files),
- `Uninstall` registry keys for common apps (Chrome, 7-Zip, VLC, Firefox,
  Notepad++) so the installed-program list isn't empty,
- Chrome/Edge **Bookmarks** files and Explorer typed-path MRUs,
- `RegisteredOwner` / `RegisteredOrganization` set to a realistic name.

Optionally make the disk look used with `--decoy-fill-mb N` (or `DECOY_FILL_MB`):
it writes an `N`-MB zero-filled file, so the **guest** sees less free space while
the qcow2/snapshot on the host stays small (zeros don't consume image space). A
120 GB disk reporting 98% free is a classic sandbox signal.

## Cloning a real hardware identity

Generic SMBIOS presets are fine for casual use, but sophisticated malware
cross-checks DMI against known-good OEM patterns. To spoof a **real** machine you
own:

```bash
# on the reference machine
sudo dmidecode > reference-dmi.txt

# on the CAPE host
capevm.py clone-dmi --from-file reference-dmi.txt --out /opt/capevm/work/dmi-profile.json
capevm.py build --dmi-profile /opt/capevm/work/dmi-profile.json --name win10x64_1 ...
```

By default the vendor/model/BIOS strings are cloned but serials and UUID are
**regenerated uniquely per VM** (identical serials across guests is itself an
anomaly). Add `--keep-dmi-serials` to clone them verbatim.

---

## Self-signed HTTPS (optional)

The CAPE web UI runs HTTP by default. To put self-signed TLS in front of it, pass
`--tls` (or set `ENABLE_TLS=1` in `sandbox.conf`):

```bash
sudo ./cape-deploy.sh all --tls          # full build with HTTPS on the UI
sudo ./cape-deploy.sh tls                # add/refresh TLS on an existing install
```

The `tls` stage:
- generates a self-signed cert (`openssl`, SAN includes `TLS_SERVER_NAME` and the
  host IP, validity `TLS_DAYS`),
- installs an nginx vhost terminating TLS on **:443** and proxying to the existing
  web socket on `127.0.0.1:$WEB_PORT` (with a :80→:443 redirect unless
  `TLS_REDIRECT_HTTP=0`), and
- patches Django so it accepts the HTTPS origin: appends an idempotent block
  setting `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, secure cookies, and
  `SECURE_PROXY_SSL_HEADER` (originals backed up first).

It is safe to re-run: existing cert, vhost, and settings block are detected and
left alone, and if `nginx -t` fails the vhost is removed rather than left broken.

**The local automation is unchanged** — `smoketest.sh`, `cape-export.py`, and
`navlayer.py` keep talking to `http://127.0.0.1:$WEB_PORT`, so they need no flags.
Only human browsers go through HTTPS (and will see the expected self-signed
warning). If you ever force the API clients through the HTTPS endpoint instead,
`curl` needs `-k` and the Python clients need an unverified context or a `--cafile`.

Relevant `sandbox.conf` keys: `ENABLE_TLS`, `TLS_SERVER_NAME`, `TLS_CERT`,
`TLS_KEY`, `TLS_DAYS`, `TLS_REDIRECT_HTTP`.

> Self-signed is fine for an **isolated, internal** sandbox you control — pair it
> with `netiso.sh` and never expose the CAPE UI publicly; it's an admin surface
> that can submit and detonate malware. `ALLOWED_HOSTS` is set to `['*']` on the
> assumption the host is isolated; narrow it if your deployment differs.

## Troubleshooting

**`CuckooCriticalError: Cannot bind ResultServer on port 2042`**
The result-server IP/interface isn't up or is mismatched. Ensure `RESULTSERVER_IP`
is an address on `NETWORK_IFACE`, the bridge is up (`ip link show virbr0`), and
nothing else holds the port (`ss -lntp | grep 2042`).

**Agent never comes up (build times out waiting on the agent)**
Open the guest console (VNC on `127.0.0.1`) and check `C:\provision.log`. Usual
causes: the 32-bit Python installer wasn't provided/failed; the static IP didn't
match the libvirt subnet; the NIC isn't named `Ethernet` (adjust the `netsh`
lines in `capevm.py`'s provisioning). Confirm reachability with
`nc -vz <guest-ip> 8000`.

**Unattended install stops asking for an edition/key**
The `autounattend.xml` `InstallFrom` value (`Windows 10 Pro`) must match an
edition in your ISO, or a product key is required. Edit `render_autounattend()`
in `capevm.py`, or remove the `InstallFrom` block to let Setup choose.

**`virsh snapshot-list` shows no snapshot / `verify` flags it missing**
The snapshot is only taken if the agent answered after the stealth reboot. Fix
provisioning, then run `capevm.py snapshot --name <vm>` once it's up.

**MongoDB won't install / "Mongo >= 5 is not supported"**
`cape2.sh` checks for the AVX CPU flag. On hosts without AVX it falls back to
Mongo 4.4; pass `--disable-mongodb-avx-check` to `cape2.sh` only if you know what
you're doing.

**`PermissionError: .../log/cuckoo.log` or qcow2 "not readable"**
Ownership drift. Most things run as the `cape` user; only the rooter runs as
root. Re-`chown -R cape:cape $CAPE_ROOT` and ensure the libvirt/qemu user can
read the disk images under `/var/lib/libvirt/images`.

**Malware still detects the VM**
Confirm `kvm-qemu.sh` actually ran (host-layer patching), prefer a cloned real
DMI over a preset, raise specs, and enable CAPE's own anti-evasion: the
`human_windows` auxiliary, sleep-skipping, and YARA-driven debugger bypasses.

---

## Upgrades & maintenance

- **CAPE:** `cd $CAPE_ROOT && git pull`, then restart the services.
- **Community sigs:** `sudo ./cape-deploy.sh community` (or `utils/community.py -waf`).
- **Rebuild a guest:** `capevm.py destroy --name <vm>` then `buildvm` again. DMI
  fingerprints are deterministic per VM name, so a rebuild reproduces the same
  identity.
- Keep your installer logs — they're the fastest way to diagnose a broken
  upgrade.

---

## Honest limitations

- `capevm.py`'s SMBIOS presets are plausible, not real-machine clones — clone a
  reference machine for serious work.
- The deepest fingerprints (RDTSC timing, firmware/ACPI OEM strings) are a
  host-layer concern handled by `kvm-qemu.sh`, not the guest builder.
- The in-guest provisioning script runs blind; validate it over VNC on the first
  build before trusting `build` unattended.
- This automates the supported install path but does not turn CAPE into a
  hardened, monitored, highly-available production service — that's a separate
  layer of work (network isolation, observability, backup/retention, HA).
