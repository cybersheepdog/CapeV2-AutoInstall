# CAPEv2 Automated Deployment + `capevm` Guest Builder

[![Build Status](https://img.shields.io/badge/platform-Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/CapeV2-AutoInstall.svg?style=flat-square)](https://github.com/cybersheepdog/CapeV2-AutoInstall/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/CapeV2-AutoInstall)

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

## Virtualization stack: distro vs. source (`HOST_MODE`)

The `host` stage sets up KVM/QEMU/libvirt. It has two modes:

- **`HOST_MODE=distro` (default, recommended).** Installs `qemu-system-x86`,
  `libvirt-daemon-system`, `virtinst`, etc. from Ubuntu's repos. These track your
  kernel and self-heal on `apt upgrade` — no `/usr/local` drift. `capevm.py` still
  applies all the domain-level stealth (SMBIOS/DMI spoof, hidden hypervisor bit,
  real-OUI MAC, CPU topology, DIMM/disk strings, decoy profile), so you keep the
  anti-detection that matters.
- **`HOST_MODE=source` (opt-in).** Runs CAPE's `kvm-qemu.sh` to build a patched
  QEMU/SeaBIOS from source, adding deeper firmware-string patches. The trade-off
  is fragility: the source build installs into `/usr/local`, and every kernel or
  libvirt update can desync it (missing libs, `libvirt.so` version mismatches,
  emulator/ROM path issues). Only choose this if you need those firmware patches
  and are prepared to manage `/usr/local` drift yourself.

Set it in `sandbox.conf` (`HOST_MODE="distro"`) or inline: `sudo HOST_MODE=source ./cape-deploy.sh host`.

## Updating a sandbox host

A malware-analysis host should stay patched, but it should **not** blindly
auto-upgrade its kernel and virtualization stack — a surprise kernel + reboot is
how you end up with no display, no `virbr0`, or a broken driver mid-analysis.

Apply the recommended policy (opt-in — it changes unattended-upgrades behavior):
```
sudo ./cape-deploy.sh update-policy
```
This keeps **security updates auto-installing**, but excludes the kernel and
qemu/libvirt from the *unattended* timer and disables auto-reboot. Those packages
remain fully updatable — you just apply them **by hand, deliberately**, during a
maintenance window with no analysis running.

**Post-kernel-update checklist** (run after `sudo apt upgrade` pulls a new kernel):
1. Confirm DKMS/driver modules rebuilt for the new kernel (if you run a GPU
   driver): `dkms status` and `ls /lib/modules/$(uname -r)/`.
2. Reboot deliberately: `sudo reboot`.
3. After boot, verify the stack: `sudo virsh net-start default` (should already be
   autostarted), `ip -br link show virbr0` (UP), `nvidia-smi` if applicable.
4. Re-check MongoDB — a new kernel can cross the 8.0 incompatibility line; the
   `deps` stage handles it, or just run `sudo ./cape-deploy.sh deps`.
5. Smoke-test: `sudo ./cape-deploy.sh smoketest`.

On `HOST_MODE=distro`, most of this self-heals; on `HOST_MODE=source` you may also
need to reconcile the `/usr/local` qemu/libvirt build after a libvirt update.

## Troubleshooting

> **What the installer handles for you.** The `deps` stage (part of `all`, or run
> standalone with `sudo ./cape-deploy.sh deps`) installs and configures the
> runtime pieces the official CAPE/KVM installers don't reliably leave working:
> `qemu-img`/`virtinst`/`xorriso`, a **traversable `/etc/poetry`** (else services
> die with `203/EXEC`), **`libvirt-python`** in CAPE's venv (else the scheduler
> throws `ModuleNotFoundError: libvirt`), common processing deps, a patched
> **oscrypto** (else static/report processing fails on OpenSSL 3.x), and a
> **kernel-aware MongoDB** (MongoDB 8.0 crashes on Linux kernel 6.19+ per
> SERVER-121912, so on affected kernels it installs MongoDB 7.0 instead). The
> `register` stage sets both `machinery = kvm` (exactly once) and the
> `[resultserver] ip` in `cuckoo.conf`. Most of the failures below are therefore
> handled automatically now — they're kept for reference and manual recovery.

**Report page: "Report doesn't exist anymore! Or maybe just target data is missing"**
The task shows `reported` and the Mongo doc exists, but the report page errors and
the doc is missing its `target`/`static` sections. Cause: `oscrypto` (a CAPE
dependency) can't parse OpenSSL 3.x version strings on Ubuntu 24.04 and raises
`LibraryNotFoundError: Error detecting the version of libcrypto`, so CAPE's
static/CAPE processing modules fail to import and write an incomplete report. Fix:
`sudo -u cape bash -c 'cd /opt/CAPEv2 && /etc/poetry/bin/poetry run pip install --force-reinstall --no-deps "oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437"'`
then `sudo systemctl restart cape-processor cape-web` and **re-run the analysis**
(existing reports written while it was broken stay incomplete). The `deps` stage
now does this automatically.


**`cape.service` crash-loops with `Failed to execute /etc/poetry/bin/poetry: Permission denied` (203/EXEC)**
`/etc/poetry` isn't traversable by the non-root `cape` user. Fix:
`sudo chmod -R o+rX /etc/poetry`. (The `deps` stage does this.)

**`configparser.DuplicateOptionError: option 'machinery' ... already exists`**
`cuckoo.conf` has two `machinery =` lines. Keep one:
`sudo sed -i '/^machinery *=/d' /opt/CAPEv2/conf/cuckoo.conf && sudo sed -i '/^\[cuckoo\]/a machinery = kvm' /opt/CAPEv2/conf/cuckoo.conf`.
(The `register` stage now does this idempotently.)

**`ModuleNotFoundError: No module named 'libvirt'` (scheduler/processor)**
`libvirt-python` isn't in CAPE's venv. Install build deps then the binding:
`sudo apt install -y pkg-config libvirt-dev python3-dev` then
`sudo -u cape bash -c 'cd /opt/CAPEv2 && /etc/poetry/bin/poetry run pip install libvirt-python'`.
(The `deps` stage does this.)

**`mongod` won't start: "Linux kernel versions 6.19 and newer has a known incompatibility" (SERVER-121912)**
MongoDB 8.0+ refuses to start on kernel 6.19+. Use MongoDB **7.0** (jammy repo runs
on noble). The `deps` stage detects the kernel and installs 7.0 automatically.

**`qemu-system-x86_64` symlink loop / "unable to find any emulator" after a source build**
`kvm-qemu.sh` may install a suffixed binary (e.g. `-spice`) without symlinking it,
or leave the ROM blobs in `/tmp/qemu-*_builded`. `capevm`'s preflight now detects
this and prints the fix: symlink the real binary to `/usr/bin/qemu-system-x86_64`,
`ldconfig` for `/usr/local/lib`, copy `.../usr/share/qemu` into `/usr/share/`, and
`sudo systemctl restart libvirtd`.

**`CuckooCriticalError: Cannot bind ResultServer on ... :2042`**
The `[resultserver] ip` in `cuckoo.conf` doesn't match a host address (often left at
the default `192.168.1.1`). Set it to `RESULTSERVER_IP`:
`sudo sed -i '/^\[resultserver\]/,/^\[/ s/^ip *=.*/ip = 192.168.122.1/' /opt/CAPEv2/conf/cuckoo.conf`.
(The `register` stage now sets this.)

**`domain '<vm>' already exists` / "disk already in use by other guests"**
A stale domain from a failed build. Rebuild cleanly with
`sudo ./cape-deploy.sh buildvm` after `FORCE=1` (or `capevm.py build --force`),
which tears the old domain/disk down first.

**Agent never comes up (build times out waiting on the agent)**
Open the guest console (VNC on `127.0.0.1`) and check `C:\provision.log`. Usual
causes: the 32-bit Python installer wasn't provided/failed; the static IP didn't
match the libvirt subnet; the NIC isn't named `Ethernet` (adjust the `netsh`
lines in `capevm.py`'s provisioning). Confirm reachability with
`nc -vz <guest-ip> 8000`.

**Unattended install stops at a Windows Setup / OOBE screen**
Fixed in current `capevm`: the answer file supplies the Win10 Pro generic key and
an `oobeSystem` International-Core block that skips region/keyboard/account. A
stray "Networks" flyout can still appear at first desktop — click **No**;
provisioning continues underneath.

**MongoDB and the AVX CPU flag**
MongoDB 5.0+ requires AVX. `cape2.sh` checks for it; on a host without AVX it
falls back to an older Mongo. Your CPU almost certainly has AVX — this only bites
very old/virtualized hosts.

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
