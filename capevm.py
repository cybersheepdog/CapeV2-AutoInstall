#!/usr/bin/env python3
"""
capevm.py — libvirt-native VM builder for CAPEv2 (KVM/QEMU), with anti-detection
hardening so analysis guests don't look obviously like VMs.

Purpose (same as before, now hardened): build a Windows analysis guest on KVM,
install CAPE's agent so it autostarts, scrub the obvious VM fingerprints, bring
the guest to a ready/running state, take the named snapshot CAPE reverts to, and
print the conf/kvm.conf stanza. This is the legitimate, intended job of a sandbox
builder — if the guest is trivially detectable, evasive malware refuses to run
and you observe nothing.

Anti-detection layers added in this version:
  Hypervisor / CPU
    * disable the CPUID hypervisor-present bit (-feature hypervisor)
    * hide the KVM paravirt signature (<kvm><hidden state=on/>)
    * strip Hyper-V enlightenments + hypervclock timer ("Microsoft Hv" leak)
  Firmware / DMI
    * spoof SMBIOS (system/bios/baseboard/chassis) to a realistic OEM identity
      with randomized serials, UUID and asset tag, surfaced via <sysinfo>
  Devices
    * real-vendor MAC OUI instead of the 52:54:00 QEMU range
    * realistic disk serial; SATA+e1000 (no virtio driver tells)
    * EJECT install + seed CD-ROMs before snapshot (removes "QEMU DVD-ROM" + the
      answer file)
  Guest (Windows)
    * rename machine off defaults, hide the agent, add light "lived-in" decoys
    * deliberately does NOT install qemu-guest-agent (a major tell)
  Specs
    * realistic CPU/RAM/disk defaults (tiny VMs are themselves a sandbox signal)

Honest limits (no builder can fix these alone):
  * RDTSC/timing-based VM exits, and OEM strings baked into SeaBIOS/ACPI tables,
    are addressed at the HOST level by CAPE's installer/kvm-qemu.sh, which patches
    QEMU/SeaBIOS source. Run that too. Perfect stealth is unattainable; this is an
    arms race — raise the cost, don't expect invisibility.

================================ SAFETY ====================================
These guests run LIVE MALWARE. Build/run only on a dedicated, network-isolated,
disposable host. You own egress control.

Shells out to: qemu-img, virt-install, virsh, genisoimage/mkisofs/xorriso.
Does NOT require libvirt-python.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    name: str = "win10x64_1"
    ip: str = "192.168.122.101"
    netmask_cidr: int = 24
    gateway: str = "192.168.122.1"
    resultserver_ip: str = "192.168.122.1"
    dns: str = "192.168.122.1"
    bridge: str = "virbr0"
    snapshot: str = "clean"
    agent_port: int = 8000
    tags: str = "x64,win10"

    # Realism defaults: small VMs are a sandbox tell. Bump to taste.
    cpus: int = 4
    ram_mb: int = 8192
    disk_gb: int = 120

    install_iso: str = "/opt/iso/win10x64.iso"
    images_dir: str = "/var/lib/libvirt/images"
    work_dir: str = "/opt/capevm/work"

    agent_py: str = "/opt/CAPEv2/agent/agent.py"
    python_installer: str = ""
    admin_password: str = "cape1234!"
    locale: str = "en-US"

    # Stealth knobs
    smbios_profile: str = "dell"        # dell | lenovo
    platform: str = "windows"           # windows | linux
    cloud_image: str = ""               # base qcow2 cloud image (linux only)
    realistic_hw: bool = False          # present a real-CPU topology + DIMM vendor strings
    decoy: bool = True                  # seed "lived-in" user artifacts (Windows)
    decoy_fill_mb: int = 0              # optional filler so free-space ratio looks used (0=off)
    mac: str = ""                       # explicit MAC; blank => generated real-OUI
    computer_name: str = "DESKTOP-7F3K2Q9"   # avoid sandbox-y names
    dmi_profile: str = ""               # JSON profile from 'clone-dmi' (overrides preset)
    dmi_keep_serials: bool = False      # keep cloned serials/uuid (default: regen per-VM)

    extra_installers: list[str] = field(default_factory=list)
    extra_commands: list[str] = field(default_factory=list)

    @property
    def disk_path(self) -> str:
        return str(Path(self.images_dir) / f"{self.name}.qcow2")

    @property
    def seed_iso(self) -> str:
        return str(Path(self.work_dir) / f"{self.name}-seed.iso")


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"; X = "\033[0m"


def log(m): print(f"{C.B}[*]{C.X} {m}")
def ok(m): print(f"{C.G}[+]{C.X} {m}")
def warn(m): print(f"{C.Y}[!]{C.X} {m}", file=sys.stderr)
def die(m):
    print(f"{C.R}[-]{C.X} {m}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], check: bool = True, quiet: bool = False, capture: bool = False):
    if not quiet:
        log("run: " + " ".join(cmd))
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


def need(tool: str):
    if shutil.which(tool) is None:
        die(f"required tool '{tool}' not found in PATH")


def mkisofs_tool() -> str:
    for t in ("genisoimage", "mkisofs", "xorriso"):
        if shutil.which(t):
            return t
    die("need genisoimage, mkisofs, or xorriso to build the seed ISO")


def _mask(cidr: int) -> str:
    bits = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return ".".join(str((bits >> (8 * (3 - i))) & 0xff) for i in range(4))


# --------------------------------------------------------------------------- #
# Stealth identity generation (deterministic per VM name, so rebuilds match)
# --------------------------------------------------------------------------- #
# Real OUIs (publicly registered vendor prefixes) to replace QEMU's 52:54:00.
_OUIS = {
    "dell":   ["00:14:22", "B8:CA:3A", "D4:BE:D9"],
    "lenovo": ["00:21:CC", "E8:6A:64", "54:EE:75"],
    "intel":  ["00:1B:21", "3C:97:0E", "A0:36:9F"],
}

_PROFILES = {
    "dell": {
        "sys_mfr": "Dell Inc.",
        "sys_product": "OptiPlex 7090",
        "sys_family": "OptiPlex",
        "sys_sku": "0A38",
        "board_mfr": "Dell Inc.",
        "board_product": "0K240Y",
        "bios_vendor": "Dell Inc.",
        "bios_version": "2.18.0",
        "bios_date": "04/12/2023",
    },
    "lenovo": {
        "sys_mfr": "LENOVO",
        "sys_product": "11T8S0XV00",  # ThinkCentre model code; override per your fleet
        "sys_family": "ThinkCentre M70t",
        "sys_sku": "LENOVO_MT_30E0",
        "board_mfr": "LENOVO",
        "board_product": "3140",
        "bios_vendor": "LENOVO",
        "bios_version": "M2KKT4AA",
        "bios_date": "06/20/2023",
    },
}


def _rng(name: str) -> random.Random:
    seed = int(hashlib.sha256(name.encode()).hexdigest(), 16) & 0xffffffff
    return random.Random(seed)


def _svctag(r: random.Random, n: int = 7) -> str:
    a = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    return "".join(r.choice(a) for _ in range(n))


def _uuid(r: random.Random) -> str:
    h = "%032x" % r.getrandbits(128)
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def gen_mac(name: str, profile: str) -> str:
    r = _rng(name + "-mac")
    oui = r.choice(_OUIS.get(profile, _OUIS["intel"]))
    tail = ":".join("%02X" % r.randint(0, 255) for _ in range(3))
    return f"{oui}:{tail}"


def gen_smbios(cfg: Config) -> dict:
    """Build the SMBIOS identity for a VM.

    Base identity comes from a cloned DMI profile (--dmi-profile, produced by
    'clone-dmi') if given, otherwise from a built-in preset. Serials/UUID are
    regenerated deterministically per VM name by default so multiple guests
    don't share one fingerprint; pass --keep-dmi-serials to clone them verbatim.
    """
    r = _rng(cfg.name)
    base = dict(_PROFILES.get(cfg.smbios_profile, _PROFILES["dell"]))
    base.setdefault("sys_version", "01")
    base.setdefault("board_version", "A00")

    real = {}
    if cfg.dmi_profile:
        pf = Path(cfg.dmi_profile)
        if not pf.is_file():
            die(f"--dmi-profile not found: {cfg.dmi_profile}")
        loaded = json.loads(pf.read_text())
        for k, v in loaded.items():
            if k.startswith("_"):
                real[k] = v          # real serials/uuid, kept aside
            elif v:
                base[k] = v          # vendor/model/version strings override preset

    tag = _svctag(r)
    keep = bool(getattr(cfg, "dmi_keep_serials", False))

    def pick(real_key, generated):
        rv = real.get(real_key)
        return rv if (keep and rv) else generated

    return {
        **base,
        "serial": pick("_sys_serial", tag),
        "uuid": pick("_uuid", _uuid(r)),
        "asset": pick("_asset", tag),
        "board_serial": pick("_board_serial", "." + tag + "." + _svctag(r, 4)),
        "chassis_serial": pick("_chassis_serial", tag),
        "disk_serial": "S" + "".join(r.choice("0123456789ABCDEF") for _ in range(15)),
        "mac": cfg.mac or gen_mac(cfg.name, cfg.smbios_profile),
        "sys_version": base["sys_version"],
        "board_version": base["board_version"],
    }


# --- DMI cloning: read a real machine's SMBIOS and emit a reusable profile ---
def parse_dmidecode(text: str) -> dict:
    """Parse `dmidecode -t 0 -t 1 -t 2 -t 3` output into a profile dict.

    Vendor/model/version strings use plain keys; real serials/UUID/asset use
    underscore-prefixed keys so they're only applied when --keep-dmi-serials."""
    prof: dict = {}
    for block in re.split(r"\nHandle ", "\n" + text):
        m = re.search(r"DMI type (\d+)", block)
        if not m:
            continue
        t = int(m.group(1))
        kv = {}
        for line in block.splitlines():
            mm = re.match(r"\t([A-Za-z][A-Za-z /]+):\s*(.*)", line)
            if mm:
                kv[mm.group(1).strip()] = mm.group(2).strip()
        if t == 0:
            prof["bios_vendor"] = kv.get("Vendor", "")
            prof["bios_version"] = kv.get("Version", "")
            prof["bios_date"] = kv.get("Release Date", "")
        elif t == 1:
            prof["sys_mfr"] = kv.get("Manufacturer", "")
            prof["sys_product"] = kv.get("Product Name", "")
            prof["sys_version"] = kv.get("Version", "01")
            prof["sys_sku"] = kv.get("SKU Number", "")
            prof["sys_family"] = kv.get("Family", "")
            prof["_sys_serial"] = kv.get("Serial Number", "")
            prof["_uuid"] = (kv.get("UUID", "") or "").lower()
        elif t == 2:
            prof["board_mfr"] = kv.get("Manufacturer", "")
            prof["board_product"] = kv.get("Product Name", "")
            prof["board_version"] = kv.get("Version", "A00")
            prof["_board_serial"] = kv.get("Serial Number", "")
        elif t == 3:
            prof["_chassis_serial"] = kv.get("Serial Number", "")
            prof["_asset"] = kv.get("Asset Tag", "")
    return prof


def cmd_clone_dmi(cfg: Config, from_file: str, out: str):
    """Clone SMBIOS/DMI from a reference machine into a JSON profile."""
    if from_file:
        text = Path(from_file).read_text()
    else:
        need("dmidecode")
        if os.geteuid() != 0:
            warn("dmidecode usually needs root; output may be empty.")
        text = run(["dmidecode", "-t", "0", "-t", "1", "-t", "2", "-t", "3"],
                   capture=True, quiet=True).stdout
    prof = parse_dmidecode(text)
    if not prof.get("sys_mfr"):
        die("could not parse system info — pass a real `dmidecode` dump via --from-file")
    out = out or str(Path(cfg.work_dir) / "dmi-profile.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    # Drop empty real-serial keys so we don't clone blanks.
    prof = {k: v for k, v in prof.items() if v}
    Path(out).write_text(json.dumps(prof, indent=2))
    ok(f"Wrote DMI profile -> {out}")
    print(f"  system : {prof.get('sys_mfr','?')} {prof.get('sys_product','?')}")
    print(f"  bios   : {prof.get('bios_vendor','?')} {prof.get('bios_version','?')}")
    print(f"  board  : {prof.get('board_mfr','?')} {prof.get('board_product','?')}")
    warn("Use it: build --dmi-profile " + out + "  (add --keep-dmi-serials to clone "
         "exact serials; default regenerates them per VM).")


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
def preflight(cfg: Config):
    log("Preflight")
    if os.geteuid() != 0:
        warn("Not root — virsh/virt-install usually need root or libvirt group.")
    for t in ("qemu-img", "virt-install", "virsh"):
        need(t)
    mkisofs_tool()
    if not Path("/dev/kvm").exists():
        warn("/dev/kvm missing — is KVM enabled / nested virt on?")
    if not Path(cfg.install_iso).is_file():
        die(f"install ISO not found: {cfg.install_iso}")
    Path(cfg.work_dir).mkdir(parents=True, exist_ok=True)
    ok("Preflight passed")


# --------------------------------------------------------------------------- #
# autounattend.xml  (BIOS/MBR, single partition, autologon, run provision)
# --------------------------------------------------------------------------- #
def render_autounattend(cfg: Config) -> str:
    first_logon = (
        r"cmd /c for %d in (C D E F G H I J K L) do "
        r"if exist %d:\provision\provision.cmd "
        r"call %d:\provision\provision.cmd > C:\provision.log 2>&1"
    )
    return textwrap.dedent(f"""\
    <?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend">
      <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE"
            processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
            language="neutral" versionScope="nonSxS">
          <SetupUILanguage><UILanguage>{cfg.locale}</UILanguage></SetupUILanguage>
          <InputLocale>{cfg.locale}</InputLocale>
          <SystemLocale>{cfg.locale}</SystemLocale>
          <UILanguage>{cfg.locale}</UILanguage>
          <UserLocale>{cfg.locale}</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
          <DiskConfiguration>
            <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <DiskID>0</DiskID>
              <WillWipeDisk>true</WillWipeDisk>
              <CreatePartitions>
                <CreatePartition wcm:action="add">
                  <Order>1</Order><Type>Primary</Type><Extend>true</Extend>
                </CreatePartition>
              </CreatePartitions>
              <ModifyPartitions>
                <ModifyPartition wcm:action="add">
                  <Order>1</Order><PartitionID>1</PartitionID>
                  <Active>true</Active><Format>NTFS</Format><Label>Windows</Label>
                </ModifyPartition>
              </ModifyPartitions>
            </Disk>
          </DiskConfiguration>
          <ImageInstall>
            <OSImage>
              <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>
              <InstallFrom>
                <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
                  <Key>/IMAGE/NAME</Key><Value>Windows 10 Pro</Value>
                </MetaData>
              </InstallFrom>
            </OSImage>
          </ImageInstall>
          <UserData>
            <AcceptEula>true</AcceptEula>
            <ProductKey><WillShowUI>OnError</WillShowUI></ProductKey>
          </UserData>
        </component>
      </settings>

      <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
          <OOBE>
            <HideEULAPage>true</HideEULAPage>
            <HideLocalAccountScreen>true</HideLocalAccountScreen>
            <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
            <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
            <ProtectYourPC>3</ProtectYourPC>
            <NetworkLocation>Work</NetworkLocation>
          </OOBE>
          <UserAccounts>
            <AdministratorPassword><Value>{cfg.admin_password}</Value><PlainText>true</PlainText></AdministratorPassword>
          </UserAccounts>
          <AutoLogon>
            <Enabled>true</Enabled><LogonCount>99</LogonCount>
            <Username>Administrator</Username>
            <Password><Value>{cfg.admin_password}</Value><PlainText>true</PlainText></Password>
          </AutoLogon>
          <FirstLogonCommands>
            <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <Order>1</Order>
              <CommandLine>{first_logon}</CommandLine>
              <Description>CAPE provisioning</Description>
            </SynchronousCommand>
          </FirstLogonCommands>
        </component>
      </settings>
    </unattend>
    """)


# --------------------------------------------------------------------------- #
# In-guest provisioning (agent + 32-bit Python + hardening + decoys)
# --------------------------------------------------------------------------- #
def render_decoy_block(cfg: Config) -> str:
    """Batch snippet that seeds 'lived-in' artifacts so the guest doesn't read
    as a pristine sandbox: a populated user profile, installed-app uninstall
    keys, browser bookmarks, recent-path MRUs, and optional disk filler."""
    if not cfg.decoy:
        return 'echo [provision] decoy seeding disabled\n'
    r = _rng(cfg.name + "-decoy")
    first = r.choice(["john", "sarah", "michael", "emily", "david", "laura", "james"])
    last = r.choice(["smith", "johnson", "williams", "brown", "jones", "miller", "davis"])
    user = f"{first[0]}{last}"                       # e.g. jsmith
    full = f"{first.capitalize()} {last.capitalize()}"
    org = r.choice(["Acme Corp", "Contoso Ltd", "Initech", "Globex", "Umbrella Inc"])
    udir = rf"C:\Users\{user}"

    # files: (relative path under the profile, size in bytes)
    files = [
        (r"Documents\budget_2024.xlsx", 48 * 1024),
        (r"Documents\Q3_report.docx", 220 * 1024),
        (r"Documents\resume.docx", 64 * 1024),
        (r"Documents\notes.txt", 4 * 1024),
        (r"Desktop\todo.txt", 2 * 1024),
        (r"Desktop\family.jpg", 1800 * 1024),
        (r"Downloads\invoice_8842.pdf", 130 * 1024),
        (r"Downloads\zoom_installer.exe", 2300 * 1024),
        (r"Pictures\vacation1.jpg", 2600 * 1024),
        (r"Pictures\vacation2.jpg", 2200 * 1024),
    ]
    mk = []
    for sub in ("Documents", "Desktop", "Downloads", "Pictures",
                r"AppData\Roaming\Microsoft\Windows\Recent"):
        mk.append(rf'mkdir "{udir}\{sub}" 2>nul')
    for path, size in files:
        mk.append(rf'fsutil file createnew "{udir}\{path}" {size} >nul 2>&1')
    # a few recent-file stubs bump the Recent count
    for i in range(4):
        mk.append(rf'echo. > "{udir}\AppData\Roaming\Microsoft\Windows\Recent\recent{i}.lnk"')
    files_block = "\n".join(mk)

    # installed-program uninstall keys (commonly checked for "real machine")
    apps = [
        ("Google Chrome", "Google LLC", "126.0.6478.127"),
        ("7-Zip 23.01", "Igor Pavlov", "23.01"),
        ("VLC media player", "VideoLAN", "3.0.20"),
        ("Mozilla Firefox", "Mozilla", "127.0.1"),
        ("Notepad++", "Notepad++ Team", "8.6.7"),
    ]
    unin = "\n".join(
        rf'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{n}" '
        rf'/v DisplayName /d "{n}" /f >nul 2>&1' + "\n" +
        rf'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{n}" '
        rf'/v Publisher /d "{p}" /f >nul 2>&1' + "\n" +
        rf'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{n}" '
        rf'/v DisplayVersion /d "{v}" /f >nul 2>&1'
        for n, p, v in apps)

    # Explorer typed-path MRUs (string values, safe to add)
    typed = "\n".join(
        rf'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" '
        rf'/v url{i} /d "{pth}" /f >nul 2>&1'
        for i, pth in enumerate((rf"{udir}\Documents", rf"{udir}\Downloads",
                                 r"C:\Program Files", rf"{udir}\Pictures"), start=1))

    # registered owner/org
    owner = (
        rf'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" '
        rf'/v RegisteredOwner /d "{full}" /f >nul 2>&1' + "\n" +
        rf'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" '
        rf'/v RegisteredOrganization /d "{org}" /f >nul 2>&1')

    # browser bookmarks (real artifacts; plain JSON written via PowerShell)
    bm_dirs = [
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default",
        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default",
    ]
    bm_json = ('{\\"roots\\":{\\"bookmark_bar\\":{\\"children\\":['
               '{\\"name\\":\\"Gmail\\",\\"type\\":\\"url\\",\\"url\\":\\"https://mail.google.com\\"},'
               '{\\"name\\":\\"Amazon\\",\\"type\\":\\"url\\",\\"url\\":\\"https://amazon.com\\"},'
               '{\\"name\\":\\"News\\",\\"type\\":\\"url\\",\\"url\\":\\"https://bbc.com\\"}'
               '],\\"name\\":\\"Bookmarks bar\\",\\"type\\":\\"folder\\"}},\\"version\\":1}')
    bm = []
    for d in bm_dirs:
        bm.append(rf'mkdir "{d}" 2>nul')
        bm.append(rf'powershell -NoProfile -Command "Set-Content -Path \"{d}\Bookmarks\" '
                  rf'-Value \"{bm_json}\" -Encoding UTF8" 2>nul')
    bm_block = "\n".join(bm)

    fill = ""
    if cfg.decoy_fill_mb and cfg.decoy_fill_mb > 0:
        # zero-filled => cheap in the qcow2, but the GUEST sees the space used
        fill = (rf'echo [provision] filler {cfg.decoy_fill_mb}MB so free-space looks used'
                + "\n" +
                rf'fsutil file createnew C:\hibersave.dat {cfg.decoy_fill_mb * 1024 * 1024} '
                r'>nul 2>&1')

    return textwrap.dedent(rf"""\
    echo [provision] seeding lived-in decoy profile ({user})
    mkdir "{udir}" 2>nul
    {files_block}
    {unin}
    {typed}
    {owner}
    {bm_block}
    {fill}
    """)


def render_provision_cmd(cfg: Config) -> str:
    py = Path(cfg.python_installer).name if cfg.python_installer else ""

    static_ip = textwrap.dedent(rf"""\
    echo [provision] setting static IP {cfg.ip}/{cfg.netmask_cidr}
    netsh interface ip set address name="Ethernet" static {cfg.ip} {_mask(cfg.netmask_cidr)} {cfg.gateway} 1
    netsh interface ip set dns name="Ethernet" static {cfg.dns}
    """)

    if py:
        py_block = textwrap.dedent(rf"""\
        echo [provision] installing 32-bit Python
        start /wait %~dp0{py} /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
        for /d %%P in ("C:\Program Files (x86)\Python3*") do set PYDIR=%%P
        "%PYDIR%\python.exe" -m pip install --no-warn-script-location pillow
        """)
    else:
        py_block = "echo [provision] WARNING: no python_installer provided; install x86 Python manually\n"

    extra = "\n".join(rf"echo [provision] {c}" + "\n" + rf"start /wait %~dp0{c}"
                      for c in cfg.extra_commands)

    return textwrap.dedent(rf"""\
    @echo off
    rem ==== CAPE guest provisioning (generated by capevm.py) ====
    rem Runs once at first logon as Administrator. Log: C:\provision.log
    setlocal enableextensions

    {static_ip}

    {py_block}

    echo [provision] deploying CAPE agent (hidden)
    mkdir C:\agent 2>nul
    copy /y %~dp0agent.py C:\agent\agent.py
    for /d %%P in ("C:\Program Files (x86)\Python3*") do set PYW=%%P\pythonw.exe
    rem Autostart agent at boot as SYSTEM, elevated, no window:
    schtasks /create /tn WindowsTelemetrySvc /ru SYSTEM /sc onstart /rl highest /f ^
      /tr "\"%PYW%\" C:\agent\agent.py"

    echo [provision] renaming machine off default
    powershell -NoProfile -Command "Rename-Computer -NewName '{cfg.computer_name}' -Force" 2>nul

    rem ---- sandbox hygiene: reduce host interference (tune to your threat model) ----
    netsh advfirewall set allprofiles state off
    sc config wuauserv start= disabled
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f 2>nul

    rem ---- "lived-in" artifacts so it doesn't read as a fresh sandbox ----
    {render_decoy_block(cfg)}

    rem !!! Do NOT install qemu-guest-agent / spice tools — they are obvious tells. !!!

    {extra}

    rem Start agent now so the FIRST snapshot pass sees it live; it also autostarts
    rem after the stealth cold-reboot performed by the builder.
    schtasks /run /tn WindowsTelemetrySvc
    echo CAPE_PROVISION_DONE > C:\provision.done
    endlocal
    """)


# --------------------------------------------------------------------------- #
# Seed ISO
# --------------------------------------------------------------------------- #
def build_seed_iso(cfg: Config):
    log("Building seed ISO (answer file + provisioning payload)")
    stage = Path(cfg.work_dir) / f"{cfg.name}-seed"
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "provision").mkdir(parents=True)

    (stage / "autounattend.xml").write_text(render_autounattend(cfg))
    (stage / "provision" / "provision.cmd").write_text(render_provision_cmd(cfg))

    agent_src = Path(cfg.agent_py)
    if not agent_src.is_file():
        die(f"CAPE agent not found at {cfg.agent_py} — point --agent-py at agent/agent.py")
    shutil.copy(agent_src, stage / "provision" / "agent.py")

    if cfg.python_installer:
        src = Path(cfg.python_installer)
        if not src.is_file():
            die(f"python_installer not found: {cfg.python_installer}")
        shutil.copy(src, stage / "provision" / src.name)
    else:
        warn("No --python-installer; guest needs x86 Python installed another way.")

    for inst in cfg.extra_installers:
        p = Path(inst)
        if not p.is_file():
            die(f"extra installer not found: {inst}")
        shutil.copy(p, stage / "provision" / p.name)

    tool = mkisofs_tool()
    if tool == "xorriso":
        cmd = ["xorriso", "-as", "mkisofs", "-J", "-r", "-V", "CAPESEED",
               "-o", cfg.seed_iso, str(stage)]
    else:
        cmd = [tool, "-J", "-r", "-V", "CAPESEED", "-o", cfg.seed_iso, str(stage)]
    run(cmd)
    ok(f"Seed ISO -> {cfg.seed_iso}")


# --------------------------------------------------------------------------- #
# Disk + install
# --------------------------------------------------------------------------- #
def create_disk(cfg: Config):
    if Path(cfg.disk_path).exists():
        warn(f"disk already exists: {cfg.disk_path} (reusing)")
        return
    log(f"Creating qcow2 disk {cfg.disk_path} ({cfg.disk_gb}G)")
    run(["qemu-img", "create", "-f", "qcow2", cfg.disk_path, f"{cfg.disk_gb}G"])


def install(cfg: Config):
    if cfg.platform == "linux":
        install_linux(cfg)
    else:
        install_windows(cfg)


def install_windows(cfg: Config):
    create_disk(cfg)
    build_seed_iso(cfg)
    log("virt-install: unattended Windows install (SATA disk + e1000 NIC)")
    cmd = [
        "virt-install",
        "--name", cfg.name,
        "--memory", str(cfg.ram_mb),
        "--vcpus", str(cfg.cpus),
        "--cpu", "host-passthrough",
        "--machine", "pc",
        "--disk", f"path={cfg.disk_path},format=qcow2,bus=sata",
        "--disk", f"path={cfg.install_iso},device=cdrom,bus=sata",
        "--disk", f"path={cfg.seed_iso},device=cdrom,bus=sata",
        "--network", f"bridge={cfg.bridge},model=e1000",
        "--graphics", "vnc,listen=127.0.0.1",
        "--video", "qxl",
        "--os-variant", "win10",
        "--boot", "cdrom,hd",
        "--noautoconsole",
    ]
    run(cmd)
    ok(f"Domain '{cfg.name}' defined and installing.")


# --------------------------------------------------------------------------- #
# Linux guest: boot a cloud image and provision via cloud-init (NoCloud)
# --------------------------------------------------------------------------- #
def render_cloud_init(cfg: Config) -> tuple[str, str]:
    """Return (user-data, meta-data) for a NoCloud seed."""
    import base64
    agent_src = Path(cfg.agent_py)
    if not agent_src.is_file():
        die(f"CAPE agent not found at {cfg.agent_py}")
    agent_b64 = base64.b64encode(agent_src.read_bytes()).decode()

    netplan = textwrap.dedent(f"""\
        network:
          version: 2
          ethernets:
            cape0:
              match:
                name: "e*"
              dhcp4: false
              addresses: [ "{cfg.ip}/{cfg.netmask_cidr}" ]
              routes:
                - to: default
                  via: {cfg.gateway}
              nameservers:
                addresses: [ {cfg.dns} ]
        """)

    unit = textwrap.dedent("""\
        [Unit]
        Description=CAPE agent
        After=network-online.target
        [Service]
        ExecStart=/usr/bin/python3 /opt/agent/agent.py
        Restart=always
        [Install]
        WantedBy=multi-user.target
        """)

    def indent(s, n):
        pad = " " * n
        return "\n".join(pad + ln for ln in s.splitlines())

    user_data = "#cloud-config\n" + textwrap.dedent(f"""\
        hostname: {cfg.computer_name or cfg.name}
        package_update: false
        write_files:
          - path: /etc/netplan/99-cape.yaml
            permissions: '0600'
            content: |
        {indent(netplan, 6)}
          - path: /opt/agent/agent.py
            encoding: b64
            content: {agent_b64}
          - path: /etc/systemd/system/cape-agent.service
            content: |
        {indent(unit, 6)}
        runcmd:
          - [ netplan, apply ]
          - [ sh, -c, "apt-get update || true" ]
          - [ sh, -c, "apt-get install -y python3 python3-pip || true" ]
          - [ sh, -c, "pip3 install pillow || true" ]
          - [ systemctl, daemon-reload ]
          - [ systemctl, enable, --now, cape-agent ]
        """)
    meta_data = f"instance-id: iid-{cfg.name}\nlocal-hostname: {cfg.name}\n"
    return user_data, meta_data


def build_linux_seed_iso(cfg: Config):
    log("Building NoCloud cloud-init seed (user-data + meta-data)")
    stage = Path(cfg.work_dir) / f"{cfg.name}-cidata"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    ud, md = render_cloud_init(cfg)
    (stage / "user-data").write_text(ud)
    (stage / "meta-data").write_text(md)
    tool = mkisofs_tool()
    label = ["-V", "cidata"]
    if tool == "xorriso":
        cmd = ["xorriso", "-as", "mkisofs", "-J", "-r", *label, "-o", cfg.seed_iso, str(stage)]
    else:
        cmd = [tool, "-J", "-r", *label, "-o", cfg.seed_iso, str(stage)]
    run(cmd)
    ok(f"cloud-init seed -> {cfg.seed_iso}")


def install_linux(cfg: Config):
    if not cfg.cloud_image or not Path(cfg.cloud_image).is_file():
        die("linux platform needs --cloud-image pointing at a base qcow2 cloud image "
            "(e.g. Ubuntu cloud image).")
    if not Path(cfg.disk_path).exists():
        log(f"Cloning cloud image -> {cfg.disk_path} and resizing to {cfg.disk_gb}G")
        shutil.copy(cfg.cloud_image, cfg.disk_path)
        run(["qemu-img", "resize", cfg.disk_path, f"{cfg.disk_gb}G"])
    else:
        warn(f"disk already exists: {cfg.disk_path} (reusing)")
    build_linux_seed_iso(cfg)
    log("virt-install: importing Linux cloud image (cloud-init provisions agent)")
    cmd = [
        "virt-install",
        "--name", cfg.name,
        "--memory", str(cfg.ram_mb),
        "--vcpus", str(cfg.cpus),
        "--cpu", "host-passthrough",
        "--import",
        "--disk", f"path={cfg.disk_path},format=qcow2,bus=virtio",
        "--disk", f"path={cfg.seed_iso},device=cdrom",
        "--network", f"bridge={cfg.bridge},model=virtio",
        "--graphics", "vnc,listen=127.0.0.1",
        "--os-variant", "ubuntu22.04",
        "--noautoconsole",
    ]
    run(cmd)
    ok(f"Domain '{cfg.name}' defined and booting (cloud-init running).")


# --------------------------------------------------------------------------- #
# Stealth: transform the libvirt domain XML
# --------------------------------------------------------------------------- #
def _ensure(parent, tag):
    e = parent.find(tag)
    if e is None:
        e = ET.SubElement(parent, tag)
    return e


def cpu_topology(n: int):
    """Factor a vCPU count into a realistic 1-socket topology (cores, 2 threads)."""
    if n >= 2 and n % 2 == 0:
        return (1, n // 2, 2)          # e.g. 8 -> 1 socket x 4 cores x 2 threads
    return (1, max(1, n), 1)


def _dimm_smbios(cfg: Config) -> list:
    """qemu -smbios type=17 override: realistic DIMM vendor strings.

    Note: this sets manufacturer/part/speed only — NOT size. The reported RAM
    amount always equals the *assigned* memory (cfg.ram_mb), so the hardware view
    stays consistent with usable memory (an inconsistency would be its own tell).
    """
    r = _rng(cfg.name + "-dimm")
    man = r.choice(["Samsung", "Micron", "Kingston", "Crucial", "SK-Hynix"])
    speed = r.choice(["2666", "3200", "3600"])
    part = man[:2].upper() + "".join(r.choice("0123456789ABCDEF") for _ in range(10))
    serial = "".join(r.choice("0123456789ABCDEF") for _ in range(8))
    return ["-smbios",
            f"type=17,manufacturer={man},part={part},speed={speed},serial={serial}"]


def _disk_model_args(cfg: Config) -> list:
    """qemu -global overrides for the ATA disk/optical model strings (vs 'QEMU HARDDISK')."""
    r = _rng(cfg.name + "-diskmodel")
    disk = r.choice([
        "Samsung SSD 870 EVO 500GB", "WDC WD10EZEX-08WN4A0",
        "ST1000DM010-2EP102", "TOSHIBA DT01ACA100", "CT500MX500SSD1",
    ])
    optical = r.choice(["HL-DT-ST DVDRAM GUD0N", "ASUS DRW-24D5MT", "TSSTcorp CDDVDW SH-224DB"])
    return [
        "-global", f"driver=ide-hd,property=model,value={disk}",
        "-global", f"driver=ide-cd,property=model,value={optical}",
    ]


def transform_domain_xml(xml_str: str, cfg: Config, sm: dict,
                         topology: bool = False, mem: bool = False) -> str:
    """Pure function: take domain XML, return hardened domain XML.

    libvirt re-canonicalises element order on 'define', so output order here
    doesn't matter. Kept pure so it can be unit-tested without a host.
    """
    root = ET.fromstring(xml_str)

    # match domain uuid to SMBIOS uuid
    _ensure(root, "uuid").text = sm["uuid"]

    # use SMBIOS from <sysinfo>
    os_el = _ensure(root, "os")
    _ensure(os_el, "smbios").set("mode", "sysinfo")
    for old in root.findall("sysinfo"):
        root.remove(old)
    sysinfo = ET.SubElement(root, "sysinfo", {"type": "smbios"})

    def block(tag, entries):
        b = ET.SubElement(sysinfo, tag)
        for k, v in entries:
            ent = ET.SubElement(b, "entry", {"name": k})
            ent.text = v

    block("bios", [("vendor", sm["bios_vendor"]), ("version", sm["bios_version"]),
                   ("date", sm["bios_date"])])
    block("system", [("manufacturer", sm["sys_mfr"]), ("product", sm["sys_product"]),
                     ("version", sm["sys_version"]), ("serial", sm["serial"]),
                     ("uuid", sm["uuid"]), ("sku", sm["sys_sku"]),
                     ("family", sm["sys_family"])])
    block("baseboard", [("manufacturer", sm["board_mfr"]), ("product", sm["board_product"]),
                        ("version", sm["board_version"]), ("serial", sm["board_serial"])])
    block("chassis", [("manufacturer", sm["sys_mfr"]), ("version", sm["sys_version"]),
                      ("serial", sm["chassis_serial"]), ("asset", sm["asset"])])

    # CPU: host-passthrough + hide hypervisor CPUID bit
    cpu = _ensure(root, "cpu")
    cpu.set("mode", "host-passthrough")
    if not any(f.get("name") == "hypervisor" for f in cpu.findall("feature")):
        ET.SubElement(cpu, "feature", {"policy": "disable", "name": "hypervisor"})
    if topology:
        for t in cpu.findall("topology"):
            cpu.remove(t)
        s, c, th = cpu_topology(cfg.cpus)
        ET.SubElement(cpu, "topology",
                      {"sockets": str(s), "cores": str(c), "threads": str(th)})
        # video: drop the "Red Hat QXL"/virtio GPU vendor tell -> generic VGA
        for vid in root.findall("./devices/video"):
            m = _ensure(vid, "model")
            m.attrib.clear()
            m.set("type", "vga"); m.set("vram", "16384"); m.set("heads", "1")

    # features: hide KVM signature, strip Hyper-V enlightenments
    feats = _ensure(root, "features")
    hv = feats.find("hyperv")
    if hv is not None:
        feats.remove(hv)
    kvm = _ensure(feats, "kvm")
    _ensure(kvm, "hidden").set("state", "on")

    # clock: drop hypervclock timer if present
    clock = root.find("clock")
    if clock is not None:
        for t in clock.findall("timer"):
            if t.get("name") == "hypervclock":
                clock.remove(t)

    # disk: realistic serial on the primary disk
    for disk in root.findall("./devices/disk"):
        if disk.get("device") == "disk":
            _ensure(disk, "serial").text = sm["disk_serial"]

    # nic: real-OUI MAC
    for iface in root.findall("./devices/interface"):
        _ensure(iface, "mac").set("address", sm["mac"])

    # optional: realistic DIMM vendor strings via qemu:commandline (NOT size).
    # Uses literal prefixed tags + a literal xmlns:qemu attr so ElementTree emits
    # exactly what libvirt's qemu driver expects.
    if mem:
        uri = "http://libvirt.org/schemas/domain/qemu/1.0"
        root.set("xmlns:qemu", uri)
        for c in list(root):
            if c.tag == "qemu:commandline" or c.tag.endswith("}commandline"):
                root.remove(c)
        cmd = ET.SubElement(root, "qemu:commandline")
        for arg in _dimm_smbios(cfg) + _disk_model_args(cfg):
            ET.SubElement(cmd, "qemu:arg", {"value": arg})

    return ET.tostring(root, encoding="unicode")


def apply_stealth(cfg: Config):
    log("Applying stealth transform to domain XML")
    sm = gen_smbios(cfg)
    cp = run(["virsh", "dumpxml", cfg.name], capture=True, quiet=True)

    def _build(mem):
        try:
            return transform_domain_xml(cp.stdout, cfg, sm,
                                        topology=cfg.realistic_hw, mem=mem)
        except ET.ParseError as e:
            die(f"could not parse domain XML ({e}). If it contains a qemu: namespace, "
                f"remove qemu-commandline and retry.")

    out = Path(cfg.work_dir) / f"{cfg.name}-stealth.xml"
    out.write_text(_build(mem=cfg.realistic_hw))
    try:
        run(["virsh", "define", str(out)])
    except subprocess.CalledProcessError:
        if not cfg.realistic_hw:
            raise
        # the only thing that can make define choke here is the qemu DIMM block;
        # drop it and redefine with CPU topology only so the build never breaks.
        warn("realistic-hw: libvirt rejected the qemu DIMM smbios; "
             "redefining with CPU topology only.")
        out.write_text(_build(mem=False))
        run(["virsh", "define", str(out)])

    extra = " +realistic-hw" if cfg.realistic_hw else ""
    ok(f"Hardened domain redefined (SMBIOS={cfg.smbios_profile}, MAC={sm['mac']}{extra}). "
       f"XML saved: {out}")


# --------------------------------------------------------------------------- #
# CD-ROM eject / power / snapshot / conf
# --------------------------------------------------------------------------- #
def eject_cdroms(cfg: Config):
    log("Ejecting CD-ROMs (remove install + answer-file media)")
    cp = run(["virsh", "domblklist", cfg.name, "--details"], capture=True, quiet=True)
    for line in cp.stdout.splitlines():
        parts = line.split()
        # rows look like: Type Device Target Source
        if len(parts) >= 3 and parts[1] == "cdrom":
            target = parts[2]
            run(["virsh", "change-media", cfg.name, target, "--eject",
                 "--config", "--force"], check=False)
    ok("CD-ROMs ejected (config).")


def shutdown_guest(cfg: Config, timeout_s: int = 180):
    state = run(["virsh", "domstate", cfg.name], capture=True, quiet=True).stdout.strip()
    if state == "shut off":
        return
    log("Gracefully shutting guest down")
    run(["virsh", "shutdown", cfg.name], check=False)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        s = run(["virsh", "domstate", cfg.name], capture=True, quiet=True).stdout.strip()
        if s == "shut off":
            ok("Guest shut down.")
            return
        time.sleep(5)
    warn("Graceful shutdown timed out; forcing off.")
    run(["virsh", "destroy", cfg.name], check=False)


def start_guest(cfg: Config):
    log("Starting guest")
    run(["virsh", "start", cfg.name], check=False)


def wait_for_agent(cfg: Config, timeout_min: int = 60) -> bool:
    log(f"Waiting up to {timeout_min}m for CAPE agent on {cfg.ip}:{cfg.agent_port}")
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        try:
            with socket.create_connection((cfg.ip, cfg.agent_port), timeout=3):
                ok("Agent is reachable.")
                return True
        except OSError:
            time.sleep(10)
    warn("Timed out waiting for agent. Check C:\\provision.log in the console.")
    return False


def snapshot(cfg: Config):
    state = run(["virsh", "domstate", cfg.name], capture=True, quiet=True).stdout.strip()
    if state != "running":
        die(f"domain {cfg.name} is '{state}', not running. Agent must be live when "
            f"snapshotting.")
    log(f"Creating internal snapshot '{cfg.snapshot}' (live)")
    run(["virsh", "snapshot-create-as", "--domain", cfg.name,
         "--name", cfg.snapshot, "--atomic"])
    ok(f"Snapshot '{cfg.snapshot}' created.")


def genconf(cfg: Config) -> str:
    return textwrap.dedent(f"""\
    # ---- paste into {{CAPE_ROOT}}/conf/kvm.conf ----
    [kvm]
    machines = {cfg.name}
    interface = {cfg.bridge}
    dsn = qemu:///system

    [{cfg.name}]
    label = {cfg.name}
    platform = {cfg.platform}
    ip = {cfg.ip}
    arch = x64
    tags = {cfg.tags}
    snapshot = {cfg.snapshot}
    resultserver_ip = {cfg.resultserver_ip}
    reserved = no
    """)


def destroy(cfg: Config):
    warn(f"Destroying domain {cfg.name} and its disk")
    run(["virsh", "destroy", cfg.name], check=False)
    run(["virsh", "undefine", cfg.name, "--snapshots-metadata", "--nvram"], check=False)
    if Path(cfg.disk_path).exists():
        Path(cfg.disk_path).unlink()
    ok("Destroyed.")


# --------------------------------------------------------------------------- #
# Self-test (no host needed): exercises the XML transform
# --------------------------------------------------------------------------- #
_SAMPLE_XML = """<domain type='kvm'>
  <name>win10x64_1</name>
  <uuid>11111111-1111-1111-1111-111111111111</uuid>
  <memory unit='KiB'>8388608</memory>
  <vcpu>4</vcpu>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/><hyperv><relaxed state='on'/></hyperv></features>
  <cpu mode='host-passthrough'/>
  <clock offset='localtime'><timer name='hypervclock' present='yes'/></clock>
  <devices>
    <disk type='file' device='disk'><source file='/x.qcow2'/><target dev='sda' bus='sata'/></disk>
    <disk type='file' device='cdrom'><target dev='sdb' bus='sata'/></disk>
    <interface type='bridge'><mac address='52:54:00:aa:bb:cc'/><source bridge='virbr0'/><model type='e1000'/></interface>
    <video><model type='qxl' ram='65536' vram='65536' heads='1'/></video>
  </devices>
</domain>"""


def selftest():
    cfg = Config()
    sm = gen_smbios(cfg)
    out = transform_domain_xml(_SAMPLE_XML, cfg, sm)
    root = ET.fromstring(out)
    assert root.find("sysinfo") is not None, "sysinfo missing"
    assert root.find("./features/kvm/hidden").get("state") == "on", "kvm hidden missing"
    assert root.find("./features/hyperv") is None, "hyperv not stripped"
    assert any(f.get("name") == "hypervisor" for f in root.findall("./cpu/feature")), "hypervisor not disabled"
    assert root.find("./clock/timer") is None, "hypervclock not removed"
    assert root.find("./devices/disk/serial").text == sm["disk_serial"], "disk serial missing"
    mac = root.find("./devices/interface/mac").get("address")
    assert not mac.startswith("52:54:00"), "MAC still QEMU OUI"

    # realistic-hw: CPU topology product must equal vCPUs; DIMM smbios present
    rh = transform_domain_xml(_SAMPLE_XML, cfg, sm, topology=True, mem=True)
    m = re.search(r'<topology sockets="(\d+)" cores="(\d+)" threads="(\d+)"', rh)
    assert m, "topology missing"
    assert int(m[1]) * int(m[2]) * int(m[3]) == cfg.cpus, "topology != cpus"
    assert "-smbios" in rh and "type=17,manufacturer=" in rh, "DIMM smbios missing"
    assert "qemu:commandline" in rh and "xmlns:qemu" in rh, "qemu namespace missing"
    assert "driver=ide-hd,property=model" in rh, "disk model override missing"
    assert 'type="vga"' in rh, "video not switched to vga"
    assert cpu_topology(8) == (1, 4, 2), cpu_topology(8)
    # topology-only path stays valid XML (no qemu namespace)
    ET.fromstring(transform_domain_xml(_SAMPLE_XML, cfg, sm, topology=True, mem=False))

    # decoy provisioning block
    dcfg = Config(name="win10x64_1", decoy=True, decoy_fill_mb=256)
    dec = render_decoy_block(dcfg)
    assert "Uninstall" in dec and "RegisteredOwner" in dec, "decoy reg artifacts missing"
    assert "fsutil file createnew" in dec and "Bookmarks" in dec, "decoy files/bookmarks missing"
    assert "hibersave.dat 268435456" in dec, "decoy filler size wrong"
    assert render_decoy_block(Config(name="x", decoy=False)).strip().endswith("disabled")
    ok("selftest passed")
    print(f"  generated MAC : {mac}")
    print(f"  SMBIOS system : {sm['sys_mfr']} {sm['sys_product']} / SN {sm['serial']}")

    # dmidecode parser
    sample = ("Handle 0x0000, DMI type 0, 26 bytes\nBIOS Information\n"
              "\tVendor: Dell Inc.\n\tVersion: 2.18.0\n\tRelease Date: 04/12/2023\n\n"
              "Handle 0x0100, DMI type 1, 27 bytes\nSystem Information\n"
              "\tManufacturer: Dell Inc.\n\tProduct Name: OptiPlex 7090\n"
              "\tSerial Number: ABC1234\n\tUUID: 4C4C4544-0042-1234\n\tSKU Number: 0A38\n")
    pp = parse_dmidecode(sample)
    assert pp["sys_product"] == "OptiPlex 7090", "dmi parse failed"
    assert pp["_sys_serial"] == "ABC1234", "dmi serial parse failed"
    ok("dmidecode parser ok")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def apply_args(cfg: Config, a: argparse.Namespace) -> Config:
    for k in vars(cfg):
        v = getattr(a, k, None)
        if v is not None:
            setattr(cfg, k, v)
    return cfg


# Shared-config support: read canonical KEY=value lines from a sandbox.conf that
# may sit next to this script. Precedence: Config defaults < sandbox.conf < CLI.
# DMI_PROFILE is intentionally NOT mapped here — cape-deploy passes it explicitly
# only when the clone file exists, so we never auto-adopt a missing path.
_SANDBOX_MAP = {
    "RESULTSERVER_IP": ("resultserver_ip", str),
    "VM_BRIDGE": ("bridge", str),
    "INSTALL_ISO": ("install_iso", str),
    "PYTHON_INSTALLER": ("python_installer", str),
    "AGENT_PY": ("agent_py", str),
    "VM_CPUS": ("cpus", int),
    "VM_RAM_MB": ("ram_mb", int),
    "VM_DISK_GB": ("disk_gb", int),
    "SMBIOS_PROFILE": ("smbios_profile", str),
    "REALISTIC_HW": ("realistic_hw", lambda v: str(v).strip() in ("1", "true", "True", "yes")),
    "DECOY": ("decoy", lambda v: str(v).strip() in ("1", "true", "True", "yes")),
    "DECOY_FILL_MB": ("decoy_fill_mb", int),
}


def parse_shell_conf(path: Path) -> dict:
    vals = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v.startswith("("):          # bash array (e.g. VM_LIST) — skip
            continue
        if v[:1] in ("\"", "'"):       # quoted: take inside quotes, drop trailing comment
            q = v[0]
            end = v.find(q, 1)
            v = v[1:end] if end != -1 else v[1:]
        else:                          # unquoted: cut an inline ' #' comment
            v = re.split(r"\s+#", v, 1)[0].strip()
        vals[k] = v
    return vals


def apply_sandbox_conf(cfg: Config, path: Path) -> Config:
    if not path.is_file():
        return cfg
    raw = parse_shell_conf(path)
    for key, (field, conv) in _SANDBOX_MAP.items():
        if raw.get(key):
            try:
                setattr(cfg, field, conv(raw[key]))
            except (ValueError, TypeError):
                warn(f"sandbox.conf: ignoring bad value {key}={raw[key]!r}")
    return cfg


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="libvirt-native CAPEv2 VM builder with anti-detection hardening")
    p.add_argument("command",
                   choices=["build", "install", "stealth", "eject", "wait",
                            "snapshot", "genconf", "destroy", "preflight",
                            "clone-dmi", "selftest"],
                   help="build = install+provision+stealth+snapshot end to end")
    p.add_argument("--name"); p.add_argument("--ip"); p.add_argument("--bridge")
    p.add_argument("--snapshot"); p.add_argument("--install-iso", dest="install_iso")
    p.add_argument("--agent-py", dest="agent_py")
    p.add_argument("--python-installer", dest="python_installer")
    p.add_argument("--gateway"); p.add_argument("--resultserver-ip", dest="resultserver_ip")
    p.add_argument("--cpus", type=int); p.add_argument("--ram-mb", dest="ram_mb", type=int)
    p.add_argument("--disk-gb", dest="disk_gb", type=int)
    p.add_argument("--tags"); p.add_argument("--agent-port", dest="agent_port", type=int)
    p.add_argument("--smbios-profile", dest="smbios_profile", choices=["dell", "lenovo"])
    p.add_argument("--platform", choices=["windows", "linux"])
    p.add_argument("--cloud-image", dest="cloud_image",
                   help="base qcow2 cloud image for --platform linux")
    p.add_argument("--realistic-hw", dest="realistic_hw", action="store_true",
                   default=None,
                   help="present a realistic CPU topology + DIMM vendor strings")
    p.add_argument("--decoy", dest="decoy", action=argparse.BooleanOptionalAction,
                   default=None, help="seed lived-in user artifacts (default on)")
    p.add_argument("--decoy-fill-mb", dest="decoy_fill_mb", type=int, default=None,
                   help="filler MB so guest free-space ratio looks used (0=off)")
    p.add_argument("--mac"); p.add_argument("--computer-name", dest="computer_name")
    p.add_argument("--dmi-profile", dest="dmi_profile",
                   help="JSON profile from clone-dmi to spoof a real machine's identity")
    p.add_argument("--keep-dmi-serials", dest="dmi_keep_serials", action="store_true",
                   default=None, help="clone exact serials/uuid (default: regen per VM)")
    p.add_argument("--from-file", dest="from_file",
                   help="clone-dmi: parse a saved `dmidecode` dump instead of live")
    p.add_argument("--out", dest="out", help="clone-dmi: output profile path")
    p.add_argument("--timeout-min", type=int, default=60)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "selftest":
        selftest(); return
    cfg = Config()
    apply_sandbox_conf(cfg, Path(__file__).resolve().parent / "sandbox.conf")
    cfg = apply_args(cfg, args)

    if args.command == "preflight":
        preflight(cfg); return
    if args.command == "clone-dmi":
        cmd_clone_dmi(cfg, args.from_file, args.out); return
    if args.command == "install":
        preflight(cfg); install(cfg); return
    if args.command == "stealth":
        apply_stealth(cfg); return
    if args.command == "eject":
        eject_cdroms(cfg); return
    if args.command == "wait":
        wait_for_agent(cfg, args.timeout_min); return
    if args.command == "snapshot":
        snapshot(cfg); return
    if args.command == "genconf":
        print(genconf(cfg)); return
    if args.command == "destroy":
        destroy(cfg); return
    if args.command == "build":
        preflight(cfg)
        install(cfg)
        if not wait_for_agent(cfg, args.timeout_min):
            die("Agent never came up after install — fix provisioning, then re-run.")
        shutdown_guest(cfg)
        eject_cdroms(cfg)
        apply_stealth(cfg)
        start_guest(cfg)
        if wait_for_agent(cfg, args.timeout_min):
            snapshot(cfg)
            print()
            print(genconf(cfg))
            ok("Build complete. Add the stanza to conf/kvm.conf and restart cape services.")
        else:
            die("Agent didn't return after stealth reboot. Inspect the guest, then run "
                "'capevm.py snapshot --name " + cfg.name + "' once it's up.")
        return


if __name__ == "__main__":
    main()
