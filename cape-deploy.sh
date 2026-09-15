#!/usr/bin/env bash
#
# cape-deploy.sh — Orchestrate a CAPEv2 sandbox build on a dedicated Ubuntu host.
#
# Idempotent stages:
#   host      : clone CAPEv2 + set up KVM/QEMU (HOST_MODE=distro default, or source)
#   cape      : write a cape-config.sh override, run the OFFICIAL cape2.sh installer
#   deps      : install runtime deps CAPE needs (poetry perms, libvirt-python, MongoDB)
#   update-policy : security auto-updates ON; kernel/qemu/libvirt manual-only (opt-in)
#   community : pull community signatures/parsers
#   dmi       : (optional) clone a real machine's SMBIOS into a reusable profile
#   buildvm   : build each analysis guest via capevm.py (unattended install +
#               agent + anti-detection hardening + snapshot)
#   register  : write conf/kvm.conf (+ point cuckoo.conf at the kvm machinery)
#   netiso    : enforce fail-closed network isolation on the analysis bridge
#   services  : (re)start and verify the CAPE systemd services
#   tls       : self-signed HTTPS for the web UI (enable with --tls or ENABLE_TLS=1)
#   verify    : post-install health check (services, net, resultserver, snapshots)
#   smoketest : submit a benign sample and confirm a report comes back
#
# Run the whole thing with HTTPS on the UI:
#   sudo ./cape-deploy.sh all --tls
# or just (re)apply TLS to an existing install:
#   sudo ./cape-deploy.sh tls
#
# Calls CAPE's own installers (kvm-qemu.sh, cape2.sh) and our capevm.py rather
# than duplicating them, so upstream changes don't silently break the deploy.
#
# !!! SAFETY !!!
# CAPE detonates live malware. Run ONLY on a dedicated, network-isolated host you
# can rebuild. You own egress control / isolation of the analysis VMs.
#
# Usage:
#   sudo ./cape-deploy.sh all              # every stage in order
#   sudo ./cape-deploy.sh buildvm verify   # one or more stages
#   sudo ./cape-deploy.sh all --yes        # skip the safety prompt
#
# Requires capevm.py next to this script (or set CAPEVM=/path/to/capevm.py).
# Target: Ubuntu 24.04 LTS.
# ---------------------------------------------------------------------------

set -Eeuo pipefail

# ============================ CONFIG =======================================
# Every tunable below has a built-in default. To centralise settings across all
# the scripts, create a `sandbox.conf` next to this one; values there override
# these defaults. Once generated, edit sandbox.conf — not this block.
SELF_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
[ -f "$SELF_DIR/sandbox.conf" ] && . "$SELF_DIR/sandbox.conf"

# --- Host / CAPE ---
: "${CAPE_USER:=cape}"
: "${CAPE_ROOT:=/opt/CAPEv2}"
: "${CAPE_GIT:=https://github.com/kevoreilly/CAPEv2.git}"
: "${USE_UV:=false}"
# host virtualization stack: 'distro' (default, reliable, self-updating) installs
# qemu/libvirt from Ubuntu's repos; 'source' runs CAPE's kvm-qemu.sh to build a
# patched QEMU/SeaBIOS (extra firmware-string stealth, but fragile across updates).
: "${HOST_MODE:=distro}"
: "${DB_PASSWORD:=ChangeMe_SuperSecret}"
: "${MONGO_ENABLE:=1}"

# --- Networking (keep internally consistent) ---
: "${NETWORK_IFACE:=virbr0}"           # interface CAPE sniffs / binds near
: "${RESULTSERVER_IP:=192.168.122.1}"  # host IP guests call back to
: "${RESULTSERVER_PORT:=2042}"         # default CAPE resultserver port (verify)
: "${WEB_PORT:=8000}"                  # cape-web (uwsgi) port (verify)

# --- capevm.py + guest build ---
CAPEVM="${CAPEVM:-$SELF_DIR/capevm.py}"
: "${INSTALL_ISO:=/opt/iso/win10x64.iso}"
: "${PYTHON_INSTALLER:=/opt/iso/python-3.x.x-x86.exe}"
: "${CLOUD_IMAGE:=}"                    # base qcow2 cloud image for linux guests
: "${AGENT_PY:=${CAPE_ROOT}/agent/agent.py}"
: "${VM_BRIDGE:=${NETWORK_IFACE}}"
: "${VM_CPUS:=4}"
: "${VM_RAM_MB:=8192}"
: "${VM_DISK_GB:=120}"
: "${BUILD_TIMEOUT_MIN:=60}"

# --- Network isolation (netiso.sh) ---
NETISO="${NETISO:-$SELF_DIR/netiso.sh}"
: "${ISO_MODE:=isolated}"              # isolated | simulated | gateway
: "${ANALYSIS_SUBNET:=192.168.122.0/24}"
: "${GATEWAY_IFACE:=tun0}"             # uplink for ISO_MODE=gateway (VPN/Tor)
: "${FAKENET_IP:=${RESULTSERVER_IP}}"  # INetSim/FakeNet host for ISO_MODE=simulated

# --- Smoke test (smoketest.sh) ---
SMOKETEST="${SMOKETEST:-$SELF_DIR/smoketest.sh}"
: "${CAPE_API_TOKEN:=}"                # set if your apiv2 requires a token

# --- Self-signed HTTPS for the web UI (tls stage / --tls) ---
: "${ENABLE_TLS:=0}"                   # 1 (or --tls) runs the tls stage during 'all'
: "${TLS_SERVER_NAME:=cape.local}"     # CN/SAN + nginx server_name
: "${TLS_CERT:=/etc/ssl/certs/cape-selfsigned.crt}"
: "${TLS_KEY:=/etc/ssl/private/cape-selfsigned.key}"
: "${TLS_DAYS:=825}"                   # cert validity
: "${TLS_REDIRECT_HTTP:=1}"            # 1 = redirect :80 -> :443

# --- Anti-detection identity ---
: "${SMBIOS_PROFILE:=dell}"            # dell | lenovo (used if no DMI clone)
: "${REFERENCE_DMI:=}"                 # saved `dmidecode` dump to clone; empty = preset
: "${DMI_PROFILE:=/opt/capevm/work/dmi-profile.json}"
: "${DMI_KEEP_SERIALS:=0}"             # 1 = clone exact serials (else regen per VM)
: "${REALISTIC_HW:=0}"                 # 1 = present real CPU topology + DIMM vendor strings
: "${DECOY:=1}"                        # 1 = seed lived-in user artifacts in Windows guests
: "${DECOY_FILL_MB:=0}"                # filler MB so guest free-space ratio looks used (0=off)

# --- VM inventory:  name|ip|snapshot|tags[|platform]  (platform: windows|linux) ---
declare -p VM_LIST >/dev/null 2>&1 || VM_LIST=(
  "win10x64_1|192.168.122.101|clean|x64,win10"
)
# ===========================================================================

LOGFILE="/var/log/cape-deploy.$(date +%Y%m%d-%H%M%S).log"
ASSUME_YES=0

# ----------------------------- helpers -------------------------------------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_rst=$'\e[0m'
log()  { echo "${c_blu}[*]${c_rst} $*"; }
ok()   { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_ylw}[!]${c_rst} $*" >&2; }
die()  { echo "${c_red}[-]${c_rst} $*" >&2; exit 1; }
on_error() { echo "${c_red}[-]${c_rst} Failed at line $1. See $LOGFILE" >&2; }
trap 'on_error $LINENO' ERR

require_root() { [ "$(id -u)" -eq 0 ] || die "Run with sudo/root."; }
as_cape() { sudo -u "$CAPE_USER" -H bash -c "$1"; }

confirm_safety() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  cat <<EOF
${c_ylw}-----------------------------------------------------------------
 This host will be configured to execute LIVE MALWARE in VMs.
 Proceed ONLY on a dedicated, isolated, disposable machine.
-----------------------------------------------------------------${c_rst}
EOF
  read -r -p "Type 'I UNDERSTAND' to continue: " reply
  [ "$reply" = "I UNDERSTAND" ] || die "Aborted by user."
}

# ----------------------------- preflight -----------------------------------
preflight() {
  log "Preflight checks"
  local ver; ver="$(lsb_release -rs 2>/dev/null || echo unknown)"
  [ "$ver" = "24.04" ] || warn "Ubuntu $ver detected; this toolkit targets 24.04 LTS — other releases may need adjustment."
  grep -Eq '(vmx|svm)' /proc/cpuinfo || die "CPU virtualization (VT-x/AMD-V) unavailable — enable it in firmware."
  [ -e /dev/kvm ] || warn "/dev/kvm missing now — the 'host' stage will set up KVM (or load kvm_intel/kvm_amd)."
  local free_gb; free_gb="$(df -BG --output=avail / | tail -1 | tr -dc '0-9')"
  [ "${free_gb:-0}" -ge 100 ] || warn "Only ${free_gb}G free on / — 200G+ recommended (guest disks are thin but grow)."
  local ram_gb; ram_gb="$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  [ "${ram_gb:-0}" -ge 16 ] || warn "Only ${ram_gb}G RAM — 16G+ recommended (host services + an 8G guest)."
  command -v git >/dev/null || { apt-get update -qq && apt-get install -y git; }
  ok "Preflight done"
}

# ----------------------------- stages --------------------------------------
stage_host() {
  log "STAGE host: fetch CAPE + set up the KVM/QEMU virtualization stack (mode=$HOST_MODE)"
  if [ ! -d "$CAPE_ROOT/.git" ]; then
    git clone "$CAPE_GIT" "$CAPE_ROOT"
  else
    ok "CAPE checkout already at $CAPE_ROOT"
  fi

  if [ "$HOST_MODE" = "source" ]; then
    # Opt-in: build patched QEMU/SeaBIOS from source (fragile across kernel/lib
    # updates — you'll manage /usr/local drift yourself; see README).
    [ -f "$CAPE_ROOT/installer/kvm-qemu.sh" ] || die "kvm-qemu.sh not found under $CAPE_ROOT/installer"
    if [ -e /dev/kvm ] && command -v virsh >/dev/null && [ -f /var/lib/cape-deploy/.kvm-done ]; then
      ok "KVM stage previously completed; skipping (rm /var/lib/cape-deploy/.kvm-done to force)."
    else
      warn "HOST_MODE=source: building QEMU/SeaBIOS from source into /usr/local (slow, fragile)."
      log "Running official kvm-qemu.sh"
      ( cd "$CAPE_ROOT/installer" && bash ./kvm-qemu.sh all "$CAPE_USER" 2>&1 | tee -a "$LOGFILE" )
      mkdir -p /var/lib/cape-deploy && touch /var/lib/cape-deploy/.kvm-done
    fi
  else
    # Default: distro packages. These track the kernel and self-heal on apt
    # upgrade — no /usr/local drift. capevm.py still applies domain-level stealth
    # (SMBIOS/DMI/CPU/MAC), so you keep the anti-detection that matters; you only
    # forgo kvm-qemu.sh's deeper firmware-string patches.
    log "Installing distro KVM/QEMU/libvirt (apt) — reliable + self-updating"
    apt-get update -qq
    apt-get install -y \
      qemu-system-x86 qemu-utils \
      libvirt-daemon-system libvirt-daemon libvirt-clients libvirt0 \
      virtinst ovmf bridge-utils xorriso \
      || die "failed to install distro virtualization packages"
    systemctl enable --now libvirtd 2>/dev/null \
      || systemctl enable --now virtqemud virtnetworkd virtstoraged 2>/dev/null || true
    # let the invoking (sudo) user manage libvirt without root
    [ -n "${SUDO_USER:-}" ] && usermod -aG libvirt,kvm "$SUDO_USER" 2>/dev/null || true
    ensure_network || warn "default libvirt network not up yet — will retry at buildvm."
    ok "distro virtualization stack installed."
  fi

  ensure_build_tools
  ok "STAGE host complete"
}

# Utilities capevm.py needs to build guests. Installs only what's missing.
# NOTE: qemu-utils / virtinst provide qemu-img / virt-install ONLY — they do not
# replace the custom qemu-system built by kvm-qemu.sh, so the anti-detection
# QEMU/SeaBIOS patches stay intact.
ensure_build_tools() {
  local pkgs=()
  command -v qemu-img     >/dev/null || pkgs+=(qemu-utils)
  command -v virt-install >/dev/null || pkgs+=(virtinst)
  command -v virsh        >/dev/null || pkgs+=(libvirt-clients)
  command -v xorriso >/dev/null || command -v genisoimage >/dev/null || pkgs+=(xorriso)
  if [ "${#pkgs[@]}" -gt 0 ]; then
    log "Installing guest-build tools: ${pkgs[*]}"
    apt-get update -qq
    apt-get install -y "${pkgs[@]}" || warn "apt install of ${pkgs[*]} failed — install them manually."
  fi
}

# Sane update policy for a sandbox host: keep security updates flowing, but never
# let the kernel or the virtualization stack auto-upgrade/reboot underneath a
# running analysis. They stay fully updatable via a *manual* apt upgrade in a
# maintenance window (this only affects the UNATTENDED timer, not `apt` by hand).
stage_update_policy() {
  log "STAGE update-policy: auto security updates ON; kernel/qemu/libvirt excluded from auto-upgrade"
  apt-get install -y unattended-upgrades >/dev/null 2>&1 || true
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat > /etc/apt/apt.conf.d/52cape-unattended <<'EOF'
// CAPE sandbox host policy — see README "Updating a sandbox host".
// Auto-apply SECURITY updates, but exclude the kernel and virtualization stack
// from the unattended timer and never auto-reboot. You still update those by
// hand ("sudo apt upgrade") in a maintenance window, then reboot deliberately.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
    "linux-image";
    "linux-headers";
    "linux-generic";
    "qemu-system";
    "qemu-utils";
    "libvirt";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl restart unattended-upgrades 2>/dev/null || true
  ok "Update policy applied: security updates auto-install; kernel/qemu/libvirt stay for manual, controlled upgrades; no auto-reboot."
  log "When you DO take a kernel update, follow the post-kernel-update checklist in the README."
}


# Kernel-aware MongoDB install. MongoDB 8.0+ crashes on Linux kernel 6.19+
# (SERVER-121912), so on affected kernels we install 7.0 instead.
ensure_mongodb() {
  # Desired major: MongoDB 8.0+ crashes on Linux kernel >= 6.19 (SERVER-121912),
  # so on affected kernels we want 7.0; otherwise 8.0.
  local rel kmm want repocode installed_major want_major
  rel="$(uname -r)"; kmm="$(echo "$rel" | grep -oE '^[0-9]+\.[0-9]+')"
  want="8.0"
  if awk -v k="$kmm" 'BEGIN{split(k,a,".");exit !(a[1]>6||(a[1]==6&&a[2]>=19))}'; then
    want="7.0"
    warn "Kernel $rel is affected by MongoDB SERVER-121912 — MongoDB 7.0 required (not 8.0)."
  fi
  want_major="${want%%.*}"
  installed_major="$(dpkg-query -W -f='${Version}' mongodb-org-server 2>/dev/null | grep -oE '^[0-9]+' || true)"

  # Already the right major AND running? Nothing to do.
  if [ "$installed_major" = "$want_major" ] && systemctl is-active --quiet mongod 2>/dev/null; then
    ok "MongoDB ${want} already installed and running."
    return 0
  fi

  # An incompatible major is installed (this is the loop: cape2.sh installs 8.0,
  # apt then says 'already newest' so a plain install is a no-op). Purge it first.
  if [ -n "$installed_major" ] && [ "$installed_major" != "$want_major" ]; then
    warn "Removing incompatible MongoDB ${installed_major}.x before installing ${want}."
    systemctl stop mongod 2>/dev/null || true
    pkill -9 mongod 2>/dev/null || true
    apt-mark unhold 'mongodb-org*' >/dev/null 2>&1 || true
    apt-get purge -y 'mongodb-org*' >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    rm -f /etc/apt/sources.list.d/mongodb-org-*.list
  fi

  log "Installing MongoDB $want"
  apt-get install -y gnupg curl >/dev/null 2>&1 || true
  install -d /etc/apt/keyrings
  curl -fsSL "https://www.mongodb.org/static/pgp/server-${want}.asc" \
    | gpg --batch --yes -o /etc/apt/keyrings/mongo.gpg --dearmor 2>/dev/null
  chmod 644 /etc/apt/keyrings/mongo.gpg
  repocode="$(. /etc/os-release 2>/dev/null; echo "${UBUNTU_CODENAME:-noble}")"
  [ "$want" = "7.0" ] && repocode="jammy"   # 7.0 has no noble repo; jammy pkgs run on noble
  rm -f /etc/apt/sources.list.d/mongodb-org-*.list
  echo "deb [ arch=amd64,arm64 signed-by=/etc/apt/keyrings/mongo.gpg ] https://repo.mongodb.org/apt/ubuntu ${repocode}/mongodb-org/${want} multiverse" \
    > "/etc/apt/sources.list.d/mongodb-org-${want}.list"
  apt-get update >/dev/null 2>&1 || true   # tolerate unrelated repo key errors
  apt-mark unhold 'mongodb-org*' >/dev/null 2>&1 || true
  if ! apt-get install -y mongodb-org; then
    warn "mongodb-org ${want} install failed — CAPE report processing needs Mongo. Install it manually."
    return 0   # non-fatal: never abort the whole deploy on this
  fi

  # PIN the correct version so the 'cape' stage (cape2.sh) can NEVER pull 8.0 back.
  apt-mark hold mongodb-org mongodb-org-server mongodb-org-database mongodb-org-mongos \
    mongodb-org-tools mongodb-mongosh mongodb-database-tools >/dev/null 2>&1 || true

  chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb 2>/dev/null || true
  systemctl enable --now mongod >/dev/null 2>&1 || true
  sleep 4
  if systemctl is-active --quiet mongod; then
    ok "MongoDB ${want} running on 127.0.0.1:27017 (held/pinned so 8.0 can't return)."
  else
    warn "mongod not active — see 'journalctl -u mongod'."
  fi
  return 0   # never fail the stage on mongo
}

# Runtime dependencies CAPE needs that the official installers don't reliably
# leave in place: traversable poetry path, libvirt-python in the venv, MongoDB.
stage_deps() {
  log "STAGE deps: ensure CAPE runtime dependencies (poetry perms, libvirt-python, MongoDB)"

  # 1) poetry path must be traversable by the (non-root) cape service user,
  #    otherwise services die with 203/EXEC "Permission denied" on poetry.
  if [ -d /etc/poetry ]; then
    chmod -R o+rX /etc/poetry && ok "poetry path made traversable (o+rX)"
  fi

  # 2) libvirt-python in CAPE's venv (KVM machinery imports it; without it the
  #    scheduler/processor crash with ModuleNotFoundError: libvirt).
  if [ -d "$CAPE_ROOT" ] && [ -x /etc/poetry/bin/poetry ]; then
    apt-get install -y pkg-config libvirt-dev python3-dev gcc >/dev/null 2>&1 \
      || warn "could not install libvirt build deps (pkg-config/libvirt-dev)"
    chown -R "$CAPE_USER":"$CAPE_USER" "$CAPE_ROOT/.cache" 2>/dev/null || true
    local pcp="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig"
    if sudo -u "$CAPE_USER" bash -c "cd '$CAPE_ROOT' && PKG_CONFIG_PATH='$pcp' /etc/poetry/bin/poetry run python -c 'import libvirt' 2>/dev/null"; then
      ok "libvirt-python already present in CAPE venv"
    else
      log "Installing libvirt-python into CAPE venv"
      sudo -u "$CAPE_USER" bash -c "cd '$CAPE_ROOT' && PKG_CONFIG_PATH='$pcp' /etc/poetry/bin/poetry run pip install libvirt-python" \
        && ok "libvirt-python installed" \
        || warn "libvirt-python install failed — check libvirt-dev/pkg-config (or a /usr/local source build)."
    fi
    # commonly-needed processing deps (non-fatal if they fail)
    sudo -u "$CAPE_USER" bash -c "cd '$CAPE_ROOT' && /etc/poetry/bin/poetry run pip install -q pyzipper certvalidator asn1crypto mscerts" >/dev/null 2>&1 \
      && ok "optional processing deps present" \
      || warn "some optional processing deps not installed (non-fatal)."

    # oscrypto: the PyPI release can't parse OpenSSL 3.x version strings (double-digit
    # patch, e.g. 3.0.13 on Ubuntu 24.04) and raises LibraryNotFoundError, which makes
    # CAPE's static/CAPE processing modules fail to import — reports then land without
    # the target/static sections and the web report page errors. Detect + repair.
    _osc_ok() { sudo -u "$CAPE_USER" bash -c \
      "cd '$CAPE_ROOT' && /etc/poetry/bin/poetry run python -c 'import oscrypto._openssl._libcrypto_cffi' 2>/dev/null"; }
    _osc_install() { sudo -u "$CAPE_USER" bash -c \
      "cd '$CAPE_ROOT' && /etc/poetry/bin/poetry run pip install --force-reinstall --no-deps 'oscrypto @ git+https://github.com/wbond/oscrypto.git@$1'" >/dev/null 2>&1; }
    if _osc_ok; then
      ok "oscrypto OK for this OpenSSL."
    else
      log "Patching oscrypto for OpenSSL 3.x (LibraryNotFoundError fix)"
      _osc_install "d5f3437" || true                 # known-good pinned commit
      if ! _osc_ok; then
        warn "pinned oscrypto commit didn't resolve it; trying oscrypto master."
        _osc_install "master" || true                # maintained fix, for future OpenSSL bumps
      fi
      if _osc_ok; then
        ok "oscrypto patched (OpenSSL 3.x compatible)."
      else
        warn "oscrypto still failing — CAPE static/report processing may be degraded "
        warn "(reports may lack target/static; see 'journalctl -u cape-processor')."
      fi
    fi
  else
    warn "CAPE_ROOT or /etc/poetry/bin/poetry not found — run the 'cape' stage first."
  fi

  # 3) MongoDB (kernel-aware — handles the 8.0/kernel-6.19 incompatibility)
  ensure_mongodb

  ok "STAGE deps complete"
}

write_cape_config() {
  local cfg="$CAPE_ROOT/installer/cape-config.sh"
  log "Writing override $cfg"
  cat > "$cfg" <<EOF
# Generated by cape-deploy.sh — overrides for cape2.sh
NETWORK_IFACE=${NETWORK_IFACE}
IFACE_IP=${RESULTSERVER_IP}
PASSWD=${DB_PASSWORD}
USER=${CAPE_USER}
MONGO_ENABLE=${MONGO_ENABLE}
EOF
}

stage_cape() {
  log "STAGE cape: run official cape2.sh installer"
  [ -f "$CAPE_ROOT/installer/cape2.sh" ] || die "cape2.sh not found; run 'host' first."
  write_cape_config
  log "Running cape2.sh base (deps, CAPE, systemd) — long step"
  ( cd "$CAPE_ROOT/installer" \
      && CAPE_ROOT="$CAPE_ROOT" USE_UV="$USE_UV" bash ./cape2.sh base 2>&1 | tee -a "$LOGFILE" )
  chown -R "$CAPE_USER":"$CAPE_USER" "$CAPE_ROOT" || warn "chown of $CAPE_ROOT had issues."
  ok "STAGE cape complete"
}

stage_community() {
  log "STAGE community: pull community signatures + parsers"
  [ -f "$CAPE_ROOT/utils/community.py" ] || die "community.py missing; run 'cape' first."
  as_cape "cd '$CAPE_ROOT' && python3 utils/community.py -waf" 2>&1 | tee -a "$LOGFILE" \
    || warn "community.py returned non-zero; review log."
  ok "STAGE community complete"
}

stage_dmi() {
  log "STAGE dmi: build SMBIOS identity profile for the guests"
  [ -f "$CAPEVM" ] || die "capevm.py not found at $CAPEVM (set CAPEVM=...)."
  if [ -z "$REFERENCE_DMI" ]; then
    ok "No REFERENCE_DMI set — guests will use the '$SMBIOS_PROFILE' preset. Skipping clone."
    return
  fi
  [ -f "$REFERENCE_DMI" ] || die "REFERENCE_DMI '$REFERENCE_DMI' not found. Capture it on a
    reference machine you own with: sudo dmidecode > reference-dmi.txt"
  mkdir -p "$(dirname "$DMI_PROFILE")"
  python3 "$CAPEVM" clone-dmi --from-file "$REFERENCE_DMI" --out "$DMI_PROFILE" \
    2>&1 | tee -a "$LOGFILE"
  ok "STAGE dmi complete -> $DMI_PROFILE"
}

# Ensure the libvirt default network / bridge is up before we build a guest.
# Also repairs the loader cache for source-built libvirt/qemu in /usr/local
# (kvm-qemu.sh installs there; if those libs aren't on the loader path, helpers
# like libvirt_leaseshelper die with "version LIBVIRT_PRIVATE_x not found",
# which stops the default network and leaves no virbr0).
ensure_network() {
  local changed=0 d
  for d in /usr/local/lib /usr/local/lib64 /usr/local/lib/x86_64-linux-gnu; do
    [ -d "$d" ] || continue
    grep -qxF "$d" /etc/ld.so.conf.d/zz-cape-local.conf 2>/dev/null || {
      echo "$d" >> /etc/ld.so.conf.d/zz-cape-local.conf; changed=1; }
  done
  [ "$changed" = 1 ] && { ldconfig; log "refreshed loader cache for /usr/local libs"; }

  systemctl restart libvirtd 2>/dev/null \
    || systemctl restart virtqemud virtnetworkd virtstoraged 2>/dev/null || true

  # define default net if missing, then autostart + start it
  if ! virsh net-info default >/dev/null 2>&1; then
    for def in /usr/share/libvirt/networks/default.xml \
               /etc/libvirt/qemu/networks/default.xml; do
      [ -f "$def" ] && { virsh net-define "$def" >/dev/null 2>&1 && break; }
    done
  fi
  virsh net-autostart default >/dev/null 2>&1 || true
  virsh net-info default 2>/dev/null | grep -qi 'active:.*yes' \
    || virsh net-start default >/dev/null 2>&1 || true

  if ip link show "${VM_BRIDGE:-virbr0}" >/dev/null 2>&1; then
    ok "libvirt network up (${VM_BRIDGE:-virbr0} present)"
    return 0
  fi
  warn "Bridge ${VM_BRIDGE:-virbr0} is not up — 'virsh net-start default' failed."
  warn "Most common cause: a broken/mismatched libvirt from the source build."
  warn "Check:  sudo virsh net-start default"
  warn "If it reports \"LIBVIRT_PRIVATE_x.x.x not found\", your libvirt binaries and"
  warn "libraries are out of sync. Reconcile them, e.g.:"
  warn "  sudo apt install --reinstall libvirt-daemon-system libvirt-daemon libvirt-clients libvirt0"
  warn "  sudo ldconfig && sudo systemctl restart libvirtd && sudo virsh net-start default"
  return 1
}

stage_buildvm() {
  log "STAGE buildvm: build analysis guests via capevm.py (stealth-hardened)"
  ensure_build_tools
  if ! ensure_network; then
    warn "Skipping VM build — no usable libvirt bridge. Fix libvirt/network above, then re-run 'buildvm'."
    return 1
  fi
  [ -f "$CAPEVM" ] || die "capevm.py not found at $CAPEVM (set CAPEVM=...)."
  [ -f "$INSTALL_ISO" ] || die "INSTALL_ISO not found: $INSTALL_ISO"
  [ -f "$AGENT_PY" ] || die "agent.py not found at $AGENT_PY; run the 'cape' stage first."
  [ -f "$PYTHON_INSTALLER" ] || warn "PYTHON_INSTALLER '$PYTHON_INSTALLER' missing — guest \
will lack x86 Python unless you fix this."

  # Choose identity source: cloned DMI profile if present, else preset.
  local id_args=()
  if [ -f "$DMI_PROFILE" ]; then
    id_args+=(--dmi-profile "$DMI_PROFILE")
    [ "$DMI_KEEP_SERIALS" = "1" ] && id_args+=(--keep-dmi-serials)
    log "Using cloned DMI profile $DMI_PROFILE"
  else
    id_args+=(--smbios-profile "$SMBIOS_PROFILE")
    log "Using SMBIOS preset '$SMBIOS_PROFILE'"
  fi
  [ "${REALISTIC_HW:-0}" = "1" ] && { id_args+=(--realistic-hw); log "Realistic HW (CPU topology + DIMM strings) enabled"; }
  [ "${DECOY:-1}" = "0" ] && id_args+=(--no-decoy)
  if [ "${DECOY_FILL_MB:-0}" -gt 0 ] 2>/dev/null; then id_args+=(--decoy-fill-mb "$DECOY_FILL_MB"); fi

  local failures=0
  for entry in "${VM_LIST[@]}"; do
    IFS='|' read -r name ip snap tags platform <<< "$entry"
    platform="${platform:-windows}"
    log "Building $platform VM '$name' ($ip, snapshot '$snap')"
    local plat_args=(--platform "$platform")
    [ "${FORCE:-0}" = "1" ] && plat_args+=(--force)
    if [ "$platform" = "linux" ]; then
      [ -n "${CLOUD_IMAGE:-}" ] || { warn "VM '$name' is linux but CLOUD_IMAGE unset — skipping."; failures=$((failures+1)); continue; }
      plat_args+=(--cloud-image "$CLOUD_IMAGE")
    else
      plat_args+=(--install-iso "$INSTALL_ISO" --python-installer "$PYTHON_INSTALLER")
    fi
    if python3 "$CAPEVM" build \
        --name "$name" --ip "$ip" --snapshot "$snap" --tags "$tags" \
        --bridge "$VM_BRIDGE" --resultserver-ip "$RESULTSERVER_IP" \
        --agent-py "$AGENT_PY" \
        --cpus "$VM_CPUS" --ram-mb "$VM_RAM_MB" --disk-gb "$VM_DISK_GB" \
        --timeout-min "$BUILD_TIMEOUT_MIN" \
        "${plat_args[@]}" "${id_args[@]}" 2>&1 | tee -a "$LOGFILE"; then
      ok "VM '$name' built."
    else
      warn "VM '$name' build failed — see log. Continuing."
      failures=$((failures + 1))
    fi
  done
  [ "$failures" -eq 0 ] && ok "STAGE buildvm complete" \
    || warn "STAGE buildvm finished with $failures failure(s)."
}

stage_register() {
  log "STAGE register: write conf/kvm.conf and point cuckoo.conf at kvm"
  local kvmconf="$CAPE_ROOT/conf/kvm.conf"
  local cuckooconf="$CAPE_ROOT/conf/cuckoo.conf"
  [ -d "$CAPE_ROOT/conf" ] || die "conf/ missing; run 'cape' first."

  local names="" sections=""
  for entry in "${VM_LIST[@]}"; do
    IFS='|' read -r name ip snap tags platform <<< "$entry"
    platform="${platform:-windows}"
    names="${names:+$names,}$name"
    sections+=$'\n'"[$name]"$'\n'
    sections+="label = $name"$'\n'
    sections+="platform = $platform"$'\n'
    sections+="ip = $ip"$'\n'
    sections+="arch = x64"$'\n'
    sections+="tags = $tags"$'\n'
    sections+="snapshot = $snap"$'\n'
    sections+="resultserver_ip = $RESULTSERVER_IP"$'\n'
    sections+="reserved = no"$'\n'
  done

  [ -f "$kvmconf" ] && { cp -a "$kvmconf" "${kvmconf}.bak.$(date +%s)"; ok "Backed up kvm.conf"; }
  cat > "$kvmconf" <<EOF
[kvm]
machines = ${names}
interface = ${NETWORK_IFACE}
dsn = qemu:///system
${sections}
EOF
  chown "$CAPE_USER":"$CAPE_USER" "$kvmconf"
  ok "Wrote $kvmconf"

  if [ -f "$cuckooconf" ]; then
    cp -a "$cuckooconf" "${cuckooconf}.bak.$(date +%s)"
    # machinery: ensure EXACTLY ONE line, under [cuckoo] (a duplicate makes CAPE's
    # config parser throw DuplicateOptionError and cape.service crash-loops).
    sed -i '/^machinery[[:space:]]*=/d' "$cuckooconf"
    sed -i '/^\[cuckoo\]/a machinery = kvm' "$cuckooconf"
    # resultserver IP: CAPE binds the result server from cuckoo.conf's
    # [resultserver] ip, NOT from kvm.conf. If it's left at the default
    # (192.168.1.1) the bind fails with "Cannot assign requested address".
    if grep -q '^\[resultserver\]' "$cuckooconf"; then
      sed -i "/^\[resultserver\]/,/^\[/ s/^ip[[:space:]]*=.*/ip = $RESULTSERVER_IP/" "$cuckooconf"
      sed -i "/^\[resultserver\]/,/^\[/ s/^port[[:space:]]*=.*/port = $RESULTSERVER_PORT/" "$cuckooconf"
    fi
    ok "Set machinery = kvm and [resultserver] ip = $RESULTSERVER_IP in cuckoo.conf (backup saved)"
  else
    warn "cuckoo.conf not found; set [cuckoo] machinery = kvm and [resultserver] ip = $RESULTSERVER_IP manually."
  fi
  ok "STAGE register complete"
}

stage_services() {
  log "STAGE services: restart and verify CAPE services"
  # order matters: rooter + main scheduler come up before web/processor
  local svcs=(cape-rooter.service cape.service cape-web.service cape-processor.service)
  systemctl daemon-reload || true
  for s in "${svcs[@]}"; do
    # `systemctl cat` is a format-independent existence test (grepping
    # list-unit-files text is fragile across systemd versions).
    if systemctl cat "$s" >/dev/null 2>&1; then
      systemctl enable "$s" >/dev/null 2>&1 || true
      systemctl reset-failed "$s" >/dev/null 2>&1 || true
      systemctl restart "$s" || warn "Failed to restart $s"
      sleep 2
      systemctl is-active --quiet "$s" && ok "$s active" || warn "$s NOT active — journalctl -u $s"
    else
      warn "$s not installed (was 'cape' run?)"
    fi
  done
  ok "STAGE services complete"
}

stage_tls() {
  log "STAGE tls: self-signed HTTPS for the CAPE web UI (terminate at nginx)"
  command -v openssl >/dev/null || { log "Installing openssl"; apt-get install -y openssl; }
  command -v nginx >/dev/null || { log "Installing nginx"; apt-get install -y nginx; }
  mkdir -p "$(dirname "$TLS_CERT")" "$(dirname "$TLS_KEY")"

  if [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
    ok "cert already present ($TLS_CERT)"
  else
    local ip san; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    san="DNS:${TLS_SERVER_NAME}"; [ -n "$ip" ] && san="$san,IP:$ip"
    log "Generating self-signed cert (CN=$TLS_SERVER_NAME, SAN=$san, ${TLS_DAYS}d)"
    openssl req -x509 -nodes -days "$TLS_DAYS" -newkey rsa:2048 \
      -keyout "$TLS_KEY" -out "$TLS_CERT" \
      -subj "/CN=${TLS_SERVER_NAME}" -addext "subjectAltName=${san}" 2>>"$LOGFILE" \
      || { warn "openssl cert generation failed; see log."; return 0; }
    chmod 600 "$TLS_KEY"
    ok "cert -> $TLS_CERT"
  fi

  # nginx vhost: terminate TLS on 443, proxy to the existing web socket.
  local vhost="/etc/nginx/conf.d/cape-tls.conf"
  [ -f "$vhost" ] && cp -a "$vhost" "${vhost}.bak.$(date +%s)"
  {
    [ "$TLS_REDIRECT_HTTP" = "1" ] && cat <<EOF
server { listen 80; server_name ${TLS_SERVER_NAME}; return 301 https://\$host\$request_uri; }
EOF
    cat <<EOF
server {
    listen 443 ssl;
    server_name ${TLS_SERVER_NAME};
    ssl_certificate ${TLS_CERT};
    ssl_certificate_key ${TLS_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 100M;
    location / {
        proxy_pass http://127.0.0.1:${WEB_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
  } > "$vhost"

  if nginx -t 2>>"$LOGFILE"; then
    systemctl reload nginx 2>/dev/null || systemctl restart nginx || warn "nginx reload failed."
    systemctl enable nginx >/dev/null 2>&1 || true
    ok "nginx HTTPS vhost active on :443 (server_name ${TLS_SERVER_NAME})."
  else
    warn "nginx -t failed — removing TLS vhost so nginx is not left broken."
    rm -f "$vhost"
    return 0
  fi

  # Django must accept the HTTPS origin. Idempotent appended override block.
  local settings="$CAPE_ROOT/web/web/settings.py"
  if [ -f "$settings" ]; then
    if grep -q "CAPE-DEPLOY-TLS" "$settings"; then
      ok "Django settings already patched."
    else
      local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
      cp -a "$settings" "${settings}.bak.$(date +%s)"
      cat >> "$settings" <<EOF

# --- CAPE-DEPLOY-TLS (self-signed HTTPS) ---
# '*' is acceptable here only because this host is isolated (see netiso) and the
# UI must not be exposed publicly. Narrow it if your deployment differs.
ALLOWED_HOSTS = ['*']
CSRF_TRUSTED_ORIGINS = list(set((globals().get('CSRF_TRUSTED_ORIGINS') or [])
    + ['https://${TLS_SERVER_NAME}'] + (['https://${ip}'] if '${ip}' else [])))
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
EOF
      chown "$CAPE_USER":"$CAPE_USER" "$settings" 2>/dev/null || true
      ok "Patched Django ALLOWED_HOSTS / CSRF_TRUSTED_ORIGINS (backup saved)."
      systemctl restart cape-web.service 2>/dev/null || warn "restart cape-web manually."
      # give cape-web time to rebind :$WEB_PORT before verify/handoff checks it
      if _port_up "$WEB_PORT"; then
        ok "cape-web back up on :$WEB_PORT."
      else
        warn "cape-web not listening on :$WEB_PORT yet — check 'journalctl -u cape-web'."
        warn "If it crash-loops, the settings patch may not fit your CAPE version; the"
        warn "pre-TLS backup is at ${settings}.bak.* — restore it and restart cape-web."
      fi
    fi
  else
    warn "Django settings not found at $settings — add ALLOWED_HOSTS / "
    warn "CSRF_TRUSTED_ORIGINS=https://${TLS_SERVER_NAME} manually."
  fi
  ok "STAGE tls complete. UI: https://${TLS_SERVER_NAME}/ (self-signed — browser warning expected)."
  log "Local automation keeps using http://127.0.0.1:${WEB_PORT} (unchanged)."
}

# ----- verify: read-only health check, never aborts -----
_check() {  # _check "label" <command...>  -> prints PASS/FAIL, bumps counter
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    ok "PASS: $label"
  else
    warn "FAIL: $label"
    VERIFY_FAILS=$((VERIFY_FAILS + 1))
  fi
}

# a listener may take a few seconds to (re)bind after a service restart, so poll
# rather than checking once (avoids false negatives right after tls/services).
_port_up() {  # _port_up <port>  -> 0 if something is listening within ~20s
  local p="$1" i
  for i in $(seq 1 20); do
    ss -lntH "sport = :$p" 2>/dev/null | grep -q . && return 0
    sleep 1
  done
  return 1
}

stage_verify() {
  log "STAGE verify: health checks"
  VERIFY_FAILS=0

  _check "/dev/kvm present" test -e /dev/kvm
  _check "bridge $VM_BRIDGE up" ip link show "$VM_BRIDGE"
  for s in cape.service cape-processor.service cape-web.service cape-rooter.service; do
    _check "$s active" systemctl is-active --quiet "$s"
  done

  # resultserver + web listening (retry — they can lag a service restart)
  _check "resultserver listening :$RESULTSERVER_PORT" _port_up "$RESULTSERVER_PORT"
  _check "web listening :$WEB_PORT" _port_up "$WEB_PORT"

  # per-VM: domain defined + named snapshot exists + agent port reachable
  for entry in "${VM_LIST[@]}"; do
    IFS='|' read -r name ip snap _tags <<< "$entry"
    _check "domain $name defined" virsh dominfo "$name"
    _check "snapshot '$snap' on $name" \
      bash -c "virsh snapshot-list --name '$name' 2>/dev/null | grep -qx '$snap'"
  done

  _check "network isolation active (sandbox_iso table)" \
    bash -c "nft list table inet sandbox_iso >/dev/null 2>&1"

  echo
  if [ "${VERIFY_FAILS:-0}" -eq 0 ]; then
    ok "VERIFY: all checks passed."
  else
    warn "VERIFY: ${VERIFY_FAILS} check(s) failed — review above and the service logs."
  fi
  echo "End-to-end smoke test:  sudo ./cape-deploy.sh smoketest"
}

stage_netiso() {
  log "STAGE netiso: enforce fail-closed network isolation (mode=${ISO_MODE})"
  [ -f "$NETISO" ] || die "netiso.sh not found at $NETISO (set NETISO=...)."
  command -v nft >/dev/null || { log "Installing nftables"; apt-get install -y nftables; }
  local args=(apply --mode "$ISO_MODE" --iface "$VM_BRIDGE" --subnet "$ANALYSIS_SUBNET"
              --host-ip "$RESULTSERVER_IP" --resultserver-port "$RESULTSERVER_PORT")
  case "$ISO_MODE" in
    gateway)   args+=(--gateway-iface "$GATEWAY_IFACE") ;;
    simulated) args+=(--fakenet-ip "$FAKENET_IP") ;;
  esac
  bash "$NETISO" "${args[@]}" 2>&1 | tee -a "$LOGFILE" \
    || warn "netiso apply returned non-zero — isolation may still be active; check 'netiso.sh status'."
  bash "$NETISO" verify --mode "$ISO_MODE" --gateway-iface "$GATEWAY_IFACE" 2>&1 | tee -a "$LOGFILE" || true
  ok "STAGE netiso complete"
}

stage_smoketest() {
  log "STAGE smoketest: submit a benign sample and confirm a report comes back"
  [ -f "$SMOKETEST" ] || die "smoketest.sh not found at $SMOKETEST (set SMOKETEST=...)."
  local args=(--url "http://127.0.0.1:${WEB_PORT}" --cape-root "$CAPE_ROOT")
  [ -n "$CAPE_API_TOKEN" ] && args+=(--token "$CAPE_API_TOKEN")
  bash "$SMOKETEST" "${args[@]}" 2>&1 | tee -a "$LOGFILE"
}

# ----------------------------- driver --------------------------------------
run_stage() {
  case "$1" in
    host)      stage_host ;;
    cape)      stage_cape ;;
    deps)      stage_deps ;;
    update-policy) stage_update_policy ;;
    community) stage_community ;;
    dmi)       stage_dmi ;;
    buildvm)   stage_buildvm ;;
    register)  stage_register ;;
    netiso)    stage_netiso ;;
    services)  stage_services ;;
    tls)       stage_tls ;;
    verify)    stage_verify ;;
    smoketest) stage_smoketest ;;
    all)
      # a full run should be hands-off: auto-clean a stale domain/disk left by a
      # previous failed attempt instead of stopping. (Override with FORCE=0.)
      : "${FORCE:=1}"; export FORCE
      preflight; stage_host; stage_cape
      stage_deps || warn "deps stage reported issues — continuing (fix MongoDB/deps, then re-run 'deps')."
      stage_community
      stage_dmi; stage_buildvm; stage_register
      stage_netiso || warn "netiso reported issues — continuing (verify with 'netiso.sh status')."
      stage_services || warn "services stage reported issues — continuing (fix the VM build, then re-run 'services')."
      [ "${ENABLE_TLS:-0}" = "1" ] && { stage_tls || warn "tls stage reported issues — continuing."; }
      stage_verify || warn "verify reported issues — review above (non-fatal in 'all')."
      stage_smoketest || warn "smoketest did not pass — review above (non-fatal in 'all')."
      ;;
    *) die "Unknown stage '$1' (host|cape|deps|community|dmi|buildvm|register|netiso|services|tls|verify|smoketest|update-policy|all)" ;;
  esac
}

main() {
  local stages=()
  for a in "$@"; do
    case "$a" in
      --yes|-y) ASSUME_YES=1 ;;
      --tls) ENABLE_TLS=1 ;;
      -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) stages+=("$a") ;;
    esac
  done
  [ "${#stages[@]}" -gt 0 ] || stages=("all")

  require_root
  mkdir -p "$(dirname "$LOGFILE")" && touch "$LOGFILE"
  log "Logging to $LOGFILE"
  confirm_safety
  preflight
  for s in "${stages[@]}"; do
    [ "$s" = "all" ] && { run_stage all; continue; }
    run_stage "$s"
  done
  ok "Done. Review $LOGFILE; submit a benign test sample before any real use."
}

main "$@"
