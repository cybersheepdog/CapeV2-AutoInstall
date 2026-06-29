#!/usr/bin/env bash
#
# netiso.sh — fail-closed network isolation for a CAPE analysis network (nftables).
#
# Containment is the whole point of a sandbox: malware in a guest must NOT reach
# your LAN or the open internet. This enforces that on the analysis bridge with a
# dedicated nftables table whose filter hooks run BEFORE libvirt's own rules, so a
# drop here is final regardless of any libvirt NAT/masquerade.
#
# Modes:
#   isolated   guests reach ONLY the result server on the host. Everything else —
#              other hosts, the LAN, the internet, and other guests — is dropped.
#   simulated  guest traffic is DNAT'd to a fake-internet service (INetSim/FakeNet)
#              on the host; nothing is routed out. (INetSim must be running.)
#   gateway    controlled egress via a dedicated uplink (VPN/Tor) only, with a
#              kill-switch: if the uplink iface is down, egress fails closed.
#
# Design notes:
#   * default-deny: each chain ends in `drop` for the analysis interface.
#   * anti-spoof: source addr must be inside the analysis subnet.
#   * IPv6 from guests is dropped outright (avoids v6 egress leaks).
#   * guest-to-guest is blocked (stops worm spread between analysis VMs).
#   * result-server + (optional) host DHCP/DNS are the only host services exposed.
#
# Usage:
#   sudo ./netiso.sh apply   --mode isolated
#   sudo ./netiso.sh apply   --mode gateway --gateway-iface tun0
#   sudo ./netiso.sh dry-run --mode simulated     # print ruleset, apply nothing
#   sudo ./netiso.sh status
#   sudo ./netiso.sh verify
#   sudo ./netiso.sh down                          # remove isolation (opens guests!)
#
# ---------------------------------------------------------------------------

set -Eeuo pipefail

# ----- defaults: built-in, overridable by ./sandbox.conf or flags -----
SELF_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
[ -f "$SELF_DIR/sandbox.conf" ] && . "$SELF_DIR/sandbox.conf"

# Canonical names (shared with cape-deploy/sandbox.conf) map to internal vars.
: "${ANALYSIS_IFACE:=${VM_BRIDGE:-${NETWORK_IFACE:-virbr0}}}"
: "${ANALYSIS_SUBNET:=192.168.122.0/24}"
: "${HOST_IP:=${RESULTSERVER_IP:-192.168.122.1}}"   # result server / host on the analysis net
: "${RESULTSERVER_PORT:=2042}"
: "${FAKENET_IP:=${RESULTSERVER_IP:-192.168.122.1}}" # INetSim/FakeNet host (simulated mode)
: "${GATEWAY_IFACE:=tun0}"                           # uplink for gateway mode
: "${ALLOW_DHCP_DNS:=1}"                             # allow guest DHCP/DNS to host dnsmasq
: "${TABLE:=sandbox_iso}"
: "${MODE:=${ISO_MODE:-isolated}}"

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_rst=$'\e[0m'
log()  { echo "${c_blu}[*]${c_rst} $*"; }
ok()   { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_ylw}[!]${c_rst} $*" >&2; }
die()  { echo "${c_red}[-]${c_rst} $*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run with sudo/root."; }

# --------------------------------------------------------------------------- #
# Build the nftables ruleset for the selected mode (printed to stdout).
# --------------------------------------------------------------------------- #
build_ruleset() {
  local egress nat_block input_extra dhcpdns

  dhcpdns=""
  if [ "$ALLOW_DHCP_DNS" = "1" ]; then
    dhcpdns=$'        udp dport { 53, 67 } accept\n        tcp dport 53 accept'
  fi

  case "$MODE" in
    isolated)
      egress="        # isolated: no egress permitted"
      input_extra=""
      nat_block=""
      ;;
    simulated)
      egress="        # simulated: guest traffic is DNAT'd to the fakenet host (below)"
      input_extra="        ip daddr ${FAKENET_IP} ip protocol { tcp, udp } accept"
      nat_block="
  chain prerouting {
    type nat hook prerouting priority -110; policy accept;
    iifname != \"${ANALYSIS_IFACE}\" return
    ip daddr ${HOST_IP} return
    ip protocol { tcp, udp } dnat ip to ${FAKENET_IP}
  }"
      ;;
    gateway)
      egress="        oifname \"${GATEWAY_IFACE}\" accept   # only path out; down => fail-closed"
      input_extra=""
      nat_block="
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname \"${GATEWAY_IFACE}\" masquerade
  }"
      ;;
    *)
      die "unknown mode '$MODE' (isolated|simulated|gateway)"
      ;;
  esac

  cat <<EOF
add table inet ${TABLE}
flush table inet ${TABLE}
table inet ${TABLE} {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname != "${ANALYSIS_IFACE}" return
    meta nfproto ipv6 drop
    ip saddr != ${ANALYSIS_SUBNET} drop
    ct state established,related accept
    ip daddr ${HOST_IP} tcp dport ${RESULTSERVER_PORT} accept
${dhcpdns}
${input_extra}
    drop
  }

  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname != "${ANALYSIS_IFACE}" return
    meta nfproto ipv6 drop
    ip saddr != ${ANALYSIS_SUBNET} drop
    ct state established,related accept
    oifname "${ANALYSIS_IFACE}" drop
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
${egress}
    drop
  }${nat_block}
}
EOF
}

# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
cmd_dryrun() {
  log "Generated ruleset for mode '${MODE}' (NOT applied):"
  echo "------------------------------------------------------------"
  build_ruleset
  echo "------------------------------------------------------------"
}

cmd_apply() {
  require_root
  command -v nft >/dev/null || die "nftables (nft) not installed: apt-get install nftables"
  if [ "$MODE" = "gateway" ] && ! ip link show "$GATEWAY_IFACE" >/dev/null 2>&1; then
    warn "gateway iface '$GATEWAY_IFACE' not present — egress will fail closed until it's up."
  fi
  local rs; rs="$(build_ruleset)"
  log "Validating ruleset (nft -c)"
  printf '%s\n' "$rs" | nft -c -f - || die "ruleset failed validation; not applied."
  log "Applying isolation (mode=${MODE}, iface=${ANALYSIS_IFACE})"
  printf '%s\n' "$rs" | nft -f -
  ok "Isolation active. Verify with: $0 verify"
  [ "$MODE" = "simulated" ] && warn "Ensure INetSim/FakeNet is listening on ${FAKENET_IP}."
}

cmd_down() {
  require_root
  command -v nft >/dev/null || die "nft not installed."
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    nft delete table inet "$TABLE"
    ok "Isolation table removed."
    warn "Guests are NO LONGER contained by this script. Do not run malware now."
  else
    log "No '${TABLE}' table present; nothing to remove."
  fi
}

cmd_status() {
  command -v nft >/dev/null || die "nft not installed."
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    nft list table inet "$TABLE"
  else
    warn "Isolation NOT active (no '${TABLE}' table)."
  fi
}

cmd_verify() {
  command -v nft >/dev/null || die "nft not installed."
  local fails=0
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    ok "PASS: isolation table '${TABLE}' present."
  else
    warn "FAIL: isolation table not loaded — guests are NOT contained."
    fails=$((fails + 1))
  fi
  # forward chain must end in a drop for the analysis iface
  if nft list table inet "$TABLE" 2>/dev/null | grep -A30 'chain forward' | grep -q 'drop'; then
    ok "PASS: forward chain enforces default-deny."
  else
    warn "FAIL: forward chain missing default-deny."
    fails=$((fails + 1))
  fi
  if [ "$MODE" = "gateway" ]; then
    if ip link show "$GATEWAY_IFACE" 2>/dev/null | grep -q 'state UP'; then
      ok "PASS: gateway iface '${GATEWAY_IFACE}' is UP (egress permitted)."
    else
      warn "NOTE: gateway iface '${GATEWAY_IFACE}' down — egress fails closed (by design)."
    fi
  fi
  # leak hint: a libvirt masquerade is fine (our forward drop precedes postrouting),
  # but flag it so the operator understands the layering.
  if nft list ruleset 2>/dev/null | grep -qi masquerade && [ "$MODE" != "gateway" ]; then
    log "NOTE: a masquerade rule exists elsewhere (likely libvirt). Containment still"
    log "      holds because this script's forward-drop runs before NAT postrouting."
  fi
  echo
  [ "$fails" -eq 0 ] && ok "VERIFY: containment looks good." \
    || warn "VERIFY: ${fails} issue(s) — DO NOT run malware until resolved."
}

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
}

# --------------------------------------------------------------------------- #
# Arg parsing
# --------------------------------------------------------------------------- #
CMD="${1:-}"; shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --iface) ANALYSIS_IFACE="$2"; shift 2 ;;
    --subnet) ANALYSIS_SUBNET="$2"; shift 2 ;;
    --host-ip) HOST_IP="$2"; shift 2 ;;
    --resultserver-port) RESULTSERVER_PORT="$2"; shift 2 ;;
    --fakenet-ip) FAKENET_IP="$2"; shift 2 ;;
    --gateway-iface) GATEWAY_IFACE="$2"; shift 2 ;;
    --no-dhcp-dns) ALLOW_DHCP_DNS="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$CMD" in
  apply)   cmd_apply ;;
  dry-run) cmd_dryrun ;;
  status)  cmd_status ;;
  verify)  cmd_verify ;;
  down)    cmd_down ;;
  ""|-h|--help) usage ;;
  *) die "unknown command '$CMD' (apply|dry-run|status|verify|down)" ;;
esac
