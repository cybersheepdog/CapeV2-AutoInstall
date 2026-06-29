#!/usr/bin/env bash
#
# watchdog.sh — operational hygiene for a long-running CAPE sandbox.
#
# Catches the quiet failure modes that degrade a sandbox over time: disk filling
# up, a dead service, an analysis VM stuck running, and old results never pruned.
#
#   check         read-only report (safe; use this in cron/systemd timer)
#   reap          act on findings: restart dead services, revert stuck VMs to
#                 their clean snapshot, prune old analyses (needs --yes)
#   install-timer install a systemd timer that runs `check` every 30 min
#   status        same as check
#
# Tunables come from sandbox.conf (WATCHDOG_DISK_PCT, WATCHDOG_STUCK_MIN,
# WATCHDOG_RETENTION_DAYS) or flags. Reap is never automatic.
#
# Usage:
#   ./watchdog.sh check
#   sudo ./watchdog.sh reap --yes
#   sudo ./watchdog.sh install-timer
# ---------------------------------------------------------------------------

set -Eeuo pipefail

SELF_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
[ -f "$SELF_DIR/sandbox.conf" ] && . "$SELF_DIR/sandbox.conf"

: "${CAPE_USER:=cape}"
: "${CAPE_ROOT:=/opt/CAPEv2}"
: "${WATCHDOG_DISK_PCT:=90}"
: "${WATCHDOG_STUCK_MIN:=120}"
: "${WATCHDOG_RETENTION_DAYS:=30}"
declare -p VM_LIST >/dev/null 2>&1 || VM_LIST=( "win10x64_1|192.168.122.101|clean|x64,win10" )

SERVICES=(cape.service cape-processor.service cape-web.service cape-rooter.service)
ANALYSES_DIR="${CAPE_ROOT}/storage/analyses"
ASSUME_YES=0
REAP=0

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_rst=$'\e[0m'
log()  { echo "${c_blu}[*]${c_rst} $*"; }
ok()   { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_ylw}[!]${c_rst} $*" >&2; }
die()  { echo "${c_red}[-]${c_rst} $*" >&2; exit 1; }

ISSUES=0
note_issue() { ISSUES=$((ISSUES + 1)); }

# --------------------------------------------------------------------------- #
check_disk() {
  log "Disk"
  local pct
  pct="$(df --output=pcent "$CAPE_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"
  if [ "${pct:-0}" -ge "$WATCHDOG_DISK_PCT" ]; then
    warn "/ holding $CAPE_ROOT is ${pct}% full (threshold ${WATCHDOG_DISK_PCT}%)."
    note_issue
  else
    ok "disk ${pct}% (under ${WATCHDOG_DISK_PCT}%)."
  fi
}

check_services() {
  log "Services"
  for s in "${SERVICES[@]}"; do
    if ! systemctl list-unit-files 2>/dev/null | grep -q "^$s"; then
      warn "$s not installed."; continue
    fi
    if systemctl is-active --quiet "$s"; then
      ok "$s active."
    else
      warn "$s is DOWN."
      note_issue
      if [ "$REAP" = "1" ]; then
        log "reap: restarting $s"
        systemctl restart "$s" && ok "$s restarted." || warn "restart of $s failed."
      fi
    fi
  done
}

# qemu process elapsed seconds for a libvirt domain, or empty if not running
_vm_etimes() {
  local name="$1" pid
  pid="$(pgrep -f "guest=${name}," 2>/dev/null | head -1 || true)"
  [ -n "$pid" ] || return 0
  ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' '
}

check_stuck_vms() {
  log "Stuck analysis VMs"
  local stuck_s=$(( WATCHDOG_STUCK_MIN * 60 ))
  local any=0
  for entry in "${VM_LIST[@]}"; do
    IFS='|' read -r name _ip snap _tags <<< "$entry"
    local et; et="$(_vm_etimes "$name")"
    [ -n "${et:-}" ] || continue
    any=1
    if [ "$et" -ge "$stuck_s" ]; then
      warn "$name has been running ${et}s (> ${WATCHDOG_STUCK_MIN}m) — likely stuck."
      note_issue
      if [ "$REAP" = "1" ]; then
        log "reap: reverting $name to snapshot '$snap'"
        virsh snapshot-revert "$name" "$snap" 2>/dev/null \
          && ok "$name reverted to '$snap'." \
          || warn "revert of $name failed (check 'virsh snapshot-list $name')."
      fi
    else
      ok "$name running ${et}s (active analysis, under threshold)."
    fi
  done
  [ "$any" = "0" ] && ok "no analysis VMs currently running."
}

check_retention() {
  log "Retention (analyses older than ${WATCHDOG_RETENTION_DAYS}d)"
  if [ "$WATCHDOG_RETENTION_DAYS" = "0" ]; then
    ok "retention disabled."
    return
  fi
  if [ ! -d "$ANALYSES_DIR" ]; then
    warn "analyses dir not found: $ANALYSES_DIR"
    return
  fi
  mapfile -t old < <(find "$ANALYSES_DIR" -mindepth 1 -maxdepth 1 -type d \
                       -mtime +"$WATCHDOG_RETENTION_DAYS" 2>/dev/null || true)
  if [ "${#old[@]}" -eq 0 ]; then
    ok "nothing older than ${WATCHDOG_RETENTION_DAYS}d."
    return
  fi
  warn "${#old[@]} analysis dir(s) older than ${WATCHDOG_RETENTION_DAYS}d."
  note_issue
  if [ "$REAP" = "1" ]; then
    log "reap: pruning ${#old[@]} old analysis dir(s)"
    local n=0
    for d in "${old[@]}"; do rm -rf -- "$d" && n=$((n + 1)); done
    ok "pruned $n dir(s). NOTE: run CAPE's utils/cleaners.py to drop matching DB records."
  else
    log "(reap to delete; also run utils/cleaners.py for DB records)"
  fi
}

# --------------------------------------------------------------------------- #
run_checks() {
  ISSUES=0
  check_disk
  check_services
  check_stuck_vms
  check_retention
  echo
  if [ "$ISSUES" -eq 0 ]; then
    ok "WATCHDOG: healthy."
  else
    warn "WATCHDOG: ${ISSUES} issue(s)."
    [ "$REAP" = "0" ] && echo "Run 'sudo $0 reap --yes' to act on them."
  fi
}

cmd_reap() {
  [ "$(id -u)" -eq 0 ] || die "reap needs root."
  if [ "$ASSUME_YES" != "1" ]; then
    warn "reap will restart services, REVERT stuck VMs, and DELETE old analyses."
    read -r -p "Proceed? type 'yes': " r; [ "$r" = "yes" ] || die "aborted."
  fi
  REAP=1
  run_checks
}

cmd_install_timer() {
  [ "$(id -u)" -eq 0 ] || die "install-timer needs root."
  local svc=/etc/systemd/system/cape-watchdog.service
  local tmr=/etc/systemd/system/cape-watchdog.timer
  cat > "$svc" <<EOF
[Unit]
Description=CAPE sandbox watchdog (read-only health check)
[Service]
Type=oneshot
ExecStart=$(readlink -f "$0") check
EOF
  cat > "$tmr" <<EOF
[Unit]
Description=Run CAPE watchdog every 30 minutes
[Timer]
OnBootSec=10min
OnUnitActiveSec=30min
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now cape-watchdog.timer
  ok "Installed cape-watchdog.timer (check every 30m; view: journalctl -u cape-watchdog)."
}

# --------------------------------------------------------------------------- #
CMD="${1:-check}"; shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1; shift ;;
    --disk-pct) WATCHDOG_DISK_PCT="$2"; shift 2 ;;
    --stuck-min) WATCHDOG_STUCK_MIN="$2"; shift 2 ;;
    --retention-days) WATCHDOG_RETENTION_DAYS="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$CMD" in
  check|status) run_checks ;;
  reap)         cmd_reap ;;
  install-timer) cmd_install_timer ;;
  -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '$CMD' (check|reap|install-timer|status)" ;;
esac
