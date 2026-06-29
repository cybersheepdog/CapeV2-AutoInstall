#!/usr/bin/env bash
#
# smoketest.sh — prove the CAPE pipeline actually ANALYZES, end to end.
#
# `verify` (in cape-deploy.sh) confirms the infrastructure is up. This goes
# further: it submits a known-benign sample and asserts the whole chain runs —
# submit -> schedule -> VM revert -> agent -> execute -> result server ->
# processing -> report. A green run here means the sandbox works, not just that
# the daemons are alive.
#
# It talks to CAPE's REST API (apiv2). If your API requires a token, pass
# --token or set CAPE_API_TOKEN. The sample is a harmless .bat that just exits;
# override with --sample if you prefer your own benign file.
#
# Usage:
#   ./smoketest.sh                               # defaults: http://127.0.0.1:8000
#   ./smoketest.sh --url http://127.0.0.1:8000 --token <tok>
#   ./smoketest.sh --sample /path/to/benign.exe --package exe --timeout-min 15
#
# Exit code: 0 = PASS, non-zero = FAIL (usable in CI / as a deploy gate).
# ---------------------------------------------------------------------------

set -Eeuo pipefail

SELF_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
[ -f "$SELF_DIR/sandbox.conf" ] && . "$SELF_DIR/sandbox.conf"

BASE_URL="${CAPE_URL:-http://127.0.0.1:${WEB_PORT:-8000}}"
TOKEN="${CAPE_API_TOKEN:-}"
SAMPLE=""
PACKAGE="bat"
TIMEOUT_MIN="15"
: "${CAPE_ROOT:=/opt/CAPEv2}"

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_rst=$'\e[0m'
log()  { echo "${c_blu}[*]${c_rst} $*"; }
ok()   { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_ylw}[!]${c_rst} $*" >&2; }
die()  { echo "${c_red}[-]${c_rst} $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --url) BASE_URL="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --sample) SAMPLE="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --timeout-min) TIMEOUT_MIN="$2"; shift 2 ;;
    --cape-root) CAPE_ROOT="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

command -v curl >/dev/null || die "curl not found."
command -v python3 >/dev/null || die "python3 not found."

AUTH=()
[ -n "$TOKEN" ] && AUTH=(-H "Authorization: Token ${TOKEN}")

TMPDIR_T="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_T"' EXIT

# ---- benign sample -------------------------------------------------------- #
if [ -z "$SAMPLE" ]; then
  SAMPLE="${TMPDIR_T}/smoketest.bat"
  cat > "$SAMPLE" <<'EOF'
@echo off
rem CAPE smoke test — benign, intentionally does nothing.
echo cape-smoketest-ok
exit /b 0
EOF
  log "Using generated benign sample: smoketest.bat (package=${PACKAGE})"
else
  [ -f "$SAMPLE" ] || die "sample not found: $SAMPLE"
  log "Using sample: $SAMPLE (package=${PACKAGE})"
fi

# ---- helper: GET json to a file, echo HTTP code --------------------------- #
api_get() {  # api_get <path> <outfile>
  curl -s -o "$2" -w '%{http_code}' "${AUTH[@]}" "${BASE_URL}$1"
}

# ---- submit --------------------------------------------------------------- #
log "Submitting to ${BASE_URL}/apiv2/tasks/create/file/"
resp="${TMPDIR_T}/submit.json"
code="$(curl -s -o "$resp" -w '%{http_code}' "${AUTH[@]}" \
  -F "file=@${SAMPLE}" -F "package=${PACKAGE}" -F "timeout=60" \
  "${BASE_URL}/apiv2/tasks/create/file/" || true)"

if [ "$code" = "401" ] || [ "$code" = "403" ]; then
  die "API auth required (HTTP $code). Set --token / CAPE_API_TOKEN, or check conf/api.conf."
fi
[ "$code" = "200" ] || { cat "$resp" 2>/dev/null | head -c 400; echo; \
  die "submit failed (HTTP $code). Is cape-web up at ${BASE_URL}?"; }

TASK_ID="$(python3 - "$resp" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
data = d.get("data", d)
tid = None
if isinstance(data, dict):
    tid = (data.get("task_ids") or [None])[0] if data.get("task_ids") else data.get("task_id")
print(tid if tid is not None else "")
PY
)"
[ -n "$TASK_ID" ] || { head -c 400 "$resp"; echo; die "could not parse task id from submit response."; }
ok "Submitted as task ${TASK_ID}"

# ---- poll status ---------------------------------------------------------- #
log "Waiting up to ${TIMEOUT_MIN}m for task ${TASK_ID} to report"
deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
status="unknown"
while [ "$(date +%s)" -lt "$deadline" ]; do
  vf="${TMPDIR_T}/view.json"
  vcode="$(api_get "/apiv2/tasks/view/${TASK_ID}/" "$vf" || true)"
  if [ "$vcode" = "200" ]; then
    status="$(python3 - "$vf" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
data = d.get("data", d)
task = data.get("task", data) if isinstance(data, dict) else {}
print(task.get("status", "unknown"))
PY
)"
    case "$status" in
      reported) ok "Status: reported"; break ;;
      failed_analysis|failed_processing|failed_reporting)
        die "Task ${TASK_ID} ended in '${status}'. Check the analysis log / journalctl." ;;
      *) printf '\r%s    ' "    status: ${status} ($(date +%H:%M:%S))" ;;
    esac
  fi
  sleep 15
done
echo
[ "$status" = "reported" ] || die "Timed out; last status '${status}'. Is a VM built and are cape/cape-processor running?"

# ---- assert the report has real content ----------------------------------- #
log "Fetching report to confirm processing produced content"
rf="${TMPDIR_T}/report.json"
rcode="$(api_get "/apiv2/tasks/get/report/${TASK_ID}/?format=json" "$rf" || true)"
[ "$rcode" = "200" ] || die "report fetch failed (HTTP $rcode)."

python3 - "$rf" <<'PY' || exit 1
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"[-] report is not valid JSON: {e}"); sys.exit(1)
data = d.get("data", d)
report = data if isinstance(data, dict) else {}
info = report.get("info", {})
checks = {
    "has info block": bool(info),
    "machine assigned": bool((info.get("machine") or {})),
    "behavior/processing present": any(k in report for k in ("behavior", "processing", "signatures", "target")),
}
ok = True
for label, passed in checks.items():
    print(("[+] PASS: " if passed else "[-] FAIL: ") + label)
    ok = ok and passed
sys.exit(0 if ok else 1)
PY

echo
ok "SMOKE TEST PASSED — the pipeline analyzed task ${TASK_ID} end to end."
