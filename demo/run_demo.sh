#!/usr/bin/env bash
# Full end-to-end demo, built for screen recording. POSIX/macOS/Linux version
# of demo/run_demo.ps1 -- see that file for the Windows path, which is the one
# verified on the development machine.
#
# Everything it starts, it stops, including on Ctrl+C.
#
#   ./demo/run_demo.sh              full run, ~2m20s
#   ./demo/run_demo.sh --skip-calib reuse an existing baseline, ~1m30s

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8000}"
BASE="http://127.0.0.1:${PORT}"
LOG="$ROOT/data/logs/requests.jsonl"
CALIB="$ROOT/data/logs/benign_calib.jsonl"
THRESHOLDS="$ROOT/thresholds.json"
SKIP_CALIB=0
[ "${1:-}" = "--skip-calib" ] && SKIP_CALIB=1

# Prefer the venv interpreter; fall back to whatever python3 is on PATH.
if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"
elif [ -x "$ROOT/.venv/Scripts/python.exe" ]; then PY="$ROOT/.venv/Scripts/python.exe"
else PY="$(command -v python3 || command -v python)"; fi

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'
MAG=$'\033[1;35m'; CYN=$'\033[1;36m'; DIM=$'\033[2m'; OFF=$'\033[0m'

PIDS=()
# One trap for every exit path, so no python process outlives the script.
cleanup() {
  echo; echo "${DIM}cleaning up...${OFF}"
  for pid in "${PIDS[@]:-}"; do
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      echo "${DIM}  stopped pid $pid${OFF}"
    fi
  done
  wait 2>/dev/null || true
  echo "${DIM}done.${OFF}"
}
trap cleanup EXIT INT TERM

banner() {
  local color="${2:-$CYN}"
  printf '\n%s%s\n  %s\n%s%s\n\n' "$color" "$(printf '=%.0s' {1..74})" "$1" \
    "$(printf '=%.0s' {1..74})" "$OFF"
}
step() { printf '  %s> %s%s\n' "$DIM" "$1" "$OFF"; }

track() { "$@" >/dev/null 2>&1 & PIDS+=($!); }

# --- Live scoring printed into THIS console, so a recording catches it.
# --- Announces a key only when its evidence changes; silence means clean.
declare -A ANNOUNCED
watch_inline() {
  local deadline=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -f "$LOG" ]; then
      local json
      json="$("$PY" "$ROOT/detector/score.py" --log "$LOG" \
              --thresholds "$THRESHOLDS" --json 2>/dev/null || true)"
      if [ -n "$json" ]; then
        while IFS=$'\t' read -r key flags nreq sigs; do
          [ -z "${key:-}" ] && continue
          if [ "${ANNOUNCED[$key]:-}" != "$sigs" ]; then
            ANNOUNCED[$key]="$sigs"
            printf '\n  %s[ALERT %s] EXTRACTION SUSPECTED  api_key=%s  flags=%s/10  requests=%s%s\n' \
              "$RED" "$(date +%H:%M:%S)" "$key" "$flags" "$nreq" "$OFF"
            printf '      %ssignals: %s%s\n\n' "$RED" "$sigs" "$OFF"
          fi
        done < <(printf '%s' "$json" | "$PY" -c '
import json, sys
try:
    v = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for k, r in v.items():
    if r.get("verdict") != "ATTACK":
        continue
    sig = ", ".join("%s(%.1f)" % (n, r["z"][n])
                    for n in sorted(r["flags"], key=lambda n: -r["z"][n]))
    print("\t".join([k, str(r["n_flags"]), str(r["n_requests"]), sig]))
')
        local summary
        summary="$(printf '%s' "$json" | "$PY" -c '
import json, sys
try:
    v = json.load(sys.stdin)
except Exception:
    sys.exit(0)
tot = sum(r["n_requests"] for r in v.values())
bad = sum(r["verdict"] == "ATTACK" for r in v.values())
print("%d %d" % (tot, bad))
')"
        if [ -n "$summary" ] && [ "${summary##* }" = "0" ]; then
          printf '  %s[%s] %s requests scored - all clean%s\n' \
            "$GRN" "$(date +%H:%M:%S)" "${summary%% *}" "$OFF"
        fi
      fi
    fi
    sleep 3
  done
}

if [ ! -x "$PY" ] && ! command -v "$PY" >/dev/null; then
  echo "${RED}No python interpreter found. Create the venv first:${OFF}"
  echo "  python -m venv .venv && .venv/bin/python -m pip install -r api/requirements.txt"
  exit 1
fi

banner "EXTRACTION DETECTOR - LIVE DEMO" "$MAG"
echo "  A sentiment API is about to be cloned by an attacker."
echo "  The attacker will run at roughly one query per second --"
echo "  the same rate as a normal customer. No rate limit would fire."
echo

step "starting the victim API on port $PORT"
cd "$ROOT"
"$PY" -m uvicorn api.main:app --host 127.0.0.1 --port "$PORT" >/dev/null 2>&1 &
PIDS+=($!)

step "waiting for the model to load (first run downloads ~268MB)"
ready=0
for _ in $(seq 1 150); do
  if curl -s -m 2 "$BASE/health" 2>/dev/null | grep -q '"model_loaded":true'; then
    ready=1; break
  fi
  sleep 2
done
[ "$ready" = "1" ] || { echo "${RED}API did not become ready.${OFF}"; exit 1; }
printf '  %sAPI ready: model_loaded=true%s\n' "$GRN" "$OFF"

if [ "$SKIP_CALIB" = "1" ] && [ -f "$THRESHOLDS" ]; then
  step "reusing existing baseline (--skip-calib)"
else
  banner "CALIBRATION: learning what normal looks like" "$YEL"
  echo "  Four ordinary customers, 45 queries each."
  echo "  The detector sees ONLY benign traffic here -- it never"
  echo "  learns any attack signature. That is what keeps the"
  echo "  evaluation honest."
  echo
  rm -f "$LOG"
  for i in 0 1 2 3; do
    track "$PY" traffic/generate.py --profile benign --n 45 --rate 6 \
      --jitter 0.5 --api-key "cal-user-$i" --seed $((100 + i))
  done
  wait
  mv "$LOG" "$CALIB"
  step "fitting the baseline"
  "$PY" detector/calibrate.py --log "$CALIB" --out "$THRESHOLDS" | head -1
fi
rm -f "$LOG"

banner "PHASE 1: Normal traffic - watch the console" "$GRN"
echo "  Two ordinary customers are now querying the API."
printf '  %sThe detector is watching live. Expect NO alerts.%s\n\n' "$GRN" "$OFF"
step "two customers sending traffic; detector scoring live every 3s"
for i in 0 1; do
  track "$PY" traffic/generate.py --profile benign --n 30 --rate 1.5 \
    --jitter 0.5 --api-key "customer-$i" --seed $((200 + i))
done
watch_inline 26
printf '\n  %sPhase 1 over: no alerts, as expected.%s\n' "$GRN" "$OFF"

banner "PHASE 2: Attacker starts now" "$RED"
echo "  Same rate as the customers above. Poisson-spaced, so the"
echo "  timing looks human too. The only difference is WHAT it asks:"
echo "  systematic probes around the model's decision boundary."
printf '\n  %sWatch for the ALERT line.%s\n\n' "$RED" "$OFF"
track "$PY" traffic/generate.py --profile boundary --n 40 --rate 1.5 \
  --attacker-pacing poisson --api-key "extraction-attacker" --seed 303
watch_inline 32

banner "RESULT" "$MAG"
"$PY" detector/score.py --log "$LOG" --thresholds "$THRESHOLDS"
echo
"$PY" eval/evaluate.py --log "$LOG" --thresholds "$THRESHOLDS" \
  --attack-prefix extraction-
banner "DEMO COMPLETE" "$MAG"
