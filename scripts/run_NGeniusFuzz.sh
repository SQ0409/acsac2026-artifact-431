#!/usr/bin/env bash
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -f "$ROOT/config/local.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/config/local.env"
  set +a
fi

if [ -z "${SCTP_ENDPOINT:-}" ]; then
  echo "SCTP_ENDPOINT is not set. Copy config/config.example.env to config/local.env and set it to the Open5GS AMF NGAP listener." >&2
  exit 2
fi

# The fuzzer checks this kernel setting before starting.  On distributions
# that pipe crashes to an external collector, temporarily switch to the
# plain 'core' format and restore the original value when this script exits.
ORIGINAL_CORE_PATTERN=""
CORE_PATTERN_CHANGED=0
restore_core_pattern() {
  if [ "$CORE_PATTERN_CHANGED" -eq 1 ]; then
    if [ "$(id -u)" -eq 0 ]; then
      printf '%s\n' "$ORIGINAL_CORE_PATTERN" > /proc/sys/kernel/core_pattern || true
    elif command -v sudo >/dev/null 2>&1; then
      printf '%s\n' "$ORIGINAL_CORE_PATTERN" | sudo tee /proc/sys/kernel/core_pattern >/dev/null || true
    fi
  fi
}
prepare_core_pattern() {
  [ -r /proc/sys/kernel/core_pattern ] || return 0
  ORIGINAL_CORE_PATTERN="$(cat /proc/sys/kernel/core_pattern)"
  case "$ORIGINAL_CORE_PATTERN" in
    \|*)
      echo "Preparing crash-dump handling (sudo may ask for your password)..." >&2
      if [ "$(id -u)" -eq 0 ]; then
        printf 'core\n' > /proc/sys/kernel/core_pattern
      else
        command -v sudo >/dev/null 2>&1 || {
          echo "sudo is required to adjust /proc/sys/kernel/core_pattern." >&2
          exit 1
        }
        sudo -v
        printf 'core\n' | sudo tee /proc/sys/kernel/core_pattern >/dev/null
      fi
      CORE_PATTERN_CHANGED=1
      ;;
  esac
}

trap restore_core_pattern EXIT
FUZZER_PID=0
stop_fuzzer() {
  if [ "$FUZZER_PID" -gt 0 ] && kill -0 "$FUZZER_PID" 2>/dev/null; then
    kill -TERM "$FUZZER_PID" 2>/dev/null || true
  fi
}
trap 'stop_fuzzer; exit 130' INT TERM
prepare_core_pattern

ENDPOINT="$SCTP_ENDPOINT"
TARGET="${NGENIUSFUZZ_TARGET:-${AFLNET_TARGET:-$ROOT/targets/sctp_send}}"
mkdir -p "$ROOT/input" "$ROOT/output"
if [ ! -s "$ROOT/input/seed.bin" ]; then "$ROOT/seed-generator/generate_seed.sh"; fi

export AFL_NO_UI=1
export AFL_QUIET="${AFL_QUIET:-0}"
set +e
"$ROOT/aflnet/afl-fuzz" -T NGeniusFuzz -m 5000 -t 5000+ -d \
  -i "$ROOT/input" -o "$ROOT/output" -x "$ROOT/config/ngap_nas.dict" \
  -N "$ENDPOINT" -P NGAP -D 300 -W 125 -w 4500 -q 1 -s 2 \
  -E -R -K -Z "$ROOT/config/knowledge.json" -n -- "$TARGET" &
FUZZER_PID=$!
wait "$FUZZER_PID"
status=$?
FUZZER_PID=0
set -e
exit "$status"
