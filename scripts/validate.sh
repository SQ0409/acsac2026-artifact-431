#!/usr/bin/env bash
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1" >&2
    exit 1
  }
}

need make
need gcc
need python3
need xxd

echo "[1/5] Building NGeniusFuzz core, targets, and seed generator..."
make -C "$ROOT/aflnet" clean all
make -C "$ROOT/targets" clean all
make -C "$ROOT/seed-generator" clean all

echo "[2/5] Regenerating input/seed.bin..."
"$ROOT/seed-generator/generate_seed.sh"
test -s "$ROOT/input/seed.bin"

echo "[3/5] Checking knowledge.json..."
python3 - "$ROOT/config/knowledge.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
assert isinstance(d.get("rules"), list) and d["rules"], "rules[] is empty"
print("knowledge.json: valid ({} rule)".format(len(d["rules"])))
PY

echo "[4/5] Checking target executables..."
test -x "$ROOT/targets/dummy"
test -x "$ROOT/targets/sctp_send"

echo "[5/5] Checking NGeniusFuzz command-line entry point..."
# Some AFL builds use status 1 for the usage screen; either status still
# proves that the executable started and parsed the command-line entry point.
set +e
"$ROOT/aflnet/afl-fuzz" -h >/dev/null 2>&1
help_status=$?
set -e
test "$help_status" -eq 0 -o "$help_status" -eq 1
echo "Offline validation passed. Open5GS is not required for this stage."
