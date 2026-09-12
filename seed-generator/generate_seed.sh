#!/usr/bin/env bash
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
GEN="$ROOT/seed-generator/encode_ngsetup"
OUT="$ROOT/input/seed.bin"

if [ ! -x "$GEN" ]; then
  echo "encode_ngsetup is not built; run: make -C seed-generator" >&2
  exit 1
fi
mkdir -p "$ROOT/input"
hex="$($GEN | tr -d '[:space:]')"
case "$hex" in
  (''|*[!0-9A-Fa-f]*) echo "generator returned invalid hex" >&2; exit 1;;
esac
if [ $(( ${#hex} % 2 )) -ne 0 ]; then echo "odd-length hex" >&2; exit 1; fi
printf '%s' "$hex" | xxd -r -p > "$OUT"
echo "Wrote $OUT ($(wc -c < "$OUT") bytes)"
