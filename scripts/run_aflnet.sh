#!/usr/bin/env bash
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [ -f "$ROOT/config/local.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/config/local.env"
  set +a
fi
ENDPOINT="${SCTP_ENDPOINT:-sctp://127.0.0.1/38412}"
TARGET="${AFLNET_TARGET:-$ROOT/targets/sctp_send}"
mkdir -p "$ROOT/input" "$ROOT/output"
if [ ! -s "$ROOT/input/seed.bin" ]; then "$ROOT/seed-generator/generate_seed.sh"; fi
exec "$ROOT/aflnet/afl-fuzz" -m 5000 -t 5000+ -d \
  -i "$ROOT/input" -o "$ROOT/output" -x "$ROOT/config/ngap_nas.dict" \
  -N "$ENDPOINT" -P NGAP -D 300 -W 125 -w 4500 -q 1 -s 2 \
  -E -R -K -Z "$ROOT/config/knowledge.json" -n -- "$TARGET"
