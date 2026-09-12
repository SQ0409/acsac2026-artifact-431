#!/usr/bin/env bash
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
make -C "$ROOT/aflnet" clean all
make -C "$ROOT/targets" clean all
make -C "$ROOT/seed-generator" clean all
"$ROOT/seed-generator/generate_seed.sh"
echo "Build completed. Use scripts/run_aflnet.sh after configuring Open5GS."
