#!/usr/bin/env bash
set -e

# Unit tests first, with the race detector.
go test -count=1 -race ./...

# Skip fuzzing if requested (e.g. for quick local iteration).
if [ "${1:-}" = "--no-fuzz" ]; then
    echo "Skipping fuzz (--no-fuzz)"
    exit 0
fi

# Fuzz each target for FUZZTIME (default 5s). Override with e.g.
#   FUZZTIME=30s ./run_test.sh
FUZZTIME="${FUZZTIME:-5s}"

# Enumerate the fuzz targets so adding a new FuzzXxx picks it up automatically.
FUZZ_FUNCS=$(go test -list '^Fuzz' ./... | grep -E '^Fuzz[A-Za-z0-9_]+$')

for fuzz in $FUZZ_FUNCS; do
    echo ">>> Fuzzing $fuzz for $FUZZTIME"
    go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="$FUZZTIME" ./...
done
