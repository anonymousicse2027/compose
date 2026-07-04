#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <klee-replay> <gcov-binary> <result-dir> [result-dir ...]"
    echo "Replays every .ktest under each result dir and collects crashing runs."
    exit 1
fi

KLEE_REPLAY="$1"; shift
BIN="$1"; shift
ROOTS=("$@")

[[ -x "$KLEE_REPLAY" ]] || { echo "klee-replay not executable: $KLEE_REPLAY"; exit 1; }
[[ -x "$BIN" ]] || { echo "binary not executable: $BIN"; exit 1; }

for ROOT in "${ROOTS[@]}"; do
    [[ -d "$ROOT" ]] || { echo "result dir not found: $ROOT"; continue; }

    while IFS= read -r -d '' KTEST; do
        OUT="${KTEST}.replay.out"
        ERR="${KTEST}.replay.err"
        KT_DIR="$(dirname "$KTEST")"
        [[ -w "$KT_DIR" ]] || { echo "no write permission: $KT_DIR"; continue; }
        if ! timeout 20s "$KLEE_REPLAY" "$BIN" "$KTEST" >"$OUT" 2>"$ERR"; then
            echo "RC=$?" >>"$ERR"
        fi
    done < <(find "$ROOT" -type f -name '*.ktest' -print0)

    OUTFILE="$ROOT/crash_output.txt"
    : > "$OUTFILE"
    find "$ROOT" -type f -name '*.replay.err' -print0 \
        | xargs -0 -r grep -H -E "CRASHED|Received signal" >> "$OUTFILE" || true

    echo "saved: $OUTFILE  ($(wc -l < "$OUTFILE") crashing run(s))"
done
