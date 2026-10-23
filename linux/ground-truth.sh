#!/usr/bin/env bash
# Phase 5 v2 Stage 0: ground-truth regression set. For the three reproduced
# paths (P15/P16/P17) separates, per version, input validity / reach /
# error trigger / memory error and - on fixed versions - the block point.
# Verdict rules live in linux/ground-truth-eval.py (fixtures: --self-test).
#
# Issue #1 follow-up (plan §12.6 R1): one run_id per invocation; every
# sub-runner is told where to write and stamps the run_id into its result;
# exit codes are captured and checked; nothing is discovered by mtime, so a
# failed run can no longer pick up an earlier or other-version summary.
# Exit: 0 = expectations met, 2 = expectation not met, 1 = harness failure.
# Usage: ground-truth.sh <version> [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
port=${2:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
run_id="gt-$stamp-$version-$$"
outdir="$base/evidence/ground-truth-$stamp-$version"
mkdir -p "$outdir"
export GROUND_TRUTH_OUT="$outdir"
echo "run_id=$run_id out=$outdir"

# P15 - Path A (HashTable partial init): crash config + pre-counter control.
RUN_ID="$run_id" MATRIX_OUT="$outdir/patha" \
  bash linux/apache-patha-matrix.sh "$version" 1 "$port" > "$outdir/patha.log" 2>&1
patha_rc=$?
echo "P15 matrix exit=$patha_rc"

# P16 - Path B (stale PS globals).
RUN_ID="$run_id" MATRIX_OUT="$outdir/pathb" \
  bash linux/apache-pathb-matrix.sh "$version" 1 "$port" > "$outdir/pathb.log" 2>&1
pathb_rc=$?
echo "P16 matrix exit=$pathb_rc"

# P17 - Path C (post-RINIT BG(unserialize) on FPM).
python3 linux/poc-pathc.py --version "$version" --iterations 1 \
  --run-id "$run_id" --summary-out "$outdir/pathc-summary.json" \
  > "$outdir/pathc.log" 2>&1
pathc_rc=$?
echo "P17 runner exit=$pathc_rc"

python3 linux/ground-truth-eval.py --version "$version" --run-id "$run_id" \
  --patha "$outdir/patha/summary.json" --patha-rc "$patha_rc" \
  --pathb "$outdir/pathb/summary.json" --pathb-rc "$pathb_rc" \
  --pathc "$outdir/pathc-summary.json" --pathc-rc "$pathc_rc" \
  --out "$outdir/ground-truth.json"
