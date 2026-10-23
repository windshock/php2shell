#!/usr/bin/env bash
# Plan §13.6 step 4: re-derive the Phase 5 v2 gates with the v2.1 fail-closed
# judges, all from ONE source SHA, strictly sequential (3 GB lab VM, fixed
# ports). Every step's exit code and output location go to rederive.json.
#   1 ground-truth 8.4.4 / 8.4.27          (P15-P17, new P17 producer-line rule)
#   2 G3/G4 batch with --cov (ON/OFF x 3)   (causal G3, G4, code edges)
#   3 coverage map over that batch          (exact/nearby/gap, binary SHA)
#   4 G5 SAPI batch (apache/fpm x ON/OFF)   (split environment/comparison gate)
#   5 FlowFusion bridge, 100 programs       (three-axis verdicts, seed 11)
#   6 differential triage                   (event-backed block points)
# Usage: rederive-v21.sh [budget_s]
set -u
cd /mnt/c/Users/user/Downloads/php
budget=${1:-600}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
root="$base/evidence/rederive-v21-$stamp"
mkdir -p "$root"
sha=$(git -c safe.directory="*" rev-parse HEAD 2>/dev/null || echo unknown)
dirty=$(git -c safe.directory="*" status --porcelain linux | wc -l)
steps=()
step() {  # name command...
  local name=$1; shift
  echo "=== $name $(date -u +%H:%M:%S)"
  "$@" > "$root/$name.log" 2>&1
  local rc=$?
  steps+=("$name=$rc")
  echo "    rc=$rc"
}
step ground_truth_8.4.4 bash linux/ground-truth.sh 8.4.4
step ground_truth_8.4.27 bash linux/ground-truth.sh 8.4.27
EXPLORE_EXTRA=--cov step g34_cov bash linux/explore-g34.sh 8.4.4 "$budget" 1 2 3
g34=$(grep '^ROOT=' "$root/g34_cov.log" | sed 's/ROOT=//')
step g3_report python3 linux/explore-report.py g3 "$g34"/on-s1/ "$g34"/on-s2/ "$g34"/on-s3/ \
  "$g34"/off-s1/ "$g34"/off-s2/ "$g34"/off-s3/
step coverage_map python3 linux/coverage-map.py --binary "$base/install/8.4.4-cov/bin/php" \
  --campaign "$g34"/on-s1 "$g34"/on-s2 "$g34"/on-s3 "$g34"/off-s1 "$g34"/off-s2 "$g34"/off-s3 \
  --out "$root/coverage-map.json"
step g5_batch bash linux/explore-g5.sh 8.4.4 "$budget" 1
g5=$(grep '^ROOT=' "$root/g5_batch.log" | sed 's/ROOT=//')
step g5_report python3 linux/explore-report.py g5 "$g34"/off-s1/ "$g34"/on-s1/ \
  "$g5"/apache-off-s1/ "$g5"/apache-on-s1/ "$g5"/fpm-off-s1/ "$g5"/fpm-on-s1/ --cutoff "$budget"
step flowfusion python3 linux/flowfusion-bridge.py run --count 100 --seed 11 --version 8.4.4
step triage python3 linux/differential-triage.py
python3 - "$root" "$sha" "$dirty" "$g34" "$g5" "${steps[@]}" <<'PY'
import json, sys
root, sha, dirty, g34, g5, *steps = sys.argv[1:]
json.dump(dict(scope='v2.1 re-derivation (plan §13.6 step 4)', source_sha=sha,
               uncommitted_linux_changes=int(dirty), g34_batch=g34, g5_batch=g5,
               steps={s.rsplit('=', 1)[0]: int(s.rsplit('=', 1)[1]) for s in steps}),
          open(root + '/rederive.json', 'w'), indent=2)
PY
echo "ROOT=$root"
