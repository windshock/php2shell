#!/usr/bin/env bash
# #3 CoreGuard: full measurement of C (8.4.27 + every patch in
# linux/coreguard/patches) against B, driven from the repository (rule R12).
#   1. build C asanext; development tests phase1 / phase2b / phase3
#   2. regression control: lifecycle explorer OFF on C, COREGUARD_MODE=observe,
#      events logged next to the campaign (expected: no request-state residue)
#   3. build C normalext; PHPT observe / enforce vs the B baseline run
#   4. performance: C disabled / observe / enforce, then B again
# Hold-out cases are NOT run here (holdout-eval.py, once per case).
# Usage: measure-c.sh B_PHPT_RUN_DIR [explore_budget_s]
set -u
cd /mnt/c/Users/user/Downloads/php
b_phpt=${1:?B PHPT run dir}
budget=${2:-600}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=/home/phplab/php-lab/evidence/coreguard-measure-$stamp
mkdir -p "$root"
log() { echo "$*" | tee -a "$root/steps.log"; }
rcs=()
record() {  # name rc
  rcs+=("$1=$2"); log "$1 rc=$2"
}
bash linux/coreguard/build-coreguard.sh asanext > "$root/build-asanext.log" 2>&1 \
  || { log "build asanext failed"; exit 1; }
for t in phase1 phase2b phase3; do
  python3 linux/coreguard/$t-tests.py > "$root/$t-tests.log" 2>&1; record "$t-tests" $?
done
COREGUARD_MODE=observe COREGUARD_LOG=$root/explore-events.log \
  python3 linux/lifecycle-explore.py --version 8.4.27 --flavor coreguard-asanext --feedback off \
  --faults --seed 1 --budget "$budget" --out "$root/explore-off-s1" > "$root/explore.log" 2>&1
record explore $?
bash linux/coreguard/build-coreguard.sh normalext > "$root/build-normalext.log" 2>&1 \
  || { log "build normalext failed"; exit 1; }
for m in observe enforce; do
  COREGUARD_MODE=$m COREGUARD_LOG=$root/phpt-events-$m.log PHPT_BASELINE=$b_phpt \
    bash linux/coreguard/phpt-baseline.sh 8.4.27-coreguard-normalext 4 > "$root/phpt-$m.log" 2>&1
  record "phpt-$m" $?
done
for m in disabled observe enforce; do
  COREGUARD_MODE=$m COREGUARD_LOG=$root/perf-events-$m.log python3 linux/coreguard/perf-baseline.py \
    --build 8.4.27-coreguard-normalext --repeats 3 -n 5000 -c 8 > "$root/perf-$m.log" 2>&1
  record "perf-$m" $?
done
python3 linux/coreguard/perf-baseline.py --build 8.4.27-normalext --repeats 3 -n 5000 -c 8 \
  > "$root/perf-B.log" 2>&1
record perf-B $?
python3 - "$root" "${rcs[@]}" <<'PY'
import json, sys
sys.path.insert(0, '/mnt/c/Users/user/Downloads/php/linux')
import provenance
root, *rcs = sys.argv[1:]
codes = {s.rsplit('=', 1)[0]: int(s.rsplit('=', 1)[1]) for s in rcs}
json.dump(dict(scope='CoreGuard C measurement driver run', root=root,
               steps=open(root + '/steps.log').read().splitlines(),
               step_rcs=codes, failed_steps=[k for k, v in codes.items() if v != 0],
               complete=all(v == 0 for v in codes.values()),
               **provenance.provenance()),
          open(root + '/summary.json', 'w'), indent=2)
PY
# #5 P1-E: any failed step fails the driver; results stay on disk either way.
failed=$(printf '%s
' "${rcs[@]}" | awk -F= '$2!=0{n++} END{print n+0}')
log "failed_steps=$failed"
log "ROOT=$root"
[ "$failed" -eq 0 ]
