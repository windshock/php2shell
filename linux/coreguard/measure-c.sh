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
bash linux/coreguard/build-coreguard.sh asanext > "$root/build-asanext.log" 2>&1 \
  || { log "build asanext failed"; exit 1; }
for t in phase1 phase2b phase3; do
  python3 linux/coreguard/$t-tests.py > "$root/$t-tests.log" 2>&1; log "$t-tests rc=$?"
done
COREGUARD_MODE=observe COREGUARD_LOG=$root/explore-events.log \
  python3 linux/lifecycle-explore.py --version 8.4.27 --flavor coreguard-asanext --feedback off \
  --faults --seed 1 --budget "$budget" --out "$root/explore-off-s1" > "$root/explore.log" 2>&1
log "explore rc=$?"
bash linux/coreguard/build-coreguard.sh normalext > "$root/build-normalext.log" 2>&1 \
  || { log "build normalext failed"; exit 1; }
for m in observe enforce; do
  COREGUARD_MODE=$m COREGUARD_LOG=$root/phpt-events-$m.log PHPT_BASELINE=$b_phpt \
    bash linux/coreguard/phpt-baseline.sh 8.4.27-coreguard-normalext 4 > "$root/phpt-$m.log" 2>&1
  log "phpt $m rc=$?"
done
for m in disabled observe enforce; do
  COREGUARD_MODE=$m COREGUARD_LOG=$root/perf-events-$m.log python3 linux/coreguard/perf-baseline.py \
    --build 8.4.27-coreguard-normalext --repeats 3 -n 5000 -c 8 > "$root/perf-$m.log" 2>&1
  log "perf $m rc=$?"
done
python3 linux/coreguard/perf-baseline.py --build 8.4.27-normalext --repeats 3 -n 5000 -c 8 \
  > "$root/perf-B.log" 2>&1
log "perf B rc=$?"
python3 - "$root" <<'PY'
import json, sys
sys.path.insert(0, '/mnt/c/Users/user/Downloads/php/linux')
import provenance
root = sys.argv[1]
json.dump(dict(scope='CoreGuard C measurement driver run', root=root,
               steps=open(root + '/steps.log').read().splitlines(), **provenance.provenance()),
          open(root + '/summary.json', 'w'), indent=2)
PY
log "ROOT=$root"
