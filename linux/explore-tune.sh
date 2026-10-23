#!/usr/bin/env bash
# #4 H3 / plan §13.3a: calibrate the redesigned feedback (--feedback state)
# on the TUNING set only (R49, R55 - docs/coreguard/holdout-v1.json).
# 1. run-repro R49/R55 on 8.4.27 asanext (regression check of the shared
#    case extraction, must stay "reproduced" as in H2 round 2).
# 2. tuning pool from the same reproducers (fused-pool.py --cases refuses
#    hold-out records).
# 3. explorer, feedback state, opcache loaded: the observer must report the
#    signals the redesign rewards - R49 -> G key (GC protected at request
#    shutdown) + R key, R55 -> A key (ASAN, attributed). A missing signal
#    means the signal does not work; it is never tuned against the hold-out.
# Usage: explore-tune.sh [budget_s] [seed]
set -u
cd /mnt/c/Users/user/Downloads/php
budget=${1:-300}
seed=${2:-1}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=/home/phplab/php-lab/evidence/explore-tune-$stamp-8.4.27
mkdir -p "$root"
python3 linux/corpus/run-repro.py --cases R49 R55 --versions 8.4.27 --flavor asanext \
  > "$root/repro.log" 2>&1
echo "repro rc=$?"
python3 linux/fused-pool.py --out "$root/pool" --cases R49,R55 > "$root/pool.log" 2>&1 \
  || { echo "pool generation failed"; cat "$root/pool.log"; exit 1; }
out="$root/state-s$seed"
python3 linux/lifecycle-explore.py --version 8.4.27 --flavor asanext --opcache \
  --fused-pool "$root/pool" --feedback state --seed "$seed" --budget "$budget" \
  --out "$out" > "$out.log" 2>&1
rc=$?
echo "explore exit=$rc"
python3 linux/batch-check.py "$root" "$out=$rc"
batch_rc=$?
echo "ROOT=$root"
exit $batch_rc
