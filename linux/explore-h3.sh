#!/usr/bin/env bash
# #4 H3 (plan §13.4/§13.6-6): exploration on the official fixed build with
# arbitrary-code requests (fused action, H2.5), OFF baseline vs the
# redesigned state feedback (plan §13.3a, calibrated on the tuning set by
# explore-tune.sh). Measures whether the explorer rediscovers the #3
# hold-out failure patterns (R23/R46/R51), which reproduce on 8.4.27 as CLI
# scripts, and records every other memory error and class signal (G/R/A).
# Both modes use the same pool, budget, seeds and opcache setting.
# Any memory error whose signature matches no known record is a potential
# new finding: it stays in the local evidence tree (plan §11.2 D1).
# Usage: explore-h3.sh [budget_s] [pool_count] [seeds...]   (MODES="off state")
set -u
cd /mnt/c/Users/user/Downloads/php
budget=${1:-600}
count=${2:-200}
shift 2 2>/dev/null || true
seeds=${*:-1 2 3}
modes=${MODES:-off state}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=/home/phplab/php-lab/evidence/explore-h3-$stamp-8.4.27
mkdir -p "$root"
python3 linux/fused-pool.py --out "$root/pool" --count "$count" --seed 11 --version 8.4.27 \
  > "$root/pool.log" 2>&1 || { echo "pool generation failed"; exit 1; }
runs=()
for s in $seeds; do
  for m in $modes; do
    out="$root/$m-s$s"
    echo "=== $m seed=$s -> $out"
    python3 linux/lifecycle-explore.py --version 8.4.27 --flavor asanext --opcache \
      --fused-pool "$root/pool" --feedback "$m" --seed "$s" --budget "$budget" \
      --out "$out" > "$out.log" 2>&1
    rc=$?
    runs+=("$out=$rc")
    echo "exit=$rc"
  done
done
python3 linux/batch-check.py "$root" "${runs[@]}"
batch_rc=$?
echo "ROOT=$root"
exit $batch_rc
