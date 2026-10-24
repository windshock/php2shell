#!/usr/bin/env bash
# #2 2x2 protocol (plan 14.2 #2, preregistration docs/exploration-2x2-prereg.md):
# generator {F=fused pool, H=lifecycle grammar} x feedback {off,state},
# seeds 1..3, budget 600s each - 12 runs, identical environment
# (8.4.27-asanext, cli, gdb observer, opcache). The fused pool is generated
# ONCE (seed 11, count 200) and shared by F0/F1 (program matching). Hold-out
# records R23/R46/R51 are never used. Usage: explore-2x2.sh [budget_s]
# Env overrides for prereg-sanctioned partial reruns (invalidation clause):
# ROOT=<existing run root> GENS="H" MODES="state" SEEDS="1 2 3" POOL=<pool dir>
set -u
cd /mnt/c/Users/user/Downloads/php
budget=${1:-600}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=${ROOT:-/home/phplab/php-lab/evidence/explore-2x2-$stamp}
gens=${GENS:-"F H"}
modes=${MODES:-"off state"}
seeds=${SEEDS:-"1 2 3"}
mkdir -p "$root"
# fail-closed host-disk gate (2026-10-24 ext4 remount-ro incident: C: at
# 100% blocked vhdx growth; every evidence GB costs ~2GB on C: - vhdx +
# var/linux-evidence mirror). EXPECT_GB overrides the campaign estimate.
expect_gb=${EXPECT_GB:-5}
avail_mb=$(df -B1M /mnt/c | awk 'NR==2 {print $4}')
need_mb=$(( expect_gb * 2 * 1024 + 10240 ))
if [ "${avail_mb:-0}" -lt "$need_mb" ]; then
  echo "C: free ${avail_mb}MB < required ${need_mb}MB (evidence x2 + 10GB) - refusing (fail-closed)"
  exit 1
fi
if [[ " $gens " == *" F "* ]] && [ ! -d "${POOL:-$root/pool}" ]; then
  python3 linux/fused-pool.py --out "$root/pool" --count 200 --seed 11 --version 8.4.27 \
    > "$root/pool.log" 2>&1 || { echo "pool generation failed"; exit 1; }
fi
runs=()
for gen in $gens; do
  for m in $modes; do
    for s in $seeds; do
      cell="$gen$([ "$m" = off ] && echo 0 || echo 1)"
      out="$root/$cell-s$s"
      echo "=== $cell seed=$s -> $out"
      if [ "$gen" = F ]; then
        python3 linux/lifecycle-explore.py --version 8.4.27 --flavor asanext --opcache \
          --fused-pool "$root/pool" --feedback "$m" --seed "$s" --budget "$budget" \
          --out "$out" > "$out.log" 2>&1
      else
        python3 linux/lifecycle-explore.py --version 8.4.27 --flavor asanext --opcache \
          --feedback "$m" --seed "$s" --budget "$budget" \
          --out "$out" > "$out.log" 2>&1
      fi
      rc=$?
      runs+=("$out=$rc")
      echo "exit=$rc"
    done
  done
done
python3 linux/batch-check.py "$root" "${runs[@]}"
rc=$?
echo "ROOT=$root"
exit $rc
