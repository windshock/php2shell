#!/usr/bin/env bash
# G5: SAPI profiles compared on the same criteria as G3/G4 (8.4.4, same
# hold-out, same seeds, fast observer, equal budget per run). The CLI
# reference comes from the G3/G4 batch truncated to the same budget by
# explore-report.py g5.
# Usage: explore-g5.sh [version] [budget_s] [seed]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
budget=${2:-600}
seed=${3:-1}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=/home/phplab/php-lab/evidence/explore-g5-$stamp-$version
mkdir -p "$root"
holdout="parse_oom>upload_nofile parse_oom>upload_small runtime_oom>upload_small"
for sapi in apache fpm; do
  for fb in off on; do
    out="$root/$sapi-$fb-s$seed"
    echo "=== $sapi $fb seed=$seed -> $out"
    # shellcheck disable=SC2086
    python3 linux/lifecycle-explore.py --version "$version" --sapi "$sapi" --feedback "$fb" \
      --seed "$seed" --budget "$budget" --exclude-pairs $holdout --out "$out" > "$out.log" 2>&1
    echo "exit=$? $(tail -c 300 "$out.log" | tr -d '\n' | cut -c1-240)"
  done
done
echo "ROOT=$root"
