#!/usr/bin/env bash
# G3 (hold-out rediscovery) + G4 (feedback ON vs OFF) campaign batch.
# Same version, observer, budget and seeds for both arms; 3 independent RNG
# seeds each; runs strictly sequential (one php process at a time - the
# 3 GB lab VM and the fixed explorer port allow no parallelism).
# Hold-out: the answer pairs of P16 (parse_oom>upload_nofile), Bug S
# (parse_oom>upload_small) and P17 (runtime_oom>upload_small) are excluded
# from the initial corpus; the default seeds are benign single requests.
# Usage: explore-g34.sh [version] [budget_s] [seeds...]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
budget=${2:-900}
shift 2 2>/dev/null || true
seeds=${*:-1 2 3}
stamp=$(date -u +%Y%m%dT%H%M%S)
root=/home/phplab/php-lab/evidence/explore-g34-$stamp-$version
mkdir -p "$root"
holdout="parse_oom>upload_nofile parse_oom>upload_small runtime_oom>upload_small"
for s in $seeds; do
  for fb in on off; do
    out="$root/$fb-s$s"
    echo "=== $fb seed=$s -> $out"
    # shellcheck disable=SC2086
    python3 linux/lifecycle-explore.py --version "$version" --feedback "$fb" --seed "$s" \
      --budget "$budget" --exclude-pairs $holdout --out "$out" > "$out.log" 2>&1
    echo "exit=$? $(tail -c 400 "$out.log" | tr -d '\n' | cut -c1-300)"
  done
done
python3 linux/explore-report.py g4 --on "$root"/on-s*/ --off "$root"/off-s*/ > "$root/g4.json"
echo "ROOT=$root"
