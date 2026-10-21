#!/usr/bin/env bash
# Phase 4: build the fixed PHP version and re-run the identical inputs.
# Usage: phase4.sh 8.4.27 [asan] [affected=8.4.4]
set -u
ver=${1:?usage: phase4.sh <fixed-version> [asan|normal] [affected-version]}
flavor=${2:-asan}
affected=${3:-8.4.4}
cd /mnt/c/Users/user/Downloads/php || exit 1
stamp=$(date -u +%Y%m%dT%H%M%S)
log="/home/phplab/php-lab/evidence/phase4-$stamp.log"
mkdir -p "$(dirname "$log")"
echo "phase4 $affected -> $ver-$flavor" | tee -a "$log"

bash linux/build.sh "$ver" "$flavor" 2>&1 | tee -a "$log"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then echo "BUILD_FAILED rc=$rc" | tee -a "$log"; exit 1; fi

cat > /tmp/phase4-advisory.json <<JSON
{
  "cve": "CVE-PENDING-OFFICIAL-MAPPING",
  "official_url": "https://www.php.net/security/",
  "affected_version": "$affected",
  "fixed_version": "$ver",
  "regression_source": "phase4 rerun of lab probes"
}
JSON

python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile standard 2>&1 | tee -a "$log"
python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile oom      2>&1 | tee -a "$log"
python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile parts    2>&1 | tee -a "$log"
python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile cleanup  2>&1 | tee -a "$log"

python3 linux/poc-bgserialize.py --version "$ver" --iterations 5 2>&1 | tee -a "$log" || true
python3 linux/gdb-probe.py --version "$ver" --flavor "$flavor" --allocator tracked --memory-limit 8M 2>&1 | tee -a "$log"
python3 linux/gdb-unserialize.py --version "$ver" --flavor "$flavor" --allocator tracked --memory-limit 5M 2>&1 | tee -a "$log"

python3 linux/http-compare.py --before "$affected-$flavor" --after "$ver-$flavor" \
  --scenario progress-lifecycle --advisory /tmp/phase4-advisory.json 2>&1 | tee -a "$log"
python3 linux/http-compare.py --before "$affected-$flavor" --after "$ver-$flavor" \
  --scenario oom-residue --advisory /tmp/phase4-advisory.json 2>&1 | tee -a "$log"

python3 linux/verify-evidence.py 2>&1 | tee -a "$log"
echo "PHASE4_DONE log=$log" | tee -a "$log"
