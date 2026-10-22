#!/usr/bin/env bash
# P15 (CVE-2026-109618 Path A) OOM-site sweep on Apache mod_php.
# Fresh httpd per config; memory_limit x parts x nesting grid. The PHP fatal
# log records the exact allocation site ("exhausted at <file>:<line>"), which
# the runner classifies (key-allocation region vs resize vs parser buffers).
# Usage: apache-patha-sweep.sh <version> [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
port=${2:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
outdir="$base/evidence/poc-patha-$stamp-$version"
run="$base/evidence/apache-lab-$version-patha"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
export POC_OUT_DIR="$outdir"
mkdir -p "$outdir" "$run/asan-archive"

for limit in 4M 8M 16M 32M 64M 128M 256M; do
  for cfg in "500 10" "500 30" "1000 30" "1000 60" "1020 90"; do
    set -- $cfg
    parts=$1; nest=$2
    bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
    sleep 0.3
    mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
    : > "$run/php-error.log" 2>/dev/null || true
    APACHE_LAB_MEMORY_LIMIT="$limit" bash linux/apache-lab.sh start "$port" >/dev/null 2>&1 || {
      echo "limit=$limit parts=$parts nest=$nest start-failed"; continue; }
    limit_bytes=$(python3 -c "print(int('$limit'.rstrip('M'))*1024*1024)")
    POC_MEMORY_LIMIT="$limit" POC_MEMORY_LIMIT_BYTES="$limit_bytes" \
    POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
      python3 linux/poc-patha.py --port "$port" --version "$version" \
        --parts "$parts" --nest "$nest" 2>&1 | tail -1
  done
done
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
echo "outdir: $outdir"
