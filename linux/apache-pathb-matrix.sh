#!/usr/bin/env bash
# P16 (CVE-2026-109619 Path B, stale PS globals) reproduction rate on Apache
# mod_php: fresh httpd process per iteration, producer request A reused from
# the Bug S repro, consumer request B = progress fields without a file part.
# Usage: apache-pathb-matrix.sh [version] [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
iterations=${2:-3}
port=${3:-18088}
base=/home/phplab/php-lab
run="$base/evidence/apache-lab-$version-pathb"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
mkdir -p "$run/asan-archive"
for i in $(seq 1 "$iterations"); do
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  if ! bash linux/apache-lab.sh start "$port" >/dev/null; then
    echo "iter $i: start failed"
    continue
  fi
  POC_SESSION_DIR="$run/sessions" POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-pathb.py --external --port "$port" --iterations 1 --version "$version" \
    > "/tmp/poc-pathb-$version-$i.json" 2>/dev/null || true
  python3 -c "
import json
d = json.load(open('/tmp/poc-pathb-$version-$i.json'))
r = json.load(open(d['evidence'] + '/result.json'))
print('iter', $i, 'reproduced', r['reproduced'], '/', r['iterations'],
      'rate', r['reproduction_rate'],
      'detail', r['iterations_detail'])"
done
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
echo "asan archive count: $(ls "$run"/asan-archive 2>/dev/null | wc -l)"
