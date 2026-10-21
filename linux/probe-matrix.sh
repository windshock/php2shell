#!/usr/bin/env bash
# Sequential probe matrix. Each run gets its own evidence directory;
# ports 18085/19085/18086 are exclusive, so runs must not overlap.
# Exit status reflects every run: a single failed profile fails the matrix.
set -u
set -o pipefail
cd /mnt/c/Users/user/Downloads/php
stamp=$(date -u +%Y%m%dT%H%M%S)
mkdir -p /home/phplab/php-lab/evidence
log=/home/phplab/php-lab/evidence/probe-matrix-$stamp.log
failures=0
runs=0
run() {
  runs=$((runs + 1))
  echo "=== $* ===" | tee -a "$log"
  python3 linux/probe.py "$@" 2>&1 | tee -a "$log"
  rc=${PIPESTATUS[0]}
  echo "--- exit=$rc ---" | tee -a "$log"
  if [ "$rc" -ne 0 ]; then
    failures=$((failures + 1))
  fi
}
case "${1:-standard}" in
  standard)
    run --version 8.4.4 --flavor asan --allocator system  --buffering off --profile standard
    run --version 8.4.4 --flavor asan --allocator zend    --buffering off --profile standard
    run --version 8.4.4 --flavor asan --allocator tracked --buffering on  --profile standard
    run --version 8.4.4 --flavor asan --allocator zend    --buffering on  --profile standard
    run --version 8.5.4 --flavor asan --allocator tracked --buffering off --profile standard
    run --version 8.5.4 --flavor asan --allocator zend    --buffering off --profile standard
    ;;
  oom)
    run --version 8.4.4 --flavor asan --allocator tracked --buffering off --profile oom
    run --version 8.4.4 --flavor asan --allocator tracked --buffering off --profile oomps
    run --version 8.5.4 --flavor asan --allocator tracked --buffering off --profile oom
    run --version 8.5.4 --flavor asan --allocator tracked --buffering off --profile oomps
    ;;
  lax)
    run --version 8.4.4 --flavor asan --allocator tracked --buffering off --profile lax
    ;;
esac
echo "runs=$runs failures=$failures" | tee -a "$log"
echo "LOG: $log"
[ "$failures" -eq 0 ]
