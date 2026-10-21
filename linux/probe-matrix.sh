#!/usr/bin/env bash
# Sequential probe matrix. Each run gets its own evidence directory;
# ports 18085/19085/18086 are exclusive, so runs must not overlap.
set -u
cd /mnt/c/Users/user/Downloads/php
stamp=$(date -u +%Y%m%dT%H%M%S)
mkdir -p /home/phplab/php-lab/evidence
log=/home/phplab/php-lab/evidence/probe-matrix-$stamp.log
run() {
  echo "=== $* ===" | tee -a "$log"
  python3 linux/probe.py "$@" 2>&1 | tee -a "$log"
  echo "--- exit=$? ---" | tee -a "$log"
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
echo "LOG: $log"
