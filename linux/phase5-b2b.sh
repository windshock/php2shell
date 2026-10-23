#!/usr/bin/env bash
# Phase 5 B2-b: does the 8.4.27 soft/hard (memory_hard_limit_percent=200%)
# model still bail out mid-parse when a single chunked request delivers more
# than twice memory_limit, and does that leave an observable memory error?
# Positive control: same shape on 8.4.4 (no soft/hard split there).
# Usage: phase5-b2b.sh <version> [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
port=${2:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
outdir="$base/evidence/b2b-hardlimit-$stamp-$version"
run="$base/evidence/apache-lab-$version-phase5-b2b"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
mkdir -p "$outdir" "$run/asan-archive"

# ~20MB body: one huge field value (delivered chunked, no Content-Length) plus
# nested empty-file parts so hash registration activity follows the big value.
python3 - "$outdir/body.bin" <<'PY'
import sys
boundary = 'B2BBnd'
parts = []
parts.append(('--%s\r\nContent-Disposition: form-data; name="pad"\r\n\r\n%s\r\n'
              % (boundary, 'D' * (18 * 1024 * 1024))).encode())
suffix = '[x0][x1][x2]'
for i in range(300):
    parts.append(('--%s\r\nContent-Disposition: form-data; name="f[%d]%s"; '
                  'filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
                  % (boundary, i, suffix)).encode())
parts.append(('--%s--\r\n' % boundary).encode())
open(sys.argv[1], 'wb').write(b''.join(parts))
print('body bytes:', sum(len(p) for p in parts))
PY

bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
sleep 0.3
: > "$run/php-error.log" 2>/dev/null || true
bash linux/apache-lab.sh start "$port" >/dev/null 2>&1 || { echo "start failed"; exit 1; }
http=$(curl -s -o /dev/null -w '%{http_code}' --max-time 120 -X POST \
  -H 'Content-Type: multipart/form-data; boundary=B2BBnd' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary "@$outdir/body.bin" \
  "http://127.0.0.1:$port/upload" 2>&1 || true)
pid=$(cat "$run/httpd.pid" 2>/dev/null || true)
sleep 1
alive=no; kill -0 "$pid" 2>/dev/null && alive=yes
python3 - "$version" "$http" "$alive" "$run/php-error.log" "$run" "$outdir" <<'PY'
import glob, json, os, sys
version, http, alive, log_path, run, outdir = sys.argv[1:7]
log = open(log_path, errors='replace').read() if os.path.exists(log_path) else ''
asan = []
for path in sorted(glob.glob(run + '/asan.*')):
    if os.path.isfile(path):
        text = open(path, errors='replace').read()
        if 'AddressSanitizer' in text:
            asan.append(dict(file=path, summary=next(
                (l for l in text.splitlines() if 'SUMMARY' in l), '')))
json.dump(dict(version=version, http=http or None, worker_alive=alive,
               soft_limit='8M (hard=200% => 16M on 8.4.27)',
               fatal_logged='Allowed memory size' in log,
               fatal_lines=[l for l in log.splitlines() if 'Allowed memory' in l][:2],
               asan_reports=asan),
          open(outdir + '/result.json', 'w'), indent=2)
print(json.dumps(dict(version=version, http=http, alive=alive,
                      fatal='Allowed memory size' in log, asan=len(asan))))
PY
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
echo "outdir: $outdir"
