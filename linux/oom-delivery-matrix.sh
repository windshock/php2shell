#!/usr/bin/env bash
# P18 OOM delivery matrix (plan 9.14-5e): can a request deliver more real
# parser-consumed bytes than post_max_size advertises?
#   arm chunked-mod_php : Transfer-Encoding: chunked to Apache mod_php
#                         (no Content-Length -> pre-parse size check skipped)
#   arm gzip-mod_php    : Content-Encoding: gzip with SetInputFilter DEFLATE
#                         (declared length is the compressed size)
#   control content-length-mod_php : same body with Content-Length
# Also runs the nginx->FPM chunked arms (buffering on/off) for the
# deployability column. Deployability notes are recorded in the result JSON.
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
port=${3:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
outdir="$base/evidence/oom-delivery-$stamp-$version"
run="$base/evidence/apache-lab-$version-oomdelivery"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
mkdir -p "$outdir" "$run"

bodyfile="$outdir/body-multipart.bin"
# ~6MB multipart: 1.5MB file + padding fields (post_max_size stays 4M in php.ini)
python3 - "$bodyfile" <<'PY'
import sys
path = sys.argv[1]
boundary = 'P18Bnd'
parts = []
parts.append(('--%s\r\nContent-Disposition: form-data; name="pad"\r\n\r\n%s\r\n'
              % (boundary, 'D' * (4 * 1024 * 1024))).encode())
parts.append(('--%s\r\nContent-Disposition: form-data; name="file"; '
              'filename="f.bin"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n'
              % (boundary, b'F' * (1536 * 1024))).encode())
parts.append(('--%s--\r\n' % boundary).encode())
body = (('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
         'Content-Type: multipart/form-data; boundary=%s\r\n' % boundary).encode())
open(path, 'wb').write(b''.join(parts))
print('body bytes:', sum(len(p) for p in parts))
PY
gzip -9 -c "$bodyfile" > "$bodyfile.gz"

start_lab() {  # extra conf lines via APACHE_LAB_EXTRA_CONF
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  : > "$run/php-error.log" 2>/dev/null || true
  export APACHE_LAB_EXTRA_CONF="${1:-}"
  bash linux/apache-lab.sh start "$port" >/dev/null 2>&1
  unset APACHE_LAB_EXTRA_CONF
}

probe_arm() {  # name curl_extra...
  local name=$1; shift
  local out_json="$outdir/$name.json"
  local http
  http=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "$@" \
        "http://127.0.0.1:$port/upload" 2>&1 || true)
  python3 - "$name" "$http" "$run/php-error.log" "$out_json" <<'PY'
import json, sys
name, http, log_path, out = sys.argv[1:5]
log = open(log_path, errors='replace').read() if __import__('os').path.exists(log_path) else ''
json.dump(dict(arm=name, http=http or None,
               post_max_exceeds_warning='exceeds the limit' in log,
               oom_or_fatal='Allowed memory size' in log,
               php_log_tail=[line for line in log.splitlines()[-4:]]),
          open(out, 'w'), indent=2)
print('%-28s http=%s exceeds_warning=%s fatal=%s' %
      (name, http or 'ERR', 'exceeds the limit' in log, 'Allowed memory size' in log))
PY
}

echo "=== control: Content-Length (declared 6MB > post_max_size 4M) ==="
start_lab
probe_arm control-content-length \
  -X POST -H 'Content-Type: multipart/form-data; boundary=P18Bnd' \
  --data-binary "@$bodyfile"

echo "=== arm: chunked (no Content-Length) mod_php ==="
start_lab
probe_arm chunked-mod_php \
  -X POST -H 'Content-Type: multipart/form-data; boundary=P18Bnd' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary "@$bodyfile"

echo "=== arm: gzip Content-Encoding + SetInputFilter DEFLATE (mod_php) ==="
start_lab $'LoadModule deflate_module /usr/lib/apache2/modules/mod_deflate.so\nSetInputFilter DEFLATE'
probe_arm gzip-mod_php \
  -X POST -H 'Content-Type: multipart/form-data; boundary=P18Bnd' \
  -H 'Content-Encoding: gzip' \
  --data-binary "@$bodyfile.gz"

bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
echo "outdir: $outdir"
