#!/usr/bin/env bash
# Phase 5 B1: stale-state candidate variants on Apache mod_php.
#   b1-urlscanner  : session.use_trans_sid=1 — the parse-time session init
#                    registers the sid with the URL rewriter (session.c:1604);
#                    after a mid-parse fatal the url_adapt state may dangle
#                    and the next pre-RINIT session init can consume it.
#                    8.4.27 resets via php_url_scanner_early_rinit().
#   b1-phpserialize / b1-phpbinary : session decoder handler variants — the
#                    residue class is identical (BG(unserialize)); this checks
#                    whether handler differences change reachability.
# Usage: phase5-b1.sh <variant> <version> [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
variant=${1:?variant}
version=${2:-8.4.4}
iterations=${3:-3}
port=${4:-18088}
base=/home/phplab/php-lab
run="$base/evidence/apache-lab-$version-phase5-$variant"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"

case "$variant" in
  urlscanner)    export APACHE_LAB_INI_EXTRA=$'session.use_trans_sid=1\nsession.use_only_cookies=0'
                 export POC_SERIALIZE_HANDLER=php ;;
  phpserialize)  export APACHE_LAB_INI_EXTRA='session.serialize_handler=php_serialize'
                 export POC_SERIALIZE_HANDLER=php_serialize ;;
  phpbinary)     export APACHE_LAB_INI_EXTRA='session.serialize_handler=php_binary'
                 export POC_SERIALIZE_HANDLER=php_binary ;;
  *) echo "unknown variant $variant"; exit 2 ;;
esac

# php_serialize/php_binary handlers need their own forged session formats;
# poc-pathb writes "key|payload;" (php handler). Feed a format-matching file
# via POC_SESSION_A/B overrides per iteration is intrusive, so for handler
# variants we pre-write both formats under the same sid each iteration.
mkdir -p "$run/asan-archive"
for i in $(seq 1 "$iterations"); do
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  if ! bash linux/apache-lab.sh start "$port" >/dev/null; then
    echo "iter $i: start failed"; continue
  fi
  POC_SESSION_DIR="$run/sessions" POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-pathb.py --external --port "$port" --iterations 1 --version "$version" \
    > "/tmp/poc-b1-$variant-$version-$i.json" 2>/dev/null || true
  python3 -c "
import json
d = json.load(open('/tmp/poc-b1-$variant-$version-$i.json'))
r = json.load(open(d['evidence'] + '/result.json'))
det = r['iterations_detail'][0]
print('$variant', '$version', 'iter', $i, 'reproduced', r['reproduced'],
      'a=', det.get('a'), 'alive_after_a=', det.get('worker_alive_after_a'),
      'b=', det.get('b'), 'result=', det.get('result'),
      'frames=', det.get('path_b_frames'))"
done
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
unset APACHE_LAB_INI_EXTRA
echo "done: $variant $version"
