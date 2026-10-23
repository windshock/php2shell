#!/usr/bin/env bash
# P15 (CVE-2026-109618 Path A) reproduction matrix on Apache mod_php.
# Crash config: nest=8 segments padded to 302 chars steer the memory_limit
# crossing onto the key zend_string_init inside _zend_hash_str_add_or_update_i
# (zend_hash.c:958, after nNumUsed++). Control config: a limit whose crossing
# lands on _zend_new_array (before nNumUsed++) must NOT crash.
#
# Issue #1: harness failures, missing expected reproductions and a crashing
# control run now propagate to the exit code and summary.json.
# Issue #1 follow-up (plan §12.6 R4/R7a): every run gets a run_id, its own
# Apache run directory and one raw-result directory per iteration, so reruns
# never overwrite earlier evidence. MATRIX_OUT / RUN_ID let a caller
# (ground-truth.sh) name the outputs instead of discovering them by mtime.
# Usage: apache-patha-matrix.sh <version> [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
iterations=${2:-3}
port=${3:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
run_id=${RUN_ID:-patha-$stamp-$version-$$}
outdir="${MATRIX_OUT:-$base/evidence/poc-patha-$stamp-$version-matrix}"
run="$base/evidence/apache-lab-$version-patha-$run_id"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
mkdir -p "$outdir" "$run/asan-archive"

case "${EXPECT:-auto}" in
  auto) case "$version" in 8.4.27|8.5.12) EXPECT=extinct ;; *) EXPECT=reproduce ;; esac ;;
esac

summary="$outdir/summary.json"
echo '[]' > "$summary"
failures=0
run_one() {  # limit label expectation
  local limit=$1 label=$2 expectation=$3
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  : > "$run/php-error.log" 2>/dev/null || true
  if ! APACHE_LAB_MEMORY_LIMIT="$limit" bash linux/apache-lab.sh start "$port" >/dev/null 2>&1; then
    echo "$label: start failed"
    failures=$((failures + 1))
    python3 - "$summary" "$label" <<'PY'
import json, sys
path, label = sys.argv[1:3]
data = json.loads(open(path).read())
data.append(dict(label=label, status='start_failed'))
open(path, 'w').write(json.dumps(data, indent=2))
PY
    return
  fi
  local limit_bytes safe raw_dir out_json
  limit_bytes=$(python3 -c "print(int('${limit}'.rstrip('M'))*1024*1024)")
  safe=$(echo "$label" | tr -c 'a-zA-Z0-9-' '_')
  raw_dir="$outdir/raw-$safe"
  out_json="$outdir/result-$safe.json"
  POC_RUN_ID="$run_id" POC_OUT_DIR="$raw_dir" \
    POC_MEMORY_LIMIT="$limit" POC_MEMORY_LIMIT_BYTES="$limit_bytes" \
    POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-patha.py --port "$port" --version "$version" \
      --parts 1000 --nest 8 --seg-pad 300 > "$out_json" 2>"$outdir/stderr-$safe.log"
  local rc=$?
  python3 - "$summary" "$label" "$rc" "$raw_dir" "$expectation" "$run_id" <<'PY'
import glob, json, sys
path, label, rc, raw_dir, expectation, run_id = sys.argv[1:7]
data = json.loads(open(path).read())
raw = sorted(glob.glob(raw_dir + '/result-*.json'))
result = json.load(open(raw[0])) if len(raw) == 1 else None
if int(rc) != 0 or result is None:
    data.append(dict(label=label, status='runner_failed', rc=int(rc), raw_files=len(raw)))
elif result.get('run_id') != run_id:
    data.append(dict(label=label, status='foreign_result', rc=int(rc),
                     found_run_id=result.get('run_id')))
else:
    verdict = result.get('verdict')
    entry = dict(label=label, status='ok', verdict=verdict, run_id=run_id,
                 raw_result=raw[0],
                 teardown_frames=result.get('asan_teardown_frames'),
                 oom_logged=result.get('oom_logged'),
                 oom_tried_bytes=result.get('oom_tried_bytes'),
                 oom_limit_bytes=result.get('oom_limit_bytes'),
                 pre_counter_crossing=result.get('pre_counter_crossing_hint', False),
                 http_status=result.get('status'),
                 connection_reset=result.get('connection_reset'),
                 script_reached=result.get('script_reached'),
                 input=dict(parts=result.get('parts'), nest=result.get('nest'),
                            seg_pad=result.get('seg_pad'),
                            memory_limit=result.get('memory_limit'),
                            body_bytes=result.get('body_bytes')))
    if expectation == 'reproduce' and verdict != 'fatal_and_teardown_memory_error':
        entry['status'] = 'expected_reproduction_missing'
    if expectation == 'extinct' and verdict not in ('no_fatal', 'fatal_only',
                                                    'fatal_and_other_asan',
                                                    'parts_limit'):
        entry['status'] = 'unexpected_memory_error'
    if expectation == 'control_no_crash' and verdict == 'fatal_and_teardown_memory_error':
        entry['status'] = 'control_crashed'
    data.append(entry)
open(path, 'w').write(json.dumps(data, indent=2))
PY
  local last
  last=$(python3 -c "import json; print(json.load(open('$summary'))[-1]['status'])")
  echo "$label: $last"
  case "$last" in ok) ;; *) failures=$((failures + 1)) ;; esac
}

for i in $(seq 1 "$iterations"); do
  run_one 32M "crash-$i" "$EXPECT"
done
run_one 28M control control_no_crash
bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
python3 - "$summary" "$failures" "$version" "$EXPECT" "$run_id" "$run" <<'PY'
import json, sys
path, failures, version, expect, run_id, run = sys.argv[1:7]
data = json.loads(open(path).read())
json.dump(dict(run_id=run_id, version=version, expect=expect, failed=int(failures),
               apache_run_dir=run, entries=data,
               statuses=[d['status'] for d in data]), open(path, 'w'), indent=2)
PY
echo "failures=$failures expect=$EXPECT run_id=$run_id"
[ "$failures" -eq 0 ]
