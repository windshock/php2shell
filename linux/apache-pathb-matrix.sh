#!/usr/bin/env bash
# P16 (CVE-2026-109619 Path B, stale PS globals) reproduction matrix on Apache
# mod_php: fresh httpd process per iteration, producer request A reused from
# the Bug S repro, consumer request B = progress fields without a file part.
#
# Issue #1: harness failures and missing expected reproductions now
# propagate to the exit code and a summary.json (EXPECT=reproduce|extinct;
# fixed versions are expected to extinguish the path).
# Issue #1 follow-up (plan §12.6 R3/R7a): per-iteration results live in the
# matrix directory (no fixed /tmp path), the runner exit code must be 0/1
# (poc-pathb: 1 = not reproduced) and the result must carry this run_id;
# each run has its own Apache run directory. MATRIX_OUT / RUN_ID let a
# caller (ground-truth.sh) name the outputs.
# Usage: apache-pathb-matrix.sh [version] [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
iterations=${2:-3}
port=${3:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
run_id=${RUN_ID:-pathb-$stamp-$version-$$}
outdir="${MATRIX_OUT:-$base/evidence/poc-pathb-$stamp-$version-matrix}"
run="$base/evidence/apache-lab-$version-pathb-$run_id"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
mkdir -p "$outdir" "$run/asan-archive"

case "${EXPECT:-auto}" in
  auto) case "$version" in 8.4.27|8.5.12) EXPECT=extinct ;; *) EXPECT=reproduce ;; esac ;;
esac

summary="$outdir/summary.json"
echo '[]' > "$summary"
failures=0
for i in $(seq 1 "$iterations"); do
  bash linux/apache-lab.sh stop "$port" >/dev/null 2>&1
  sleep 0.3
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  if ! bash linux/apache-lab.sh start "$port" >/dev/null; then
    echo "iter $i: start failed"
    failures=$((failures + 1))
    python3 - "$summary" "$i" start_failed <<'PY'
import json, sys
path, i, note = sys.argv[1:4]
data = json.loads(open(path).read())
data.append(dict(iteration=int(i), status=note))
open(path, 'w').write(json.dumps(data, indent=2))
PY
    continue
  fi
  iter_json="$outdir/iter-$i.json"
  POC_RUN_ID="$run_id" \
    POC_SESSION_DIR="$run/sessions" POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 "${POC_PATHB_CMD:-linux/poc-pathb.py}" --external --port "$port" --iterations 1 --version "$version" \
    > "$iter_json" 2> "$outdir/iter-$i.stderr.log"
  rc=$?
  python3 - "$summary" "$i" "$rc" "$iter_json" "$EXPECT" "$run_id" "$version" <<'PY'
import json, os, sys
path, i, rc, iter_json, expect, run_id, version = sys.argv[1:8]
data = json.loads(open(path).read())
rc = int(rc)
result = None
try:
    evidence = json.load(open(iter_json))['evidence']
    result = json.load(open(evidence + '/result.json'))
except Exception as exc:
    data.append(dict(iteration=int(i), status='runner_failed', rc=rc, error=str(exc)))
if result is not None:
    if rc not in (0, 1):
        data.append(dict(iteration=int(i), status='runner_failed', rc=rc))
    elif result.get('run_id') != run_id or result.get('version') != version:
        data.append(dict(iteration=int(i), status='foreign_result', rc=rc,
                         found_run_id=result.get('run_id'),
                         found_version=result.get('version')))
    else:
        reproduced = result['reproduced']
        data.append(dict(iteration=int(i), status='ok', rc=rc, run_id=run_id,
                         reproduced=reproduced,
                         detail=result['iterations_detail'][0],
                         record=result['results'][0], evidence=evidence))
        if expect == 'reproduce' and reproduced < 1:
            data[-1]['status'] = 'expected_reproduction_missing'
        if expect == 'extinct' and reproduced > 0:
            data[-1]['status'] = 'unexpected_reproduction'
open(path, 'w').write(json.dumps(data, indent=2))
PY
  last=$(python3 -c "import json; print(json.load(open('$summary'))[-1]['status'])")
  echo "iter $i: $last (expect=$EXPECT)"
  case "$last" in ok) ;; *) failures=$((failures + 1)) ;; esac
done
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
