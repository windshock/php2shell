#!/usr/bin/env bash
# P16 (CVE-2026-109619 Path B, stale PS globals) reproduction matrix on Apache
# mod_php: fresh httpd process per iteration, producer request A reused from
# the Bug S repro, consumer request B = progress fields without a file part.
#
# Issue #1: harness failures and missing expected reproductions now
# propagate to the exit code and a summary.json (EXPECT=reproduce|extinct;
# fixed versions are expected to extinguish the path).
# Usage: apache-pathb-matrix.sh [version] [iterations] [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
iterations=${2:-3}
port=${3:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
run="$base/evidence/apache-lab-$version-pathb"
outdir="$base/evidence/poc-pathb-$stamp-$version-matrix"
export APACHE_LAB_PREFIX="$base/install/$version-apache"
export APACHE_LAB_RUN="$run"
export POC_OUT_DIR="$outdir"
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
  POC_SESSION_DIR="$run/sessions" POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-pathb.py --external --port "$port" --iterations 1 --version "$version" \
    > "/tmp/poc-pathb-$version-$i.json" 2>/dev/null
  rc=$?
  python3 - "$summary" "$i" "$rc" "/tmp/poc-pathb-$version-$i.json" "$EXPECT" <<'PY'
import json, os, sys
path, i, rc, tmp, expect = sys.argv[1:6]
data = json.loads(open(path).read())
if not os.path.exists(tmp):
    data.append(dict(iteration=int(i), status='runner_failed', rc=int(rc)))
else:
    evidence = json.load(open(tmp))['evidence']
    result = json.load(open(evidence + '/result.json'))
    reproduced = result['reproduced']
    data.append(dict(iteration=int(i), status='ok', reproduced=reproduced,
                     detail=result['iterations_detail'][0], evidence=evidence))
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
python3 - "$summary" "$failures" "$version" "$EXPECT" <<'PY'
import json, sys
path, failures, version, expect = sys.argv[1:5]
data = json.loads(open(path).read())
json.dump(dict(version=version, expect=expect, failed=int(failures),
               entries=data,
               statuses=[d['status'] for d in data]), open(path, 'w'), indent=2)
PY
echo "failures=$failures expect=$EXPECT"
[ "$failures" -eq 0 ]
