#!/usr/bin/env bash
# Issue #5-5 failure-injection fixtures for explore-g34.sh / explore-g5.sh:
# a fake explorer (EXPLORE_CMD) that exits 3, writes no summary, writes zero
# executions, or behaves - the batch must exit non-zero for every bad case.
# Usage: bash linux/tests/batch-fixtures.sh
set -u
cd /mnt/c/Users/user/Downloads/php
tmp=$(mktemp -d)
fails=0
cat > "$tmp/fake.py" <<'PY'
import json, os, sys
from pathlib import Path
out = Path(sys.argv[sys.argv.index('--out') + 1])
mode = os.environ['FAKE_MODE']
if mode == 'rc3':
    sys.exit(3)
out.mkdir(parents=True, exist_ok=True)
if mode == 'nosummary':
    sys.exit(0)
execs = 0 if mode == 'zero' else 3
(out / 'execs.jsonl').write_text('')
(out / 'summary.json').write_text(json.dumps(dict(
    execs=execs, aborted=False, harness_errors=0, feedback='on', seed=1, wall_s=1,
    grammar={}, excluded_pairs=[])))
PY
for mode in good rc3 nosummary zero; do
  FAKE_MODE=$mode EXPLORE_CMD="python3 $tmp/fake.py" \
    bash linux/explore-g34.sh 8.4.4 1 1 > "$tmp/$mode.log" 2>&1
  rc=$?
  root=$(grep '^ROOT=' "$tmp/$mode.log" | sed 's/ROOT=//')
  want_ok=1; [ "$mode" = good ] || want_ok=0
  got_ok=0; [ "$rc" -eq 0 ] && got_ok=1
  batch=$( [ -f "$root/batch.json" ] && python3 -c "import json;d=json.load(open('$root/batch.json'));print(len(d['valid']),'valid',d['failed'])")
  if [ "$got_ok" -eq "$want_ok" ] && [ -f "$root/batch.json" ]; then
    echo "PASS $mode -> exit $rc ($batch)"
  else
    echo "FAIL $mode -> exit $rc ($batch)"; fails=$((fails + 1))
  fi
  rm -rf "$root"
done
rm -rf "$tmp"
echo "fixture_failures=$fails"
exit $((fails > 0))
