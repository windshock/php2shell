#!/usr/bin/env bash
# Issue #1 follow-up (plan §12.6.3) failure-injection fixtures for the P15/P16
# matrix runners. Each case must end with the expected exit code / status:
#   1. pathb: runner prints a stale result of an earlier run  -> foreign_result, exit 1
#   2. pathb: runner dies with rc=139 (no result)             -> runner_failed, exit 1
#   3. patha: two iterations of the same config keep two raw results (no overwrite)
# Case 3 drives the real Apache lab (8.4.4) and takes ~30s.
# Usage: bash linux/tests/matrix-fixtures.sh
set -u
cd /mnt/c/Users/user/Downloads/php
base=/home/phplab/php-lab
tmp=$(mktemp -d)
fails=0
report() { if [ "$1" = ok ]; then echo "PASS $2"; else echo "FAIL $2 ($3)"; fails=$((fails + 1)); fi; }

# Fake runners. The stale one points at a real earlier pathb result whose
# run_id differs (or is absent) - exactly what the old fixed /tmp path let in.
stale=$(ls -d "$base"/evidence/poc-pathb-*-8.4.4 2>/dev/null | grep -v matrix | head -1)
cat > "$tmp/stale.py" <<PY
import json; print(json.dumps({"evidence": "$stale"}))
PY
cat > "$tmp/crash.py" <<'PY'
import os; os._exit(139)
PY

for name in stale crash; do
  out="$tmp/pathb-$name"
  POC_PATHB_CMD="$tmp/$name.py" MATRIX_OUT="$out" RUN_ID="fixture-$name" \
    bash linux/apache-pathb-matrix.sh 8.4.4 1 18088 > "$tmp/$name.log" 2>&1
  rc=$?
  status=$(python3 -c "import json;print(json.load(open('$out/summary.json'))['statuses'][0])")
  want=foreign_result; [ "$name" = crash ] && want=runner_failed
  if [ "$rc" -ne 0 ] && [ "$status" = "$want" ]; then
    report ok "pathb $name result -> $status, exit $rc"
  else
    report fail "pathb $name result" "status=$status rc=$rc"
  fi
done

out="$tmp/patha-two"
MATRIX_OUT="$out" RUN_ID="fixture-patha" \
  bash linux/apache-patha-matrix.sh 8.4.4 2 18088 > "$tmp/patha.log" 2>&1
rc=$?
raws=$(ls "$out"/raw-crash-*/result-*.json 2>/dev/null | wc -l)
ids=$(python3 -c "
import glob, json
print(sorted({json.load(open(p))['run_id'] for p in glob.glob('$out/raw-*/result-*.json')}))")
if [ "$raws" -eq 2 ] && [ "$ids" = "['fixture-patha']" ] && [ "$rc" -eq 0 ]; then
  report ok "patha 2 iterations keep 2 raw results ($ids), exit $rc"
else
  report fail "patha raw preservation" "raws=$raws ids=$ids rc=$rc"
fi

rm -rf "$tmp"
echo "fixture_failures=$fails"
exit $((fails > 0))
