#!/usr/bin/env bash
# #3 CoreGuard Phase 0: PHPT compatibility baseline of a build (B = 8.4.27).
# Tests run from a clean `git archive` copy of the source, never from the
# source tree (run-tests.php writes .out/.diff files next to each test).
# The same script and test set measure C later; regressions = tests that
# pass on B and fail on C.
# Usage: phpt-baseline.sh [build=8.4.27-normalext] [jobs=4] [dirs...]
set -u
build=${1:-8.4.27-normalext}
jobs=${2:-4}
shift 2 2>/dev/null || true
dirs=${*:-Zend/tests ext/standard/tests/serialize ext/session/tests ext/opcache/tests ext/soap/tests ext/simplexml/tests ext/spl/tests}
base=/home/phplab/php-lab
prefix=$base/install/$build
version=${build%%-*}
src=$base/sources/php-$version
[ -x "$prefix/bin/php" ] || { echo "build missing: $prefix"; exit 1; }
stamp=$(date -u +%Y%m%dT%H%M%S)
run=$base/evidence/coreguard-phpt-$stamp-$build
mkdir -p "$run/src"
git -c safe.directory='*' -C "$src" archive HEAD | tar -x -C "$run/src"
so=$(ls "$prefix"/lib/php/extensions/*/opcache.so 2>/dev/null | head -1)
opc=()
[ -n "$so" ] && opc=(-d "zend_extension=$so")
cd "$run/src"
start=$(date +%s)
TEST_PHP_EXECUTABLE=$prefix/bin/php NO_INTERACTION=1 \
  "$prefix/bin/php" -n run-tests.php -q -j"$jobs" -p "$prefix/bin/php" "${opc[@]}" \
  --set-timeout 120 -W "$run/results.txt" $dirs > "$run/run-tests.log" 2>&1
rc=$?
end=$(date +%s)
python3 - "$run" "$build" "$rc" "$((end - start))" "$dirs" <<'PY'
import json, re, sys
sys.path.insert(0, '/mnt/c/Users/user/Downloads/php/linux')
import provenance
run, build, rc, secs, dirs = sys.argv[1:]
log = open(run + '/run-tests.log', errors='replace').read()
counts = {k: int(v) for k, v in re.findall(r'^Tests (\w+)\s*:\s*(\d+)', log, re.M)}
summary = dict(scope='CoreGuard Phase 0 PHPT baseline', build=build, run_tests_rc=int(rc),
               seconds=int(secs), dirs=dirs.split(), counts=counts, **provenance.provenance())
json.dump(summary, open(run + '/summary.json', 'w'), indent=2)
print(json.dumps(dict(run=run, counts=counts, rc=int(rc), citable=summary['citable']), indent=2))
PY
# per-test results (and the B comparison when PHPT_BASELINE=<B run dir>)
python3 /mnt/c/Users/user/Downloads/php/linux/coreguard/phpt-parse.py "$run" \
  ${PHPT_BASELINE:+--compare "$PHPT_BASELINE"}
# the archive copy is only scratch for run-tests; keep logs and results
rm -rf "$run/src"
