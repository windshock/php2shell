#!/usr/bin/env bash
# Phase 5 C1: php-fuzz-unserialize with integrated corpus (official seeds +
# session/progress shaped seeds from this project) and repeated long runs.
# Crash artifacts land in the run dir via -artifact_prefix.
# Usage: fuzz-phase5.sh [minutes_per_run] [runs]
set -u
base=/home/phplab/php-lab
src="$base/sources/php-8.4.4"
build="$base/builds/8.4.4-fuzzer"
minutes=${1:-25}
runs=${2:-3}
outdir="$base/evidence/fuzz-phase5-$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$outdir/corpus" "$outdir/dict"
cp -r "$src/sapi/fuzzer/corpus/unserialize/." "$outdir/corpus/"

# Project-shaped seeds: the residue class needs unserialize inputs that
# resemble session payloads and reference/destructor structures.
python3 - "$outdir/corpus" <<'PY'
import sys
from pathlib import Path
c = Path(sys.argv[1])
A100 = 'A' * 100
seeds = {
    'lab-php-handler-session': 'big|%s' % ('s:%d:"%s";' % (len(A100), A100)),
    'lab-php-serialize-session': 'a:1:{s:3:"big";s:%d:"%s";}' % (len(A100), A100),
    'lab-progress-entry': ('a:5:{s:14:"bytes_processed";i:0;s:11:"done_upload";b:0;'
                           's:5:"files";a:1:{i:0;a:5:{s:4:"name";s:1:"a";'
                           's:8:"full_path";s:1:"a";s:4:"type";s:0:"";'
                           's:8:"tmp_name";s:0:"";s:5:"error";i:4;}}}'),
    'lab-references-r': 'a:2:{i:0;O:8:"stdClass":0:{}i:1;r:2;}',
    'lab-references-R': 'a:2:{i:0;O:8:"stdClass":1:{s:1:"x";i:1;}i:1;R:3;}',
    'lab-serializable': 'C:3:"Foo":6:{foobar}',
    'lab-incomplete': ('O:22:"__PHP_Incomplete_Class":1:{'
                       's:27:"__PHP_Incomplete_Class_Name";s:3:"Foo";}'),
    'lab-deep-nesting': 'a:1:{i:0;' * 32 + 'i:1;' + '}' * 32,
    'lab-big-string': 's:65536:"%s";' % ('B' * 65536),
}
for name, body in seeds.items():
    (c / name).write_text(body)
print('seeds_total=%d' % len(list(c.iterdir())))
PY

"$build/sapi/cli/php" "$src/sapi/fuzzer/generate_unserialize_dict.php" \
  > "$outdir/dict/unserialize" 2> "$outdir/dict/gen.log" || true
dict_arg=""
if [ -s "$outdir/dict/unserialize" ]; then dict_arg="-dict=$outdir/dict/unserialize"; fi
echo "dict_lines=$(wc -l < "$outdir/dict/unserialize" 2>/dev/null || echo 0)"

for run in $(seq 1 "$runs"); do
  echo "=== run $run / $runs ($minutes min) ==="
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
    timeout $((minutes * 60 + 120)) "$build/sapi/fuzzer/php-fuzz-unserialize" \
    $dict_arg -max_total_time=$((minutes * 60)) -rss_limit_mb=2048 \
    -artifact_prefix="$outdir/" -print_final_stats=1 \
    "$outdir/corpus" > "$outdir/fuzz-run$run.log" 2>&1
  rc=$?
  crashes=$(ls "$outdir" | grep -c '^crash-' || true)
  units=$(ls "$outdir/corpus" | wc -l)
  echo "run=$run rc=$rc crash_artifacts=$crashes corpus_units=$units"
  tail -4 "$outdir/fuzz-run$run.log"
  if [ "$crashes" -gt 0 ]; then
    echo "CRASH ARTIFACTS in $outdir — stopping further runs"
    break
  fi
done
echo "OUT=$outdir"
