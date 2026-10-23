#!/usr/bin/env bash
# Phase 5 C1: php-fuzz-unserialize with an integrated corpus (official seeds +
# session/progress shaped seeds) and repeated timed runs.
#
# Scope note (issue #1): php-fuzz-unserialize covers the unserialize() entry
# point ONLY - it does not exercise HTTP multipart parsing or cross-request
# state lifetime. Those are covered by the P15-P17 runners and Phase 5 v2
# Stage 1.
#
# Normal seeds must actually pass unserialize() (verified by the positive
# control below); malformed variants are deliberately separate seeds.
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

# Project-shaped seeds. Normal seeds are valid serialized data; malformed
# variants are separate entries (issue #1: the previous 'progress' seed was
# accidentally malformed).
python3 - "$outdir/corpus" <<'PY'
import sys
from pathlib import Path
c = Path(sys.argv[1])
A100 = 'A' * 100
deep = 'a:1:{i:0;' * 32 + 'i:1;' + '}' * 32
normal = {
    'lab-php-serialize-session': 'a:1:{s:3:"big";s:%d:"%s";}' % (len(A100), A100),
    'lab-progress-entry': ('a:3:{s:15:"bytes_processed";i:0;'
                           's:11:"done_upload";b:0;'
                           's:5:"files";a:1:{i:0;a:5:{s:4:"name";s:1:"a";'
                           's:9:"full_path";s:1:"a";s:4:"type";s:0:"";'
                           's:8:"tmp_name";s:0:"";s:5:"error";i:4;}}}'),
    'lab-references-r': 'a:2:{i:0;O:8:"stdClass":0:{}i:1;r:2;}',
    'lab-references-R': 'a:2:{i:0;O:8:"stdClass":1:{s:1:"x";i:1;}i:1;R:3;}',
    'lab-serializable': 'C:3:"Foo":6:{foobar}',
    'lab-incomplete': ('O:22:"__PHP_Incomplete_Class":1:{'
                       's:27:"__PHP_Incomplete_Class_Name";s:3:"Foo";}'),
    'lab-deep-nesting': deep,
    'lab-big-string': 's:65536:"%s";' % ('B' * 65536),
}
# Session-handler formats ("key|value") are only valid inside session
# decode, not as standalone unserialize() input; kept as shape seeds with
# their own category so the positive control stays meaningful (issue #1).
session_format = {
    'lab-php-handler-session': 'big|%s' % ('s:%d:"%s";' % (len(A100), A100)),
}
malformed = {
    'lab-malformed-progress-counts': ('a:5:{s:14:"bytes_processed";i:0;'
                                      's:11:"done_upload";b:0;'
                                      's:5:"files";a:1:{i:0;a:5:{s:4:"name";s:1:"a";'
                                      's:8:"full_path";s:1:"a";s:4:"type";s:0:"";'
                                      's:8:"tmp_name";s:0:"";s:5:"error";i:4;}}}'),
    'lab-malformed-truncated': 'a:2:{i:0;i:1;',
    'lab-malformed-bad-ref': 'a:1:{i:0;r:99;}',
}
for name, body in {**normal, **malformed, **session_format}.items():
    (c / name).write_text(body)
(c / '.seed-manifest.json').write_text(__import__('json').dumps(
    dict(normal=sorted(normal), malformed=sorted(malformed),
         session_format=sorted(session_format)), indent=2))
print('seeds_total=%d (normal=%d malformed=%d session_format=%d)' % (
    len(list(c.iterdir())) - 1, len(normal), len(malformed), len(session_format)))
PY

# Positive control (issue #1): every "normal" seed must pass unserialize()
# through the fuzzer build's own CLI binary before fuzzing starts.
"$build/sapi/cli/php" -r '
$names = json_decode(file_get_contents($argv[1] . "/.seed-manifest.json"), true)["normal"];
$out = [];
foreach ($names as $n) {
  $data = file_get_contents($argv[1] . "/" . $n);
  $v = @unserialize($data);
  $out[$n] = ($v !== false || $data === "b:0;") ? "pass" : "fail";
}
file_put_contents($argv[2], json_encode(["positive_control" => $out]));
echo "positive_control=" . count(array_keys($out, "pass")) . "/" . count($out) . "\n";
' "$outdir/corpus" "$outdir/seed-control.json" || echo 'positive_control=script-error'

"$build/sapi/cli/php" "$src/sapi/fuzzer/generate_unserialize_dict.php" \
  > "$outdir/dict/unserialize" 2> "$outdir/dict/gen.log" || true
dict_arg=""
dict_ok=false
if [ -s "$outdir/dict/unserialize" ]; then dict_arg="-dict=$outdir/dict/unserialize"; dict_ok=true; fi

overall_rc=0
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
  timed_out=false; [ "$rc" -eq 124 ] && timed_out=true
  execs=$(grep -oP 'stat::number_of_executed_units: \K[0-9]+' "$outdir/fuzz-run$run.log" | tail -1)
  python3 - "$outdir" "$run" "$rc" "$crashes" "$units" "$timed_out" "$execs" <<'PY'
import json, sys
out, run, rc, crashes, units, timed_out, execs = sys.argv[1:8]
path = out + '/runs.json'
data = json.loads(open(path).read()) if __import__('os').path.exists(path) else []
data.append(dict(run=int(run), rc=int(rc), timed_out=timed_out == 'true',
                 crash_artifacts=int(crashes), corpus_units=int(units),
                 executed_units=int(execs) if execs else None))
open(path, 'w').write(json.dumps(data, indent=2))
PY
  echo "run=$run rc=$rc timed_out=$timed_out crash_artifacts=$crashes corpus_units=$units executed=$execs"
  tail -4 "$outdir/fuzz-run$run.log"
  if [ "$crashes" -gt 0 ] || [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then overall_rc=1; fi
  if [ "$crashes" -gt 0 ]; then
    echo "CRASH ARTIFACTS in $outdir — stopping further runs"
    break
  fi
done
echo "dict_ok=$dict_ok"
echo "OUT=$outdir"
exit $overall_rc
