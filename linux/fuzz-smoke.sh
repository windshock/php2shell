#!/usr/bin/env bash
# Smoke-run the official php-fuzz-unserialize fuzzer (60s, local only).
set -u
base=/home/phplab/php-lab
src="$base/sources/php-8.4.4"
build="$base/builds/8.4.4-fuzzer"
out="$base/evidence/fuzz-unserialize-$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$out/corpus" "$out/dict"
"$build/sapi/cli/php" "$src/sapi/fuzzer/generate_unserialize_dict.php" > "$out/dict/unserialize" 2> "$out/dict/gen.log" || true
echo "dict_lines=$(wc -l < "$out/dict/unserialize")"
dict_arg=""
if [ -s "$out/dict/unserialize" ]; then dict_arg="-dict=$out/dict/unserialize"; fi
cp -r "$src/sapi/fuzzer/corpus/unserialize/." "$out/corpus/"
echo "seed_files=$(ls "$out/corpus" | wc -l)"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
  timeout 150 "$build/sapi/fuzzer/php-fuzz-unserialize" \
  $dict_arg -max_total_time=60 -rss_limit_mb=2048 \
  -print_final_stats=1 "$out/corpus" > "$out/fuzz.log" 2>&1
FUZZ_EXIT=$?
echo "FUZZ_EXIT=$FUZZ_EXIT"
echo "OUT=$out"
crashes=$(ls "$out/corpus" | grep -c '^crash-' || true)
echo "crash_artifacts=$crashes"
tail -8 "$out/fuzz.log"
if [ "$crashes" -gt 0 ]; then
  echo 'CRASH_ARTIFACTS_FOUND — inspect the corpus'
  exit 3
fi
if [ "$FUZZ_EXIT" -ne 0 ]; then
  echo "FUZZER_FAILED rc=$FUZZ_EXIT (124 means the timeout wrapper stopped it)"
  exit 1
fi
exit 0
