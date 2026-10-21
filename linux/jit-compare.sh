#!/usr/bin/env bash
# JIT vs non-JIT differential run (ZendDiff-style methodology, output level).
# Same script, same PHP build, only opcache.jit differs. Compares stdout,
# exit code and wall time; records evidence.
set -u
base=/home/phplab/php-lab
php="$base/install/8.4.4-jit/bin/php"
script=/mnt/c/Users/user/Downloads/php/linux/tests/jit-diff.php
out="$base/evidence/jit-compare-$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$out" /tmp/jit-sessions
opcache=$(ls "$base"/install/8.4.4-jit/lib/php/extensions/*/opcache.so 2>/dev/null | head -1)
[ -n "$opcache" ] || { echo "opcache.so not found"; exit 1; }

run() {
  local label=$1 jit=$2
  local t0 t1
  t0=$(date +%s%N)
  "$php" -n -d "zend_extension=$opcache" -d opcache.enable_cli=1 \
    -d "opcache.jit=$jit" -d opcache.jit_buffer_size=64M \
    -d session.save_path=/tmp/jit-sessions -d session.use_cookies=0 \
    -d session.cache_limiter= "$script" > "$out/$label.out" 2> "$out/$label.err"
  echo "exit=$?" > "$out/$label.exit"
  t1=$(date +%s%N)
  echo "$(( (t1 - t0) / 1000000 ))" > "$out/$label.ms"
}

run off off
run tracing tracing
run function function

diff -q "$out/off.out" "$out/tracing.out" >/dev/null && same_tracing=yes || same_tracing=no
diff -q "$out/off.out" "$out/function.out" >/dev/null && same_function=yes || same_function=no

{
  echo "{"
  echo "  \"scope\": \"JIT differential; output level, local lab only\","
  echo "  \"off_ms\": $(cat "$out/off.ms"),"
  echo "  \"tracing_ms\": $(cat "$out/tracing.ms"),"
  echo "  \"function_ms\": $(cat "$out/function.ms"),"
  echo "  \"off_exit\": $(cut -d= -f2 "$out/off.exit"),"
  echo "  \"tracing_exit\": $(cut -d= -f2 "$out/tracing.exit"),"
  echo "  \"function_exit\": $(cut -d= -f2 "$out/function.exit"),"
  echo "  \"stdout_same_tracing\": \"$same_tracing\","
  echo "  \"stdout_same_function\": \"$same_function\""
  echo "}"
} > "$out/result.json"
cat "$out/result.json"
echo "OUT=$out"
[ "$same_tracing" = yes ] && [ "$same_function" = yes ]
