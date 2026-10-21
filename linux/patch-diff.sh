#!/usr/bin/env bash
# Diff the PHP2Shell-relevant files between the affected and fixed release.
set -euo pipefail
base=/home/phplab/php-lab
old="$base/sources/php-8.4.4"
new="$base/sources/php-8.4.27"
out="$base/evidence/patch-diff-8.4.4-8.4.27.txt"
: > "$out"
for f in ext/session/session.c ext/session/php_session.h ext/standard/var.c \
         ext/standard/var_unserializer.re ext/standard/basic_functions.c \
         main/main.c main/php_variables.c main/rfc1867.c Zend/zend_alloc.c; do
  echo "===== $f =====" >> "$out"
  diff -u "$old/$f" "$new/$f" >> "$out" || true
done
echo "wrote $out"
echo "--- files with changes:"
grep -c '^=====' "$out" >/dev/null || true
awk '/^=====/{f=$0; n=0} /^@@/{n++; c[f]=n} END{for (k in c) print c[k], k}' "$out" | sort -rn
echo "--- lines mentioning the serialize/unserialize context or request init:"
grep -n -E '^[+-].*(BG\((un)?serialize|php_var_(un)?serialize|rfc1867|request_startup|session_upload|upload_progress)' "$out" | head -40 || true
