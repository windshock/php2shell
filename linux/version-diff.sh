#!/usr/bin/env bash
# Compare the PHP2Shell-relevant source files between pristine 8.4.4 and 8.5.4.
# Read-only: produces a unified diff, changes nothing.
set -euo pipefail
old=/mnt/c/Users/user/Downloads/php/sources/php-src-php-8.4.4
new=/home/phplab/php-lab/sources/php-8.5.4
out=/home/phplab/php-lab/evidence/version-diff-8.4.4-8.5.4.txt
mkdir -p "$(dirname "$out")"
: > "$out"
for f in ext/session/session.c ext/session/php_session.h ext/session/mod_files.c \
         ext/standard/var.c ext/standard/basic_functions.c \
         main/main.c main/php_variables.c main/rfc1867.c; do
  echo "===== $f =====" >> "$out"
  diff -u "$old/$f" "$new/$f" >> "$out" || true
done
echo "wrote $out"
wc -l "$out"
