#!/usr/bin/env bash
# Phase 5 A1: extract the "protection map" from the 8.4.4 -> 8.4.27 diff.
# Lists every hunk in the security-relevant files that adds an early reset,
# an OOM guard, or a scope restriction. Raw evidence for findings section 9.
set -euo pipefail
base=/home/phplab/php-lab
old="$base/sources/php-8.4.4"
new="$base/sources/php-8.4.27"
out="$base/evidence/patch-protect-map"
mkdir -p "$out"

files=(Zend/zend_alloc.c main/rfc1867.c ext/standard/var_unserializer.re \
       ext/session/session.c main/main.c ext/standard/basic_functions.c \
       ext/standard/var.c main/php_variables.c ext/session/php_session.h \
       ext/session/mod_files.c ext/standard/url_scanner_ex.c \
       ext/standard/url_scanner_ex.h ext/standard/php_var.h)

: > "$out/hunks.txt"
for f in "${files[@]}"; do
  if [[ ! -e "$old/$f" || ! -e "$new/$f" ]]; then
    echo "### MISSING $f" >> "$out/hunks.txt"
    continue
  fi
  python3 - "$old/$f" "$new/$f" "$f" >> "$out/hunks.txt" <<'PY'
import difflib, sys, re
old_p, new_p, name = sys.argv[1:4]
a = open(old_p, errors='replace').read().splitlines()
b = open(new_p, errors='replace').read().splitlines()
marker = re.compile(r'early_rinit|rinit_session_globals|ZEND_HAS_OOM|hard_limit|'
                    r'in_rfc1867|memset\(&BG\(|serialize_lock|url_scanner|'
                    r'array_init_singleton|set_incomplete_classes_only|'
                    r'zend_try|zend_end_try|ZEND_TRY|ZEND_END_TRY')
diff = list(difflib.unified_diff(a, b, n=3, lineterm=''))
cur = []
def flush(cur, name):
    if not cur:
        return
    changed = [l for l in cur if l[:1] in '+-']
    if changed and any(marker.search(l) for l in changed):
        print('### HUNK %s' % name)
        print('\n'.join(cur))
        print()
for line in diff:
    if line.startswith('---') or line.startswith('+++'):
        continue
    if line.startswith('@@'):
        flush(cur, name)
        cur = [line]
    else:
        cur.append(line)
flush(cur, name)
PY
  diff -u "$old/$f" "$new/$f" > "$out/$(echo "$f" | tr / _).diff" 2>/dev/null || true
done
wc -l "$out/hunks.txt"
echo "outdir: $out"
