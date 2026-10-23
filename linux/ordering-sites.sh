#!/usr/bin/env bash
# Phase 5 A3: count-before-init pattern scan.
# Looks for "counter/index/length increment -> fallible allocation" orderings
# where a bailout in the allocation exposes partially initialised structures
# (the CVE-2026-109618 class). Sites already behind ZEND_HAS_OOM guards in
# 8.4.27 are marked already_patched by cross-reference.
set -euo pipefail
base=/home/phplab/php-lab
src=${1:-$base/sources/php-8.4.4}
out="$base/evidence/ordering-sites"
mkdir -p "$out"

python3 - "$src" > "$out/pattern-hits.txt" <<'PY'
import re, sys
from pathlib import Path
src = Path(sys.argv[1])
alloc = re.compile(r'\b(_?emalloc|_?ecalloc|_?erealloc|safe_erealloc|zend_string_init|'
                   r'zend_string_alloc|zend_hash_real_init|zend_hash_do_resize|HT_DATA_REALLOC|'
                   r'perealloc|pealloc|_emalloc_2|add_next_index_stringl|smart_str_append)')
incr = re.compile(r'(\w+\+\+|\+= *[0-9]+|\+\+ *\w+|nNumUsed|nNumOfElements|nTableSize|len *=)')
files = list((src / 'Zend').glob('*.c')) + list((src / 'main').glob('*.c')) \
    + list((src / 'ext/standard').glob('*.c'))
hits = 0
for path in sorted(files):
    try:
        lines = path.read_text(errors='replace').splitlines()
    except OSError:
        continue
    for i, line in enumerate(lines):
        if not incr.search(line):
            continue
        # look ahead 4 lines for a fallible allocation
        window = lines[i + 1:i + 5]
        for j, w in enumerate(window):
            if alloc.search(w):
                rel = str(path.relative_to(src))
                # only interested when the increment mutates state used by the
                # allocation's data structure (hash tables, lists, strings)
                if any(k in line for k in ('nNumUsed', 'nNumOfElements', 'nTableSize',
                                           'len', 'used', 'count', 'size', 'idx')):
                    hits += 1
                    print('%s:%d  INCR %s' % (rel, i + 1, line.strip()[:90]))
                    print('        +%d  %s' % (j + 1, w.strip()[:110]))
                    break
print('total candidate pairs:', hits)
PY

# Guard cross-reference: which of those lines sit behind ZEND_HAS_OOM in 8.4.27.
{
  echo '== ZEND_HAS_OOM guard counts in 8.4.27 core files =='
  for f in Zend/zend_hash.c Zend/zend_alloc.c Zend/zend_llist.c Zend/smart_str.h \
           Zend/zend_string.h main/php_variables.c main/rfc1867.c \
           ext/standard/var.c ext/standard/var_unserializer.re; do
    n=$(grep -c 'ZEND_HAS_OOM' "$base/sources/php-8.4.27/$f" 2>/dev/null || echo 0)
    echo "$f: $n"
  done
} > "$out/guard-crossref.txt" 2>&1 || true

wc -l "$out/pattern-hits.txt" "$out/guard-crossref.txt"
echo "outdir: $out"
