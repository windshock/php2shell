#!/usr/bin/env python3
"""Phase 5 v2 Stage 2 MVP: classified fault-site map.

Extends ordering-sites.sh with category buckets over the request-parse and
(un)serialize surfaces:

  count_before_fallible   counter/index bump followed by a fallible alloc
  init_fallible_destroy   *_INIT ... fallible window ... *_DESTROY pairing
  global_ptr_request_free module-global pointer assigned request memory
  refcount_then_fallible  refcount bump followed by a fallible alloc
  reentrancy              user-code callbacks inside INIT..DESTROY windows

This is still regex/heuristic (the full AST/call-graph version is the
deferved Stage 2 deliverable); hits are hypotheses, never verdicts.
Guard cross-reference marks sites that 8.4.27 protects via ZEND_HAS_OOM or
fallible allocations.

Usage: python3 linux/fault-site-map.py [--src /home/phplab/php-lab/sources/php-8.4.4]
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

FALLIBLE = re.compile(r'\b(emalloc|ecalloc|erealloc|safe_erealloc|zend_string_init|'
                      r'zend_string_alloc|zend_hash_real_init|zend_hash_do_resize|'
                      r'zend_hash_add|zend_hash_update|zend_symtable|smart_str_append|'
                      r'add_assoc|add_next_index)')
COUNTER = re.compile(r'(\w*\+\+|\w* *= *\w* \+ 1|nNumUsed|nNumOfElements|nTableSize|'
                     r'\bht->n|len *=|used_slots)')
REFCOUNT = re.compile(r'Z_(TRY_)?ADDREF|GC_ADDREF|ZVAL_COPY\(')
CALLBACK = re.compile(r'zend_call_function|zend_call_method|unserialize_callback|'
                     r'ce->unserialize|->unserialize\(')
INIT_DESTROY = re.compile(r'PHP_VAR_(UN)?SERIALIZE_(INIT|DESTROY)')
GLOBAL_PTR = re.compile(r'\b(PS|BG)\(\w+\) *=(?!=)')
WINDOW = 6

FILES = ['Zend/zend_hash.c', 'Zend/zend_alloc.c', 'Zend/zend_llist.c',
         'main/php_variables.c', 'main/rfc1867.c', 'main/SAPI.c',
         'ext/standard/var.c', 'ext/standard/var_unserializer.re',
         'ext/standard/basic_functions.c', 'ext/session/session.c',
         'ext/session/mod_files.c']


def scan(src):
    sites = {k: [] for k in ('count_before_fallible', 'init_fallible_destroy',
                             'global_ptr_request_free', 'refcount_then_fallible',
                             'reentrancy')}
    for rel in FILES:
        path = src / rel
        if not path.exists():
            continue
        lines = path.read_text(errors='replace').splitlines()
        in_window = 0
        for i, line in enumerate(lines):
            if INIT_DESTROY.search(line):
                if '_INIT' in line.upper() or 'INIT(' in line:
                    in_window = 1
                else:
                    in_window = 0
                continue
            if in_window and FALLIBLE.search(line):
                sites['init_fallible_destroy'].append('%s:%d' % (rel, i + 1))
            if in_window and CALLBACK.search(line):
                sites['reentrancy'].append('%s:%d' % (rel, i + 1))
            if COUNTER.search(line) and not line.strip().startswith('*'):
                window = lines[i + 1:i + 1 + WINDOW]
                if any(FALLIBLE.search(w) for w in window):
                    sites['count_before_fallible'].append('%s:%d' % (rel, i + 1))
            if REFCOUNT.search(line):
                window = lines[i + 1:i + 1 + WINDOW]
                if any(FALLIBLE.search(w) for w in window):
                    sites['refcount_then_fallible'].append('%s:%d' % (rel, i + 1))
            if GLOBAL_PTR.search(line) and any(k in line for k in ('emalloc', 'ecalloc',
                                                                   'zend_string', 'estrndup')):
                sites['global_ptr_request_free'].append('%s:%d' % (rel, i + 1))
    return sites


def guard_counts(fixed_src):
    counts = {}
    for rel in FILES:
        path = fixed_src / rel
        if path.exists():
            counts[rel] = len(re.findall(r'ZEND_HAS_OOM|fallible', path.read_text(errors='replace')))
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path,
                        default=Path('/home/phplab/php-lab/sources/php-8.4.4'))
    parser.add_argument('--fixed-src', type=Path,
                        default=Path('/home/phplab/php-lab/sources/php-8.4.27'))
    parser.add_argument('--out', type=Path,
                        default=Path('/home/phplab/php-lab/evidence/fault-site-map'))
    args = parser.parse_args()
    sites = scan(args.src)
    guards = guard_counts(args.fixed_src)
    args.out.mkdir(parents=True, exist_ok=True)
    summary = dict(scope='Phase 5 v2 Stage 2 MVP fault-site map (heuristic; '
                         'hypotheses only)',
                   source=str(args.src),
                   categories={k: dict(count=len(v), sites=v[:60]) for k, v in sites.items()},
                   guard_crossreference=dict(
                       note='ZEND_HAS_OOM/fallible occurrences per file in 8.4.27',
                       counts=guards))
    (args.out / 'fault-site-map.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: len(v) for k, v in sites.items()}, indent=2))
    print('out:', args.out / 'fault-site-map.json')


if __name__ == '__main__':
    main()
