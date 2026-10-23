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

Scope reporting (issue #1 follow-up, plan §12.6 R6): every target file is
listed as present/missing with its line count; any missing file marks the
result scope_incomplete and exits 2 unless --allow-missing is given, so the
category counts always come with their denominator.

Usage: python3 linux/fault-site-map.py [--src /home/phplab/php-lab/sources/php-8.4.4]
                                       [--allow-missing] | --self-test
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


def scan(src, files=FILES):
    sites = {k: [] for k in ('count_before_fallible', 'init_fallible_destroy',
                             'global_ptr_request_free', 'refcount_then_fallible',
                             'reentrancy')}
    coverage = {}
    for rel in files:
        path = src / rel
        if not path.exists():
            coverage[rel] = dict(status='missing')
            continue
        lines = path.read_text(errors='replace').splitlines()
        coverage[rel] = dict(status='present', lines=len(lines))
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
    return sites, coverage


def guard_counts(fixed_src, files=FILES):
    counts, missing = {}, []
    for rel in files:
        path = fixed_src / rel
        if path.exists():
            counts[rel] = len(re.findall(r'ZEND_HAS_OOM|fallible', path.read_text(errors='replace')))
        else:
            missing.append(rel)
    return counts, missing


def scope_status(coverage, guard_missing):
    missing = sorted(k for k, v in coverage.items() if v['status'] == 'missing')
    return dict(files_total=len(coverage), files_present=len(coverage) - len(missing),
                files_missing=missing, fixed_src_missing=sorted(guard_missing),
                lines_scanned=sum(v.get('lines', 0) for v in coverage.values()),
                scope_complete=not missing and not guard_missing)


def run_self_test():
    import tempfile
    passed = total = 0
    with tempfile.TemporaryDirectory() as tmp:
        src, fixed = Path(tmp) / 'src', Path(tmp) / 'fixed'
        for root in (src, fixed):
            (root / 'Zend').mkdir(parents=True)
            (root / 'Zend/a.c').write_text('ht->nNumUsed++;\nkey = zend_string_init(s, l, 0);\n')
        (fixed / 'Zend/b.c').write_text('')
        files = ['Zend/a.c', 'Zend/b.c']
        for name, want_complete, want_hits in (('missing source file reported', False, 1),):
            sites, cov = scan(src, files)
            _, gmiss = guard_counts(fixed, files)
            scope = scope_status(cov, gmiss)
            ok = (scope['scope_complete'] is want_complete
                  and scope['files_missing'] == ['Zend/b.c']
                  and len(sites['count_before_fallible']) == want_hits)
            total += 1
            passed += ok
            print('%s %s %s' % ('PASS' if ok else 'FAIL', name, scope))
        (src / 'Zend/b.c').write_text('')
        sites, cov = scan(src, files)
        _, gmiss = guard_counts(fixed, files)
        scope = scope_status(cov, gmiss)
        ok = scope['scope_complete'] and scope['files_present'] == 2
        total += 1
        passed += ok
        print('%s complete scope accepted %s' % ('PASS' if ok else 'FAIL', scope))
    print('self_test=%d/%d' % (passed, total))
    return 0 if passed == total else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path,
                        default=Path('/home/phplab/php-lab/sources/php-8.4.4'))
    parser.add_argument('--fixed-src', type=Path,
                        default=Path('/home/phplab/php-lab/sources/php-8.4.27'))
    parser.add_argument('--out', type=Path,
                        default=Path('/home/phplab/php-lab/evidence/fault-site-map-'
                                     + __import__('time').strftime('%Y%m%dT%H%M%S')))
    parser.add_argument('--allow-missing', action='store_true',
                        help='accept an incomplete scan (still reported)')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    sites, coverage = scan(args.src)
    guards, guard_missing = guard_counts(args.fixed_src)
    scope = scope_status(coverage, guard_missing)
    args.out.mkdir(parents=True, exist_ok=True)
    summary = dict(scope='Phase 5 v2 Stage 2 MVP fault-site map (heuristic; '
                         'hypotheses only)',
                   source=str(args.src),
                   coverage=dict(scope, files=coverage,
                              status='complete' if scope['scope_complete']
                              else 'scope_incomplete'),
                   categories={k: dict(count=len(v), sites=v[:60]) for k, v in sites.items()},
                   guard_crossreference=dict(
                       note='ZEND_HAS_OOM/fallible occurrences per file in 8.4.27',
                       counts=guards))
    (args.out / 'fault-site-map.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: len(v) for k, v in sites.items()}, indent=2))
    print(json.dumps({k: scope[k] for k in ('files_total', 'files_present', 'files_missing',
                                            'fixed_src_missing', 'lines_scanned',
                                            'scope_complete')}))
    print('out:', args.out / 'fault-site-map.json')
    if not scope['scope_complete'] and not args.allow_missing:
        print('scope_incomplete: missing target files (use --allow-missing to accept)')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
