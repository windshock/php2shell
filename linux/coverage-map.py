#!/usr/bin/env python3
"""Phase 5 v2 Stage 4: coverage map and gap list (plan §12.3 Stage 4).

Fuzz Introspector needs an LTO/introspector build pipeline that this lab
does not have; this is the equivalent built from what the lab does have:
SanitizerCoverage edge PCs (.sancov files of lifecycle-explore.py --cov
campaigns) symbolized with llvm-symbolizer against the cov build.

  covered      unique source lines / functions / files reached
  candidates   fault-site-map.py hypotheses (count_before_fallible, ...),
               classified per site (issue #5-10):
                 exact_site_covered      the candidate line itself executed
                 nearby_source_coverage  only a line within +WINDOW executed
                 gap                     nothing in the window executed
               fault_path_reached (the risky operation actually failing
               there) is NOT measurable from coverage and is reported as such
  integrity    symbolizer/nm exit codes, output counts and the unresolved
               ratio are checked (>5% unresolved -> incomplete); every
               campaign's recorded binary SHA-256 must match --binary
  gaps         per request-path file: functions with no covered line,
               to re-prioritize static candidates and generator actions

Usage: coverage-map.py --campaign DIR... [--binary PHP] [--fault-map JSON]
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = Path('/home/phplab/php-lab')
WINDOW = 6
REQUEST_PATH = ('main/rfc1867.c', 'main/php_variables.c', 'main/SAPI.c', 'main/main.c',
                'ext/session/session.c', 'ext/session/mod_files.c', 'ext/standard/var.c',
                'ext/standard/var_unserializer.re', 'ext/standard/basic_functions.c',
                'Zend/zend_hash.c')
SANCOV_MAGIC64 = 0xC0BFFFFFFFFFFF64


def read_pcs(campaigns):
    pcs, files = set(), 0
    for d in campaigns:
        for path in Path(d).glob('exec-*/cov/php.*.sancov'):
            data = path.read_bytes()
            if len(data) < 8 or int.from_bytes(data[:8], 'little') != SANCOV_MAGIC64:
                continue
            files += 1
            for i in range(8, len(data) - 7, 8):
                pcs.add(int.from_bytes(data[i:i + 8], 'little'))
    return pcs, files


class Incomplete(Exception):
    pass


def check_symbolizer(rc, lines, n):
    """Fail-closed symbolization (issue #5-10): rc, line count, unresolved."""
    if rc != 0:
        raise Incomplete('llvm-symbolizer exit %d' % rc)
    if len(lines) != 2 * n:
        raise Incomplete('symbolizer returned %d lines for %d addresses' % (len(lines), n))
    unresolved = sum(1 for i in range(1, len(lines), 2) if lines[i].startswith('??'))
    ratio = unresolved / max(n, 1)
    if ratio > 0.05:
        raise Incomplete('%.1f%% of addresses unresolved' % (100 * ratio))
    return ratio


def classify_site(covered, rel, line):
    lines = covered.get(rel, ())
    if line in lines:
        return 'exact_site_covered'
    if any(l in lines for l in range(line + 1, line + WINDOW + 1)):
        return 'nearby_source_coverage'
    return 'gap'


def symbolize(binary, pcs):
    """pc -> (function, relative source path, line)."""
    ordered = sorted(pcs)
    proc = subprocess.run(['llvm-symbolizer', '--obj=%s' % binary, '--output-style=GNU',
                           '--no-inlines', '--functions=linkage'],
                          input='\n'.join('0x%x' % (pc - 1) for pc in ordered) + '\n',
                          capture_output=True, text=True, timeout=1800)
    lines = proc.stdout.splitlines()
    symbolize.unresolved_ratio = check_symbolizer(proc.returncode, lines, len(ordered))
    out = {}
    for idx, pc in enumerate(ordered):
        func = lines[2 * idx] if 2 * idx < len(lines) else '??'
        loc = lines[2 * idx + 1] if 2 * idx + 1 < len(lines) else '??:0'
        match = re.match(r'(.*):(\d+)', loc)
        path = match.group(1) if match else '??'
        rel = re.sub(r'^.*/(?:sources/php-[^/]*|builds/[^/]*)/', '', path)
        out[pc] = (func, rel, int(match.group(2)) if match else 0)
    return out


def function_ranges(binary, files):
    """All functions defined in the given source files (from DWARF via
    llvm-dwarfdump is heavy; nm + symbolizer is enough for a gap list)."""
    res = subprocess.run(['nm', '--defined-only', '-C', str(binary)], capture_output=True,
                         text=True, timeout=600)
    if res.returncode != 0 or not res.stdout.strip():
        raise Incomplete('nm failed or returned no symbols (rc %d)' % res.returncode)
    nm = res.stdout.splitlines()
    funcs = [line.split()[-1] for line in nm if re.search(r' [tT] ', line)]
    addrs = [line.split()[0] for line in nm if re.search(r' [tT] ', line)]
    proc = subprocess.run(['llvm-symbolizer', '--obj=%s' % binary, '--output-style=GNU',
                           '--no-inlines'],
                          input='\n'.join('0x' + a for a in addrs) + '\n',
                          capture_output=True, text=True, timeout=1800)
    lines = proc.stdout.splitlines()
    if proc.returncode != 0 or len(lines) != 2 * len(addrs):
        raise Incomplete('function symbolization incomplete')
    by_file = defaultdict(set)
    for idx, name in enumerate(funcs):
        loc = lines[2 * idx + 1] if 2 * idx + 1 < len(lines) else ''
        rel = re.sub(r'^.*/(?:sources/php-[^/]*|builds/[^/]*)/', '', loc.rsplit(':', 1)[0])
        if rel in files:
            by_file[rel].add(name)
    return by_file


def self_test():
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    cov = {'Zend/zend_hash.c': {955, 960}}
    check('candidate line executed -> exact_site_covered',
          classify_site(cov, 'Zend/zend_hash.c', 955) == 'exact_site_covered')
    check('only a later line executed -> nearby_source_coverage',
          classify_site(cov, 'Zend/zend_hash.c', 956) == 'nearby_source_coverage')
    check('nothing in window -> gap', classify_site(cov, 'Zend/zend_hash.c', 100) == 'gap')

    def raises(*args):
        try:
            check_symbolizer(*args)
        except Incomplete:
            return True
        return False
    check('symbolizer non-zero exit -> incomplete', raises(1, ['f', 'a.c:1'], 1))
    check('symbolizer short output -> incomplete', raises(0, ['f'], 1))
    check('high unresolved ratio -> incomplete',
          raises(0, ['??', '??:0'] * 10 + ['f', 'a.c:1'] * 10, 20))
    check('clean symbolization accepted', not raises(0, ['f', 'a.c:1'] * 3, 3))
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--campaign', nargs='+', required=True)
    parser.add_argument('--binary', default=str(BASE / 'install/8.4.4-cov/bin/php'))
    parser.add_argument('--fault-map', default=None,
                        help='fault-site-map.json (default: newest under evidence/)')
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    binary_sha = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
    mismatch = []
    for d in args.campaign:
        summary = Path(d) / 'summary.json'
        recorded = json.loads(summary.read_text()).get('binary_sha256') if summary.exists() \
            else None
        if recorded != binary_sha:
            mismatch.append(dict(campaign=str(d), recorded=recorded))
    if mismatch:
        # Different or unrecorded build: PCs could come from another binary.
        print(json.dumps(dict(status='incomplete', reason='binary not verified for campaigns',
                              binary_sha256=binary_sha, mismatch=mismatch), indent=2))
        return 2
    pcs, nfiles = read_pcs(args.campaign)
    if not pcs:
        print(json.dumps(dict(status='incomplete', error='no sancov data',
                              campaigns=args.campaign)))
        return 2
    try:
        sym = symbolize(args.binary, pcs)
    except Incomplete as exc:
        print(json.dumps(dict(status='incomplete', reason=str(exc))))
        return 2
    covered_lines = defaultdict(set)
    covered_funcs = defaultdict(set)
    for func, rel, line in sym.values():
        covered_lines[rel].add(line)
        covered_funcs[rel].add(func)

    fmap = Path(args.fault_map) if args.fault_map else max(
        (BASE / 'evidence').glob('fault-site-map*/fault-site-map.json'),
        key=lambda p: p.stat().st_mtime)
    fault = json.loads(fmap.read_text())
    cand = {}
    for category, info in fault['categories'].items():
        buckets = defaultdict(list)
        for site in info['sites']:
            rel, _, line = site.rpartition(':')
            buckets[classify_site(covered_lines, rel, int(line))].append(site)
        cand[category] = dict(total=len(info['sites']),
                              exact_site_covered=len(buckets['exact_site_covered']),
                              nearby_source_coverage=len(buckets['nearby_source_coverage']),
                              gap=len(buckets['gap']), fault_path_reached='not_measurable',
                              gaps=buckets['gap'][:40],
                              nearby_only=buckets['nearby_source_coverage'][:40])

    try:
        defined = function_ranges(args.binary, set(REQUEST_PATH))
    except Incomplete as exc:
        print(json.dumps(dict(status='incomplete', reason=str(exc))))
        return 2
    request_path = {}
    for rel in REQUEST_PATH:
        funcs = defined.get(rel, set())
        hit = covered_funcs.get(rel, set()) & funcs
        request_path[rel] = dict(functions=len(funcs), covered=len(hit),
                                 lines_covered=len(covered_lines.get(rel, ())),
                                 uncovered_examples=sorted(funcs - hit)[:15])
    report = dict(scope='Stage 4 coverage map (sancov + llvm-symbolizer; Fuzz Introspector '
                        'substitute)', status='complete', binary_sha256=binary_sha,
                  unresolved_ratio=round(symbolize.unresolved_ratio, 4),
                  campaigns=args.campaign, sancov_files=nfiles, unique_edges=len(pcs),
                  covered_files=len(covered_lines),
                  covered_lines=sum(len(v) for v in covered_lines.values()),
                  fault_map=str(fmap), candidates=cand, request_path=request_path)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
    print(json.dumps({k: report[k] for k in ('sancov_files', 'unique_edges', 'covered_files',
                                             'covered_lines')}
                     | {'candidates': {k: 'exact %d, nearby-only %d, gap %d / %d' % (
                         v['exact_site_covered'], v['nearby_source_coverage'], v['gap'],
                         v['total']) for k, v in cand.items()},
                        'request_path': {k: '%d/%d fn' % (v['covered'], v['functions'])
                                         for k, v in request_path.items()}}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
