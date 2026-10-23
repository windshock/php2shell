#!/usr/bin/env python3
"""Phase 5 v2 Stage 4: coverage map and gap list (plan §12.3 Stage 4).

Fuzz Introspector needs an LTO/introspector build pipeline that this lab
does not have; this is the equivalent built from what the lab does have:
SanitizerCoverage edge PCs (.sancov files of lifecycle-explore.py --cov
campaigns) symbolized with llvm-symbolizer against the cov build.

  covered      unique source lines / functions / files reached
  candidates   fault-site-map.py hypotheses (count_before_fallible, ...):
               reached = a covered line within [line, line+WINDOW] of the
               same file, else a coverage GAP (never executed by any run)
  gaps         per request-path file: functions with no covered line,
               to re-prioritize static candidates and generator actions

Usage: coverage-map.py --campaign DIR... [--binary PHP] [--fault-map JSON]
"""
import argparse
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


def symbolize(binary, pcs):
    """pc -> (function, relative source path, line)."""
    ordered = sorted(pcs)
    proc = subprocess.run(['llvm-symbolizer', '--obj=%s' % binary, '--output-style=GNU',
                           '--no-inlines', '--functions=linkage'],
                          input='\n'.join('0x%x' % (pc - 1) for pc in ordered) + '\n',
                          capture_output=True, text=True, timeout=1800)
    lines = proc.stdout.splitlines()
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
    nm = subprocess.run(['nm', '--defined-only', '-C', str(binary)], capture_output=True,
                        text=True, timeout=600).stdout.splitlines()
    funcs = [line.split()[-1] for line in nm if re.search(r' [tT] ', line)]
    addrs = [line.split()[0] for line in nm if re.search(r' [tT] ', line)]
    proc = subprocess.run(['llvm-symbolizer', '--obj=%s' % binary, '--output-style=GNU',
                           '--no-inlines'],
                          input='\n'.join('0x' + a for a in addrs) + '\n',
                          capture_output=True, text=True, timeout=1800)
    lines = proc.stdout.splitlines()
    by_file = defaultdict(set)
    for idx, name in enumerate(funcs):
        loc = lines[2 * idx + 1] if 2 * idx + 1 < len(lines) else ''
        rel = re.sub(r'^.*/(?:sources/php-[^/]*|builds/[^/]*)/', '', loc.rsplit(':', 1)[0])
        if rel in files:
            by_file[rel].add(name)
    return by_file


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--campaign', nargs='+', required=True)
    parser.add_argument('--binary', default=str(BASE / 'install/8.4.4-cov/bin/php'))
    parser.add_argument('--fault-map', default=None,
                        help='fault-site-map.json (default: newest under evidence/)')
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    pcs, nfiles = read_pcs(args.campaign)
    if not pcs:
        print(json.dumps(dict(error='no sancov data', campaigns=args.campaign)))
        return 2
    sym = symbolize(args.binary, pcs)
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
        reached, gaps = [], []
        for site in info['sites']:
            rel, _, line = site.rpartition(':')
            line = int(line)
            hit = any(l in covered_lines.get(rel, ()) for l in range(line, line + WINDOW + 1))
            (reached if hit else gaps).append(site)
        cand[category] = dict(total=len(info['sites']), reached=len(reached),
                              gaps=gaps[:40])

    defined = function_ranges(args.binary, set(REQUEST_PATH))
    request_path = {}
    for rel in REQUEST_PATH:
        funcs = defined.get(rel, set())
        hit = covered_funcs.get(rel, set()) & funcs
        request_path[rel] = dict(functions=len(funcs), covered=len(hit),
                                 lines_covered=len(covered_lines.get(rel, ())),
                                 uncovered_examples=sorted(funcs - hit)[:15])
    report = dict(scope='Stage 4 coverage map (sancov + llvm-symbolizer; Fuzz Introspector '
                        'substitute)',
                  campaigns=args.campaign, sancov_files=nfiles, unique_edges=len(pcs),
                  covered_files=len(covered_lines),
                  covered_lines=sum(len(v) for v in covered_lines.values()),
                  fault_map=str(fmap), candidates=cand, request_path=request_path)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
    print(json.dumps({k: report[k] for k in ('sancov_files', 'unique_edges', 'covered_files',
                                             'covered_lines')}
                     | {'candidates': {k: '%d/%d' % (v['reached'], v['total'])
                                       for k, v in cand.items()},
                        'request_path': {k: '%d/%d fn' % (v['covered'], v['functions'])
                                         for k, v in request_path.items()}}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
