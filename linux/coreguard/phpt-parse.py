#!/usr/bin/env python3
"""Parse a phpt-baseline.sh run (run-tests.php -W results) and optionally
compare it with a baseline run: regressions = tests PASSED on the baseline
that do not pass on this run (the B vs C compatibility check, #3 Phase 0/5).

Writes <run>/per-test.json and updates <run>/summary.json (per_test,
status_counts, and comparison when --compare is given).

Usage: phpt-parse.py RUN [--compare BASELINE_RUN]
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

LINE = re.compile(r'^([A-Z]+)\t(\S+\.phpt)\s*$')


def parse(run):
    results = {}
    for line in (run / 'results.txt').read_text(errors='replace').splitlines():
        m = LINE.match(line)
        if m:
            path = m.group(2)
            rel = path.split('/src/', 1)[1] if '/src/' in path else path
            results[rel] = m.group(1)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('run', type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    res = parse(args.run)
    (args.run / 'per-test.json').write_text(json.dumps(res, indent=1, sort_keys=True))
    summary = json.loads((args.run / 'summary.json').read_text())
    summary['per_test'] = len(res)
    summary['status_counts'] = dict(collections.Counter(res.values()))
    if args.compare:
        base = parse(args.compare)
        regress = sorted(t for t, s in base.items() if s == 'PASSED' and res.get(t) != 'PASSED')
        fixed = sorted(t for t, s in res.items() if s == 'PASSED' and base.get(t) not in (None, 'PASSED'))
        summary['comparison'] = dict(baseline=str(args.compare), baseline_tests=len(base),
                                     common=len(set(base) & set(res)),
                                     regressions=[dict(test=t, status=res.get(t)) for t in regress],
                                     newly_passing=fixed)
    (args.run / 'summary.json').write_text(json.dumps(summary, indent=2))
    out = dict(run=str(args.run), per_test=len(res), status_counts=summary['status_counts'])
    if args.compare:
        out['regressions'] = len(summary['comparison']['regressions'])
        out['regression_list'] = summary['comparison']['regressions'][:20]
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
