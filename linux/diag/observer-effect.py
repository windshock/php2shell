#!/usr/bin/env python3
"""Diagnostic (findings §10.7 / §10.8, R12 re-run): does the gdb observer
change the outcome? Runs the same sequence N times with observer=none and
observer=gdb and compares per-step responses, hang classification and ASAN
signatures. Default sequence: parse_oom -> parse_oom on 8.4.4 (the Path B
self-deadlock); the observer must not create or remove the hang.

Observation only.
Usage: python3 linux/diag/observer-effect.py [--version 8.4.4] [--repeats 2] [--seq JSON]
"""
import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
_spec = importlib.util.spec_from_file_location('lifecycle_explore', HERE.parent / 'lifecycle-explore.py')
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)
import provenance  # noqa: E402

DEFAULT = {"limit": "8M", "steps": [{"a": "parse_oom"}, {"a": "parse_oom"}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--seq', help='sequence JSON file (copied into the evidence dir)')
    args = parser.parse_args()
    seq = json.loads(Path(args.seq).read_text()) if args.seq else DEFAULT
    root = ex.BASE / 'evidence' / ('diag-observer-effect-%s-%s' % (
        time.strftime('%Y%m%dT%H%M%S', time.gmtime()), args.version))
    root.mkdir(parents=True)
    inputs = provenance.preserve_inputs([args.seq], root) if args.seq else []
    (root / 'sequence.json').write_text(json.dumps(seq))
    runs = []
    for rep in range(args.repeats):
        for obs in ('none', 'gdb'):
            res = ex.execute(seq, ex.BASE / 'install' / (args.version + '-asan'),
                             root / ('%s-%d' % (obs, rep)), obs)
            _, steps, found = ex.observe(res, seq)
            runs.append(dict(observer=obs, repeat=rep,
                             outcome=[(s.get('a'), s.get('response'), bool(s.get('hung')))
                                      for s in steps],
                             signatures=sorted({f['sig'] for f in found})))
    by_obs = {o: sorted(json.dumps([r['outcome'], r['signatures']]) for r in runs
                        if r['observer'] == o) for o in ('none', 'gdb')}
    same = len(set(by_obs['none'] + by_obs['gdb'])) == 1
    report = dict(scope='diagnostic: observer effect', version=args.version, sequence=seq,
                  inputs=inputs, **provenance.provenance(), runs=runs,
                  outcomes_identical_across_observers=same)
    (root / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(out=str(root), citable=report['citable'],
                          identical=same, runs=runs), indent=2))
    return 0 if same else 2


if __name__ == '__main__':
    sys.exit(main())
