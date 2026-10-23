#!/usr/bin/env python3
"""#4 H3 report: OFF vs state feedback over an explore-h3.sh root.

Per run: executions, integrity, fused steps (and how many returned
normally), new G/R/A keys, memory-error signatures. Per mode: totals and
hold-out rediscovery.

Hold-out rediscovery (docs/coreguard/holdout-v1.json) is matched on the
observable signature of each H2 reproduction, nothing broader:
  R46  ASAN report whose frames include php_var_serialize_intern
  R51  zend_mm_panic / zend_mm_get_next_free_slot (Zend heap check)
  R23  not ASAN-observable (GC stops); a G key is the same CLASS signal but
       cannot be attributed to R23, so it is reported as class_signal only.
Signatures that match no known record (hold-out, tuning R55, the CVE paths)
are listed as `unknown_local_only`: potential new findings that stay in the
local evidence tree (plan §11.2 D1) - never published from this report.

Usage: h3-report.py ROOT [--json OUT]
"""
import argparse
import collections
import json
import sys
from pathlib import Path

HOLDOUT_SIGS = {'R46': ('php_var_serialize_intern',),
                'R51': ('zend_mm_panic', 'zend_mm_get_next_free_slot')}
KNOWN_SIGS = {'R55 (tuning)': ('zend_gc_collect_cycles',),
              'P15/P17 path': ('php_var_unserialize', 'zend_hash'),
              'Path C / Bug S': ('php_session', 'ps_srlzr')}


def classify(sig):
    for rid, needles in HOLDOUT_SIGS.items():
        if any(n in sig for n in needles):
            return 'holdout:' + rid
    for name, needles in KNOWN_SIGS.items():
        if any(n in sig for n in needles):
            return 'known:' + name
    return 'unknown_local_only'


def run_stats(d):
    summary = json.loads((d / 'summary.json').read_text())
    execs = [json.loads(l) for l in (d / 'execs.jsonl').read_text().splitlines() if l.strip()]
    integ = collections.Counter(e.get('integrity') for e in execs if e.get('grammar_ok'))
    fused = completed = 0
    keys = collections.Counter()
    sigs = {}
    for e in execs:
        for st in e.get('steps', []):
            if st.get('a') == 'fused':
                fused += 1
                completed += bool(st.get('completed'))
            asan = st.get('asan')
            if st.get('oracle') == 'memory_error_confirmed' and asan:
                sigs.setdefault(asan['sig'], dict(first_exec=e['exec'], t=e['t'],
                                                  cls=classify(asan['sig'])))
        for k in e.get('new_keys', []):
            keys[k[0]] += 1
    return dict(run=d.name, feedback=summary.get('feedback'), seed=summary.get('seed'),
                execs=summary.get('execs'), integrity=dict(integ), fused_steps=fused,
                fused_completed=completed, new_keys=dict(keys),
                g_keys=sorted(k for e in execs for k in e.get('new_keys', []) if k[0] == 'G'),
                signatures=sigs)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('root', type=Path)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    runs = [run_stats(d) for d in sorted(args.root.iterdir())
            if d.is_dir() and (d / 'summary.json').exists()]
    modes = {}
    for r in runs:
        m = modes.setdefault(r['feedback'], dict(runs=0, execs=0, fused_steps=0,
                                                 fused_completed=0, G=0, R=0, A=0,
                                                 holdout=set(), unknown=set(), class_signal=0))
        m['runs'] += 1
        for f in ('execs', 'fused_steps', 'fused_completed'):
            m[f] += r[f] or 0
        for k in 'GRA':
            m[k] += r['new_keys'].get(k, 0)
        m['class_signal'] += bool(r['g_keys'])
        for sig, info in r['signatures'].items():
            if info['cls'].startswith('holdout:'):
                m['holdout'].add(info['cls'][8:])
            elif info['cls'] == 'unknown_local_only':
                m['unknown'].add(sig)
    for m in modes.values():
        m['holdout_rediscovered'] = sorted(m.pop('holdout'))
        m['unknown_local_only'] = len(m.pop('unknown'))
        m['runs_with_gc_class_signal'] = m.pop('class_signal')
    out = dict(root=str(args.root), runs=runs, modes=modes,
               note='unknown signatures: D1, local evidence only')
    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
    print(json.dumps(dict(modes=modes), indent=2))
    print('\n%-14s %-6s %5s %6s %5s %3s %3s %3s  signatures' %
          ('run', 'mode', 'execs', 'fused', 'compl', 'G', 'R', 'A'))
    for r in runs:
        print('%-14s %-6s %5s %6d %5d %3d %3d %3d  %s' % (
            r['run'], r['feedback'], r['execs'], r['fused_steps'], r['fused_completed'],
            r['new_keys'].get('G', 0), r['new_keys'].get('R', 0), r['new_keys'].get('A', 0),
            ', '.join('%s[%s]' % (v['cls'], k if not v['cls'].startswith('unknown') else 'redacted')
                      for k, v in r['signatures'].items()) or '-'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
