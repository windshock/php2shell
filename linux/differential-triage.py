#!/usr/bin/env python3
"""Phase 5 v2 Stage 4: differential triage, vulnerable vs fixed (plan §12.3).

For each sequence the same input runs on both versions (CLI server, gdb
state observer) and every step is compared on more than response/ASAN:

  failure site   normalized fatal location (producer landing)
  state          normalized request-owned state at php_request_startup
                 entry (ownership: null/fresh/carried, BG levels, PS ids)
  outcome        response class, ASAN signature, hang

The first step where the vulnerable run shows a memory error or hang is the
consumer; the classification says WHERE the fixed version stopped it:

  delivery_blocked      the producer's failure site is gone on the fixed build
  reset_inside_startup  carried state is still visible at startup entry on
                        the fixed build, yet nothing is consumed (an early
                        RINIT/MULTIPART_EVENT_START reset inside startup)
  residue_not_formed    the state the vulnerable consumer found carried is
                        already null/0 at the fixed producer's SHUTDOWN: the
                        producer unwound cleanly (e.g. fallible allocation +
                        delayed OOM, ZEND_HAS_OOM) - nothing was left to reset
  cleared_between       non-null at the fixed producer's shutdown but clean
                        at the consumer's startup entry
  state_not_carried     clean at consumer startup, producer shutdown unobserved
  NOT_FIXED             the fixed build shows the same error (alert)
  no_difference         neither version errs (negative control)

Positive controls are the known paths (Bug S, P16, P17 and the explorer's
minimal P17 variant); P15 (mod_php only) is classified by ground-truth.sh.
Exit: 0 = controls behave, 2 = a control misbehaves or NOT_FIXED.
Usage: differential-triage.py [--vuln 8.4.4] [--fixed 8.4.27] [--seqs FILE]
"""
import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location('lifecycle_explore', HERE / 'lifecycle-explore.py')
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)

DEFAULT = [
    dict(name='BugS_bg_serialize', control='positive', seq=dict(limit='8M', steps=[
        {'a': 'session'}, {'a': 'parse_oom'}, {'a': 'upload_cookie'}])),
    dict(name='P16_path_b', control='positive', seq=dict(limit='8M', steps=[
        {'a': 'parse_oom'}, {'a': 'upload_nofile'}])),
    dict(name='P17_path_c', control='positive', seq=dict(limit='16M', steps=[
        {'a': 'runtime_oom', 'mb': 14}, {'a': 'upload_small'}])),
    dict(name='P17_variant_explorer_min', control='positive', seq=dict(limit='16M', steps=[
        {'a': 'runtime_oom', 'mb': 14}, {'a': 'parse_oom'}])),
    dict(name='PathB_flock_deadlock', control='positive', seq=dict(limit='8M', steps=[
        {'a': 'parse_oom'}, {'a': 'parse_oom'}])),
    dict(name='negative_normal', control='negative', seq=dict(limit='16M', steps=[
        {'a': 'session'}, {'a': 'upload_small'}, {'a': 'unser_small'}])),
]


def run(seq, version, out):
    res = ex.execute(seq, ex.BASE / 'install' / (version + '-asan'), out, 'gdb')
    _, steps, _ = ex.observe(res, seq)
    shutdown = {}
    for st in res['states']:
        match = ex.re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'shutdown':
            shutdown[int(match.group(1))] = st
    return [dict(shutdown=shutdown.get(s.get('i')),i=s.get('i'), a=s.get('a'), response=s.get('response'),
                 failure_sites=s.get('failure_sites', []), state=s.get('state'),
                 asan=(s.get('asan') or {}).get('sig'), hung=bool(s.get('hung')),
                 harness_error=s.get('harness_error'))
            for s in steps]


def classify(vuln, fixed):
    consumer = next((s for s in vuln if s.get('asan') or s.get('hung')), None)
    if consumer is None:
        bad = next((s for s in fixed if s.get('asan') or s.get('hung')), None)
        return ('NOT_FIXED' if bad else 'no_difference'), None
    k = consumer['i']
    fixed_k = next((s for s in fixed if s['i'] == k), None)
    if fixed_k and (fixed_k.get('asan') == consumer.get('asan') and consumer.get('asan')
                    or (consumer.get('hung') and fixed_k.get('hung'))):
        return 'NOT_FIXED', k
    producer_v = [s for s in vuln if s['i'] < k and s['failure_sites']]
    producer_f = [s for s in fixed if s['i'] < k and s['failure_sites']]
    if producer_v and not producer_f:
        return 'delivery_blocked', k
    carried = lambda s: s and s.get('state') and 'carried' in s['state']  # noqa: E731
    if carried(fixed_k):
        return 'reset_inside_startup', k
    # Which fields did the vulnerable consumer find carried? Look at them
    # at the fixed producer's shutdown.
    fields = []
    for item in (consumer.get('state') or '').split(','):
        key, _, val = item.partition('=')
        if val == 'carried':
            fields.append(key)
        if key in ('ser', 'unser') and val not in ('0', ''):
            fields.append(key + '_level')
    prod = next((s for s in fixed if s['i'] == k - 1), None)
    shut = (prod or {}).get('shutdown')
    if not shut or not fields:
        return 'state_not_carried', k
    live = [f for f in fields if shut.get(f)]
    return ('residue_not_formed' if not live else 'cleared_between'), k


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--vuln', default='8.4.4')
    parser.add_argument('--fixed', default='8.4.27')
    parser.add_argument('--seqs', help='JSON list of {name, control, seq}')
    args = parser.parse_args()
    cases = json.loads(Path(args.seqs).read_text()) if args.seqs else DEFAULT
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = ex.BASE / 'evidence' / ('differential-triage-%s' % stamp)
    rows, problems = [], []
    for case in cases:
        vuln = run(case['seq'], args.vuln, root / case['name'] / args.vuln)
        fixed = run(case['seq'], args.fixed, root / case['name'] / args.fixed)
        verdict, k = classify(vuln, fixed)
        diff = []
        for v in vuln:
            f = next((x for x in fixed if x['i'] == v['i']), None)
            if f is None:
                diff.append(dict(i=v['i'], a=v['a'], fixed='not_reached'))
                continue
            fields = {key: (v[key], f[key]) for key in ('response', 'failure_sites', 'state',
                                                       'asan', 'hung') if v[key] != f[key]}
            levels = lambda st: st and {x: st.get(x) for x in (  # noqa: E731
                'ser_level', 'unser_level') if st.get(x)}
            if levels(v['shutdown']) != levels(f['shutdown']):
                fields['shutdown_levels'] = (levels(v['shutdown']), levels(f['shutdown']))
            if fields:
                diff.append(dict(i=v['i'], a=v['a'], **fields))
        rows.append(dict(name=case['name'], control=case.get('control'), verdict=verdict,
                         consumer_step=k, differences=diff))
        if verdict == 'NOT_FIXED':
            problems.append('%s: same error on %s' % (case['name'], args.fixed))
        if case.get('control') == 'positive' and verdict == 'no_difference':
            problems.append('%s: positive control did not reproduce on %s'
                            % (case['name'], args.vuln))
        if case.get('control') == 'negative' and verdict != 'no_difference':
            problems.append('%s: negative control reported %s' % (case['name'], verdict))
        if any(s.get('harness_error') for s in vuln + fixed):
            problems.append('%s: harness error' % case['name'])
    report = dict(scope='Stage 4 differential triage; observation only', vuln=args.vuln,
                  fixed=args.fixed, rows=rows, problems=problems, ok=not problems)
    root.mkdir(parents=True, exist_ok=True)
    (root / 'triage.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(rows=[dict(name=r['name'], verdict=r['verdict'],
                                     consumer_step=r['consumer_step']) for r in rows],
                          problems=problems, out=str(root)), indent=2))
    return 0 if not problems else 2


if __name__ == '__main__':
    sys.exit(main())
