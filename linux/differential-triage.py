#!/usr/bin/env python3
"""Phase 5 v2 Stage 4: differential triage, vulnerable vs fixed (plan §12.3,
fail-closed per issue #5-9 / plan §13.3).

For each sequence the same input runs on both versions (CLI server, gdb
state + event observer). Before any classification both runs must pass the
execution-integrity check (verdicts.integrity): a harness failure, a step
that never ran or a missing observer yields harness_failed / not_reached /
inconclusive - never a block verdict.

Per sequence the report keeps separate columns:
  observed_outcome            producer_failure_absent | consumer_ran_without_error
  observed_state_at_shutdown  absent_at_observed_shutdown |
                              present_at_observed_shutdown | unobserved
  inferred_fix_mechanism      a hypothesis from the patch source, never a fact
  verified_block_point        only from an instrumentation EVENT differential:
                              the fixed producer step destroys an (un)serialize
                              context that the vulnerable producer skipped
                              (destroy events also fire in ordinary requests,
                              so presence alone is not evidence) - else null
  status                      validated (event-backed) | inferred
and every ASAN on the fixed build: the same signature is NOT_FIXED, any
other is NEW_MEMORY_ERROR.

Positive controls: Bug S, P16, P17, the explorer's minimal P17 variant, the
Path B flock deadlock; negative control: a normal sequence. P15 (mod_php
only) is classified by ground-truth.sh.
Exit: 0 = controls behave, 2 = control misbehaves / NOT_FIXED /
NEW_MEMORY_ERROR / integrity failure.
Usage: differential-triage.py [--vuln 8.4.4] [--fixed 8.4.27] [--seqs FILE]
"""
import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location('lifecycle_explore', HERE / 'lifecycle-explore.py')
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)
import verdicts  # noqa: E402

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
        match = re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'shutdown':
            shutdown[int(match.group(1))] = st
    rows = []
    for s in steps:
        rows.append(dict(s, shutdown=shutdown.get(s.get('i')),
                         asan=(s.get('asan') or {}).get('sig') if isinstance(s.get('asan'), dict)
                         else s.get('asan')))
    integ = verdicts.integrity(seq, steps, res['states'], 'gdb')
    return rows, integ, res.get('events', [])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--vuln', default='8.4.4')
    parser.add_argument('--fixed', default='8.4.27')
    parser.add_argument('--seqs', help='JSON list of {name, control, seq}')
    args = parser.parse_args()
    cases = json.loads(Path(args.seqs).read_text()) if args.seqs else DEFAULT
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    run_id = 'triage-%s-%s-%s' % (stamp, args.vuln, args.fixed)
    root = ex.BASE / 'evidence' / ('differential-triage-%s' % stamp)
    rows, problems = [], []
    for case in cases:
        vuln, v_int, v_events = run(case['seq'], args.vuln, root / case['name'] / args.vuln)
        fixed, f_int, f_events = run(case['seq'], args.fixed, root / case['name'] / args.fixed)
        row = verdicts.triage(vuln, v_int, fixed, f_int, f_events, vuln_events=v_events)
        row.update(name=case['name'], control=case.get('control'),
                   fixed_events=sorted({e.get('name') for e in f_events}),
                   vuln_integrity_detail=v_int, fixed_integrity_detail=f_int)
        rows.append(row)
        verdict = row['verdict']
        if verdict in ('harness_failed', 'not_reached', 'inconclusive',
                       'integrity_failed'):
            problems.append('%s: integrity %s' % (case['name'], verdict))
        if verdict == 'target_absent_new_memory_error':
            problems.append('%s: target vanished but NEW_MEMORY_ERROR on %s '
                            '(overall %s)' % (case['name'], args.fixed,
                                              row.get('overall_patch_verdict')))
        if verdict == 'NOT_FIXED':
            problems.append('%s: same error on %s' % (case['name'], args.fixed))
        if row.get('new_memory_errors') and verdict != 'target_absent_new_memory_error':
            problems.append('%s: NEW_MEMORY_ERROR on %s: %s'
                            % (case['name'], args.fixed, row['new_memory_errors']))
        if case.get('control') == 'positive' and verdict == 'no_difference':
            problems.append('%s: positive control did not reproduce on %s'
                            % (case['name'], args.vuln))
        if case.get('control') == 'negative' and verdict != 'no_difference':
            problems.append('%s: negative control reported %s' % (case['name'], verdict))
    report = dict(scope='Stage 4 differential triage (fail-closed); observation only',
                  run_id=run_id, vuln=args.vuln, fixed=args.fixed, rows=rows,
                  problems=problems, ok=not problems)
    root.mkdir(parents=True, exist_ok=True)
    (root / 'triage.json').write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(dict(run_id=run_id, rows=[dict(
        name=r['name'], verdict=r['verdict'], status=r.get('status'),
        observed_state_at_shutdown=r.get('observed_state_at_shutdown'),
        verified_block_point=r.get('verified_block_point'),
        fixed_events=r['fixed_events']) for r in rows],
        problems=problems, out=str(root)), indent=2))
    return 0 if not problems else 2


if __name__ == '__main__':
    sys.exit(main())
