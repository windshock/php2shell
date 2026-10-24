#!/usr/bin/env python3
"""#6 P1 (first half, plan 15.1): OFFLINE read-only shadow statistics for
the frozen invariant_signals layer (docs/invariant-signals-prereg.md 1-2).

Applies the frozen stage definitions literally over existing campaign
evidence (observer STATE/EVENT + execs.jsonl only - no new observation):

I-GC  preconditions (v2): step k has an _zend_bailout EVENT and ended
      NORMALLY (completed or no failure_sites - the existing G-key
      predicate; v1 counted terminating fatals too, which always leave
      gc_protected set at the next pre-gc_reset startup - 274/274 on the
      2x2 corpus, a tautology; docs/invariant-signals-prereg.md v2 note);
      progress: the SAME worker pid shows gc_protected=1 at the STARTUP
      boundary of step k+1 (or an oom_while_gc_protected event at k);
      candidate: both. anomaly_no_bailout_protected counts next-startup
      protection WITHOUT a bailout event (event loss / shutdown bailout).
I-REQ preconditions: step k ended abnormally (failure_sites non-empty);
      progress: startup[k+1] (same pid) has request-owned residue
      (ser/unser level > 0, ps_id/ps_mod/ps_session_vars set, url_hosts>0);
      candidate: both.

Overlap statistics (frozen mapping section 2): I-GC candidates vs G: keys
in the same exec, I-REQ candidate steps vs H: keys in the same exec -
these decide the shadow extractor's replacement (never additive) rules.

Usage: invariant-shadow-stats.py <run_dir> [...] | --self-test
"""
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

_spec = importlib.util.spec_from_file_location('lexp', HERE / 'lifecycle-explore.py')
lexp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lexp)
BASE = Path('/home/phplab/php-lab')
STEP_RE = re.compile(r'[?&]step=(\d+)')
OWNED_POINTER_FIELDS = ('ps_id', 'ps_mod', 'ps_session_vars')


def parse_exec(exec_dir):
    """(startups, events_by_step, observer_status) from observer.log."""
    obs = exec_dir / 'observer.log'
    if not obs.exists():
        return {}, {}, 'gdb_missing'
    startups, events = {}, {}
    saw_state = False
    for line in obs.read_text(errors='replace').splitlines():
        if line.startswith('STATE '):
            saw_state = True
            try:
                st = json.loads(line[6:])
            except ValueError:
                continue
            m = STEP_RE.search(st.get('uri') or '')
            if m and st.get('tag') == 'startup':
                startups[int(m.group(1))] = st
        elif line.startswith('EVENT '):
            try:
                ev = json.loads(line[6:])
            except ValueError:
                continue
            m = STEP_RE.search(ev.get('uri') or '')
            if m:
                events.setdefault(int(m.group(1)), []).append(ev)
    return startups, events, ('gdb_ok' if saw_state else 'observer_error')


def shadow_one_exec(exec_dir, row):
    """Frozen stage evaluation for one exec; counts only, no rewards."""
    startups, events, status = parse_exec(exec_dir)
    out = dict(observer_status=status, definition='v2',
               igc=dict(preconditions=0, progress=0, candidate=0,
                        anomaly_no_bailout_protected=0),
               ireq=dict(preconditions=0, progress=0, candidate=0))
    if status != 'gdb_ok':
        return out
    steps = row.get('steps') or []
    by_idx = {s.get('i'): s for s in steps if isinstance(s, dict)}
    for k in sorted(set(events) | set(by_idx)):  # steps without events count too
        evs = events.get(k, [])
        step = by_idx.get(k)
        nxt = startups.get(k + 1)
        next_protected = (nxt is not None
                          and nxt.get('pid') == startups.get(k, {}).get('pid')
                          and nxt.get('gc_protected') == 1)
        # I-GC (v2): caught bailout + NORMAL return only
        bailout = any(e.get('name') == '_zend_bailout' for e in evs)
        if bailout and next_protected:
            ended_normally = step is not None and (
                step.get('completed') or not step.get('failure_sites'))
            if ended_normally:
                out['igc']['preconditions'] += 1
                oom_prot = any(e.get('name') == 'zend_mm_delayed_error'
                               and e.get('gc_protected') and not e.get('in_shutdown')
                               for e in evs)
                if next_protected or oom_prot:
                    out['igc']['progress'] += 1
                    out['igc']['candidate'] += 1
            # terminating fatal after bailout: expected engine state, not a
            # signal (v2 note) - no stage counted
        elif next_protected and not bailout:
            out['igc']['anomaly_no_bailout_protected'] += 1
        # I-REQ
        if step is not None and step.get('failure_sites'):
            out['ireq']['preconditions'] += 1
            if nxt is not None and nxt.get('pid') == startups.get(k, {}).get('pid'):
                residue = (nxt.get('ser_level', 0) > 0 or nxt.get('unser_level', 0) > 0
                           or any(nxt.get(f) for f in OWNED_POINTER_FIELDS)
                           or nxt.get('url_hosts', 0) > 0)
                if residue:
                    out['ireq']['progress'] += 1
                    out['ireq']['candidate'] += 1
    return out


def shadow_run(run_dir):
    run_dir = Path(run_dir)
    execs = {}
    jl = run_dir / 'execs.jsonl'
    if not jl.exists():
        return None
    for line in jl.read_text(errors='replace').splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        execs[r['exec']] = r
    per_exec, agg = {}, dict(
        observer=dict(gdb_ok=0, gdb_missing=0, observer_error=0),
        igc=dict(preconditions=0, progress=0, candidate=0,
                 anomaly_no_bailout_protected=0),
        ireq=dict(preconditions=0, progress=0, candidate=0),
        overlap=dict(igc_candidate_execs_with_G=0, ireq_candidate_execs_with_H=0,
                     execs_with_G=0, execs_with_H=0, igc_candidates=0,
                     ireq_candidates=0))
    for exec_dir in sorted(run_dir.glob('exec-*')):
        n = int(exec_dir.name.split('-')[1])
        row = execs.get(n)
        if row is None:
            continue
        res = shadow_one_exec(exec_dir, row)
        per_exec[n] = res
        agg['observer'][res['observer_status']] += 1
        for inv in ('igc', 'ireq'):
            for stage in res[inv]:
                agg[inv][stage] += res[inv][stage]
        keys = row.get('new_keys') or []
        has_g = any(isinstance(k, str) and k.startswith('G:') for k in keys)
        has_h = any(isinstance(k, str) and k.startswith('H:') for k in keys)
        agg['overlap']['execs_with_G'] += has_g
        agg['overlap']['execs_with_H'] += has_h
        agg['overlap']['igc_candidates'] += res['igc']['candidate']
        agg['overlap']['ireq_candidates'] += res['ireq']['candidate']
        agg['overlap']['igc_candidate_execs_with_G'] += bool(res['igc']['candidate'] and has_g)
        agg['overlap']['ireq_candidate_execs_with_H'] += bool(res['ireq']['candidate'] and has_h)
    return dict(run=run_dir.parent.name + '/' + run_dir.name, aggregate=agg)


def self_test():
    import tempfile
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    def snap(step, **kw):
        base = dict(tag='startup', pid=7, uri='/x?step=%d' % step, ser_level=0,
                    ser_data=0, unser_level=0, unser_data=0, lock=0, ps_id=0, ps_mod=0,
                    ps_status=1, ps_vars_type=0, ps_session_vars=0, url_hosts=0,
                    modules_activated=0, gc_enabled=1, gc_active=0, gc_protected=0,
                    gc_runs=0)
        base.update(kw)
        return base

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / 'exec-0000'
        d.mkdir()
        # step0: caught bailout + NORMAL end, next startup protected ->
        #        I-GC v2 candidate
        # step1: bailout + TERMINATING fatal (failure_sites), next startup
        #        protected -> expected engine state, NO I-GC stage (v2);
        #        abnormal end + ps residue -> I-REQ candidate
        # step2: no bailout, next startup protected -> anomaly class
        (d / 'observer.log').write_text(
            'STATE %s\n' % json.dumps(snap(0)) +
            'EVENT %s\n' % json.dumps(dict(name='_zend_bailout', uri='/x?step=0')) +
            'STATE %s\n' % json.dumps(snap(1, gc_protected=1)) +
            'EVENT %s\n' % json.dumps(dict(name='_zend_bailout', uri='/x?step=1')) +
            'STATE %s\n' % json.dumps(snap(2, gc_protected=1, ps_id=99)) +
            'STATE %s\n' % json.dumps(snap(3, gc_protected=1)))
        row = dict(exec=0, new_keys=[],
                   steps=[dict(i=0, response='s200', failure_sites=[]),
                          dict(i=1, response='s500', failure_sites=['oom']),
                          dict(i=2, response='s200', failure_sites=[])])
        r = shadow_one_exec(d, row)
        check('I-GC v2: normal-return bailout -> candidate, fatal excluded, anomaly counted',
              r['igc'] == dict(preconditions=1, progress=1, candidate=1,
                               anomaly_no_bailout_protected=1))
        check('I-REQ candidate (abnormal end + residue)', r['ireq'] == dict(
            preconditions=1, progress=1, candidate=1))
        check('definition marker v2', r['definition'] == 'v2')
        (d / 'observer.log').unlink()
        check('missing observer -> gdb_missing, zero stages',
              shadow_one_exec(d, row)['observer_status'] == 'gdb_missing')
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    runs = [a for a in sys.argv[1:] if not a.startswith('--')]
    if not runs:
        print('usage: invariant-shadow-stats.py <run_dir> [...]')
        return 2
    results = [r for r in (shadow_run(p) for p in runs) if r]
    out_dir = BASE / 'evidence' / ('invariant-shadow-%s' %
                                   time.strftime('%Y%m%dT%H%M%S', time.gmtime()))
    out_dir.mkdir(parents=True)
    summary = dict(scope='#6 P1 offline shadow statistics (read-only, frozen '
                   'definitions docs/invariant-signals-prereg.md 1-2)',
                   runs=results, **provenance.provenance())
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2))
    tot = dict(igc=dict(preconditions=0, progress=0, candidate=0,
                        anomaly_no_bailout_protected=0),
               ireq=dict(preconditions=0, progress=0, candidate=0),
               overlap=dict(igc_candidate_execs_with_G=0, ireq_candidate_execs_with_H=0,
                            execs_with_G=0, execs_with_H=0, igc_candidates=0,
                            ireq_candidates=0))
    for r in results:
        for inv in ('igc', 'ireq'):
            for st in tot[inv]:
                tot[inv][st] += r['aggregate'][inv][st]
        for k in tot['overlap']:
            tot['overlap'][k] += r['aggregate']['overlap'][k]
    print(json.dumps(dict(out=str(out_dir), totals=tot, runs=len(results),
                          citable=summary['citable']), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
