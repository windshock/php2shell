#!/usr/bin/env python3
"""Fail-closed verdicts shared by lifecycle-explore.py (replay), flowfusion-
bridge.py and differential-triage.py (issue #5 P0 items 1, 2, 9; plan §13.3).

A run that did not reach what it claims to test is never success, clean or
extinct. Every verdict below first establishes execution integrity:

  harness_failed   the harness raised (server start, binary missing, ...)
  inconclusive     the run executed but its observer is missing/incomplete
  not_reached      fewer steps executed than planned, with no in-run cause
                   (memory error, hang, process lost) that explains the stop
  executed         every planned step ran, or the run legitimately ended
                   at a step that produced the memory error / hang / loss

Only `executed` runs feed the higher verdicts.

Usage: verdicts.py --self-test
"""
import json
import re
import sys

# ------------------------------------------------------------ integrity


def integrity(seq, steps, states=None, observer='gdb'):
    """seq: planned sequence; steps: observe()'d steps; states: raw gdb
    STATE records (startup/shutdown) when the gdb observer ran."""
    planned = len(seq.get('steps', []))
    harness = next((s['harness_error'] for s in steps if 'harness_error' in s), None)
    executed = [s for s in steps if 'i' in s]
    last = executed[-1] if executed else None
    ended_by = None
    if last is not None:
        if last.get('asan'):
            ended_by = 'memory_error'
        elif last.get('hung'):
            ended_by = 'hang'
        elif last.get('alive_after') is False:
            ended_by = 'process_lost'
        elif last.get('ended_by_probe'):
            ended_by = 'probe'
    startups = set()
    for st in states or []:
        match = re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'startup':
            startups.add(int(match.group(1)))
    # A request aborted mid-upload never reaches php_request_startup, so it
    # legitimately has no startup record (it is not an observer failure).
    observed_ok = (observer != 'gdb') or all(
        s['i'] in startups or s.get('response') in ('aborted', 'reset') for s in executed)
    complete = len(executed) == planned
    if harness:
        status = 'harness_failed'
    elif not executed:
        status = 'not_reached'
    elif not observed_ok:
        status = 'inconclusive'
    elif not complete and ended_by is None:
        status = 'not_reached'
    else:
        status = 'executed'
    return dict(status=status, planned=planned, executed=len(executed),
                ended_by=ended_by, harness_error=harness, observer_ok=observed_ok)


def sigs(steps):
    return {s['asan']['sig'] if isinstance(s.get('asan'), dict) else s.get('asan')
            for s in steps if s.get('asan')}


def _sig(step):
    asan = step.get('asan')
    return asan.get('sig') if isinstance(asan, dict) else asan


# ------------------------------------------------- replay differential (#5-1)


def differential(target, vuln_steps, vuln_int, fixed_steps, fixed_int):
    """Fixed-version verdict for a target signature reproduced on the
    vulnerable version. extinct is true ONLY with a verified run AND an
    observed block point."""
    out = dict(target=target, vuln_integrity=vuln_int['status'],
               fixed_integrity=fixed_int['status'], extinct=False, evidence=[],
               new_memory_errors=[])
    k = next((s['i'] for s in vuln_steps if 'i' in s and _sig(s) == target), None)
    if vuln_int['status'] != 'executed' or k is None:
        out['verdict'] = 'inconclusive'
        out['reason'] = 'target not reproduced on the vulnerable run'
        return out
    if fixed_int['status'] in ('harness_failed', 'inconclusive'):
        out['verdict'] = fixed_int['status']
        return out
    fixed_k = next((s for s in fixed_steps if s.get('i') == k), None)
    found = sigs(fixed_steps)
    out['new_memory_errors'] = sorted(x for x in found if x != target)
    if target in found:
        out['verdict'] = 'reproduced'
        return out
    if fixed_k is None:
        out['verdict'] = 'not_reached'
        out['reason'] = 'fixed run never executed the consumer step %d' % k
        return out
    vuln_k = next(s for s in vuln_steps if s.get('i') == k)
    prod_v = [x for s in vuln_steps if s.get('i', 99) < k for x in s.get('failure_sites', [])]
    prod_f = [x for s in fixed_steps if s.get('i', 99) < k for x in s.get('failure_sites', [])]
    if prod_v and not prod_f:
        out['evidence'].append('producer_failure_site_absent')
    carried = lambda st: bool(st) and ('carried' in st or re.search(r'(^|,)(un)?ser=[12]', st))  # noqa: E731
    v_state, f_state = vuln_k.get('state'), fixed_k.get('state')
    if carried(v_state) and f_state not in (None, 'unobserved', 'observer_error') \
            and not carried(f_state):
        out['evidence'].append('carried_state_absent_at_consumer_start')
    if out['evidence']:
        out['verdict'] = 'extinct_at_verified_block_point'
        out['extinct'] = True
    else:
        out['verdict'] = 'inconclusive'
        out['reason'] = 'target absent but no observed block point'
    return out


# ------------------------------------------------- FlowFusion taxonomy (#5-2)

CONSUMER_STEPS = 3


def flowfusion(gen_ok, steps, states, log_text):
    """Three axes: generation, request 0, consumers; then the summary."""
    res = dict(generation='generated' if gen_ok else 'not_generated')
    if not gen_ok:
        res.update(request0='not_applicable', consumers='not_applicable',
                   verdict='not_generated')
        return res
    harness = next((s['harness_error'] for s in steps if 'harness_error' in s), None)
    executed = {s['i']: s for s in steps if 'i' in s}
    startups = set()
    for st in states or []:
        match = re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'startup':
            startups.add(int(match.group(1)))
    if harness and not executed:
        res.update(request0='server_start_failed', consumers='not_applicable',
                   verdict='harness_failed', harness_error=harness)
        return res
    if 0 not in startups:
        res['request0'] = 'request0_not_executed'
    elif re.search(r'PHP Parse error', log_text or ''):
        res['request0'] = 'program_compile_error'
    elif re.search(r'PHP Fatal error', log_text or ''):
        res['request0'] = 'program_runtime_fatal'   # valid exploration case
    elif executed.get(0, {}).get('response', '').startswith('error'):
        res['request0'] = 'request0_timeout'
    else:
        res['request0'] = 'program_completed'
    consumers_seen = all(i in startups for i in range(1, CONSUMER_STEPS + 1))
    ended_early = any(s.get('asan') or s.get('alive_after') is False for s in executed.values())
    res['consumers'] = ('consumers_observed' if consumers_seen else
                        'ended_by_memory_error' if ended_early else 'consumer_incomplete')
    found = sigs(steps)
    violations = any(s.get('violations') for i, s in executed.items() if i > 0)
    if harness:
        res['verdict'] = 'harness_failed'
        res['harness_error'] = harness
    elif res['request0'] in ('request0_not_executed', 'request0_timeout'):
        res['verdict'] = 'not_reached'
    elif found:
        step0 = any(_sig(s) for i, s in executed.items() if i == 0)
        res['verdict'] = 'intra_request' if step0 else 'cross_request'
        res['signatures'] = sorted(found)
    elif res['consumers'] != 'consumers_observed':
        res['verdict'] = 'consumer_incomplete'
    elif violations:
        res['verdict'] = 'carried_state'
    else:
        res['verdict'] = 'clean'
    res['lifecycle_observed'] = res['verdict'] in ('clean', 'carried_state', 'cross_request',
                                                  'intra_request')
    res['program_executed'] = res['request0'] in ('program_completed', 'program_runtime_fatal')
    return res


# ------------------------------------------------- triage evidence (#5-9)


def triage(vuln_steps, vuln_int, fixed_steps, fixed_int, fixed_events, vuln_events=None):
    """observed_outcome / observed_state_at_shutdown / inferred_fix_mechanism
    / verified_block_point (needs a recorded instrumentation event)."""
    row = dict(vuln_integrity=vuln_int['status'], fixed_integrity=fixed_int['status'])
    consumer = next((s for s in vuln_steps if 'i' in s and (s.get('asan') or s.get('hung'))),
                    None)
    if vuln_int['status'] != 'executed' or fixed_int['status'] != 'executed':
        bad = vuln_int['status'] if vuln_int['status'] != 'executed' else fixed_int['status']
        row['verdict'] = bad
        return row
    found_f = sigs(fixed_steps)
    if consumer is None:
        row['verdict'] = 'no_difference' if not found_f and not any(
            s.get('hung') for s in fixed_steps) else 'NEW_MEMORY_ERROR'
        row['new_memory_errors'] = sorted(found_f)
        return row
    k = consumer['i']
    fixed_k = next((s for s in fixed_steps if s.get('i') == k), None)
    target = _sig(consumer)
    row['consumer_step'] = k
    row['new_memory_errors'] = sorted(x for x in found_f if x != target)
    if (target and target in found_f) or (consumer.get('hung') and fixed_k and fixed_k.get('hung')):
        row['verdict'] = 'NOT_FIXED'
        return row
    if fixed_k is None:
        row['verdict'] = 'not_reached'
        return row
    shut = (next((s for s in fixed_steps if s.get('i') == k - 1), {}) or {}).get('shutdown')
    levels = {x: (shut or {}).get(x) for x in ('ser_level', 'unser_level')}
    pointers = {x: (shut or {}).get(x) for x in ('ser_data', 'unser_data', 'ps_id', 'ps_mod')}
    row['observed_state_at_shutdown'] = (
        'unobserved' if not shut else
        'absent_at_observed_shutdown' if not any(levels.values()) and not any(
            pointers.values()) else 'present_at_observed_shutdown')
    prod_v = any(s.get('failure_sites') for s in vuln_steps if s.get('i', 99) < k)
    prod_f = any(s.get('failure_sites') for s in fixed_steps if s.get('i', 99) < k)
    row['observed_outcome'] = ('producer_failure_absent' if prod_v and not prod_f else
                               'consumer_ran_without_error')
    # Mechanism stays an inference unless an instrumentation event shows it.
    # Destroy events also fire in ordinary requests, so only a DIFFERENTIAL
    # counts: the fixed producer step destroys a context more often than the
    # vulnerable producer step (whose fatal skipped that destroy).
    def count(events, name, step):
        return sum(1 for e in events or [] if e.get('name') == name
                   and re.search(r'step=%d\b' % step, e.get('uri') or ''))
    gained = [name for name in ('php_var_unserialize_destroy', 'php_var_serialize_destroy')
              if count(fixed_events, name, k - 1) > count(vuln_events, name, k - 1)]
    row['producer_destroy_differential'] = gained
    if gained and vuln_events is not None:
        row['verified_block_point'] = 'producer_context_destroyed'
    elif (count(fixed_events, 'php_basic_early_rinit', k)
          and row['observed_state_at_shutdown'] == 'present_at_observed_shutdown'):
        row['verified_block_point'] = 'early_rinit_reset'
    else:
        row['verified_block_point'] = None
    row['inferred_fix_mechanism'] = (
        'producer unwinds cleanly (fallible alloc + delayed OOM)'
        if row['observed_state_at_shutdown'] == 'absent_at_observed_shutdown' else
        'reset between requests' if row['observed_state_at_shutdown'] ==
        'present_at_observed_shutdown' else 'unknown')
    row['verdict'] = 'extinct'
    row['status'] = 'validated' if row['verified_block_point'] else 'inferred'
    return row


# ---------------------------------------------------------------- fixtures


def self_test():
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    seq2 = dict(steps=[{'a': 'runtime_oom'}, {'a': 'upload_small'}])
    st = lambda i: [dict(tag='startup', uri='/x?step=%d' % i)]  # noqa: E731
    target = 'heap-use-after-free:tmp_var'
    vuln = [dict(i=0, a='runtime_oom', failure_sites=['oom@index.php:31'], state='ser=0,unser=0',
                 response='s500', alive_after=True),
            dict(i=1, a='upload_small', failure_sites=[], state='ser=0,unser=1,unser_data=carried',
                 asan=dict(sig=target), response='no_status', alive_after=False)]
    v_int = integrity(seq2, vuln, st(0) + st(1))
    check('vulnerable run integrity executed (ended by memory error)',
          v_int['status'] == 'executed' and v_int['ended_by'] == 'memory_error')
    seq3 = dict(steps=[{'a': 'abort_upload'}, {'a': 'runtime_oom'}, {'a': 'upload_small'}])
    aborted = [dict(i=0, a='abort_upload', response='aborted', alive_after=True),
               dict(vuln[0], i=1), dict(vuln[1], i=2)]
    check('aborted upload without a startup record is not an observer failure',
          integrity(seq3, aborted, st(1) + st(2))['status'] == 'executed')
    check('completed request without a startup record is an observer failure',
          integrity(seq3, [dict(aborted[0], response='s200')] + aborted[1:],
                    st(1) + st(2))['status'] == 'inconclusive')
    good_fixed = [dict(i=0, a='runtime_oom', failure_sites=['oom@index.php:31'],
                       state='ser=0,unser=0', response='s500', alive_after=True),
                  dict(i=1, a='upload_small', failure_sites=[], state='ser=0,unser=0',
                       response='s200', alive_after=True)]
    d = differential(target, vuln, v_int, good_fixed, integrity(seq2, good_fixed, st(0) + st(1)))
    check('fixed verified run with clean consumer start -> extinct',
          d['extinct'] and d['verdict'] == 'extinct_at_verified_block_point')
    # 1. fixed binary missing / start failure
    bad = [dict(harness_error='server/observer exited during startup')]
    d = differential(target, vuln, v_int, bad, integrity(seq2, bad, []))
    check('fixed start failure -> harness_failed, extinct=false',
          not d['extinct'] and d['verdict'] == 'harness_failed')
    # 2. consumer not executed
    short = good_fixed[:1]
    d = differential(target, vuln, v_int, short, integrity(seq2, short, st(0)))
    check('fixed consumer not executed -> not_reached, extinct=false',
          not d['extinct'] and d['verdict'] == 'not_reached')
    # 3. observer failure
    d = differential(target, vuln, v_int, good_fixed, integrity(seq2, good_fixed, []))
    check('fixed observer missing -> inconclusive, extinct=false',
          not d['extinct'] and d['verdict'] == 'inconclusive')
    # 4. absent target but no block evidence (consumer state unobserved)
    nob = [dict(good_fixed[0]), dict(good_fixed[1], state='unobserved')]
    d = differential(target, vuln, v_int, nob, integrity(seq2, nob, st(0) + st(1), observer='none'))
    check('absent target without block evidence -> inconclusive',
          not d['extinct'] and d['verdict'] == 'inconclusive')
    # 5. different ASAN on fixed
    other = [dict(good_fixed[0]), dict(good_fixed[1], asan=dict(sig='heap-buffer-overflow:x'),
                                       alive_after=False)]
    d = differential(target, vuln, v_int, other, integrity(seq2, other, st(0) + st(1)))
    check('different ASAN on fixed is reported as new memory error',
          d['new_memory_errors'] == ['heap-buffer-overflow:x'])

    # FlowFusion
    four = st(0) + st(1) + st(2) + st(3)
    ok_steps = [dict(i=i, response='s200', alive_after=True) for i in range(4)]
    f = flowfusion(True, ok_steps, four, '')
    check('FF completed + consumers observed -> clean', f['verdict'] == 'clean')
    f = flowfusion(True, [dict(i=0, response='s500', alive_after=True)] + ok_steps[1:], four,
                   'PHP Fatal error:  Uncaught Error: Interface "R" not found in x on line 3')
    check('FF runtime fatal 500 with consumers -> clean and program_executed',
          f['verdict'] == 'clean' and f['request0'] == 'program_runtime_fatal'
          and f['program_executed'])
    f = flowfusion(True, ok_steps, four, 'PHP Parse error:  syntax error, unexpected x')
    check('FF parse error -> program_compile_error, not program_executed',
          f['request0'] == 'program_compile_error' and not f['program_executed'])
    f = flowfusion(True, [dict(harness_error='startup timeout')], [], '')
    check('FF server not started -> harness_failed', f['verdict'] == 'harness_failed')
    f = flowfusion(True, ok_steps[:1], st(1), '')
    check('FF request 0 not executed -> not_reached', f['verdict'] == 'not_reached')
    f = flowfusion(False, [], [], '')
    check('FF generator failure -> not_generated', f['verdict'] == 'not_generated')
    f = flowfusion(True, ok_steps[:1], st(0), '')
    check('FF consumers not run -> consumer_incomplete', f['verdict'] == 'consumer_incomplete')

    # Triage
    seq = dict(steps=[{'a': 'p'}, {'a': 'c'}])
    tv = [dict(vuln[0], shutdown=dict(unser_level=1, unser_data=5)), dict(vuln[1])]
    tf = [dict(good_fixed[0], shutdown=dict(unser_level=0, unser_data=0)), dict(good_fixed[1])]
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf, integrity(seq, tf, st(0) + st(1)), [])
    check('triage without events -> inferred, absent_at_observed_shutdown',
          t['status'] == 'inferred' and t['observed_state_at_shutdown'] ==
          'absent_at_observed_shutdown' and t['verified_block_point'] is None)
    ev = [dict(name='php_var_unserialize_destroy', uri='/unserialize?step=0')]
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf, integrity(seq, tf, st(0) + st(1)),
               ev, vuln_events=[])
    check('triage destroy only on fixed producer -> validated', t['status'] == 'validated')
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf, integrity(seq, tf, st(0) + st(1)),
               ev, vuln_events=ev)
    check('triage destroy on both sides (ordinary request) -> inferred',
          t['status'] == 'inferred')
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf, integrity(seq, tf, st(0) + st(1)), ev)
    check('triage without vulnerable events -> inferred', t['status'] == 'inferred')
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf[:1], integrity(seq, tf[:1], st(0)), [])
    check('triage fixed consumer skipped -> not_reached', t['verdict'] == 'not_reached')
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), bad, integrity(seq, bad, []), [])
    check('triage fixed start failure -> harness_failed', t['verdict'] == 'harness_failed')
    tf2 = [dict(tf[0]), dict(tf[1], asan=dict(sig='heap-buffer-overflow:y'), alive_after=False)]
    t = triage(tv, integrity(seq, tv, st(0) + st(1)), tf2, integrity(seq, tf2, st(0) + st(1)), [])
    check('triage different ASAN on fixed recorded', t['new_memory_errors'] == [
        'heap-buffer-overflow:y'])
    both_bad = triage(bad, integrity(seq, bad, []), bad, integrity(seq, bad, []), [])
    check('triage both sides harness failure -> harness_failed',
          both_bad['verdict'] == 'harness_failed')
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        sys.exit(self_test())
    print(__doc__)
