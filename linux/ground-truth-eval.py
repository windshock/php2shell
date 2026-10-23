#!/usr/bin/env python3
"""Phase 5 v2 Stage 0 evaluator for the P15/P16/P17 ground-truth set.

Split out of ground-truth.sh (issue #1 follow-up, plan §12.6 R1) so the
verdict rules can be exercised by fixtures (--self-test). For every path it
records, per version:

  input_valid      the trigger input had the intended shape (size, limits,
                   working session lab) - otherwise nothing was tested
  reached          the request was actually processed by PHP
  error_triggered  the fatal/OOM the path needs occurred where expected
  memory_error     the memory error itself (teardown consumption / UAF)
  block_point      fixed versions only: WHERE the patch stopped the path
                   (delivery_blocked / consumption_removed / consumption_absent)

A fixed version passes only with input_valid AND reached AND a classified
block_point AND no memory error: "no memory error" alone is not extinction.

Inputs are named explicitly by the caller and must carry the caller's
run_id and version - results are never discovered by mtime.

Exit codes: 0 = all expectations met, 2 = expectation not met,
1 = harness failure (missing/foreign result, unexpected runner exit code).
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

FIXED_VERSIONS = ('8.4.27', '8.5.12')
P15_INPUT = dict(parts=1000, nest=8, seg_pad=300, memory_limit='32M')
P17_LIMIT_BYTES = 16 * 1024 * 1024


class Harness(Exception):
    """Evidence cannot be attributed to this run: harness failure."""


def load(name, path, run_id, version):
    try:
        data = json.loads(Path(path).read_text())
    except Exception as exc:
        raise Harness('%s: result unreadable (%s)' % (name, exc))
    if data.get('run_id') != run_id:
        raise Harness('%s: foreign result (run_id %r, expected %r)'
                      % (name, data.get('run_id'), run_id))
    if data.get('version') != version:
        raise Harness('%s: result is for version %r, expected %r'
                      % (name, data.get('version'), version))
    return data


def eval_p15(summary, expect):
    entries = summary.get('entries', [])
    crash = [e for e in entries if str(e.get('label', '')).startswith('crash')]
    control = next((e for e in entries if e.get('label') == 'control'), None)
    bad = [e for e in entries if e.get('status') in ('runner_failed', 'foreign_result',
                                                     'start_failed')]
    if bad:
        raise Harness('P15: matrix entries failed: %s' % [e.get('label') for e in bad])
    if not crash or control is None:
        raise Harness('P15: crash or control entry missing')
    rows, problems = [], []
    for e in crash:
        inp = e.get('input') or {}
        input_valid = (all(inp.get(k) == v for k, v in P15_INPUT.items())
                       and (inp.get('body_bytes') or 0) > 0)
        oom = bool(e.get('oom_logged'))
        row = dict(path='P15_path_a', label=e.get('label'), input_valid=input_valid,
                   reached=bool(oom or e.get('script_reached')),
                   error_triggered=bool(oom and e.get('oom_tried_bytes') is not None),
                   memory_error=e.get('verdict') == 'fatal_and_teardown_memory_error',
                   verdict=e.get('verdict'), teardown_frames=e.get('teardown_frames'))
        if expect == 'reproduce':
            row['expectation_met'] = (input_valid and row['reached']
                                      and row['error_triggered'] and row['memory_error'])
        else:
            block = None
            if not oom and e.get('script_reached'):
                block = 'delivery_blocked'      # parser stopped before the limit
            elif oom and e.get('verdict') == 'fatal_only':
                block = 'consumption_removed'   # fatal still lands, no consumption
            row['block_point'] = block
            row['expectation_met'] = (input_valid and row['reached'] and block is not None
                                      and not row['memory_error'])
        if not row['expectation_met']:
            problems.append('P15 %s: expectation %s not met: %s' % (e.get('label'), expect, row))
        rows.append(row)
    # Differential control: on a vulnerable build the 28M crossing must land
    # before nNumUsed++ (56B _zend_new_array) and must not crash.
    if expect == 'reproduce':
        control_ok = (control.get('verdict') == 'fatal_only'
                      and control.get('pre_counter_crossing') is True)
    else:
        control_ok = control.get('verdict') != 'fatal_and_teardown_memory_error'
    if not control_ok:
        problems.append('P15 control: %s' % control)
    rows.append(dict(path='P15_control', verdict=control.get('verdict'),
                     pre_counter_crossing=control.get('pre_counter_crossing'),
                     expectation_met=control_ok))
    return rows, problems


def eval_p16(summary, expect):
    entries = summary.get('entries', [])
    bad = [e for e in entries if e.get('status') in ('runner_failed', 'foreign_result',
                                                     'start_failed')]
    if bad or not entries:
        raise Harness('P16: matrix entries failed or missing: %s' % bad)
    rows, problems = [], []
    for e in entries:
        rec = e.get('record') or {}
        oom = bool(rec.get('oom_logged'))
        alive_a = rec.get('worker_alive_after_a') is True
        # On a reproduction B aborts the process mid-request (no status, not
        # always a reset); its ASAN report - already restricted by poc-pathb
        # to this iteration's window - is then the evidence that B ran.
        consumer_ran = (rec.get('request_b_status') is not None
                        or bool(rec.get('request_b_connection_reset'))
                        or rec.get('asan') is not None)
        row = dict(path='P16_path_b', iteration=e.get('iteration'),
                   input_valid=rec.get('session_roundtrip_ok') is True,
                   reached=rec.get('request_a_status') is not None,
                   error_triggered=oom, worker_survived_a=alive_a,
                   consumer_ran=consumer_ran,
                   memory_error=rec.get('result') == 'path_b_reproduced')
        base = row['input_valid'] and row['reached'] and oom and alive_a and consumer_ran
        if expect == 'reproduce':
            row['expectation_met'] = base and row['memory_error']
        else:
            # The producer still fatals on the fixed build and the consumer
            # runs without consuming anything. WHY (residue never formed vs a
            # reset) is not observable here - differential-triage.py shows
            # residue_not_formed (findings §10.11), so the label stays neutral.
            row['block_point'] = ('consumption_absent' if base and rec.get('asan') is None
                                  else None)
            row['expectation_met'] = (base and row['block_point'] is not None
                                      and not row['memory_error'])
        if not row['expectation_met']:
            problems.append('P16 iter %s: expectation %s not met: %s'
                            % (e.get('iteration'), expect, row))
        rows.append(row)
    return rows, problems


def eval_p17(summary, expect):
    runs = summary.get('runs', [])
    if not runs:
        raise Harness('P17: no runs in summary')
    rows, problems = [], []
    for run in runs:
        limit = run.get('oom_limit_bytes')
        row = dict(path='P17_path_c', iteration=run.get('iteration'),
                   input_valid=limit == P17_LIMIT_BYTES,
                   effective_limit_bytes=limit,
                   reached=run.get('request_a_status') is not None,
                   error_triggered=bool(run.get('fatal_in_unserialize')),
                   worker_survived_a=run.get('worker_survived_a') is True,
                   consumer_ran=run.get('request_b_status') is not None
                   or run.get('result') == 'path_c_reproduced',
                   memory_error=run.get('result') == 'path_c_reproduced')
        base = (row['input_valid'] and row['reached'] and row['error_triggered']
                and row['worker_survived_a'] and row['consumer_ran'])
        if expect == 'reproduce':
            row['expectation_met'] = base and row['memory_error']
        else:
            # Mechanism attribution: see differential-triage.py (the fixed
            # unserializer unwinds via fallible allocation; no residue).
            row['block_point'] = ('consumption_absent' if base and run.get('asan') is None
                                  and run.get('result') == 'no_uaf_observed' else None)
            row['expectation_met'] = (base and row['block_point'] is not None
                                      and not row['memory_error'])
        if not row['expectation_met']:
            problems.append('P17 iter %s: expectation %s not met: %s'
                            % (run.get('iteration'), expect, row))
        rows.append(row)
    return rows, problems


def evaluate(args):
    expect = 'extinct' if args.version in FIXED_VERSIONS else 'reproduce'
    rows, problems, harness = [], [], []
    # Matrix runners already fold the version expectation into their exit
    # code (0 = met). poc-pathc exits 1 when it did not reproduce.
    pathc_ok_rc = 0 if expect == 'reproduce' else 1
    specs = (('P15', args.patha, args.patha_rc, 0, eval_p15),
             ('P16', args.pathb, args.pathb_rc, 0, eval_p16),
             ('P17', args.pathc, args.pathc_rc, pathc_ok_rc, eval_p17))
    for name, path, rc, ok_rc, fn in specs:
        try:
            # Runners exit 0/1 by design; anything else (traceback-free
            # crash, signal, timeout) means the run cannot be trusted.
            if rc not in (0, 1):
                raise Harness('%s: runner exit code %s' % (name, rc))
            summary = load(name, path, args.run_id, args.version)
            if rc != ok_rc:
                problems.append('%s: runner exit %d, expected %d for %s'
                                % (name, rc, ok_rc, expect))
            r, p = fn(summary, expect)
            rows.extend(r)
            problems.extend(p)
        except Harness as exc:
            harness.append(str(exc))
    result = dict(scope='Phase 5 v2 Stage 0 ground-truth regression',
                  run_id=args.run_id, version=args.version, expectation=expect,
                  paths=rows, harness_failures=harness, problems=problems,
                  ok=not harness and not problems,
                  metrics_definitions=dict(
                      input_valid='trigger input had the intended shape/limits',
                      reached='trigger request processed by PHP',
                      error_triggered='the required fatal/OOM occurred at the expected place',
                      memory_error='ASAN-confirmed memory error attributed to the path',
                      block_point='fixed versions: where the patch stopped the path'))
    code = 1 if harness else 2 if problems else 0
    return result, code


# ---------------------------------------------------------------- self-test
def _fixtures(run_id, version):
    vuln = version not in FIXED_VERSIONS
    crash = dict(label='crash-1', status='ok', run_id=run_id,
                 verdict='fatal_and_teardown_memory_error' if vuln else 'no_fatal',
                 oom_logged=vuln, oom_tried_bytes=328 if vuln else None,
                 script_reached=not vuln, teardown_frames=['zend_array_destroy'] if vuln else [],
                 input=dict(P15_INPUT, body_bytes=2563920))
    control = dict(label='control', status='ok', run_id=run_id,
                   verdict='fatal_only' if vuln else 'no_fatal',
                   pre_counter_crossing=True if vuln else None)
    patha = dict(run_id=run_id, version=version, entries=[crash, control])
    rec = dict(session_roundtrip_ok=True, request_a_status=500, oom_logged=True,
               worker_alive_after_a=True, request_b_status=None if vuln else 400,
               request_b_connection_reset=False,
               asan={'is_uaf': True} if vuln else None,
               result='path_b_reproduced' if vuln else 'no_uaf_observed')
    pathb = dict(run_id=run_id, version=version,
                 entries=[dict(iteration=1, status='ok', record=rec)])
    run = dict(iteration=1, oom_limit_bytes=P17_LIMIT_BYTES, request_a_status=500,
               fatal_in_unserialize=True, worker_survived_a=True,
               request_b_status=None if vuln else 200,
               asan={'is_uaf': True} if vuln else None,
               result='path_c_reproduced' if vuln else 'no_uaf_observed')
    pathc = dict(run_id=run_id, version=version, runs=[run])
    return patha, pathb, pathc


def run_self_test():
    cases = []

    def case(name, version, mutate, rcs, want):
        cases.append((name, version, mutate, rcs, want))

    ok_rcs = lambda v: (0, 0, 0 if v not in FIXED_VERSIONS else 1)  # noqa: E731
    case('vulnerable reproduces', '8.4.4', None, ok_rcs('8.4.4'), 0)
    case('fixed extinguishes with block point', '8.4.27', None, ok_rcs('8.4.27'), 0)
    case('sub-runner crashed (rc=139)', '8.4.4', None, (139, 0, 0), 1)

    def foreign(a, b, c):
        b['run_id'] = 'older-run'
    case('stale result from another run', '8.4.4', foreign, ok_rcs('8.4.4'), 1)

    def other_version(a, b, c):
        c['version'] = '8.4.4'
    case('result of another version', '8.4.27', other_version, ok_rcs('8.4.27'), 1)

    def unreached(a, b, c):
        a['entries'][0]['script_reached'] = False   # nothing processed the input
    case('fixed: P15 input never reached PHP', '8.4.27', unreached, ok_rcs('8.4.27'), 2)

    def consumer_never_sent(a, b, c):
        b['entries'][0]['record'].update(request_b_status=None, asan=None,
                                         result='no_uaf_observed')
    case('fixed: P16 consumer never ran', '8.4.27', consumer_never_sent,
         ok_rcs('8.4.27'), 2)

    def no_producer(a, b, c):
        c['runs'][0]['fatal_in_unserialize'] = False
    case('fixed: P17 producer did not fatal', '8.4.27', no_producer, ok_rcs('8.4.27'), 2)

    def wrong_limit(a, b, c):
        c['runs'][0]['oom_limit_bytes'] = 8 * 1024 * 1024
    case('effective memory_limit differs', '8.4.27', wrong_limit, ok_rcs('8.4.27'), 2)

    def no_fatal_substring(a, b, c):
        a['entries'][0].update(verdict='no_fatal', oom_logged=False, oom_tried_bytes=None)
    case("vulnerable 'no_fatal' is not 'fatal'", '8.4.4', no_fatal_substring,
         ok_rcs('8.4.4'), 2)

    def control_landed_late(a, b, c):
        a['entries'][1]['pre_counter_crossing'] = False
    case('vulnerable: control not pre-counter', '8.4.4', control_landed_late,
         ok_rcs('8.4.4'), 2)

    passed = 0
    report = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, version, mutate, rcs, want in cases:
            run_id = 'gt-selftest'
            files = _fixtures(run_id, version)
            if mutate:
                mutate(*files)
            paths = []
            for label, data in zip(('a', 'b', 'c'), files):
                p = Path(tmp) / ('%s-%s.json' % (label, len(report)))
                p.write_text(json.dumps(data))
                paths.append(str(p))
            ns = argparse.Namespace(version=version, run_id=run_id,
                                    patha=paths[0], pathb=paths[1], pathc=paths[2],
                                    patha_rc=rcs[0], pathb_rc=rcs[1], pathc_rc=rcs[2])
            _, code = evaluate(ns)
            good = code == want
            passed += good
            report.append(dict(case=name, expected_exit=want, exit=code, passed=good))
    missing = argparse.Namespace(version='8.4.4', run_id='x', patha='/nonexistent',
                                 pathb='/nonexistent', pathc='/nonexistent',
                                 patha_rc=0, pathb_rc=0, pathc_rc=0)
    _, code = evaluate(missing)
    report.append(dict(case='result files missing', expected_exit=1, exit=code,
                       passed=code == 1))
    passed += code == 1
    print(json.dumps(dict(self_test=report, passed=passed, total=len(report)), indent=2))
    return 0 if passed == len(report) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--version')
    parser.add_argument('--run-id')
    for name in ('patha', 'pathb', 'pathc'):
        parser.add_argument('--' + name)
        parser.add_argument('--%s-rc' % name, type=int)
    parser.add_argument('--out')
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    result, code = evaluate(args)
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text)
    print(json.dumps(dict(run_id=result['run_id'], version=result['version'],
                          expectation=result['expectation'],
                          paths=[dict(path=r['path'], met=r['expectation_met'])
                                 for r in result['paths']],
                          harness_failures=result['harness_failures'],
                          problems=result['problems'], ok=result['ok'],
                          exit=code), indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())
