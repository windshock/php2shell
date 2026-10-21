#!/usr/bin/env python3
"""HTTP-level before/after comparison with an explicit verdict vocabulary.

Runs ONE deterministic scenario against two builds with identical SAPI,
allocator, buffering and inputs, then compares normalized observations.
This is the HTTP counterpart to linux/compare.py (which compares PHPT runs).

Verdict vocabulary (plan section 9.5):
  code_path_reached / memory_error_observed / crash_observed /
  request_aborted_worker_exit / regression_difference_observed /
  inconclusive / not_run

Local loopback lab only. Observation only: no exploitation attempt.
"""
import argparse
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe import Lab, multipart, session_snapshot, worker_pid  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'
SESSION_FIELD = 'PHPSESSID'


def error_signatures(text, limit=8):
    """Stable error identity: severity + first 80 chars, without timestamps."""
    found = []
    for line in text.splitlines():
        match = re.search(r'PHP (Fatal error|Warning|Notice|Deprecated):\s*(.{0,80})', line)
        if match:
            found.append('%s: %s' % (match.group(1), match.group(2).strip()))
    return sorted(set(found))[:limit]


def run_progress(lab, tag):
    """Deterministic single upload-progress request; stable observations only."""
    first = lab.request('/session')['visits']
    pid_first = worker_pid(lab.out)
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    payload = b'Z' * (64 * 1024)
    result = multipart(18085, '/upload',
                       fields=[(PROGRESS_FIELD, 'cmp1')],
                       file_spec=('file', 'cmp.bin', payload),
                       cookie=f'PHPSESSID={sid}',
                       sampler=lambda: session_snapshot(lab, ['cmp1']),
                       chunk_size=32768, chunk_delay=0.05)
    mid = [s for s in result['samples'] if 'cmp1' in s]
    after_visits = lab.request('/session')['visits']
    pid_last = worker_pid(lab.out)
    stable = dict(
        upload_status=result['status'],
        upload_ok=(b'"ok":true' in result['body']),
        progress_key_mid_upload=bool(mid),
        progress_key_cleaned=(not session_snapshot(lab, ['cmp1'])),
        visits_increment=(after_visits - first),
        asan_reports=len(lab.asan_reports()),
        error_signatures=error_signatures(lab.php_error_log()))
    runtime = dict(worker_pid_first=pid_first, worker_pid_last=pid_last,
                   worker_reused=(pid_first is not None and pid_first == pid_last),
                   worker_restarted=(pid_first != pid_last))
    status = 'code_path_reached' if mid else 'not_run'
    return dict(tag=tag, scenario='progress-lifecycle', observations=stable,
                runtime=runtime, status=status)


def run_oom(lab, tag):
    """OOM bailout + follow-up request; records worker lifecycle, not exploitability."""
    sid_big = 'cmpbig' + secrets.token_hex(8)
    sid_small = 'cmpsmall' + secrets.token_hex(8)
    big = 'A' * (3 * 1024 * 1024)
    (lab.out / 'sessions' / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
    (lab.out / 'sessions' / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
    pid_before = worker_pid(lab.out)
    req_n = multipart(18085, '/upload',
                      fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'cmpn')],
                      file_spec=('file', 'n.bin', b'K' * 32768))
    time.sleep(0.4)
    oom_logged = 'Allowed memory size of' in lab.php_error_log()
    pid_after_n = worker_pid(lab.out)
    req_n1 = multipart(18085, '/upload',
                       fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'cmpn1')],
                       file_spec=('file', 'n1.bin', b'L' * 16384))
    time.sleep(0.3)
    asan = lab.asan_reports()
    fpm_error = (lab.out / 'fpm-error.log')
    exits = re.findall(r'exited with code (\d+)', fpm_error.read_text(errors='replace')) if fpm_error.exists() else []
    stable = dict(
        oom_fatal_logged=oom_logged,
        request_n_status=req_n['status'],
        worker_survived_oom=(pid_before == pid_after_n),
        request_n1_status=req_n1['status'],
        worker_exit_codes=sorted(set(exits)),
        asan_reports=len(asan),
        error_signatures=error_signatures(lab.php_error_log()))
    if asan:
        status = 'memory_error_observed'
    elif req_n['status'] in (500, 502) and pid_before != pid_after_n:
        status = 'request_aborted_worker_exit'
    elif oom_logged:
        status = 'code_path_reached'
    else:
        status = 'not_run'
    return dict(tag=tag, scenario='oom-residue', observations=stable,
                runtime=dict(worker_pid_before=pid_before,
                             worker_pid_after=worker_pid(lab.out)),
                status=status)


SCENARIOS = {'progress-lifecycle': run_progress, 'oom-residue': run_oom}


def execute(build, flavor, allocator, buffering, ini_extra, scenario, tag):
    lab = Lab(*build.split('-'), allocator=allocator, buffering=buffering,
              ini_extra=ini_extra, profile='cmp-' + tag)
    try:
        lab.start()
        return SCENARIOS[scenario](lab, tag)
    finally:
        lab.stop()


def compare(before, after):
    differences = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            differences.append(dict(field=key, before=before.get(key), after=after.get(key)))
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True, help='e.g. 8.4.4-asan (affected build)')
    parser.add_argument('--after', required=True, help='e.g. 8.4.4-asan (fixed build or control)')
    parser.add_argument('--scenario', choices=sorted(SCENARIOS), default='progress-lifecycle')
    parser.add_argument('--allocator', choices=['zend', 'system', 'tracked'], default='tracked')
    parser.add_argument('--buffering', choices=['on', 'off'], default='off')
    parser.add_argument('--after-ini', action='append', default=[],
                        help='extra INI for the after run (control experiments only)')
    parser.add_argument('--advisory', type=Path, default=None,
                        help='optional JSON with affected_version/fixed_version; only then '
                             'may a difference be called regression_difference_observed')
    parser.add_argument('--before-version', default=None,
                        help='override version for the before build (default: from --before)')
    args = parser.parse_args()

    build_before = args.before
    build_after = args.after
    flavor = build_before.rsplit('-', 1)[-1]
    if build_after.rsplit('-', 1)[-1] != flavor:
        raise SystemExit('Both builds must use the same flavor (asan/normal)')
    ini_base = ['session.upload_progress.min_freq=0']
    if args.scenario == 'oom-residue':
        ini_base.append('memory_limit=8M')
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('http-compare-%s-%s' % (stamp, args.scenario))
    out.mkdir(parents=True)

    runs = {}
    errors = {}
    for tag, build in (('before', build_before), ('after', build_after)):
        try:
            runs[tag] = execute(build, flavor, args.allocator, args.buffering,
                                ini_base + (args.after_ini if tag == 'after' else []),
                                args.scenario, tag)
        except Exception as exc:  # keep the other side's evidence
            errors[tag] = '%s: %s' % (type(exc).__name__, exc)
    result = dict(scope='HTTP comparison; observation only; not a CVE verdict',
                  scenario=args.scenario, before=build_before, after=build_after,
                  allocator=args.allocator, buffering=args.buffering,
                  after_ini_extra=args.after_ini, runs=runs, errors=errors)
    if errors or len(runs) != 2:
        result['status'] = 'inconclusive'
        result['differences'] = []
    else:
        result['differences'] = compare(runs['before']['observations'],
                                        runs['after']['observations'])
        result['runtime'] = {tag: runs[tag].get('runtime') for tag in runs}
        if result['differences']:
            mapped = False
            advisory = None
            if args.advisory:
                advisory = json.loads(args.advisory.read_text())
                mapped = (advisory.get('affected_version') == runs['before']['observations'].get('version')
                          or advisory.get('affected_version') == args.before.split('-')[0]) \
                    and (advisory.get('fixed_version') == args.after.split('-')[0])
            result['advisory'] = advisory
            result['status'] = ('regression_difference_observed' if mapped
                                else 'difference_observed')
        else:
            result['status'] = 'identical'
    result['evidence'] = str(out)
    (out / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ('scenario', 'before', 'after', 'status',
                                             'differences', 'errors', 'evidence')}, indent=2))
    return 0 if result['status'] in ('identical', 'difference_observed',
                                     'regression_difference_observed') else 2


if __name__ == '__main__':
    sys.exit(main())
