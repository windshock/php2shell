#!/usr/bin/env python3
"""GDB instrumentation for the BG(unserialize) cross-request candidate (Bug U).

Sequence (single CLI server process):
  health, one session roundtrip
  request A: 3MB forged session + multipart progress -> OOM inside unserialize
             (memory_limit must allow s_read but not the decoded string)
  request B: small session + progress -> parse-time decode reuses the freed
             unserialize context if the residue survived.

Observation only: no exploitation attempt, no heap grooming.
"""
import argparse
import http.cookiejar
import importlib.util
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

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gdb_probe_mod', HERE / 'gdb-probe.py')
gdb_probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gdb_probe)
GDB_COMMANDS, parse_marks, as_int = gdb_probe.GDB_COMMANDS, gdb_probe.parse_marks, gdb_probe.as_int

sys.path.insert(0, str(HERE))
from probe import multipart  # noqa: E402

REPO = HERE.parent
BASE = Path('/home/phplab/php-lab')
PORT = 18089
SESSION_FIELD = 'PHPSESSID'
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['asan'], default='asan')
    parser.add_argument('--allocator', choices=['zend', 'system', 'tracked'], default='tracked')
    parser.add_argument('--memory-limit', default='5M',
                        help='must let s_read succeed but make the decoded string allocation fail')
    args = parser.parse_args()

    prefix = BASE / 'install' / (args.version + '-' + args.flavor)
    manifest = json.loads((prefix / 'build-manifest.json').read_text())
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
    out = BASE / 'evidence' / ('probe-gdb-unser-%s-%s-%s' % (stamp, args.version, args.allocator))
    for name in ('sessions', 'uploads'):
        (out / name).mkdir(parents=True)
    ini = (REPO / 'config/php.ini').read_text() + '\n'
    ini += ('session.upload_progress.min_freq=0\n'
            'memory_limit=%s\n'
            'session.save_path=%s\n'
            'upload_tmp_dir=%s\n'
            'error_log=%s\n' % (args.memory_limit, out / 'sessions', out / 'uploads', out / 'php-error.log'))
    (out / 'php.ini').write_text(ini)
    (out / 'gdb.cmd').write_text(GDB_COMMANDS.format(
        ini=out / 'php.ini', port=PORT, docroot=REPO / 'web',
        router=REPO / 'web/index.php', php=prefix / 'bin/php'))
    env = os.environ.copy()
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    env['USE_ZEND_ALLOC'] = '1' if args.allocator == 'zend' else '0'
    env['USE_TRACKED_ALLOC'] = '1' if args.allocator == 'tracked' else '0'

    report = dict(scope='GDB BG(unserialize) instrumentation; observation only',
                  build=manifest, allocator=args.allocator,
                  memory_limit=args.memory_limit, evidence=str(out),
                  steps=[], requests=[], checks=[])
    log_handle = (out / 'gdb.log').open('w')
    gdb = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')],
                           env=env, stdout=log_handle, stderr=subprocess.STDOUT,
                           start_new_session=True)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(path, timeout=10):
        with opener.open('http://127.0.0.1:%d%s' % (PORT, path), timeout=timeout) as res:
            return json.load(res)

    def wait_ready(timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if gdb.poll() is not None:
                raise RuntimeError('gdb exited before the server was ready')
            try:
                if request('/health', timeout=2).get('ok'):
                    return
            except Exception:
                time.sleep(0.4)
        raise RuntimeError('server startup timeout under gdb')

    try:
        wait_ready()
        report['steps'].append('ready')
        request('/health')
        assert request('/session')['visits'] >= 1
        report['steps'].append('health+session')
        sid_big = 'gdubig' + secrets.token_hex(8)
        big = 'A' * (3 * 1024 * 1024)
        (out / 'sessions' / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
        req_a = multipart(PORT, '/upload',
                          fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'gU')],
                          file_spec=('file', 'ua.bin', b'U' * 32768))
        report['steps'].append('decode_oom#1')
        report['checks'].append(dict(name='request_a', status=req_a['status'],
                                     aborted=req_a['aborted']))
        # No request may run between A and B (basic RINIT would memset the state).
        sid_small = 'gdusmall' + secrets.token_hex(8)
        (out / 'sessions' / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
        try:
            req_b = multipart(PORT, '/upload',
                              fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'gU2')],
                              file_spec=('file', 'ub.bin', b'V' * 16384))
            report['checks'].append(dict(name='request_b', status=req_b['status'],
                                         aborted=req_b['aborted']))
        except Exception as exc:
            report['checks'].append(dict(name='request_b', error=str(exc)))
            req_b = None
        report['steps'].append('decode_followup#1')
        try:
            report['checks'].append(dict(name='health_after', result=request('/health', timeout=6)))
        except Exception as exc:
            report['checks'].append(dict(name='health_after', error=str(exc)))
    finally:
        if gdb.poll() is None:
            os.killpg(gdb.pid, signal.SIGTERM)
            try:
                gdb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(gdb.pid, signal.SIGKILL)
                gdb.wait()
        log_handle.close()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.socket() as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(('127.0.0.1', PORT))
                break
            except OSError:
                time.sleep(0.2)

    log_text = (out / 'gdb.log').read_text(errors='replace')
    report['requests'] = parse_marks(log_text)
    report['asan_reports'] = sorted(str(p) for p in out.glob('asan.*') if p.is_file())
    php_log = out / 'php-error.log'
    report['php_error_log'] = php_log.read_text(errors='replace')[:4000] if php_log.exists() else ''

    requests = report['requests']
    levels = [as_int((r['startup'] or {}).get('unser_level')) for r in requests]
    oom_index = None
    for index, item in enumerate(requests):
        if item['unser_init'] and not item['unser_destroy'] \
                and as_int((item['shutdown'] or {}).get('unser_level')) > 0:
            oom_index = index
            break
    next_index = oom_index + 1 if oom_index is not None and oom_index + 1 < len(requests) else None
    reuse = [index for index, item in enumerate(requests)
             if any(as_int(field.get('unser_level')) > 0 for field in item['unser_init'])]
    report['verdict'] = dict(
        mode='unserialize',
        oom_bailout_logged='Allowed memory size of' in report['php_error_log'],
        decode_cancel_warning='Failed to decode session object' in report['php_error_log'],
        oom_request_index=oom_index,
        reuse_request_index=next_index,
        residue_level_at_next_request_start=(levels[next_index] if next_index is not None else None),
        unserialize_reuse_request_indexes=reuse,
        post_oom_reuse_observed=(oom_index is not None
                                 and any(index > oom_index for index in reuse)),
        asan_report_count=len(report['asan_reports']),
        memory_error_observed=bool(report['asan_reports']),
        request_levels=levels)
    (out / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'evidence': report['evidence'], 'checks': report['checks'],
                      'verdict': report['verdict']}, indent=2))
    return report


if __name__ == '__main__':
    main()
