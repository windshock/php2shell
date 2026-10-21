#!/usr/bin/env python3
"""GDB request-lifetime instrumentation for the PHP2Shell pre-patch analysis.

Runs the CLI built-in server under GDB with breakpoints that print
BG(serialize).level/.data, BG(serialize_lock) and the multipart callback
events at well-defined points. Sequential requests on one process make the
cross-request state visible without touching the PHP source.

Local loopback only. Observation and state recording; no exploitation.
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
from probe import multipart, session_snapshot  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
PORT = 18086

GDB_COMMANDS = r'''set pagination off
set confirm off
set breakpoint pending on
set width 0
file {php}
handle SIGPIPE nostop noprint pass
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
break php_request_startup
commands
silent
printf "MARK REQ_STARTUP ser_level=%u ser_data=%p ser_lock=%u unser_level=%u\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data, basic_globals.serialize_lock, basic_globals.unserialize.level
continue
end
break php_hash_environment
commands
silent
printf "MARK HASH_ENV ser_level=%u ser_data=%p\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data
continue
end
break zend_activate_modules
commands
silent
printf "MARK ACTIVATE_MODULES ser_level=%u ser_data=%p\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data
continue
end
break php_var_serialize_init
commands
silent
printf "MARK SER_INIT_ENTER ser_level=%u ser_data=%p\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data
continue
end
break php_var_serialize_destroy
commands
silent
printf "MARK SER_DESTROY_ENTER ser_level=%u ser_data=%p\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data
continue
end
break php_session_flush
commands
silent
printf "MARK SESSION_FLUSH write=%d ser_level=%u\n", write, basic_globals.serialize.level
continue
end
break php_session_rfc1867_callback
commands
silent
printf "MARK RFC1867_CB event=%u\n", event
continue
end
break php_request_shutdown
commands
silent
printf "MARK REQ_SHUTDOWN ser_level=%u ser_data=%p\n", basic_globals.serialize.level, (void*)basic_globals.serialize.data
continue
end
run -c {ini} -S 127.0.0.1:{port} -t {docroot} {router}
'''


def parse_marks(log_text):
    requests, current = [], None
    for line in log_text.splitlines():
        match = re.search(r'MARK (\w+)(.*)$', line)
        if not match:
            continue
        kind, rest = match.group(1), match.group(2)
        fields = dict(re.findall(r'(\w+)=(\S+)', rest))
        if kind == 'REQ_STARTUP':
            current = dict(startup=fields, hash_env=None, activate=None,
                           ser_init=[], ser_destroy=[], flush=[], callbacks=[],
                           shutdown=None)
            requests.append(current)
        elif current is None:
            continue
        elif kind == 'HASH_ENV':
            current['hash_env'] = fields
        elif kind == 'ACTIVATE_MODULES':
            current['activate'] = fields
        elif kind == 'SER_INIT_ENTER':
            current['ser_init'].append(fields)
        elif kind == 'SER_DESTROY_ENTER':
            current['ser_destroy'].append(fields)
        elif kind == 'SESSION_FLUSH':
            current['flush'].append(fields)
        elif kind == 'RFC1867_CB':
            current['callbacks'].append(fields.get('event'))
        elif kind == 'REQ_SHUTDOWN':
            current['shutdown'] = fields
    return requests


def as_int(value, default=-1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['normal', 'asan'], default='asan')
    parser.add_argument('--allocator', choices=['zend', 'system', 'tracked'], default='tracked')
    parser.add_argument('--memory-limit', default='8M')
    args = parser.parse_args()

    prefix = BASE / 'install' / (args.version + '-' + args.flavor)
    manifest = json.loads((prefix / 'build-manifest.json').read_text())
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
    out = BASE / 'evidence' / ('probe-gdb-%s-%s-%s-%s' % (stamp, args.version, args.flavor, args.allocator))
    for name in ('sessions', 'uploads'):
        (out / name).mkdir(parents=True)
    ini = (REPO / 'config/php.ini').read_text() + '\n'
    ini += ('session.upload_progress.min_freq=0\n'
            'memory_limit=%s\n'
            'session.save_path=%s\n'
            'upload_tmp_dir=%s\n'
            'error_log=%s\n' % (args.memory_limit, out / 'sessions', out / 'uploads', out / 'php-error.log'))
    (out / 'php.ini').write_text(ini)
    commands = GDB_COMMANDS.format(ini=out / 'php.ini', port=PORT,
                                   docroot=REPO / 'web', router=REPO / 'web/index.php',
                                   php=prefix / 'bin/php')
    (out / 'gdb.cmd').write_text(commands)

    env = os.environ.copy()
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    env['USE_ZEND_ALLOC'] = '1' if args.allocator == 'zend' else '0'
    env['USE_TRACKED_ALLOC'] = '1' if args.allocator == 'tracked' else '0'

    report = dict(scope='GDB state instrumentation; observation only; not a CVE verdict',
                  build=manifest, allocator=args.allocator, memory_limit=args.memory_limit,
                  evidence=str(out), steps=[], requests=[], checks=[])
    gdb_log = (out / 'gdb.log').open('w')
    gdb = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')],
                           env=env, stdout=gdb_log, stderr=subprocess.STDOUT,
                           start_new_session=True)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(path, data=None, headers=None, timeout=10):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=data, headers=headers or {})
        with opener.open(req, timeout=timeout) as res:
            return json.load(res)

    def wait_ready(timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if gdb.poll() is not None:
                raise RuntimeError('gdb exited before the server was ready')
            try:
                health = request('/health', timeout=2)
                if health.get('ok'):
                    return health
            except Exception:
                time.sleep(0.4)
        raise RuntimeError('server startup timeout under gdb')

    try:
        report['checks'].append(dict(name='startup_health', result=wait_ready()))
        # 1: plain health request (control: no session, no serialization during parse)
        request('/health')
        report['steps'].append('health#1')
        # 2: two session roundtrips (control: serialize during RSHUTDOWN, level 0 -> 1 -> 0)
        assert request('/session')['visits'] == 1
        assert request('/session')['visits'] == 2
        report['steps'].append('session#2')
        sid = [c.value for c in jar if c.name == 'PHPSESSID'][0]
        # 3: small upload progress (control: parse-time serialize with clean state)
        multipart(PORT, '/upload', fields=[('PHP_SESSION_UPLOAD_PROGRESS', 'g1')],
                  file_spec=('file', 'g1.bin', b'A' * (64 * 1024)),
                  cookie='PHPSESSID=' + sid, chunk_size=32768, chunk_delay=0.05)
        report['steps'].append('upload_small#1')
        # 4: OOM request: 3MB forged session under memory_limit -> bailout mid-encode
        sid_big = 'gdbig' + secrets.token_hex(8)
        big = 'A' * (3 * 1024 * 1024)
        (out / 'sessions' / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
        oom = multipart(PORT, '/upload',
                        fields=[('PHPSESSID', sid_big), ('PHP_SESSION_UPLOAD_PROGRESS', 'g2')],
                        file_spec=('file', 'g2.bin', b'B' * 32768))
        report['steps'].append('upload_oom#1')
        report['checks'].append(dict(name='oom_request', status=oom['status'], aborted=oom['aborted']))
        # 5: follow-up progress request (reuse probe)
        sid_small = 'gdsmall' + secrets.token_hex(8)
        (out / 'sessions' / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
        follow = None
        try:
            follow = multipart(PORT, '/upload',
                               fields=[('PHPSESSID', sid_small), ('PHP_SESSION_UPLOAD_PROGRESS', 'g3')],
                               file_spec=('file', 'g3.bin', b'C' * 16384))
            report['steps'].append('upload_followup#1')
            report['checks'].append(dict(name='followup_request', status=follow['status'],
                                         aborted=follow['aborted']))
        except Exception as exc:
            report['steps'].append('upload_followup#1:connection_error')
            report['checks'].append(dict(name='followup_request', error=str(exc)))
        # 6: liveness after the sequence
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
        gdb_log.close()
        for port in (PORT,):
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', port))
                    break
                except OSError:
                    time.sleep(0.2)

    log_text = (out / 'gdb.log').read_text(errors='replace')
    report['requests'] = parse_marks(log_text)
    report['gdb_exit_code'] = gdb.returncode
    report['signal_observed'] = 'Program received signal' in log_text
    report['asan_reports'] = sorted(str(p) for p in out.glob('asan.*') if p.is_file())
    php_log = out / 'php-error.log'
    report['php_error_log'] = php_log.read_text(errors='replace')[:4000] if php_log.exists() else ''

    # ---- verdicts from the recorded transitions
    requests = report['requests']
    levels_at_start = [as_int((r['startup'] or {}).get('ser_level')) for r in requests]
    report['checks'].append(dict(name='request_count', count=len(requests),
                                 expected=7, levels_at_request_start=levels_at_start))
    callback_events = [e for r in requests for e in r['callbacks']]
    report['checks'].append(dict(name='rfc1867_callback_events', events=callback_events))
    # Identify the OOM request by its recorded transition, not by a fixed index:
    # it entered serialize, never destroyed, and ended with level > 0.
    oom_index = None
    for index, request in enumerate(requests):
        shutdown_level = as_int((request['shutdown'] or {}).get('ser_level'))
        if request['ser_init'] and not request['ser_destroy'] and shutdown_level > 0:
            oom_index = index
            break
    next_index = (oom_index + 1) if oom_index is not None and oom_index + 1 < len(requests) else None
    reuse_indexes = [index for index, request in enumerate(requests)
                     if any(as_int(field.get('ser_level')) > 0 for field in request['ser_init'])]
    control_indexes = list(range(oom_index)) if oom_index is not None else list(range(len(requests)))
    oom_bailout = 'Allowed memory size of' in report['php_error_log']
    report['verdict'] = dict(
        callback_reached=bool(callback_events),
        callback_events_seen=sorted({int(e) for e in callback_events if e is not None}),
        control_state_clean=all(levels_at_start[i] == 0 for i in control_indexes),
        oom_bailout_logged=oom_bailout,
        oom_request_index=oom_index,
        reuse_request_index=next_index,
        residue_level_at_next_request_start=(levels_at_start[next_index]
                                             if next_index is not None else None),
        serialize_context_reuse_request_indexes=reuse_indexes,
        post_oom_reuse_observed=(oom_index is not None
                                 and any(index > oom_index for index in reuse_indexes)),
        asan_report_count=len(report['asan_reports']),
        memory_error_observed=bool(report['asan_reports']),
        request_levels=levels_at_start)
    (out / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in ('evidence', 'checks', 'verdict')}, indent=2))
    return report


if __name__ == '__main__':
    main()
