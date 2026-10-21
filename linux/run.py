#!/usr/bin/env python3
"""Linux FPM lab. Servers run as phplab and listen only on loopback."""
import argparse
import hashlib
import http.cookiejar
import json
import os
import re
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')

def checked(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)

def verify(version, flavor, allocator, buffering, hold=False):
    if not re.fullmatch(r'8\.[0-9]+\.[0-9]+', version):
        raise ValueError('Expected stable 8.x.y version')
    prefix = BASE / 'install' / (version + '-' + flavor)
    manifest = json.loads((prefix / 'build-manifest.json').read_text())
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
    out = BASE / 'evidence' / (stamp + '-' + version + '-' + flavor + '-' + allocator + '-' + buffering)
    out.mkdir(parents=True)
    for name in ('sessions', 'uploads', 'nginx'):
        (out / name).mkdir()
    env = os.environ.copy()
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=' + str(out / 'asan'),
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    env['USE_ZEND_ALLOC'] = '1' if allocator == 'zend' else '0'
    env['USE_TRACKED_ALLOC'] = '1' if allocator == 'tracked' else '0'
    php = str(prefix / 'bin/php')
    source = BASE / 'sources' / ('php-' + version)
    tests = [str(REPO / 'linux/tests/serialize_session.phpt'),
             str(source / 'ext/session/tests/session_encode_basic.phpt'),
             str(source / 'ext/session/tests/session_decode_basic.phpt')]
    unit = out / 'phpt.log'
    with unit.open('w') as log:
        checked([php, '-n', str(source / 'run-tests.php'),
                 '-n', '-q', '--offline', '-p', php, *tests],
                env={**env, 'NO_INTERACTION': '1', 'REPORT_EXIT_STATUS': '1'}, stdout=log, stderr=subprocess.STDOUT)
    # Fail if test runner silently skipped the required extension.
    unit_text = unit.read_text()
    if not re.search(r'Tests passed\s*:\s*3\s+\(100\.0%\)', unit_text):
        raise RuntimeError('PHPT did not prove a passing test; inspect ' + str(unit))
    fpm_port, http_port = 19084, 18085
    for port in (fpm_port, http_port):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
    ini = out / 'php.ini'
    ini.write_text((REPO / 'config/php.ini').read_text() + '\n'
                   + 'session.save_path=' + str(out / 'sessions') + '\n'
                   + 'upload_tmp_dir=' + str(out / 'uploads') + '\n'
                   + 'error_log=' + str(out / 'php-error.log') + '\n')
    # Additional paths belong to [Session] in ini but PHP accepts directives there.
    fpm = out / 'fpm.conf'
    fpm.write_text(f'''[global]
daemonize = no
error_log = {out}/fpm-error.log
pid = {out}/fpm.pid
[lab]
user = phplab
group = phplab
listen = 127.0.0.1:{fpm_port}
pm = static
pm.max_children = 1
clear_env = no
catch_workers_output = yes
rlimit_core = unlimited
access.log = {out}/fpm-access.log
''')
    nginx = out / 'nginx.conf'
    nginx.write_text(f'''daemon off;
pid {out}/nginx.pid;
error_log {out}/nginx-error.log;
events {{ worker_connections 64; }}
http {{
 access_log {out}/nginx-access.log;
 client_body_temp_path {out}/nginx;
 fastcgi_temp_path {out}/nginx;
 proxy_temp_path {out}/nginx;
 uwsgi_temp_path {out}/nginx;
 scgi_temp_path {out}/nginx;
 server {{
  listen 127.0.0.1:{http_port};
  client_max_body_size 4m;
  location / {{
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME {REPO}/web/index.php;
   fastcgi_pass 127.0.0.1:{fpm_port};
   fastcgi_request_buffering {buffering};
  }}
 }}
}}
''')
    processes = []
    handles = []
    report = dict(scope='environment verification, not a CVE verdict', build=manifest,
                  allocator=allocator, buffering=buffering, evidence=str(out), checks=[])
    try:
        for name, cmd in (('fpm', [str(prefix / 'sbin/php-fpm'), '-c', str(ini), '-y', str(fpm)]),
                          ('nginx', ['/usr/sbin/nginx', '-p', str(out), '-c', str(nginx)])):
            log = (out / (name + '-console.log')).open('w')
            handles.append(log)
            processes.append(subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True))
        base = 'http://127.0.0.1:' + str(http_port)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def request(path, data=None, headers=None):
            with opener.open(urllib.request.Request(base + path, data=data, headers=headers or {}), timeout=5) as res:
                return json.load(res)
        for attempt in range(100):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('Server startup failed; inspect ' + str(out))
            try:
                health = request('/health')
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('Server startup timeout')
        assert health['ok'] and health['php'] == version and health['sapi'] == 'fpm-fcgi', health
        assert health['upload_progress'] == '1', health
        assert health['debug'] == (flavor == 'asan'), health
        assert health['allocator_env'] == {key: env[key] for key in ('USE_ZEND_ALLOC', 'USE_TRACKED_ALLOC')}, health
        master = int((out / 'fpm.pid').read_text())
        first_worker = subprocess.check_output(['pgrep', '-P', str(master)], text=True).strip()
        report['checks'].append(dict(name='nginx_fpm_health', result=health))
        assert request('/session')['visits'] == 1
        assert request('/session')['visits'] == 2
        report['checks'].append(dict(name='session_cookie_roundtrip', ok=True))
        payload = b'php-linux-environment-check\n'
        boundary = 'LabEnvironmentBoundary'
        body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="check.txt"\r\nContent-Type: text/plain\r\n\r\n').encode() + payload + ('\r\n--' + boundary + '--\r\n').encode()
        result = request('/upload', body, {'Content-Type': 'multipart/form-data; boundary=' + boundary})
        assert result == dict(ok=True, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()), result
        report['checks'].append(dict(name='multipart_upload_sha256', result=result))
        # Same FPM worker serves each request; capture its PID and runtime allocator env.
        master = int((out / 'fpm.pid').read_text())
        child = subprocess.check_output(['pgrep', '-P', str(master)], text=True).strip()
        assert child == first_worker, 'FPM worker restarted during verification'
        report['fpm_worker_pid'] = child
        report['same_worker_reused'] = True
        report['worker_allocator_env'] = health['allocator_env']
        report['status'] = 'passed'
        if hold:
            print('Ready: ' + base + '; evidence: ' + str(out) + '; Ctrl+C to stop', flush=True)
            try:
                while True:
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError('Server exited during interactive run')
                    time.sleep(.5)
            except KeyboardInterrupt:
                pass
    except BaseException as exc:
        report['status'] = 'failed'
        report['error'] = str(exc)
        raise
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        for handle in handles:
            handle.close()
        report['servers_stopped'] = all(p.poll() is not None for p in processes)
        reports = list(out.glob('asan.*'))
        report['asan_reports'] = [str(p) for p in reports]
        if reports:
            report['status'] = 'failed'
            report['error'] = 'ASAN error captured'
        (out / 'result.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    if report['status'] != 'passed':
        raise RuntimeError(report.get('error'))
    return report

def calibration(version):
    if not re.fullmatch(r'8\.[0-9]+\.[0-9]+', version):
        raise ValueError('Expected stable 8.x.y version')
    out = BASE / 'evidence' / ('calibration-' + version)
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'asan-probe'
    checked(['clang', '-g', '-O0', '-fsanitize=address', '-fno-omit-frame-pointer',
             str(REPO / 'linux/asan-probe.c'), '-o', str(binary)])
    result = subprocess.run([str(binary)], capture_output=True, text=True,
                            env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:symbolize=1'})
    (out / 'asan-probe.log').write_text(result.stderr)
    assert result.returncode != 0 and 'heap-use-after-free' in result.stderr and 'asan-probe.c:' in result.stderr
    # Demonstrate symbolized stack capture for the actual PHP executable without a PHP fault.
    prefix = BASE / 'install' / (version + '-asan')
    gdb = subprocess.run(['gdb', '--batch', '-ex', 'set pagination off', '-ex', 'break php_request_startup',
                          '-ex', 'run', '-ex', 'bt', '--args', str(prefix / 'bin/php'), '-n', '-r', 'echo "calibration";'],
                         capture_output=True, text=True,
                         env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
    (out / 'php-gdb.log').write_text(gdb.stdout + gdb.stderr)
    assert gdb.returncode == 0 and 'php_request_startup' in gdb.stdout and 'main.c:' in gdb.stdout
    (out / 'result.json').write_text(json.dumps(dict(scope='toolchain calibration; not a CVE reproduction',
        php_version=version, probe_exit_code=result.returncode, heap_use_after_free_detected=True,
        source_line_symbolized=True, php_gdb_exit_code=gdb.returncode, php_source_stack=True), indent=2))
    print('ASAN positive control and PHP source-level debugger: passed')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['verify', 'calibrate', 'serve'])
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['normal', 'asan'], default='asan')
    parser.add_argument('--allocator', choices=['zend', 'system', 'tracked'], default='tracked')
    parser.add_argument('--buffering', choices=['on', 'off'], default='on')
    args = parser.parse_args()
    if args.action == 'calibrate':
        calibration(args.version)
    else:
        verify(args.version, args.flavor, args.allocator, args.buffering, hold=args.action == 'serve')
