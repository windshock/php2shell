#!/usr/bin/env python3
"""#3 CG-2: Phase 3 enforce isolation safety under PHP-FPM (plan 14.2 CG-2).

The Phase 3 containment ends the process with _exit(70). Under FPM the
master replaces the worker; this harness measures whether that replacement
stays healthy under REPEATED guard terminations (restart amplification) or
degrades availability - the attack surface the review flagged.

Matrix (modes: B=8.4.27-normalext baseline, C disabled/observe/enforce on
8.4.27-coreguard-normalext), pm.max_children in {1, 4}, N repeated
fault-injecting requests per cell:
  - worker pid before/after each fault (replacement observed?)
  - next healthy request after each fault (availability)
  - HTTP success rate, 5xx/reset counts
  - wall time for N faults + N healths (restart cost proxy)
  - data loss proxy: response bytes received for a streaming request
    interrupted mid-body by the guard on the SAME connection

Observation only: no heap grooming, no weaponization; faults are synthetic
destructor fatals from the phase3 test suite.
"""
import argparse
import http.client
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
HTTP_PORT, FPM_PORT = 18095, 19095

FAULT_BODY = b'''<?php
class D { function __destruct() { trigger_error("dtor", E_USER_ERROR); } }
$keep = new D;
echo "probe ";
while (true) { echo str_pad('', 4096, 'x'); flush(); usleep(1000); }
'''
HEALTH_PATH = '/health'


def lab(build, mode, max_children, out, php_ini_extra=''):
    """One FPM pool + nginx front for a (build, mode, max_children) cell."""
    for name in ('sessions', 'uploads', 'nginx'):
        (out / name).mkdir(parents=True, exist_ok=True)
    ini = (HERE.parents[1] / 'config/php.ini').read_text() + '\n'
    ini += ('memory_limit=32M\nmax_execution_time=8\nsession.save_path=%s\nupload_tmp_dir=%s\n'
            'error_log=%s\n' % (out / 'sessions', out / 'uploads', out / 'php-error.log'))
    if php_ini_extra:
        ini += php_ini_extra
    (out / 'php.ini').write_text(ini)
    (out / 'www.conf').write_text(f'''[global]
error_log = {out}/fpm-error.log
pid = {out}/fpm.pid
[lab]
user = phplab
group = phplab
listen = 127.0.0.1:{FPM_PORT}
pm = static
pm.max_children = {max_children}
clear_env = no
access.log = {out}/fpm-access.log
''')
    router = out / 'router.php'
    router.write_text('''<?php
$u = $_SERVER['REQUEST_URI'];
if ($u === '/fault') {
    class D { function __destruct() { trigger_error("dtor", E_USER_ERROR); } }
    $GLOBALS['keep'] = new D;
    echo "probe ";
    while (true) { echo str_pad('', 4096, 'x'); flush(); usleep(1000); }
}
if ($u === '/health') { echo json_encode(['ok' => true, 'pid' => getmypid()]); return true; }
echo 'not-found';
return true;
''')
    (out / 'nginx.conf').write_text(f'''daemon off;
pid {out}/nginx.pid;
error_log {out}/nginx-error.log;
events {{ worker_connections 128; }}
http {{
 access_log off;
 client_body_temp_path {out}/nginx;
 proxy_temp_path {out}/nginx;
 uwsgi_temp_path {out}/nginx;
 scgi_temp_path {out}/nginx;
 fastcgi_temp_path {out}/nginx;
 server {{
  listen 127.0.0.1:{HTTP_PORT};
  client_max_body_size 8m;
  fastcgi_request_buffering on;
  location / {{
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME {router};
   fastcgi_pass 127.0.0.1:{FPM_PORT};
  }}
 }}
}}
''')
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1')
    if mode != 'B':
        env['COREGUARD_MODE'] = mode
        env['COREGUARD_LOG'] = str(out / 'cg-events.log')
    procs = []
    logs = []
    for name, cmd in (
            ('fpm', [str(BASE / 'install' / build / 'sbin/php-fpm'),
                     '-c', str(out / 'php.ini'), '-y', str(out / 'www.conf')]),
            ('nginx', ['/usr/sbin/nginx', '-p', str(out), '-c', str(out / 'nginx.conf')])):
        log = (out / f'{name}-console.log').open('w')
        logs.append(log)
        procs.append(subprocess.Popen(cmd, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True))
    return procs, logs, env


def http_get(path, timeout=8):
    conn = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=timeout)
    try:
        conn.request('GET', path)
        res = conn.getresponse()
        body = res.read()
        return res.status, body
    except Exception as exc:
        return None, type(exc).__name__
    finally:
        conn.close()


def worker_pids(out):
    try:
        master = int((out / 'fpm.pid').read_text().strip())
        children = subprocess.check_output(
            ['pgrep', '-P', str(master)], text=True).split()
        return master, sorted(int(c) for c in children)
    except Exception:
        return None, []


def cell(build, mode, max_children, faults, root, env_extra=''):
    out = root / f'{build}-{mode}-mc{max_children}'
    out.mkdir(parents=True, exist_ok=True)
    procs, logs, env = lab(build, mode, max_children, out, env_extra)
    record = dict(build=build, mode=mode, max_children=max_children,
                  faults_requested=faults)
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            status, body = http_get(HEALTH_PATH, timeout=2)
            if status == 200 and b'"ok":true' in body:
                break
            time.sleep(0.2)
        else:
            record['error'] = 'startup timeout'
            return record
        master, pids_before = worker_pids(out)
        record['pool_master'] = master
        record['workers_before'] = pids_before
        ok = reset = err = 0
        replaced = 0
        stream_intact = 0
        t0 = time.time()
        for i in range(faults):
            status, body = http_get('/fault', timeout=6)
            if status == 200:
                ok += 1  # streamed until the client timeout - no guard hit
            elif status is None and body in ('ConnectionResetError',
                                             'BrokenPipeError', 'IncompleteRead',
                                             'OSError'):
                reset += 1
            else:
                err += 1
            _, pids_after = worker_pids(out)
            if pids_after and pids_after != pids_before:
                replaced += 1
                pids_before = pids_after
            h_status, h_body = http_get(HEALTH_PATH, timeout=6)
            if h_status != 200:
                record.setdefault('health_failures', []).append(i)
        record.update(http_200=ok, resets=reset, other_errors=err,
                      worker_replacements=replaced,
                      elapsed_s=round(time.time() - t0, 1))
        # data-loss proxy: stream interrupted mid-body keeps what it sent
        try:
            conn = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=6)
            conn.request('GET', '/fault')
            res = conn.getresponse()
            chunk = res.read(8192)
            stream_intact = len(chunk)
            conn.close()
        except Exception:
            stream_intact = -1
        record['first_chunk_bytes'] = stream_intact
        cg = out / 'cg-events.log'
        record['guard_events'] = (cg.read_text().count('COREGUARD event=')
                                  if cg.exists() else 0)
    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
        for l in logs:
            l.close()
        subprocess.run(['pkill', '-f', 'php-fpm.*%s' % out.name], capture_output=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--faults', type=int, default=10)
    parser.add_argument('--max-children', type=int, nargs='+', default=[1, 4])
    args = parser.parse_args()
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = BASE / 'evidence' / ('cg2-fpm-%s' % stamp)
    root.mkdir(parents=True)
    rows = []
    for mc in args.max_children:
        for build, mode in (('8.4.27-normalext', 'B'),
                            ('8.4.27-coreguard-normalext', 'disabled'),
                            ('8.4.27-coreguard-normalext', 'observe'),
                            ('8.4.27-coreguard-normalext', 'enforce')):
            row = cell(build, mode, mc, args.faults, root)
            rows.append(row)
            print(json.dumps(row))
    summary = dict(scope='#3 CG-2 FPM isolation matrix; observation only',
                   faults=args.faults, rows=rows, **provenance.provenance())
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(dict(out=str(root), rows=len(rows))))


if __name__ == '__main__':
    sys.exit(main())
