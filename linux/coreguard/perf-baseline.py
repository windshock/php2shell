#!/usr/bin/env python3
"""#3 CoreGuard Phase 0: performance baseline of a PHP build (B = 8.4.27).

Apache (mpm_event + proxy_fcgi) -> php-fpm (pm=static) on loopback, opcache
loaded, docroot = a copy of web/ on ext4 (drvfs would dominate timings).
Workloads (ab, keep-alive off):
  health        GET  /health
  session       GET  /session        (new session per request)
  unser_small   POST /unserialize    (small valid payload)
  upload_small  POST /upload         (16 KiB multipart file)
Per workload and repeat: req/s, p50/p95/p99 (ab percentile table), failed
requests, php-fpm worker RSS after the run. Engine CPU: Zend/bench.php
(CLI, from a clean `git archive` copy of the source - the source tree itself
is never written).

The same script, unchanged, measures C (8.4.27-coreguard) later; only
relative numbers B vs C on the same host are meaningful.

Usage: perf-baseline.py [--build 8.4.27-normalext] [--repeats 3] [-n 5000] [-c 8]
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
REPO = HERE.parents[1]
FPM_PORT, HTTP_PORT = 19100, 18190
MODS = '/usr/lib/apache2/modules'
CG_MODE = os.environ.get('COREGUARD_MODE')  # C builds: disabled / observe / enforce


def write_configs(run, prefix):
    docroot = run / 'docroot'
    docroot.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO / 'web/index.php', docroot / 'index.php')
    for name in ('sessions', 'uploads', 'httpd'):
        (run / name).mkdir(exist_ok=True)
    so = sorted(prefix.glob('lib/php/extensions/*/opcache.so'))
    ini = (REPO / 'config/php.ini').read_text() + '\n'
    ini += ('memory_limit=128M\nsession.save_path=%s\nupload_tmp_dir=%s\nerror_log=%s\n'
            % (run / 'sessions', run / 'uploads', run / 'php-error.log'))
    if so:
        ini += 'zend_extension=%s\nopcache.enable=1\nopcache.validate_timestamps=0\n' % so[0]
    (run / 'php.ini').write_text(ini)
    (run / 'php-fpm.conf').write_text(
        '[global]\npid=%s\nerror_log=%s\ndaemonize=no\n'
        '[www]\nlisten=127.0.0.1:%d\npm=static\npm.max_children=4\n'
        'catch_workers_output=yes\n' % (run / 'fpm.pid', run / 'fpm.log', FPM_PORT)
        # fpm clears the worker environment: pass the CoreGuard mode explicitly
        + ('env[COREGUARD_MODE]=%s\n' % CG_MODE if CG_MODE else ''))
    (run / 'httpd.conf').write_text('''ServerRoot {h}
PidFile {h}/httpd.pid
Listen 127.0.0.1:{port}
LoadModule mpm_event_module {m}/mod_mpm_event.so
LoadModule authz_core_module {m}/mod_authz_core.so
LoadModule dir_module {m}/mod_dir.so
LoadModule mime_module {m}/mod_mime.so
LoadModule proxy_module {m}/mod_proxy.so
LoadModule proxy_fcgi_module {m}/mod_proxy_fcgi.so
ServerName localhost
TypesConfig /etc/mime.types
DocumentRoot {d}
FallbackResource /index.php
ErrorLog {h}/error.log
LogLevel warn
<Directory />
    AllowOverride None
    Require all granted
</Directory>
<FilesMatch "\\.php$">
    SetHandler "proxy:fcgi://127.0.0.1:{fpm}"
</FilesMatch>
'''.format(h=run / 'httpd', port=HTTP_PORT, m=MODS, d=docroot, fpm=FPM_PORT))


def wait_http(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                              'http://127.0.0.1:%d/health' % HTTP_PORT],
                             capture_output=True, text=True)
        if res.stdout == '200':
            return True
        time.sleep(0.3)
    return False


def fpm_rss_kb(master_pid):
    res = subprocess.run(['ps', '-o', 'rss=', '--ppid', str(master_pid)],
                         capture_output=True, text=True)
    return [int(x) for x in res.stdout.split()]


def ab(args_extra, url, n, c, out_csv):
    cmd = ['ab', '-q', '-n', str(n), '-c', str(c), '-e', str(out_csv)] + args_extra + [url]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    text = res.stdout
    rps = re.search(r'Requests per second:\s+([\d.]+)', text)
    failed = re.search(r'Failed requests:\s+(\d+)', text)
    non2xx = re.search(r'Non-2xx responses:\s+(\d+)', text)
    pct = {}
    if out_csv.exists():
        for line in out_csv.read_text().splitlines()[1:]:
            p, ms = line.split(',')
            pct[int(float(p))] = float(ms)
    return dict(rc=res.returncode, rps=float(rps.group(1)) if rps else None,
                failed=int(failed.group(1)) if failed else None,
                non2xx=int(non2xx.group(1)) if non2xx else 0,
                p50_ms=pct.get(50), p95_ms=pct.get(95), p99_ms=pct.get(99),
                stderr=res.stderr[-300:],
                # keep ab's own output when it could not be parsed
                stdout_tail=None if rps else text[-600:])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--build', default='8.4.27-normalext')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('-n', type=int, default=5000)
    parser.add_argument('-c', type=int, default=8)
    args = parser.parse_args()
    prefix = BASE / 'install' / args.build
    if not (prefix / 'sbin/php-fpm').exists():
        print(json.dumps(dict(error='build missing', prefix=str(prefix))))
        return 1
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    run = BASE / 'evidence' / ('coreguard-perf-%s-%s%s' % (stamp, args.build,
                                                           '-' + CG_MODE if CG_MODE else ''))
    run.mkdir(parents=True)
    write_configs(run, prefix)
    bodies = run / 'bodies'
    bodies.mkdir()
    (bodies / 'unser.bin').write_bytes(b'a:2:{i:0;s:3:"abc";i:1;a:1:{s:1:"k";i:7;}}')
    boundary = 'labboundary'
    (bodies / 'upload.bin').write_bytes(
        ('--%s\r\nContent-Disposition: form-data; name="file"; filename="b.bin"\r\n'
         'Content-Type: application/octet-stream\r\n\r\n' % boundary).encode()
        + b'L' * 16384 + ('\r\n--%s--\r\n' % boundary).encode())
    url = 'http://127.0.0.1:%d' % HTTP_PORT
    workloads = {
        'health': ([], url + '/health'),
        'session': ([], url + '/session'),
        'unser_small': (['-p', str(bodies / 'unser.bin'), '-T', 'application/octet-stream'],
                        url + '/unserialize'),
        'upload_small': (['-p', str(bodies / 'upload.bin'),
                          '-T', 'multipart/form-data; boundary=' + boundary], url + '/upload'),
    }
    fpm = subprocess.Popen([str(prefix / 'sbin/php-fpm'), '-c', str(run / 'php.ini'),
                            '-y', str(run / 'php-fpm.conf'), '-F'],
                           stdout=(run / 'fpm.out').open('w'), stderr=subprocess.STDOUT)
    httpd = subprocess.run(['apache2', '-f', str(run / 'httpd.conf'), '-k', 'start'],
                           capture_output=True, text=True)
    results = dict(workloads={}, bench=[])
    status = 'ok'
    try:
        if httpd.returncode != 0 or not wait_http():
            status = 'harness_failed'
            results['error'] = 'server not ready: ' + httpd.stderr[-300:]
        else:
            for name, (extra, target) in workloads.items():
                # warm-up (opcache, session dir), not recorded
                ab(extra, target, 500, args.c, run / ('warm-%s.csv' % name))
                reps = []
                for r in range(args.repeats):
                    rec = ab(extra, target, args.n, args.c, run / ('%s-%d.csv' % (name, r)))
                    rec['fpm_worker_rss_kb'] = fpm_rss_kb(fpm.pid)
                    reps.append(rec)
                    if rec['rps'] is None or rec['failed'] or rec['non2xx']:
                        status = 'degraded'
                results['workloads'][name] = reps
    finally:
        subprocess.run(['apache2', '-f', str(run / 'httpd.conf'), '-k', 'stop'],
                       capture_output=True)
        fpm.send_signal(signal.SIGQUIT)
        try:
            fpm.wait(timeout=10)
        except subprocess.TimeoutExpired:
            fpm.kill()
    # Engine CPU: Zend/bench.php from a clean archive of the build's source.
    version = args.build.split('-')[0]
    src = BASE / 'sources' / ('php-' + version)
    bench = run / 'bench.php'
    arch = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(src), 'show',
                           'HEAD:Zend/bench.php'], capture_output=True)
    if arch.returncode == 0:
        bench.write_bytes(arch.stdout)
        for r in range(args.repeats):
            t0 = time.time()
            res = subprocess.run([str(prefix / 'bin/php'), '-n', str(bench)],
                                 capture_output=True, text=True, timeout=600)
            total = re.search(r'Total\s+([\d.]+)', res.stdout)
            results['bench'].append(dict(rc=res.returncode, wall_s=round(time.time() - t0, 3),
                                         total_s=float(total.group(1)) if total else None,
                                         opcache=False))
    # availability: worker exits seen by the fpm master (restart rate)
    fpm_log = (run / 'fpm.log').read_text(errors='replace') if (run / 'fpm.log').exists() else ''
    results['fpm_worker_exits'] = len(re.findall(r'exited (?:with code|on signal)', fpm_log))
    # The session workload leaves one file per request (~15k per run): keep
    # them as one archive so evidence sync does not copy them one by one.
    sess = run / 'sessions'
    results['session_files'] = sum(1 for _ in sess.iterdir())
    if results['session_files']:
        subprocess.run(['tar', '-czf', str(sess) + '.tar.gz', '-C', str(run), 'sessions'],
                       check=True)
        shutil.rmtree(sess)
    manifest = prefix / 'build-manifest.json'
    summary = dict(scope='CoreGuard Phase 0 performance baseline (relative use only)',
                   build=args.build, coreguard_mode=CG_MODE, status=status, n=args.n, c=args.c, repeats=args.repeats,
                   host=dict(nproc=os.cpu_count(), uname=os.uname().release),
                   build_manifest=json.loads(manifest.read_text()) if manifest.exists() else None,
                   results=results, **provenance.provenance())
    (run / 'summary.json').write_text(json.dumps(summary, indent=2))
    brief = {k: dict(rps=[r['rps'] for r in v], p95=[r['p95_ms'] for r in v])
             for k, v in results['workloads'].items()}
    print(json.dumps(dict(run=str(run), status=status, citable=summary['citable'],
                          workloads=brief, bench=[b['total_s'] for b in results['bench']]),
                     indent=2))
    return 0 if status == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
