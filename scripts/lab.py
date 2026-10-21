"""Project-local PHP lab lifecycle; Python standard library only."""
import argparse
import hashlib
import http.cookiejar
import json
from pathlib import Path
import subprocess
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '8.4.4'
PHP = ROOT / 'runtime' / ('php-' + VERSION) / 'php.exe'
URL = 'https://downloads.php.net/~windows/releases/archives/php-8.4.4-nts-Win32-vs17-x64.zip'
SOURCE = 'https://codeload.github.com/php/php-src/zip/refs/tags/php-8.4.4'

def setup():
    for name in ('downloads', 'runtime', 'sources', 'var/sessions', 'var/uploads', 'var/logs'):
        (ROOT / name).mkdir(parents=True, exist_ok=True)
    records = []
    for url, filename, target in (
        (URL, 'php-8.4.4-windows.zip', PHP.parent),
        (SOURCE, 'php-src-8.4.4.zip', ROOT / 'sources'),
    ):
        archive = ROOT / 'downloads' / filename
        if not archive.exists():
            part = archive.with_suffix('.partial')
            print('Downloading', url, flush=True)
            urllib.request.urlretrieve(url, part)
            part.replace(archive)
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                if not (target / member).resolve().is_relative_to(target.resolve()):
                    raise RuntimeError('Unsafe archive member')
            zf.extractall(target)
        records.append({'url': url, 'archive': str(archive.relative_to(ROOT)),
                        'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})
    (ROOT / 'var/download-manifest.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
    subprocess.run([str(PHP), '-n', '-v'], check=True)

def command(port):
    if not PHP.exists():
        raise RuntimeError('Run python scripts/lab.py setup first')
    for name in ('sessions', 'uploads', 'logs'):
        (ROOT / 'var' / name).mkdir(parents=True, exist_ok=True)
    return [str(PHP), '-c', str(ROOT / 'config/php.ini'),
            '-d', 'session.save_path=' + str(ROOT / 'var/sessions'),
            '-d', 'upload_tmp_dir=' + str(ROOT / 'var/uploads'),
            '-d', 'error_log=' + str(ROOT / 'var/logs/php-error.log'),
            '-S', '127.0.0.1:' + str(port), '-t', str(ROOT / 'web'), str(ROOT / 'web/index.php')]

def smoke(port):
    # Bind failures must not accidentally test a pre-existing service.
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))
    log_path = ROOT / 'var/logs/server-smoke.log'
    cmd = command(port)
    checks = []
    with log_path.open('wb') as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=log,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            base = 'http://127.0.0.1:' + str(port)
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            def request(path, data=None, headers=None):
                with opener.open(urllib.request.Request(base + path, data=data, headers=headers or {}), timeout=5) as r:
                    return json.load(r)
            for attempt in range(50):
                if proc.poll() is not None:
                    raise RuntimeError('PHP exited; see ' + str(log_path))
                try:
                    health = request('/health')
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('PHP startup timeout')
            assert health['ok'] and health['php'] == VERSION, health
            checks.append({'name': 'health', 'result': health})
            assert request('/session')['visits'] == 1
            assert request('/session')['visits'] == 2
            checks.append({'name': 'session_cookie_roundtrip', 'ok': True})
            payload = b'benign-environment-check\n'
            boundary = 'PHPEnvironmentSmokeBoundary'
            body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="check.txt"\r\nContent-Type: text/plain\r\n\r\n').encode() + payload + ('\r\n--' + boundary + '--\r\n').encode()
            result = request('/upload', body, {'Content-Type': 'multipart/form-data; boundary=' + boundary})
            assert result == {'ok': True, 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}, result
            checks.append({'name': 'multipart_tempfile_sha256', 'result': result})
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    report = {'scope': 'environment smoke only; no vulnerability reproduction',
              'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'checks': checks, 'server_stopped': proc.poll() is not None}
    target = ROOT / 'var/smoke-result.json'
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('setup', 'serve', 'smoke'))
    parser.add_argument('--port', type=int, default=18084)
    args = parser.parse_args()
    if args.action == 'setup':
        setup()
    elif args.action == 'serve':
        try:
            subprocess.run(command(args.port), check=True)
        except KeyboardInterrupt:
            pass
    else:
        smoke(args.port)
