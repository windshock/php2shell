#!/usr/bin/env python3
"""Harmless E2E probes for the pre-patch PHP2Shell analysis (plan section 5).

Local loopback lab only. No public PoC code is downloaded or executed:
every request below is built from scratch from documented PHP behavior
(session upload progress) plus normal/abnormal HTTP inputs. The probes
OBSERVE behavior and memory-safety reports; they never attempt to control
freed memory or execute attacker code. An ASAN report is a finding, not a
step towards exploitation.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
HTTP_PORT, FPM_PORT = 18085, 19085

PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'
SESSION_FIELD = 'PHPSESSID'


def checked(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def worker_pid(out):
    master = int((out / 'fpm.pid').read_text().strip())
    children = subprocess.check_output(['pgrep', '-P', str(master)], text=True).split()
    return children[0] if children else None


class Lab:
    """One single-worker FPM + nginx instance with its own evidence folder."""

    def __init__(self, version, flavor, allocator, buffering, ini_extra, profile):
        if not re.fullmatch(r'8\.[0-9]+\.[0-9]+', version):
            raise ValueError('Expected stable 8.x.y version')
        self.version, self.flavor = version, flavor
        self.allocator, self.buffering, self.profile = allocator, buffering, profile
        self.prefix = BASE / 'install' / (version + '-' + flavor)
        self.manifest = json.loads((self.prefix / 'build-manifest.json').read_text())
        stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + str(os.getpid())
        self.out = BASE / 'evidence' / (f'probe-{profile}-{stamp}-{version}-{flavor}-{allocator}-{buffering}')
        for name in ('sessions', 'uploads', 'nginx'):
            (self.out / name).mkdir(parents=True)
        self.env = os.environ.copy()
        self.env.update(
            ASAN_OPTIONS=(f'detect_leaks=0:abort_on_error=1:symbolize=1:'
                          f'log_path={self.out}/asan'),
            ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
        self.env['USE_ZEND_ALLOC'] = '1' if allocator == 'zend' else '0'
        self.env['USE_TRACKED_ALLOC'] = '1' if allocator == 'tracked' else '0'
        ini = (REPO / 'config/php.ini').read_text() + '\n'
        ini += '\n'.join(ini_extra) + '\n'
        ini += (f'session.save_path={self.out}/sessions\n'
                f'upload_tmp_dir={self.out}/uploads\n'
                f'error_log={self.out}/php-error.log\n')
        (self.out / 'php.ini').write_text(ini)
        (self.out / 'fpm.conf').write_text(f'''[global]
daemonize = no
error_log = {self.out}/fpm-error.log
pid = {self.out}/fpm.pid
[lab]
user = phplab
group = phplab
listen = 127.0.0.1:{FPM_PORT}
pm = static
pm.max_children = 1
clear_env = no
catch_workers_output = yes
rlimit_core = 0
access.log = {self.out}/fpm-access.log
''')
        (self.out / 'nginx.conf').write_text(f'''daemon off;
pid {self.out}/nginx.pid;
error_log {self.out}/nginx-error.log;
events {{ worker_connections 64; }}
http {{
 access_log {self.out}/nginx-access.log;
 client_body_temp_path {self.out}/nginx;
 fastcgi_temp_path {self.out}/nginx;
 proxy_temp_path {self.out}/nginx;
 uwsgi_temp_path {self.out}/nginx;
 scgi_temp_path {self.out}/nginx;
 server {{
  listen 127.0.0.1:{HTTP_PORT};
  client_max_body_size 4m;
  location / {{
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME {REPO}/web/index.php;
   fastcgi_pass 127.0.0.1:{FPM_PORT};
   fastcgi_request_buffering {buffering};
  }}
 }}
}}
''')
        self.processes = []
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, path, data=None, headers=None, timeout=8):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (HTTP_PORT, path),
                                     data=data, headers=headers or {})
        with self.opener.open(req, timeout=timeout) as res:
            return json.load(res)

    def start(self):
        for port in (FPM_PORT, HTTP_PORT):
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))
        for name, cmd in (('fpm', [str(self.prefix / 'sbin/php-fpm'), '-c', str(self.out / 'php.ini'),
                                   '-y', str(self.out / 'fpm.conf')]),
                          ('nginx', ['/usr/sbin/nginx', '-p', str(self.out), '-c', str(self.out / 'nginx.conf')])):
            log = (self.out / (name + '-console.log')).open('w')
            self.processes.append((log, subprocess.Popen(cmd, env=self.env, stdout=log,
                                                         stderr=subprocess.STDOUT, start_new_session=True)))
        deadline = time.time() + 15
        while time.time() < deadline:
            if any(p.poll() is not None for _, p in self.processes):
                raise RuntimeError('server startup failed; inspect ' + str(self.out))
            try:
                health = self.request('/health', timeout=2)
                if health.get('ok'):
                    return health
            except Exception:
                time.sleep(0.15)
        raise RuntimeError('server startup timeout; inspect ' + str(self.out))

    def wait_health(self, timeout=15):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                last = self.request('/health', timeout=2)
                if last.get('ok'):
                    return last
            except Exception as exc:
                last = str(exc)
            time.sleep(0.3)
        return last

    def asan_reports(self):
        return sorted(str(p) for p in self.out.glob('asan.*') if p.is_file())

    def php_error_log(self):
        path = self.out / 'php-error.log'
        return path.read_text(errors='replace') if path.exists() else ''

    def stop(self):
        for _, proc in reversed(self.processes):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        for handle, _ in self.processes:
            handle.close()


# ---------------------------------------------------------------- HTTP probe client

def multipart(port, path, fields, file_spec=None, cookie=None, sampler=None,
              abort_after=None, chunk_size=16384, chunk_delay=0.12,
              boundary=None):
    """Send a multipart/form-data POST over a raw socket.

    fields: list of (name, value) form fields, sent in order before the file.
    file_spec: (field_name, filename, payload_bytes).
    sampler: callable() -> snapshot taken after each file chunk (with delay).
    abort_after: number of file chunks to send before abruptly closing (RST).
    Returns dict(aborted, status, body, samples, elapsed).
    """
    boundary = boundary or ('ProbeBnd' + secrets.token_hex(8))
    head_parts = []
    for name, value in fields:
        head_parts.append(
            ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
             % (boundary, name, value)).encode())
    file_header = b''
    payload = b''
    if file_spec:
        field, filename, payload = file_spec
        file_header = ('--%s\r\nContent-Disposition: form-data; name="%s"; '
                       'filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n'
                       % (boundary, field, filename)).encode()
    tail = ('\r\n--%s--\r\n' % boundary).encode()
    total = (sum(len(p) for p in head_parts) + len(file_header) + len(payload)
             + len(tail))
    request_head = ('POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                    'Content-Type: multipart/form-data; boundary=%s\r\n'
                    'Content-Length: %d\r\nConnection: close\r\n'
                    % (path, boundary, total))
    if cookie:
        request_head += 'Cookie: %s\r\n' % cookie
    request_head += '\r\n'
    samples, chunks_sent = [], 0
    started = time.time()
    sock = socket.create_connection(('127.0.0.1', port), timeout=8)
    sock.settimeout(8)
    try:
        sock.sendall(request_head.encode())
        for part in head_parts:
            sock.sendall(part)
        if file_spec:
            sock.sendall(file_header)
            for offset in range(0, len(payload), chunk_size):
                if abort_after is not None and chunks_sent >= abort_after:
                    linger = struct_linger_zero()
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    sock.close()
                    return dict(aborted=True, status=None, body=b'', samples=samples,
                                elapsed=time.time() - started, chunks_sent=chunks_sent)
                sock.sendall(payload[offset:offset + chunk_size])
                chunks_sent += 1
                if sampler is not None:
                    time.sleep(chunk_delay)
                    samples.append(sampler())
            sock.sendall(tail)
        else:
            sock.sendall(tail)
        body = b''
        while True:
            try:
                block = sock.recv(65536)
            except socket.timeout:
                break
            if not block:
                break
            body += block
        status = None
        match = re.match(rb'HTTP/1\.[01] (\d+)', body)
        if match:
            status = int(match.group(1))
        return dict(aborted=False, status=status, body=body, samples=samples,
                    elapsed=time.time() - started, chunks_sent=chunks_sent)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def struct_linger_zero():
    # struct linger { int l_onoff; int l_linger; } = 1, 0 -> RST on close.
    import struct
    return struct.pack('ii', 1, 0)


def session_snapshot(lab, keys):
    """Read lab session files; report progress keys and bytes_processed."""
    found = {}
    for path in sorted((lab.out / 'sessions').glob('sess_*')):
        try:
            text = path.read_text(errors='replace')
        except OSError:
            continue
        for key in keys:
            marker = 'upload_progress_' + key
            if marker in text:
                value = re.search(r'bytes_processed";i:(\d+)', text)
                found[key] = dict(file=path.name,
                                  bytes_processed=int(value.group(1)) if value else None,
                                  session_bytes=len(text))
    return found


# ---------------------------------------------------------------- probes

def sanity(lab, report):
    php = str(lab.prefix / 'bin/php')
    version_out = checked([php, '-n', '-v'], capture_output=True, text=True).stdout
    report['checks'].append(dict(name='php_version', output=version_out.splitlines()[0]))
    test = str(REPO / 'linux/tests/serialize_session.phpt')
    log = lab.out / 'phpt.log'
    env = dict(lab.env, NO_INTERACTION='1', REPORT_EXIT_STATUS='1')
    with log.open('w') as handle:
        checked([php, '-n', str(BASE / 'sources' / ('php-' + lab.version) / 'run-tests.php'),
                 '-n', '-q', '--offline', '-p', php, test],
                env=env, stdout=handle, stderr=subprocess.STDOUT)
    if not re.search(r'Tests passed\s*:\s*1\s+\(100\.0%\)', log.read_text()):
        raise RuntimeError('PHPT pre-check failed; inspect ' + str(log))
    report['checks'].append(dict(name='phpt_precheck', result='1/1 passed'))


def probe_reachability(lab, probes):
    """P1/P2: progress key appears mid-upload, bytes grow, cleaned afterwards."""
    visits = lab.request('/session')
    assert visits['visits'] >= 1, visits
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    key = 'p1'
    payload = b'A' * (256 * 1024)
    result = multipart(HTTP_PORT, '/upload',
                       fields=[(PROGRESS_FIELD, key)],
                       file_spec=('file', 'p1.bin', payload),
                       cookie=f'PHPSESSID={sid}',
                       sampler=lambda: session_snapshot(lab, [key]))
    mid = [s for s in result['samples'] if key in s]
    growing = [s[key]['bytes_processed'] for s in mid]
    after = session_snapshot(lab, [key])
    session_file = lab.out / 'sessions' / ('sess_' + sid)
    after_text = session_file.read_text(errors='replace') if session_file.exists() else ''
    probes.append(dict(
        name='P1_P2_reachability_lifecycle',
        buffering=lab.buffering,
        response_status=result['status'],
        upload_ok=(b'"ok":true' in result['body'] and str(len(payload)).encode() in result['body']),
        mid_upload_observations=len(mid),
        bytes_processed_series=growing,
        key_present_mid_upload=bool(mid),
        key_removed_after_completion=(key not in after),
        visits_survived=('visits|i:1' in after_text),
        worker_pid=worker_pid(lab.out),
        verdict=dict(
            progress_key_reachable=bool(mid) if lab.buffering == 'off' else 'not_observable_with_buffering_on',
            bytes_monotonic=(len(set(growing)) >= 2) if lab.buffering == 'off' else 'not_observable_with_buffering_on',
            cleanup_observed=(key not in after))))


def probe_abort(lab, probes):
    """P3: abrupt client abort mid-file-data."""
    before = lab.request('/session')['visits']
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    key = 'p3'
    payload = b'B' * (192 * 1024)
    result = multipart(HTTP_PORT, '/upload',
                       fields=[(PROGRESS_FIELD, key)],
                       file_spec=('file', 'p3.bin', payload),
                       cookie=f'PHPSESSID={sid}',
                       sampler=lambda: session_snapshot(lab, [key]),
                       abort_after=4)
    time.sleep(0.5)
    state = session_snapshot(lab, [key])
    health = lab.request('/health')
    after = lab.request('/session')['visits']
    probes.append(dict(
        name='P3_client_abort',
        aborted=result['aborted'], chunks_sent=result['chunks_sent'],
        mid_abort_samples=[s for s in result['samples'] if key in s],
        key_state_after_abort=state,
        visits_before=before, visits_after=after,
        health_ok_after_abort=health.get('ok') is True,
        session_usable_after_abort=(after == before + 1),
        worker_pid=worker_pid(lab.out),
        verdict=dict(worker_survived_abort=health.get('ok') is True,
                     session_service_recovered=(after == before + 1),
                     progress_key_cleaned_on_abort=(key not in state))))


def probe_interleave(lab, probes):
    """P4: session roundtrips + progress uploads + aborts on one worker."""
    expected_visits = lab.request('/session')['visits']
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    for index in range(10):
        expected_visits += 1
        assert lab.request('/session')['visits'] == expected_visits, (index, expected_visits)
        key = 'p4%d' % index
        payload = b'C' * (48 * 1024)
        multipart(HTTP_PORT, '/upload',
                  fields=[(PROGRESS_FIELD, key)],
                  file_spec=('file', 'p4.bin', payload),
                  cookie=f'PHPSESSID={sid}',
                  abort_after=2 if index % 3 == 0 else None)
    expected_visits += 1
    final = lab.request('/session')
    probes.append(dict(
        name='P4_serialize_interleave',
        rounds=10, abort_rounds=[i for i in range(10) if i % 3 == 0],
        final_visits=final.get('visits'), expected_visits=expected_visits,
        worker_pid=worker_pid(lab.out),
        verdict=dict(visits_consistent=final.get('visits') == expected_visits,
                     worker_reused=True)))


def probe_malformed(lab, probes):
    """P5: malformed / boundary multipart inputs; robustness observation only."""
    cases = []
    # (a) truncated body: no terminating boundary, plain close.
    body = (b'--bndX\r\nContent-Disposition: form-data; name="f"; filename="x.bin"\r\n\r\n'
            + b'D' * 2048)
    cases.append(('truncated_close', body, None))
    # (b) duplicate progress fields, one empty.
    cases.append(('duplicate_progress_fields', None,
                  [(PROGRESS_FIELD, 'p5dup'), (PROGRESS_FIELD, ''), (PROGRESS_FIELD, 'p5dup2')]))
    # (c) many small parts.
    cases.append(('many_parts', None, [('f%d' % i, 'v' * 10) for i in range(200)]))
    # (d) long filename.
    cases.append(('long_filename', None, None))  # handled below
    # (e) empty field name part.
    body_e = (b'--bndE\r\nContent-Disposition: form-data; name=""\r\n\r\nvalue\r\n'
              b'--bndE\r\nContent-Disposition: form-data; name="file"; filename="e.bin"\r\n\r\n'
              + b'E' * 128 + b'\r\n--bndE--\r\n')
    cases.append(('empty_field_name', body_e, None))
    # (f) progress value with serializer metacharacters.
    cases.append(('progress_value_metachars', None, None))
    observations = []
    for name, raw, fields in cases:
        if name == 'long_filename':
            payload = b'F' * 128
            res = multipart(HTTP_PORT, '/upload',
                            fields=[(PROGRESS_FIELD, 'p5long')],
                            file_spec=('file', 'x' * 4096 + '.bin', payload))
        elif name == 'progress_value_metachars':
            res = multipart(HTTP_PORT, '/upload',
                            fields=[(PROGRESS_FIELD, 'a|b";c')],
                            file_spec=('file', 'p5m.bin', b'G' * 2048))
            if res['status'] == 200:
                time.sleep(0.3)
                lab.request('/session')  # next read of the polluted session
                time.sleep(0.3)
        elif raw is not None:
            sock = socket.create_connection(('127.0.0.1', HTTP_PORT), timeout=6)
            try:
                head = ('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                        'Content-Type: multipart/form-data; boundary=%s\r\n'
                        'Content-Length: %d\r\nConnection: close\r\n\r\n'
                        % ('bndX' if name == 'truncated_close' else 'bndE', len(raw)))
                sock.sendall(head.encode() + raw)
                sock.shutdown(socket.SHUT_WR)
                data = b''
                while True:
                    try:
                        block = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not block:
                        break
                    data += block
                res = dict(aborted=False,
                           status=int(re.match(rb'HTTP/1\.[01] (\d+)', data).group(1)) if re.match(rb'HTTP/1\.[01] (\d+)', data) else None,
                           body=data, samples=[], elapsed=0, chunks_sent=0)
            finally:
                sock.close()
        else:
            res = multipart(HTTP_PORT, '/upload', fields=fields,
                            file_spec=('file', 'p5.bin', b'H' * 256) if name != 'many_parts' else None)
        health = lab.request('/health', timeout=4) if res['status'] is not None else lab.wait_health(10)
        observations.append(dict(case=name, status=res['status'], health_ok=health.get('ok') is True,
                                 worker_pid=worker_pid(lab.out)))
    log = lab.php_error_log()
    probes.append(dict(
        name='P5_malformed_multipart',
        observations=observations,
        decode_warning_seen=('Failed to decode session object' in log),
        verdict=dict(all_workers_alive=all(o['health_ok'] for o in observations),
                     metachar_session_destroy_warning=('Failed to decode session object' in log))))


def probe_session_id_paths(lab, probes, strict):
    """P7: multipart form-field session id (no cookie); P7b uses strict=off."""
    lab.request('/session')
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    lab.jar.clear()
    key = 'p7'
    payload = b'I' * (128 * 1024)
    result = multipart(HTTP_PORT, '/upload',
                       fields=[(SESSION_FIELD, sid), (PROGRESS_FIELD, key)],
                       file_spec=('file', 'p7.bin', payload),
                       sampler=lambda: session_snapshot(lab, [key]))
    mid = [s for s in result['samples'] if key in s]
    created = None
    if not strict:
        target = 'p7b' + secrets.token_hex(8)
        multipart(HTTP_PORT, '/upload',
                  fields=[(SESSION_FIELD, target), (PROGRESS_FIELD, 'p7b')],
                  file_spec=('file', 'p7b.bin', b'J' * 2048))
        time.sleep(0.3)
        path = lab.out / 'sessions' / ('sess_' + target)
        created = dict(requested_name='sess_' + target, file_created=path.exists(),
                       size=path.stat().st_size if path.exists() else None,
                       content_head=path.read_text(errors='replace')[:120] if path.exists() else None)
    probes.append(dict(
        name='P7_session_id_via_form_field' + ('' if strict else '_lax'),
        strict_mode=strict,
        cookie_sent=False,
        response_status=result['status'],
        target_session_file=('sess_' + sid),
        key_written_into_target_session=bool(mid) if lab.buffering == 'off' else None,
        chosen_name_file_creation=created,
        verdict=dict(
            form_field_sid_honored=bool(mid) if lab.buffering == 'off' else 'not_observable_with_buffering_on',
            chosen_name_session_file_created=(created['file_created'] if created else None))))


def probe_oom_residue(lab, probes, handler='php'):
    """P6: graceful memory-limit bailout during parse, then reuse probe.

    Request N decodes+re-encodes a ~3MB forged session under memory_limit=8M
    (tracked allocator enforces the limit with a graceful fatal error). The
    encode is expected to exceed the limit mid-serialization, skipping
    PHP_VAR_SERIALIZE_DESTROY and leaving BG(serialize) residue. Request N+1
    on the same worker performs another parse-time encode, which would reuse
    the residual context if the hypothesis holds. Observation only: any ASAN
    report is recorded and the probe stops there.
    """
    limit_bytes = 8 * 1024 * 1024
    sid_big = 'p6big' + secrets.token_hex(8)
    sid_small = 'p6small' + secrets.token_hex(8)
    big = 'A' * (3 * 1024 * 1024)
    if handler == 'php':
        big_session = 'big|s:%d:"%s";' % (len(big), big)
        small_session = 'small|a:1:{i:0;i:7;}'
    else:  # php_serialize: the whole session file is one serialized array
        big_session = 'a:1:{s:3:"big";s:%d:"%s";}' % (len(big), big)
        small_session = 'a:1:{s:5:"small";a:1:{i:0;i:7;}}'
    (lab.out / 'sessions' / ('sess_' + sid_big)).write_text(big_session)
    (lab.out / 'sessions' / ('sess_' + sid_small)).write_text(small_session)
    pid_before = worker_pid(lab.out)

    request_n = multipart(HTTP_PORT, '/upload',
                          fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'p6n')],
                          file_spec=('file', 'n.bin', b'K' * 32768))
    time.sleep(0.5)
    log_after_n = lab.php_error_log()
    oom_seen = 'Allowed memory size of' in log_after_n
    pid_after_n = worker_pid(lab.out)

    asan_before = lab.asan_reports()
    request_n1 = None
    pid_after_n1 = None
    health_after = None
    if not asan_before:
        request_n1 = multipart(HTTP_PORT, '/upload',
                               fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'p6n1')],
                               file_spec=('file', 'n1.bin', b'L' * 16384))
        time.sleep(0.5)
        pid_after_n1 = worker_pid(lab.out)
        health_after = lab.wait_health(20)
    asan_after = lab.asan_reports()
    stacks = []
    for report_path in asan_after:
        text = Path(report_path).read_text(errors='replace')
        stacks.append(dict(file=str(report_path), head=text[:3000]))
    fpm_error = (lab.out / 'fpm-error.log').read_text(errors='replace') if (lab.out / 'fpm-error.log').exists() else ''
    probes.append(dict(
        name='P6_oom_serialize_residue',
        serialize_handler=handler,
        memory_limit_bytes=limit_bytes,
        request_n=dict(status=request_n['status'], aborted=request_n['aborted'],
                       elapsed=round(request_n['elapsed'], 2)),
        oom_fatal_logged=oom_seen,
        worker_pid=dict(before=pid_before, after_n=pid_after_n, after_n1=pid_after_n1),
        request_n1=(None if request_n1 is None else
                    dict(status=request_n1['status'], aborted=request_n1['aborted'],
                         elapsed=round(request_n1['elapsed'], 2))),
        health_after_n1=(None if health_after is None else
                         (health_after if isinstance(health_after, str) else dict(health_after))),
        asan_reports=asan_after,
        asan_stacks=stacks,
        worker_exited_on_signal=re.findall(r'exited on signal \d+', fpm_error),
        verdict=dict(
            graceful_oom_bailout=oom_seen,
            worker_survived_oom=(pid_before == pid_after_n),
            residue_reuse_uaf_observed=bool(asan_after))))


def probe_progress_disabled(lab, probes):
    """P9: with session.upload_progress.enabled=Off the parse-time path must not fire."""
    visits = lab.request('/session')['visits']
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    key = 'off1'
    payload = b'O' * (64 * 1024)
    result = multipart(HTTP_PORT, '/upload',
                       fields=[(PROGRESS_FIELD, key)],
                       file_spec=('file', 'off.bin', payload),
                       cookie='PHPSESSID=' + sid,
                       sampler=lambda: session_snapshot(lab, [key]),
                       chunk_size=32768, chunk_delay=0.05)
    mid = [s for s in result['samples'] if key in s]
    after = lab.request('/session')['visits']
    probes.append(dict(
        name='P9_progress_disabled_control',
        response_status=result['status'],
        upload_ok=(b'"ok":true' in result['body']),
        progress_key_observed=bool(mid),
        visits_consistent=(after == visits + 1),
        worker_pid=worker_pid(lab.out),
        verdict=dict(progress_path_disabled=not mid,
                     upload_still_works=(b'"ok":true' in result['body']))))


def probe_part_limit(lab, probes):
    """P11: does MULTIPART_EVENT_END (and progress cleanup) still run when the
    max_multipart_body_parts limit is exceeded? 19h claimed END is skipped;
    rfc1867.c:795-797 jumps to fileupload_done which emits END at :1267-1272.
    The file part is sent BEFORE the extra fields so progress data exists when
    the limit trips."""
    lab.request('/session')
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    key = 'pl1'
    boundary = 'ProbeParts' + secrets.token_hex(6)
    body = b''
    body += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
             % (boundary, PROGRESS_FIELD, key)).encode()
    body += ('--%s\r\nContent-Disposition: form-data; name="file"; filename="pl.bin"\r\n'
             'Content-Type: application/octet-stream\r\n\r\n' % boundary).encode()
    body += b'P' * 1024 + b'\r\n'
    for index in range(10):
        body += ('--%s\r\nContent-Disposition: form-data; name="f%d"\r\n\r\nv\r\n'
                 % (boundary, index)).encode()
    body += ('--%s--\r\n' % boundary).encode()
    sock = socket.create_connection(('127.0.0.1', HTTP_PORT), timeout=8)
    try:
        head = ('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                'Content-Type: multipart/form-data; boundary=%s\r\n'
                'Content-Length: %d\r\nConnection: close\r\nCookie: PHPSESSID=%s\r\n\r\n'
                % (boundary, len(body), sid))
        sock.sendall(head.encode() + body)
        data = b''
        while True:
            block = sock.recv(65536)
            if not block:
                break
            data += block
    finally:
        sock.close()
    status = None
    match = re.match(rb'HTTP/1\.[01] (\d+)', data)
    if match:
        status = int(match.group(1))
    time.sleep(0.4)
    state = session_snapshot(lab, [key])
    log = lab.php_error_log()
    limit_hit = 'Multipart body parts limit exceeded' in log
    probes.append(dict(
        name='P11_multipart_part_limit',
        response_status=status,
        part_limit_hit=limit_hit,
        progress_key_after=state,
        key_removed=(key not in state),
        verdict=dict(limit_observed=limit_hit,
                     end_and_cleanup_ran=(limit_hit and key not in state),
                     key_retained=(key in state))))


def probe_cleanup_off(lab, probes):
    """P13: with cleanup=Off the progress entry must REMAIN after completion."""
    lab.request('/session')
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    key = 'co1'
    payload = b'C' * (64 * 1024)
    result = multipart(HTTP_PORT, '/upload',
                       fields=[(PROGRESS_FIELD, key)],
                       file_spec=('file', 'co.bin', payload),
                       cookie=f'PHPSESSID={sid}')
    time.sleep(0.4)
    state = session_snapshot(lab, [key])
    session_file = lab.out / 'sessions' / ('sess_' + sid)
    text = session_file.read_text(errors='replace') if session_file.exists() else ''
    probes.append(dict(
        name='P13_cleanup_off_retention',
        response_status=result['status'],
        progress_key_after=state,
        key_retained=(key in state),
        done_flag=('done";b:1' in text),
        verdict=dict(retention_confirmed=(key in state),
                     done_flag_set=('done";b:1' in text))))


def probe_http_only_arm(lab, probes):
    """P12: can HTTP input alone (no forged session) produce a parse-time OOM?

    Sends many large form fields plus a progress field. This exercises the
    request parser's own allocations (post array growth), not session decode.
    """
    lab.request('/session')
    sid = [c.value for c in lab.jar if c.name == 'PHPSESSID'][0]
    fields = [(PROGRESS_FIELD, 'arm1')]
    fields += [('f%03d' % i, 'x' * 4096) for i in range(900)]
    result = multipart(HTTP_PORT, '/upload', fields=fields,
                       file_spec=('file', 'arm.bin', b'A' * 1024),
                       cookie=f'PHPSESSID={sid}', chunk_size=65536, chunk_delay=0.0)
    time.sleep(0.5)
    log = lab.php_error_log()
    oom = 'Allowed memory size of' in log
    health = None
    try:
        health = lab.request('/health', timeout=5)
    except Exception as exc:
        health = str(exc)
    probes.append(dict(
        name='P12_http_only_arm',
        field_count=len(fields),
        response_status=result['status'],
        oom_from_http_only=oom,
        worker_alive_after=(isinstance(health, dict) and health.get('ok') is True),
        worker_pid=worker_pid(lab.out),
        verdict=dict(http_only_oom_observed=oom,
                     worker_survived=(isinstance(health, dict) and health.get('ok') is True))))


def probe_oom_parse(lab, probes):
    """P14: CVE-2026-109618 direction — OOM while the POST parser is still
    building nested arrays. The 8.4.27 fix adds ZEND_HAS_OOM() early exits in
    php_variables.c/rfc1867.c and a memory_hard_limit_percent headroom.

    Sends urlencoded nested-array parameters large enough to exhaust
    memory_limit inside php_register_variable* during request parsing.
    Observation only: records ASAN reports and worker state.
    """
    lab.request('/session')
    pid_before = worker_pid(lab.out)
    pairs = []
    for index in range(30000):
        pairs.append('a[%d][k]=v' % index)
    body = '&'.join(pairs).encode()
    sock = socket.create_connection(('127.0.0.1', HTTP_PORT), timeout=10)
    try:
        head = ('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                'Content-Type: application/x-www-form-urlencoded\r\n'
                'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(body))
        sock.sendall(head.encode() + body)
        data = b''
        while True:
            block = sock.recv(65536)
            if not block:
                break
            data += block
    finally:
        sock.close()
    status = None
    match = re.match(rb'HTTP/1\.[01] (\d+)', data)
    if match:
        status = int(match.group(1))
    snippet = data[:160].decode('latin-1', 'replace').replace('\r', ' ').replace('\n', ' ')
    time.sleep(0.5)
    log = lab.php_error_log()
    oom = 'Allowed memory size of' in log
    pid_after = worker_pid(lab.out)
    health = None
    try:
        health = lab.request('/health', timeout=5)
    except Exception as exc:
        health = str(exc)
    reports = lab.asan_reports()
    asan_detail = None
    if reports:
        text = Path(reports[-1]).read_text(errors='replace')
        asan_detail = dict(is_heap_use_after_free='heap-use-after-free' in text,
                           first_frame=next((line.strip() for line in text.splitlines()
                                             if 'php_' in line and ' in ' in line), ''))
    probes.append(dict(
        name='P14_oom_during_post_parse',
        body_bytes=len(body), parameter_count=len(pairs),
        response_status=status, response_snippet=snippet,
        oom_during_parse=oom,
        asan_reports=len(reports), asan_detail=asan_detail,
        worker_pid_before=pid_before, worker_pid_after=pid_after,
        worker_restarted=(pid_before != pid_after),
        worker_alive_after=(isinstance(health, dict) and health.get('ok') is True),
        verdict=dict(oom_observed=oom,
                     memory_error_observed=bool(asan_detail and asan_detail['is_heap_use_after_free']),
                     worker_survived_same_process=(pid_before is not None and pid_before == pid_after))))


PROFILES = {
    'standard': dict(ini_extra=['session.upload_progress.min_freq=0'], probes=lambda lab, p: (
        probe_reachability(lab, p),
        probe_abort(lab, p),
        probe_interleave(lab, p),
        probe_malformed(lab, p),
        probe_session_id_paths(lab, p, strict=True),
    )),
    'lax': dict(ini_extra=['session.upload_progress.min_freq=0',
                           'session.use_strict_mode=Off'], probes=lambda lab, p: (
        probe_session_id_paths(lab, p, strict=False),
    )),
    'oom': dict(ini_extra=['session.upload_progress.min_freq=0',
                           'memory_limit=8M'], probes=lambda lab, p: (
        probe_oom_residue(lab, p, handler='php'),
    )),
    'oomps': dict(ini_extra=['session.upload_progress.min_freq=0',
                             'session.serialize_handler=php_serialize',
                             'memory_limit=8M'], probes=lambda lab, p: (
        probe_oom_residue(lab, p, handler='php_serialize'),
    )),
    'off': dict(ini_extra=['session.upload_progress.enabled=Off',
                           'session.upload_progress.min_freq=0'], probes=lambda lab, p: (
        probe_progress_disabled(lab, p),
    )),
    'parts': dict(ini_extra=['session.upload_progress.min_freq=0',
                             'max_multipart_body_parts=3'], probes=lambda lab, p: (
        probe_part_limit(lab, p),
    )),
    'cleanup': dict(ini_extra=['session.upload_progress.min_freq=0',
                               'session.upload_progress.cleanup=Off'], probes=lambda lab, p: (
        probe_cleanup_off(lab, p),
    )),
    'arm': dict(ini_extra=['session.upload_progress.min_freq=0',
                           'memory_limit=8M'], probes=lambda lab, p: (
        probe_http_only_arm(lab, p),
    )),
    'oomparse': dict(ini_extra=['session.upload_progress.min_freq=0',
                                'memory_limit=8M', 'post_max_size=8M',
                                'max_input_vars=50000'], probes=lambda lab, p: (
        probe_oom_parse(lab, p),
    )),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['normal', 'asan'], default='asan')
    parser.add_argument('--allocator', choices=['zend', 'system', 'tracked'], default='tracked')
    parser.add_argument('--buffering', choices=['on', 'off'], default='off')
    parser.add_argument('--profile', choices=sorted(PROFILES), default='standard')
    args = parser.parse_args()

    profile = PROFILES[args.profile]
    lab = Lab(args.version, args.flavor, args.allocator, args.buffering,
              profile['ini_extra'], args.profile)
    report = dict(scope='harmless local probes; observation only; not a CVE verdict',
                  profile=args.profile, build=lab.manifest,
                  allocator=args.allocator, buffering=args.buffering,
                  ini_extra=profile['ini_extra'], evidence=str(lab.out),
                  checks=[], probes=[])
    try:
        health = lab.start()
        report['checks'].append(dict(name='startup_health', result=health))
        assert health['php'] == args.version and health['sapi'] == 'fpm-fcgi', health
        sanity(lab, report)
        pid_first = worker_pid(lab.out)
        profile['probes'](lab, report['probes'])
        report['fpm_worker_pid'] = dict(first=pid_first, last=worker_pid(lab.out))
        report['asan_reports'] = lab.asan_reports()
        report['status'] = 'completed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        lab.stop()
        report['servers_stopped'] = all(p.poll() is not None for _, p in lab.processes)
        (lab.out / 'result.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({k: report.get(k) for k in
                          ('profile', 'status', 'evidence', 'fpm_worker_pid',
                           'asan_reports', 'error')}, indent=2))
    return report


if __name__ == '__main__':
    main()
