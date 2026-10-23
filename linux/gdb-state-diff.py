#!/usr/bin/env python3
"""Phase 5 C2: automatic request-boundary state residue diff (ZendDiff-style,
residue-specialised).

Runs the CLI server under gdb with a breakpoint at every php_request_startup
and php_request_shutdown that dumps the request-owned globals the patch
family cares about (BG serialize/unserialize, PS id/mod_data, url_adapt
hosts tables, modules_activated). The sequence exercises a normal request,
a runtime-fatal producer (unserialize OOM) and a follow-up request; the
parser then diffs "state at next request start" against the pre-fatal
baseline to report residue without a per-state hypothesis.

Observation only.
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
PORT = 18089

GDB_TEMPLATE = '''set pagination off
set confirm off
set breakpoint pending on
add-auto-load-safe-path /home/phplab/php-lab
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:log_path={asan}/asan
set environment ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
set environment USE_ZEND_ALLOC=0
set environment USE_TRACKED_ALLOC=1

break php_request_startup
commands
  silent
  printf "STATE STARTUP ser_level=%d ser_data=%p unser_level=%d unser_data=%p lock=%d ps_id=%p ps_mod=%p url_hosts=%d modules_activated=%d\\n", \\
    basic_globals.serialize.level, basic_globals.serialize.data, \\
    basic_globals.unserialize.level, basic_globals.unserialize.data, \\
    basic_globals.serialize_lock, ps_globals.id, ps_globals.mod_data, \\
    basic_globals.url_adapt_session_hosts_ht.nNumOfElements, \\
    core_globals.modules_activated
  continue
end

break php_request_shutdown
commands
  silent
  printf "STATE SHUTDOWN ser_level=%d ser_data=%p unser_level=%d unser_data=%p lock=%d ps_id=%p ps_mod=%p url_hosts=%d modules_activated=%d\\n", \\
    basic_globals.serialize.level, basic_globals.serialize.data, \\
    basic_globals.unserialize.level, basic_globals.unserialize.data, \\
    basic_globals.serialize_lock, ps_globals.id, ps_globals.mod_data, \\
    basic_globals.url_adapt_session_hosts_ht.nNumOfElements, \\
    core_globals.modules_activated
  continue
end

file {php}
set args -c {ini} -S 127.0.0.1:{port} -t {docroot} {router}
run
'''

FIELDS = ('ser_level', 'ser_data', 'unser_level', 'unser_data', 'lock',
          'ps_id', 'ps_mod', 'url_hosts', 'modules_activated')


def parse_states(log_text):
    states = []
    for line in log_text.splitlines():
        match = re.match(r'STATE (STARTUP|SHUTDOWN) (.*)', line)
        if not match:
            continue
        values = {}
        for item in match.group(2).split():
            key, _, val = item.partition('=')
            if key in FIELDS:
                values[key] = val
        states.append(dict(phase=match.group(1), **values))
    return states


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['asan'], default='asan')
    parser.add_argument('--memory-limit', default='8M')
    args = parser.parse_args()

    prefix = BASE / 'install' / (args.version + '-' + args.flavor)
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('gdb-state-diff-%s-%s' % (stamp, args.version))
    for name in ('sessions', 'uploads'):
        (out / name).mkdir(parents=True)
    ini = (REPO / 'config/php.ini').read_text() + '\n'
    ini += ('session.upload_progress.min_freq=0\n'
            'session.use_trans_sid=1\n'
            'memory_limit=%s\n'
            'session.save_path=%s\n'
            'upload_tmp_dir=%s\n'
            'error_log=%s\n' % (args.memory_limit, out / 'sessions',
                                 out / 'uploads', out / 'php-error.log'))
    (out / 'php.ini').write_text(ini)
    (out / 'gdb.cmd').write_text(GDB_TEMPLATE.format(
        asan=out, php=prefix / 'bin/php', ini=out / 'php.ini',
        port=PORT, docroot=REPO / 'web', router=REPO / 'web/index.php'))

    log_handle = (out / 'gdb.log').open('w')
    gdb = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')],
                           stdout=log_handle, stderr=subprocess.STDOUT,
                           start_new_session=True)
    report = dict(scope='request-boundary state residue diff; observation only',
                  version=args.version, memory_limit=args.memory_limit,
                  evidence=str(out), steps=[])
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def get(path, timeout=6):
        with opener.open('http://127.0.0.1:%d%s' % (PORT, path), timeout=timeout) as res:
            return json.load(res)

    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            if gdb.poll() is not None:
                raise RuntimeError('gdb exited before server ready')
            try:
                if get('/health', timeout=2).get('ok'):
                    break
            except Exception:
                time.sleep(0.4)
        report['steps'].append('ready')
        get('/session')
        sid = 'sdbig' + secrets.token_hex(8)
        big = 'A' * (3 * 1024 * 1024)
        (out / 'sessions' / ('sess_' + sid)).write_text(
            'big|s:%d:"%s";' % (len(big), big))
        multipart(PORT, '/upload', fields=[('PHPSESSID', sid),
                                           ('PHP_SESSION_UPLOAD_PROGRESS', 'sdA')],
                  file_spec=('file', 'a.bin', b'K' * 32768))
        report['steps'].append('parse_time_oom_producer')
        time.sleep(0.5)
        # Runtime-fatal producer: application-level unserialize OOM. The
        # payload must fit memory_limit when read (so the fatal lands inside
        # the decoded-string allocation, after PHP_VAR_UNSERIALIZE_INIT).
        payload_len = 6 * 1024 * 1024
        payload = ('s:%d:"%s";' % (payload_len, 'B' * payload_len)).encode()
        req = urllib.request.Request(
            'http://127.0.0.1:%d/unserialize' % PORT, data=payload,
            headers={'Content-Type': 'application/octet-stream'})
        try:
            opener.open(req, timeout=30)
        except urllib.error.HTTPError:
            pass
        report['steps'].append('runtime_oom_producer')
        time.sleep(0.5)
        # Follow-up request on the same process (this is where residue would
        # be consumed); it may abort the process under ASAN.
        try:
            get('/health', timeout=8)
            report['steps'].append('followup_ok')
        except Exception as exc:
            report['steps'].append('followup_error:%s' % exc)
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
    states = parse_states(log_text)
    report['states'] = states
    report['gdb_errors'] = [line for line in log_text.splitlines()
                            if 'No symbol' in line or 'Error in sourced' in line][:5]
    log = (out / 'php-error.log')
    report['oom_logged'] = ('Allowed memory size' in log.read_text(errors='replace')
                            if log.exists() else False)
    report['asan_reports'] = sorted(str(p) for p in out.glob('asan.*') if p.is_file())

    # Residue diff: first STARTUP after the LAST shutdown that followed an OOM.
    residues = []
    for i, state in enumerate(states):
        if state['phase'] == 'STARTUP' and i > 0:
            prev = states[i - 1]
            if prev['phase'] == 'SHUTDOWN':
                changed = {k: (prev[k], state[k]) for k in FIELDS
                           if prev.get(k) != state.get(k)}
                nonzero = {k: state[k] for k in FIELDS
                           if k not in ('modules_activated', 'lock')
                           and state.get(k) not in ('0', '(nil)', None)}
                residues.append(dict(after_shutdown_index=i - 1,
                                     carried_nonzero=nonzero, changed=changed))
    report['residue_transitions'] = residues
    (out / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(evidence=str(out), steps=report['steps'],
                          oom=report['oom_logged'],
                          asan=len(report['asan_reports']),
                          transitions=len(residues),
                          gdb_errors=report['gdb_errors']), indent=2))


if __name__ == '__main__':
    main()
