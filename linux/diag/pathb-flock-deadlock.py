#!/usr/bin/env python3
"""Diagnostic (findings §10.7, R12 re-run): the parse_oom -> parse_oom hang on
8.4.4 is a same-process flock self-deadlock on the leaked session fd.

For each version: start one ASAN CLI server, send parse_oom (request A,
forged 3 MB session, 8M limit), record the open session fds and /proc/locks
entries for the session inode, send the same request again (B) in a thread,
then sample B's blocking state (wchan, syscall number, CPU ticks over 2 s)
and the fds/locks again. Expected on 8.4.4: after A one fd holds an
exclusive FLOCK; during B a second fd waits on it (flock syscall 73,
wchan locks_lock_inode_wait, 0 CPU). Expected on 8.4.27: no leaked fd, B
answers.

Observation only. Usage: python3 linux/diag/pathb-flock-deadlock.py [--versions 8.4.4 8.4.27]
"""
import argparse
import http.cookiejar
import importlib.util
import json
import os
import secrets
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
_spec = importlib.util.spec_from_file_location('lifecycle_explore', HERE.parent / 'lifecycle-explore.py')
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)
import provenance  # noqa: E402


def session_fds(pid):
    out = []
    for fd in os.listdir('/proc/%d/fd' % pid):
        try:
            target = os.readlink('/proc/%d/fd/%s' % (pid, fd))
        except OSError:
            continue
        if 'sess_' in target:
            out.append(dict(fd=int(fd), target=Path(target).name))
    return sorted(out, key=lambda x: x['fd'])


def locks_for(inode):
    return [line.strip() for line in open('/proc/locks') if (':%d ' % inode) in line]


def one(version, root):
    out = root / version
    proc = ex.Process(ex.BASE / 'install' / (version + '-asan'), out, '8M', 'none')
    ctx = dict(sid_big='dlbig' + secrets.token_hex(6), sid_small='dlsmall' + secrets.token_hex(6))
    big = 'A' * (3 * 1024 * 1024)
    (proc.sessions / ('sess_' + ctx['sid_big'])).write_text('big|s:%d:"%s";' % (len(big), big))
    (proc.sessions / ('sess_' + ctx['sid_small'])).write_text('small|a:1:{i:0;i:7;}')
    ctx['jar'] = http.cookiejar.CookieJar()
    ctx['opener'] = urllib.request.build_opener()
    rec = dict(version=version)
    try:
        proc.start()
        pid = proc.proc.pid
        inode = os.stat(proc.sessions / ('sess_' + ctx['sid_big'])).st_ino
        rec['request_a'] = ex.send('parse_oom', {}, 0, ctx)
        time.sleep(0.5)
        rec['after_a'] = dict(session_fds=session_fds(pid), locks=locks_for(inode))
        result = {}
        t = threading.Thread(target=lambda: result.setdefault(
            'b', ex.send('parse_oom', {}, 1, ctx)), daemon=True)
        t.start()
        time.sleep(4)
        st1 = open('/proc/%d/stat' % pid).read().split()
        time.sleep(2)
        st2 = open('/proc/%d/stat' % pid).read().split()
        rec['during_b'] = dict(
            state=st2[2], cpu_ticks_2s=(int(st2[13]) + int(st2[14])) - (int(st1[13]) + int(st1[14])),
            wchan=open('/proc/%d/wchan' % pid).read().strip(),
            syscall=open('/proc/%d/syscall' % pid).read().split()[0],
            session_fds=session_fds(pid), locks=locks_for(inode))
        t.join(timeout=15)
        rec['request_b'] = result.get('b', 'still_blocked')
    except Exception as exc:
        rec['harness_error'] = str(exc)
    finally:
        proc.stop()
    d = rec.get('during_b', {})
    rec['self_deadlock'] = (len(rec.get('after_a', {}).get('session_fds', [])) >= 1
                            and d.get('syscall') == '73'
                            and 'lock' in (d.get('wchan') or '')
                            and d.get('cpu_ticks_2s') == 0)
    return rec


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--versions', nargs='+', default=['8.4.4', '8.4.27'])
    args = parser.parse_args()
    root = ex.BASE / 'evidence' / ('diag-pathb-flock-%s' % time.strftime('%Y%m%dT%H%M%S',
                                                                          time.gmtime()))
    root.mkdir(parents=True)
    rows = [one(v, root) for v in args.versions]
    report = dict(scope='diagnostic: Path B flock self-deadlock (findings §10.7)',
                  **provenance.provenance(), results=rows)
    (root / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(out=str(root), citable=report['citable'],
                          results=[dict(version=r['version'], self_deadlock=r['self_deadlock'],
                                        request_b=r.get('request_b'),
                                        during_b={k: r.get('during_b', {}).get(k) for k in
                                                  ('wchan', 'syscall', 'cpu_ticks_2s')},
                                        harness_error=r.get('harness_error'))
                                   for r in rows]), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
