#!/usr/bin/env python3
"""#3 CoreGuard Phase 1 development tests (observe-only residue detector).

C = 8.4.27-coreguard-asanext (patch 0003). 8.4.27 leaves no residue in
normal runs, so the positive control injects one with gdb: break at
php_basic_early_rinit(), set basic_globals.unserialize.level = 1, continue -
the CoreGuard check (first statement of that function) must report it.
  N1 normal CLI run, observe              no event
  N2 normal CLI run, disabled             no event
  PC injected residue, observe            event with unser_level=1
  PD injected residue, disabled           no event (guard off)
Usage: phase1-tests.py
"""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
PHP = BASE / 'install/8.4.27-coreguard-asanext/bin/php'
EVENT = 'COREGUARD event=request_state_residue'


def run(mode, inject, w):
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1', ASAN_OPTIONS='detect_leaks=0')
    if mode != 'disabled':
        env['COREGUARD_MODE'] = mode
    php = [str(PHP), '-n', '-r', 'echo "ok\\n";']
    if inject:
        cmd = ['gdb', '-q', '-batch', '-ex', 'set breakpoint pending on',
               '-ex', 'handle SIGSEGV nostop noprint pass',
               '-ex', 'break php_basic_early_rinit', '-ex', 'run',
               '-ex', 'set var basic_globals.unserialize.level = 1', '-ex', 'continue',
               '--args'] + php
    else:
        cmd = php
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=w, env=env)
    out = res.stdout + res.stderr
    return dict(rc=res.returncode, event=EVENT in out, unser_level_1='unser_level=1' in out,
                ok='ok' in res.stdout, tail=out[-400:])


def main():
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-p1-tests-%s' % stamp)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        w = Path(tmp)
        r = dict(N1=run('observe', False, w), N2=run('disabled', False, w),
                 PC=run('observe', True, w), PD=run('disabled', True, w))
    checks = [('N1 no event', not r['N1']['event'] and r['N1']['ok']),
              ('N2 no event', not r['N2']['event'] and r['N2']['ok']),
              ('PC event with unser_level=1', r['PC']['event'] and r['PC']['unser_level_1']),
              ('PD no event', not r['PD']['event'])]
    for c, v in checks:
        print('%s %s' % ('PASS' if v else 'FAIL', c))
    ok = sum(1 for _, v in checks if v)
    summary = dict(scope='CoreGuard Phase 1 development tests', checks_ok=ok,
                   checks_total=len(checks), results=r, **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('checks=%d/%d out=%s citable=%s' % (ok, len(checks), out, summary['citable']))
    return 0 if ok == len(checks) else 1


if __name__ == '__main__':
    sys.exit(main())
