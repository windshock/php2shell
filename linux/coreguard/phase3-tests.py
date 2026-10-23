#!/usr/bin/env python3
"""#3 CoreGuard Phase 3 development tests (synthetic only, no hold-out).

B = 8.4.27-asanext, C = 8.4.27-coreguard-asanext (patches 0001 + 0002).
Event: `COREGUARD event=bailout_in_destructor`. Expectations
(docs/coreguard/phase3-design.md §4):
  S1 fatal inside __destruct during unset of an array   event; enforce rc 70
  S2 fatal inside __destruct at shutdown                event (in_shutdown=1)
  S3 exception thrown in __destruct (no bailout)        no event
  S4 fatal outside any destructor                       no event
  S5 plain OOM outside destructors (restart-DoS check)  no event
  S6 normal destructors                                 no event, stdout == B
In every case disabled must match B (stdout, rc) and no ASAN report may appear
in observe/enforce that B does not show.

Usage: phase3-tests.py [--flavor asanext]
"""
import argparse
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
EVENT = 'COREGUARD event=bailout_in_destructor'
SANDBOX = ['-d', 'disable_functions=exec,shell_exec,system,passthru,proc_open,popen']
TESTS = {
    'S1_dtor_fatal_unset': ('''<?php
class D { function __destruct() { trigger_error("dtor", E_USER_ERROR); } }
$a = [new D, new D, 1];
unset($a);
echo "after\\n";
''', dict(event=True, enforce_rc=70)),
    'S2_dtor_fatal_shutdown': ('''<?php
class D { function __destruct() { trigger_error("dtor", E_USER_ERROR); } }
$keep = new D;
echo "end\\n";
''', dict(event=True, enforce_rc=70)),
    'S3_dtor_exception': ('''<?php
class D { function __destruct() { throw new Exception("x"); } }
try { $d = new D; unset($d); } catch (Exception $e) { echo "caught\\n"; }
''', dict(event=False)),
    'S4_fatal_outside_dtor': ('''<?php
class D { function __destruct() { echo "d\\n"; } }
$d = new D;
trigger_error("plain", E_USER_ERROR);
''', dict(event=False)),
    'S5_oom_outside_dtor': ('''<?php
ini_set('memory_limit', '4M');
$s = [];
while (true) { $s[] = str_repeat('x', 4096); }
''', dict(event=False)),
    'S6_normal_dtors': ('''<?php
class D { public $n; function __construct($n) { $this->n = $n; } function __destruct() { echo $this->n, "\\n"; } }
$a = [new D(1), new D(2)]; unset($a); $b = new D(3);
''', dict(event=False)),
}


def run(php, code, mode, w):
    (w / 't.php').write_text(code)
    asan = w / ('asan-%s-%d' % (mode, time.time_ns()))
    asan.mkdir()
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:log_path=%s/a' % asan)
    if mode != 'B':
        env['COREGUARD_MODE'] = mode
    res = subprocess.run([str(php), '-n'] + SANDBOX + [str(w / 't.php')], capture_output=True,
                         text=True, timeout=120, cwd=w, env=env)
    return dict(rc=res.returncode, event=EVENT in res.stderr,
                asan=any('AddressSanitizer' in p.read_text(errors='replace')
                         for p in asan.glob('a.*')),
                stdout=res.stdout[-500:], stderr=res.stderr[-300:])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--flavor', default='asanext')
    args = parser.parse_args()
    b_php = BASE / 'install' / ('8.4.27-' + args.flavor) / 'bin/php'
    c_php = BASE / 'install' / ('8.4.27-coreguard-' + args.flavor) / 'bin/php'
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-p3-tests-%s-%s' % (stamp, args.flavor))
    out.mkdir(parents=True)
    results, ok, total = {}, 0, 0
    for name, (code, exp) in TESTS.items():
        with tempfile.TemporaryDirectory(dir=out) as tmp:
            w = Path(tmp)
            row = dict(B=run(b_php, code, 'B', w))
            for mode in ('disabled', 'observe', 'enforce'):
                row[mode] = run(c_php, code, mode, w)
        checks = [('disabled == B (stdout, rc)', row['disabled']['stdout'] == row['B']['stdout']
                   and row['disabled']['rc'] == row['B']['rc']),
                  ('disabled has no event', not row['disabled']['event']),
                  ('observe event == %s' % exp['event'], row['observe']['event'] == exp['event']),
                  ('enforce event == %s' % exp['event'], row['enforce']['event'] == exp['event']),
                  ('no new ASAN', not any(row[m]['asan'] and not row['B']['asan']
                                          for m in ('disabled', 'observe', 'enforce')))]
        if exp['event']:
            checks.append(('enforce rc == 70', row['enforce']['rc'] == exp['enforce_rc']))
            checks.append(('observe stdout == B', row['observe']['stdout'] == row['B']['stdout']))
        else:
            checks.append(('enforce stdout == B', row['enforce']['stdout'] == row['B']['stdout']))
        row['checks'] = [dict(check=c, ok=bool(v)) for c, v in checks]
        ok += sum(1 for _, v in checks if v)
        total += len(checks)
        results[name] = row
        print('%-24s %s' % (name, ' '.join('%s:%s/rc%s' % (m, 'E' if row[m]['event'] else '-', row[m]['rc'])
                                           for m in ('B', 'disabled', 'observe', 'enforce'))))
        for c, v in checks:
            if not v:
                print('   FAIL', c)
    summary = dict(scope='CoreGuard Phase 3 development tests (synthetic, no hold-out)',
                   checks_ok=ok, checks_total=total, results=results, **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('checks=%d/%d out=%s citable=%s' % (ok, total, out, summary['citable']))
    return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
