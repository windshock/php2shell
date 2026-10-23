#!/usr/bin/env python3
"""#3 CoreGuard Phase 2b development tests (tuning case R49 + synthetic).

Never runs hold-out cases (docs/coreguard/holdout-v1.json). Builds:
B = 8.4.27-asanext (official), C = 8.4.27-coreguard-asanext. Each test runs
in the CLI (php -n + opcache) on B and on C in the three modes; checks the
CoreGuard event line on stderr, the CoreGuard fatal, ASAN reports, stdout.
Design and expectations: docs/coreguard/phase2b-design.md §5.

Usage: phase2b-tests.py [--flavor asanext]
"""
import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

_spec = importlib.util.spec_from_file_location('runrepro', HERE.parent / 'corpus/run-repro.py')
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
BASE = Path('/home/phplab/php-lab')
HOLDOUT = HERE.parents[1] / 'docs/coreguard/holdout-v1.json'
EVENT = 'COREGUARD event=gc_protected_after_caught_bailout'
CG_FATAL = 'CoreGuard: execution resumed after a caught bailout'

R49_CODE = rr.case_source(json.loads((HERE.parent / 'corpus/h2-cases.json').read_text())
                          ['cases']['R49'])[0]
TESTS = {
    'T1_r49_tuning': dict(code=R49_CODE, expect=dict(
        disabled=dict(event=False, cg_fatal=False),
        observe=dict(event=True, cg_fatal=False),
        enforce=dict(event=True, cg_fatal=True))),
    'T2_normal_cycles': dict(code='''<?php
class N { public $s; }
for ($i = 0; $i < 20000; $i++) { $o = new N; $o->s = $o; }
var_dump(gc_collect_cycles() > 0, gc_status()["protected"]);
''', expect={m: dict(event=False, cg_fatal=False) for m in ('disabled', 'observe', 'enforce')}),
    'T3_terminating_fatal': dict(code='''<?php
class N { public $s; }
$o = new N; $o->s = $o;
undefined_function_cg();
''', expect={m: dict(event=False, cg_fatal=False) for m in ('disabled', 'observe', 'enforce')}),
    'T4_caught_bailout_no_cycles': dict(code='''<?php
$bad = sys_get_temp_dir() . "/bad4.php";
file_put_contents($bad, "<?php\\nbreak 2;\\n");
var_dump(@opcache_compile_file($bad));
$x = 0; for ($i = 0; $i < 1000; $i++) { $x += $i; }
var_dump($x, gc_status()["protected"]);
''', expect=None),  # characterization only: detection needs a refused root
}


def run(php, code, mode, workdir):
    script = workdir / 'test.php'
    script.write_text(code)
    asan_dir = workdir / ('asan-' + mode)
    asan_dir.mkdir(exist_ok=True)
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % asan_dir,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    if mode != 'B':
        env['COREGUARD_MODE'] = mode
    args = [str(php), '-n'] + rr.opcache_args(php) + rr.SANDBOX + [
        '-d', 'sys_temp_dir=%s' % workdir, '-d', 'memory_limit=128M', str(script)]
    t0 = time.time()
    res = subprocess.run(args, capture_output=True, text=True, timeout=120, cwd=workdir, env=env)
    asan = [p.name for p in asan_dir.glob('asan.*')
            if 'AddressSanitizer' in p.read_text(errors='replace')]
    return dict(rc=res.returncode, seconds=round(time.time() - t0, 2),
                event=EVENT in res.stderr, cg_fatal=CG_FATAL in (res.stdout + res.stderr),
                asan=asan, stdout=res.stdout[-600:], stderr=res.stderr[-600:])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--flavor', default='asanext')
    args = parser.parse_args()
    holdout = {h['record'] for h in json.loads(HOLDOUT.read_text())['holdout']}
    assert not holdout & {'R49'}, 'tuning case listed as hold-out'
    b_php = BASE / 'install' / ('8.4.27-' + args.flavor) / 'bin/php'
    c_php = BASE / 'install' / ('8.4.27-coreguard-' + args.flavor) / 'bin/php'
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-p2b-tests-%s-%s' % (stamp, args.flavor))
    out.mkdir(parents=True)
    results, ok, total = {}, 0, 0
    for name, t in TESTS.items():
        with tempfile.TemporaryDirectory(dir=out) as tmp:
            w = Path(tmp)
            row = dict(B=run(b_php, t['code'], 'B', w))
            for mode in ('disabled', 'observe', 'enforce'):
                row[mode] = run(c_php, t['code'], mode, w)
        checks = []
        if t['expect']:
            for mode, exp in t['expect'].items():
                for k, v in exp.items():
                    checks.append(('%s.%s==%s' % (mode, k, v), row[mode][k] == v))
        checks.append(('no ASAN in any mode', not any(row[m]['asan'] for m in row)))
        checks.append(('disabled stdout == B stdout', row['disabled']['stdout'] == row['B']['stdout']))
        checks.append(('B has no CoreGuard event', not row['B']['event']))
        row['checks'] = [dict(check=c, ok=bool(v)) for c, v in checks]
        ok += sum(1 for _, v in checks if v)
        total += len(checks)
        results[name] = row
        print('%-28s %s' % (name, ' '.join('%s:%s' % (m, ('E' if row[m]['event'] else '-') +
                                                      ('F' if row[m]['cg_fatal'] else '-'))
                                           for m in ('B', 'disabled', 'observe', 'enforce'))))
        for c, v in checks:
            if not v:
                print('   FAIL', c)
    summary = dict(scope='CoreGuard Phase 2b development tests (tuning + synthetic, no hold-out)',
                   b=str(b_php), c=str(c_php), checks_ok=ok, checks_total=total,
                   results=results, **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('checks=%d/%d out=%s citable=%s' % (ok, total, out, summary['citable']))
    return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
