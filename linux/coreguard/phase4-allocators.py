#!/usr/bin/env python3
"""#3 CoreGuard Phase 4: allocator comparison on release builds (plan §13.5).

Question: what does each allocator guarantee against the memory errors of
the corpus, without a sanitizer build? Sampling detection (GWP-ASan) vs
deterministic checks (glibc / Scudo free-path checks) vs ZendMM.
Cases (never hold-out): R55 (tuning, 8.4.27 regression) on 8.4.27-normalext,
R41 / R42 (regression controls, fixed in 8.4.27) on 8.4.4-normal.
Allocators: zendmm (USE_ZEND_ALLOC=1), glibc (USE_ZEND_ALLOC=0), scudo
(USE_ZEND_ALLOC=0 + LD_PRELOAD Scudo standalone), scudo_gwp (Scudo with
GWP-ASan, sample rate --gwp-rate). Each config runs --repeats times.
Outcome per run:
  allocator_detected  the allocator reported and aborted (glibc "free():"/
                      "double free"/"corrupted", Scudo "ERROR:", GWP-ASan)
  crash_undetected    fatal signal without an allocator report
  silent              exit without signal or report (the error went unnoticed)
Cost: Zend/bench.php CLI time per allocator (8.4.27-normalext, 3 runs).

Usage: phase4-allocators.py [--repeats 10] [--gwp-rate 1]
"""
import argparse
import collections
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
SCUDO = '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so'
HOLDOUT = HERE.parents[1] / 'docs/coreguard/holdout-v1.json'
CASES = {'R55': '8.4.27-normalext', 'R41': '8.4.4-normal', 'R42': '8.4.4-normal'}
REPORT = re.compile(r'free\(\)|double free|corrupted|malloc\(\)|Scudo ERROR|ERROR: Scudo|'
                    r'GWP-ASan|munmap_chunk|realloc\(\)', re.I)


def env_for(alloc, gwp_rate):
    env = dict(PATH='/usr/bin:/bin')
    env['USE_ZEND_ALLOC'] = '1' if alloc == 'zendmm' else '0'
    if alloc.startswith('scudo'):
        env['LD_PRELOAD'] = SCUDO
        if alloc == 'scudo_gwp':
            env['SCUDO_OPTIONS'] = ('GWP_ASAN_Enabled=true:GWP_ASAN_SampleRate=%d:'
                                    'GWP_ASAN_MaxSimultaneousAllocations=512' % gwp_rate)
    return env


def run_case(php, code, needs, alloc, gwp_rate, w):
    script = w / 'case.php'
    script.write_text(code)
    extra = rr.opcache_args(php) if 'opcache' in needs else []
    try:
        res = subprocess.run([str(php), '-n'] + extra + rr.SANDBOX +
                             ['-d', 'sys_temp_dir=%s' % w, str(script)], capture_output=True,
                             text=True, timeout=120, cwd=w, env=env_for(alloc, gwp_rate))
    except subprocess.TimeoutExpired:
        return dict(outcome='timeout')
    out = res.stdout + res.stderr
    reported = bool(REPORT.search(res.stderr))
    sig = -res.returncode if res.returncode < 0 else None
    outcome = ('allocator_detected' if reported and (sig or res.returncode in (134, 139)) else
               'crash_undetected' if sig or res.returncode in (134, 139) else 'silent')
    return dict(outcome=outcome, rc=res.returncode, signal=sig,
                report=REPORT.search(res.stderr).group(0) if reported else None,
                tail=out[-300:])


def bench(alloc, gwp_rate, w):
    php = BASE / 'install/8.4.27-normalext/bin/php'
    src = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(BASE / 'sources/php-8.4.27'),
                          'show', 'HEAD:Zend/bench.php'], capture_output=True).stdout
    (w / 'bench.php').write_bytes(src)
    times = []
    for _ in range(3):
        res = subprocess.run([str(php), '-n', str(w / 'bench.php')], capture_output=True,
                             text=True, timeout=600, env=env_for(alloc, gwp_rate))
        m = re.search(r'Total\s+([\d.]+)', res.stdout)
        times.append(float(m.group(1)) if m else None)
    return times


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repeats', type=int, default=10)
    parser.add_argument('--gwp-rate', type=int, default=1)
    args = parser.parse_args()
    holdout = {h['record'] for h in json.loads(HOLDOUT.read_text())['holdout']}
    assert not holdout & set(CASES), 'hold-out case in the Phase 4 set'
    cases = json.loads((HERE.parent / 'corpus/h2-cases.json').read_text())['cases']
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-p4-allocators-%s' % stamp)
    out.mkdir(parents=True)
    allocs = ('zendmm', 'glibc', 'scudo', 'scudo_gwp')
    rows = {}
    for rid, build in CASES.items():
        php = BASE / 'install' / build / 'bin/php'
        code, _, needs, _ = rr.case_source(cases[rid])
        rows[rid] = dict(build=build, results={})
        for a in allocs:
            runs = []
            for _ in range(args.repeats):
                with tempfile.TemporaryDirectory(dir=out) as tmp:
                    runs.append(run_case(php, code, needs, a, args.gwp_rate, Path(tmp)))
            rows[rid]['results'][a] = dict(counts=dict(collections.Counter(r['outcome'] for r in runs)),
                                           runs=runs)
            print('%s %-10s %s' % (rid, a, rows[rid]['results'][a]['counts']))
    costs = {}
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        for a in allocs:
            costs[a] = bench(a, args.gwp_rate, Path(tmp))
            print('bench %-10s %s' % (a, costs[a]))
    summary = dict(scope='CoreGuard Phase 4 allocator comparison (release builds, no hold-out)',
                   repeats=args.repeats, gwp_rate=args.gwp_rate, scudo=SCUDO, rows=rows,
                   bench_total_s=costs, **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('out=%s citable=%s' % (out, summary['citable']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
