#!/usr/bin/env python3
"""#4 H2.5 reachability: does the class-targeted grammar reach the failure
classes at all? Runs every program of a payload-grammar pool once in the
CLI of a build (sandboxed: exec/network functions disabled, temp/session
paths inside the run dir, opcache loaded) and classifies the outcome:
  memory_error   ASAN report / zend_mm_panic / fatal signal (signature
                 classified as hold-out / known / unknown with h3-report.py)
  gc_protected   program ended normally but gc_status()['protected'] was 1
                 in its final g_gc() line (R23/R49 class symptom)
  ok / fatal     normal end / PHP fatal without memory error
Unknown signatures are potential new findings (plan §11.2 D1): reports carry
counts only; details stay in the local evidence tree.

Usage: grammar-reach.py --pool DIR [--build 8.4.27-asanext] [--jobs 4]
"""
import argparse
import collections
import concurrent.futures as cf
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

_s = importlib.util.spec_from_file_location('h3report', HERE / 'h3-report.py')
h3 = importlib.util.module_from_spec(_s)
_s.loader.exec_module(h3)
_r = importlib.util.spec_from_file_location('runrepro', HERE / 'corpus/run-repro.py')
rr = importlib.util.module_from_spec(_r)
_r.loader.exec_module(rr)
BASE = Path('/home/phplab/php-lab')


def run(php, prog, out):
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        w = Path(tmp)
        asan = w / 'asan'
        asan.mkdir()
        env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1',
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/a' % asan,
                   ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
        args = [str(php), '-n'] + rr.opcache_args(php) + rr.SANDBOX + [
            '-d', 'sys_temp_dir=%s' % w, '-d', 'session.save_path=%s' % w,
            '-d', 'memory_limit=64M', '-d', 'max_execution_time=20', str(prog)]
        try:
            res = subprocess.run(args, capture_output=True, text=True, timeout=60, cwd=w, env=env)
        except subprocess.TimeoutExpired:
            return dict(prog=prog.name, kind='hang')
        out_txt = res.stdout + res.stderr
        sig = None
        for p in asan.glob('a.*'):
            t = p.read_text(errors='replace')
            if 'AddressSanitizer' in t:
                kind = re.search(r'AddressSanitizer: ([\w-]+)', t)
                frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', t)[:4]
                sig = '%s:%s' % (kind.group(1) if kind else '?', '>'.join(frames))
                (out / ('asan-%s.txt' % prog.stem)).write_text(t[:20000])
        if sig or 'zend_mm_panic' in out_txt or 'zend_mm_heap corrupted' in out_txt \
                or res.returncode < 0 or res.returncode in (134, 139):
            sig = sig or ('zend_mm_panic' if 'zend_mm' in out_txt else 'signal:%d' % res.returncode)
            return dict(prog=prog.name, kind='memory_error', sig=sig, cls=h3.classify(sig))
        gcl = re.findall(r'^gc (\d+) (\d) (\d+)$', res.stdout, re.M)
        if 'end' in res.stdout.splitlines()[-1:] and gcl and gcl[-1][1] == '1':
            return dict(prog=prog.name, kind='gc_protected')
        if res.stdout.rstrip().endswith('end'):
            return dict(prog=prog.name, kind='ok')
        return dict(prog=prog.name, kind='fatal', rc=res.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--pool', type=Path, required=True)
    parser.add_argument('--build', default='8.4.27-asanext')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    php = BASE / 'install' / args.build / 'bin/php'
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('grammar-reach-%s-%s' % (stamp, args.build))
    out.mkdir(parents=True)
    progs = sorted(args.pool.glob('prog-*.php'))
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        rows = list(ex.map(lambda p: run(php, p, out), progs))
    kinds = collections.Counter(r['kind'] for r in rows)
    classes = collections.Counter(r['cls'] for r in rows if r['kind'] == 'memory_error')
    unknown = len({r['sig'] for r in rows if r.get('cls') == 'unknown_local_only'})
    (out / 'runs.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    pool_json = json.loads((args.pool / 'pool.json').read_text())
    summary = dict(scope='H2.5 grammar reachability (CLI, sandboxed)', build=args.build,
                   pool=str(args.pool), pool_seed=pool_json.get('seed'), programs=len(progs),
                   kinds=dict(kinds), memory_error_classes=dict(classes),
                   unknown_signatures=unknown, note='unknown signatures: D1, local evidence only',
                   **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(dict(out=str(out), programs=len(progs), kinds=dict(kinds),
                          memory_error_classes=dict(classes), unknown_signatures=unknown,
                          citable=summary['citable']), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
