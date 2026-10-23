#!/usr/bin/env python3
"""#4 H2.5: a pool of FlowFusion programs for the lifecycle explorer's
`fused` action (arbitrary PHP code as one request of a sequence).

Generates N fused programs with php/flowfusion (unchanged, prepared under
/home/phplab/php-lab/ext/flowfusion by flowfusion-bridge.py prepare), keeps
each program's --FILE-- section as prog-NNNN.php (fixtures copied next to
it), and writes router.php: /fused?p=K runs prog-K, every other path is the
lab app. pool.json records the generator command, seed, rc and each
program's strategy/parents (inputs are evidence, rules R12).

The pool must not contain reproducers of hold-out cases: FlowFusion seeds
come from the php-src tree of the given version, and unfixed issues
(R23/R46/R51 hold-out) have no test in that tree; pool.json lists the parent
test names so this can be audited.

--cases R49,R55 instead builds a tuning pool from #4 corpus reproducers
(same extraction as linux/corpus/run-repro.py). Hold-out records listed in
docs/coreguard/holdout-v1.json are refused: they are evaluation-only.

Usage: fused-pool.py --out DIR [--count 200] [--seed 1] [--version 8.4.27]
       fused-pool.py --out DIR --cases R49,R55
"""
import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location('ffbridge', HERE / 'flowfusion-bridge.py')
ff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ff)
import provenance  # noqa: E402

_spec_r = importlib.util.spec_from_file_location('runrepro', HERE / 'corpus/run-repro.py')
rr = importlib.util.module_from_spec(_spec_r)
_spec_r.loader.exec_module(rr)
HOLDOUT = HERE.parent / 'docs/coreguard/holdout-v1.json'

ROUTER = '''<?php
// fused-pool router: /fused?p=K runs program K; everything else is the lab app.
if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/fused') {{
    $k = (int)($_GET['p'] ?? -1);
    $f = __DIR__ . sprintf('/prog-%04d.php', $k);
    // LAB-FUSED-END: the program returned normally (no terminating bailout).
    if ($k >= 0 && is_file($f)) {{ require $f; error_log('LAB-FUSED-END'); }}
    else {{ http_response_code(404); }}
    return true;
}}
require '{app}';
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--count', type=int, default=200)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--version', default='8.4.27')
    parser.add_argument('--cases', help='comma-separated corpus records (tuning pool)')
    args = parser.parse_args()
    if args.cases:
        return case_pool(args)
    ff.ensure_php_src(args.version)
    src = ff.php_src_for(args.version)
    gen_dir = args.out / 'generated'
    cmd = [sys.executable, 'main.py', '--generate', str(args.count), '--out', str(gen_dir),
           '--seed', str(args.seed), '--php-src', str(src), '--php', str(src / 'sapi/cli/php')]
    gen = subprocess.run(cmd, cwd=ff.FF, capture_output=True, text=True, timeout=1800)
    rows = [line.split('\t') for line in gen.stdout.splitlines() if '\t' in line]
    programs = []
    for row in rows:
        code, ini = ff.file_section(row[0])
        if code is None:
            continue
        k = len(programs)
        (args.out / ('prog-%04d.php' % k)).write_text(code)
        for item in Path(row[0]).parent.iterdir():
            if item.is_file() and item.suffix != '.phpt' and not (args.out / item.name).exists():
                shutil.copy(item, args.out / item.name)
        programs.append(dict(p=k, phpt=row[0], strategy=row[1],
                             parents=row[4] if len(row) > 4 else '', ini_ignored=bool(ini)))
    (args.out / 'router.php').write_text(ROUTER.format(app=ff.ex.REPO / 'web/index.php'))
    pool = dict(scope='FlowFusion program pool for the lifecycle explorer (fused action)',
                generator_cmd=cmd, generator_rc=gen.returncode, seed=args.seed,
                version=args.version, programs=programs, **provenance.provenance())
    (args.out / 'pool.json').write_text(json.dumps(pool, indent=2))
    print(json.dumps(dict(out=str(args.out), programs=len(programs), rc=gen.returncode,
                          citable=pool['citable']), indent=2))
    return 0 if gen.returncode == 0 and programs else 1


def case_pool(args):
    holdout = {h['record'] for h in json.loads(HOLDOUT.read_text())['holdout']}
    wanted = [c.strip() for c in args.cases.split(',') if c.strip()]
    refused = sorted(set(wanted) & holdout)
    if refused:
        print(json.dumps(dict(error='hold-out records are evaluation-only', refused=refused)))
        return 2
    cases = json.loads((HERE / 'corpus/h2-cases.json').read_text())['cases']
    args.out.mkdir(parents=True, exist_ok=True)
    programs = []
    for rid in wanted:
        code, ini, needs, _ = rr.case_source(cases[rid])
        k = len(programs)
        (args.out / ('prog-%04d.php' % k)).write_text(code)
        programs.append(dict(p=k, record=rid, script=cases[rid]['script'], needs=needs,
                             ini_ignored=ini))
    (args.out / 'router.php').write_text(ROUTER.format(app=ff.ex.REPO / 'web/index.php'))
    pool = dict(scope='tuning pool from #4 corpus reproducers (never hold-out)',
                cases=wanted, holdout_file_sha256=__import__('hashlib').sha256(HOLDOUT.read_bytes()).hexdigest(),
                programs=programs, **provenance.provenance())
    (args.out / 'pool.json').write_text(json.dumps(pool, indent=2))
    print(json.dumps(dict(out=str(args.out), programs=len(programs),
                          citable=pool['citable']), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
