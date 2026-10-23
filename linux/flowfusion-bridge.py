#!/usr/bin/env python3
"""Phase 5 v2 Stage 4 / G5: FlowFusion -> request-lifecycle bridge.

FlowFusion (php/flowfusion) fuses php-src .phpt programs (dataflow / state /
declaration fusion) and finds bugs INSIDE one program run. Its state fusion
is intra-program: it does not test whether state survives into the NEXT
request of a long-lived worker (plan §12.3 Stage 4 scope note). This bridge
reuses FlowFusion unchanged for generation and hands each fused program to
the Stage 1 executor:

  step 0   GET /fused   - the fused program runs as one request
  step 1.. consumers    - progress upload, no-file upload, session request
                          on the SAME process (no request in between)

Classification per program (fail-closed, verdicts.flowfusion; issue #5-2):
three axes from LOG/OBSERVATION evidence, never from the HTTP status alone
  generation   generated | not_generated
  request 0    server_start_failed | request0_not_executed | request0_timeout
               | program_compile_error (generated program invalid)
               | program_runtime_fatal (valid exploration case, even as 500)
               | program_completed
  consumers    consumers_observed | consumer_incomplete | ended_by_memory_error
and the summary verdict harness_failed | not_reached | consumer_incomplete |
intra_request | cross_request | carried_state | clean. Denominators are
reported separately: lifecycle observed vs program executed.

Fused programs come from php-src tests; they run with exec/network
functions disabled and allow_url_fopen=Off. --INI-- sections of the fused
tests are not applied (recorded as a limitation).

Usage:
  flowfusion-bridge.py prepare --ff-src DIR        (copy + prepare.py --no-build)
  flowfusion-bridge.py run --count N [--seed S] [--version 8.4.4]
Observation only; findings stay in the local evidence tree (§11.2 D1).
"""
import argparse
import glob
import http.cookiejar
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location('lifecycle_explore', HERE / 'lifecycle-explore.py')
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)
import verdicts  # noqa: E402

BASE = ex.BASE
FF = BASE / 'ext' / 'flowfusion'
CONSUMERS = ('upload_small', 'upload_nofile', 'session')
SANDBOX_INI = ('disable_functions=exec,shell_exec,system,passthru,proc_open,popen,'
               'pcntl_exec,mail,fsockopen,pfsockopen,stream_socket_client,'
               'stream_socket_server,socket_create,socket_connect,curl_exec,'
               'curl_multi_exec,putenv,dl\nallow_url_fopen=Off\nallow_url_include=Off\n'
               'max_execution_time=10\n')


def php_src_for(version):
    """FlowFusion's --php-src: a COPY of the pristine sources (tests) with
    the out-of-tree ASAN CLI binary linked in - the original source tree is
    never modified (project rule)."""
    return BASE / 'ext' / ('php-src-%s' % version)


def ensure_php_src(version):
    tree = php_src_for(version)
    if not tree.exists():
        shutil.copytree(BASE / 'sources' / ('php-' + version), tree, symlinks=True)
    binary = tree / 'sapi/cli/php'
    if binary.exists() or binary.is_symlink():
        binary.unlink()
    binary.symlink_to(BASE / 'builds' / (version + '-asan') / 'sapi/cli/php')
    return tree


def prepare(args):
    src = Path(args.ff_src).resolve()
    if FF.exists():
        shutil.rmtree(FF)
    FF.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, FF, ignore=shutil.ignore_patterns('.git'))
    ensure_php_src(args.version)
    cmd = [sys.executable, 'prepare.py', '--php-src', str(php_src_for(args.version)),
           '--no-build', '--langspec', '', '-j', str(args.jobs)]
    log = (FF / 'prepare.log').open('w')
    rc = subprocess.run(cmd, cwd=FF, stdout=log, stderr=subprocess.STDOUT).returncode
    log.close()
    tail = (FF / 'prepare.log').read_text(errors='replace').splitlines()[-6:]
    print(json.dumps(dict(rc=rc, ff=str(FF), tail=tail), indent=2))
    return rc


def file_section(phpt):
    text = Path(phpt).read_text(errors='replace')
    match = re.search(r'^--FILE--\s*\n(.*?)(?=^--[A-Z_]+--\s*$|\Z)', text, re.S | re.M)
    ini = re.search(r'^--INI--\s*\n(.*?)(?=^--[A-Z_]+--\s*$|\Z)', text, re.S | re.M)
    return (match.group(1) if match else None), (ini.group(1).strip() if ini else '')


ROUTER = '''<?php
// flowfusion-bridge router: /fused runs the fused program, everything else
// is the lab app (progress upload, session, health).
if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/fused') {{
    require __DIR__ . '/fused.php';
    return true;
}}
require '{app}';
'''


def send_fused(idx):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/fused?step=%d' % (ex.PORT, idx),
                                    timeout=20) as res:
            return 's%d' % res.status
    except urllib.error.HTTPError as exc:
        return 's%d' % exc.code
    except (ConnectionResetError, BrokenPipeError):
        return 'reset'
    except Exception as exc:
        return 'error:%s' % type(exc).__name__


def run_program(code, prefix, out, limit='16M'):
    """One fused program + consumers in one CLI-server process (gdb observed)."""
    docroot = out / 'docroot'
    docroot.mkdir(parents=True, exist_ok=True)
    (docroot / 'fused.php').write_text(code)
    (docroot / 'router.php').write_text(ROUTER.format(app=ex.REPO / 'web/index.php'))
    ex.PORT = ex.CLI_PORT
    proc = ex.Process(prefix, out, limit, 'gdb', 0, docroot=docroot,
                      router=docroot / 'router.php')
    with (out / 'php.ini').open('a') as ini:
        ini.write(SANDBOX_INI)
    ctx = dict(sid_big='ffbig' + secrets.token_hex(6), sid_small='ffsmall' + secrets.token_hex(6))
    (proc.sessions / ('sess_' + ctx['sid_small'])).write_text('small|a:1:{i:0;i:7;}')
    (proc.sessions / ('sess_' + ctx['sid_big'])).write_text('big|s:1:"x";')
    ctx['jar'] = http.cookiejar.CookieJar()
    ctx['opener'] = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(ctx['jar']))
    steps = []
    step0_log = ''
    actions = ('fused',) + CONSUMERS
    # Fused php-src tests write relative files (e.g. phar tests): run the
    # server from the program's own docroot, never from the repository.
    cwd = os.getcwd()
    try:
        os.chdir(docroot)
        proc.start()
        for idx, action in enumerate(actions):
            before_log = proc.error_log.stat().st_size if proc.error_log.exists() else 0
            before_asan = {p.name for p in proc.asan_dir.glob('asan.*')}
            response = send_fused(idx) if action == 'fused' else ex.send(action, {'a': action},
                                                                         idx, ctx)
            time.sleep(0.3)
            asan = None
            deadline = time.time() + (4.0 if not response.startswith('s') else 0.8)
            while time.time() < deadline and asan is None:
                for path in sorted(proc.asan_dir.glob('asan.*')):
                    if path.name not in before_asan and path.is_file():
                        asan = ex.asan_signature(path)
                        if asan:
                            break
                time.sleep(0.2)
            log_text = ''
            if proc.error_log.exists():
                with proc.error_log.open('rb') as handle:
                    handle.seek(before_log)
                    log_text = handle.read().decode('utf-8', 'replace')
            if idx == 0:
                step0_log = log_text
            alive = proc.alive()
            steps.append(dict(i=idx, a=action, response=response,
                              failure_sites=ex.failure_sites(log_text), asan=asan,
                              alive_after=alive, hung=False, ended_by_probe=False))
            if not alive:
                break
    except Exception as exc:
        steps.append(dict(harness_error=str(exc)))
    finally:
        proc.stop()
        os.chdir(cwd)
    states = []
    if (out / 'observer.log').exists():
        for line in (out / 'observer.log').read_text(errors='replace').splitlines():
            if line.startswith('STATE '):
                try:
                    states.append(json.loads(line[6:]))
                except ValueError:
                    pass
    seq = dict(limit=limit, steps=[{'a': a} for a in actions])
    _, observed, findings = ex.observe(dict(steps=steps, states=states), seq)
    (out / 'steps.json').write_text(json.dumps(dict(steps=observed, step0_log=step0_log)))
    return observed, findings, states, step0_log


def reclassify(root):
    """Re-derive verdicts for an existing run from its evidence (observer
    log, php-error.log, recorded findings) - no rerun."""
    root = Path(root)
    rows = [json.loads(line) for line in (root / 'results.jsonl').read_text().splitlines()
            if line.strip()]
    out = []
    for r in rows:
        d = root / ('prog-%04d' % r['n'])
        if r.get('status') == 'no_file_section':
            out.append(dict(r, **verdicts.flowfusion(False, [], [], '')))
            continue
        states = []
        if (d / 'observer.log').exists():
            for line in (d / 'observer.log').read_text(errors='replace').splitlines():
                if line.startswith('STATE '):
                    try:
                        states.append(json.loads(line[6:]))
                    except ValueError:
                        pass
        if (d / 'steps.json').exists():
            data = json.loads((d / 'steps.json').read_text())
            steps, log0 = data['steps'], data['step0_log']
        else:
            seen = sorted({int(m.group(1)) for st in states if st.get('tag') == 'startup'
                           for m in [re.search(r'[?&]step=(\d+)', st.get('uri') or '')] if m})
            sig_by_step = {f['step']: f['sig'] for f in r.get('findings', [])}
            steps = [dict(i=i, response=(r.get('fused_response') if i == 0 else 'unknown'),
                          asan=(dict(sig=sig_by_step[i]) if i in sig_by_step else None),
                          violations=r.get('violations') if i > 0 else [],
                          alive_after=True) for i in seen]
            log0 = (d / 'php-error.log').read_text(errors='replace') if (
                d / 'php-error.log').exists() else ''
        v = verdicts.flowfusion(True, steps, states, log0)
        out.append(dict(n=r['n'], strategy=r.get('strategy'), old_verdict=r.get('verdict'),
                        **v))
    return out


def summarize(rows):
    count = lambda key: {k: sum(1 for r in rows if r.get(key) == k)  # noqa: E731
                         for k in sorted({r.get(key) for r in rows})}
    return dict(total=len(rows), verdicts=count('verdict'), request0=count('request0'),
                consumers=count('consumers'),
                lifecycle_observed=sum(1 for r in rows if r.get('lifecycle_observed')),
                program_executed=sum(1 for r in rows if r.get('program_executed')),
                clean_of_lifecycle_observed=sum(1 for r in rows if r.get('verdict') == 'clean'),
                clean_of_program_executed=sum(1 for r in rows if r.get('verdict') == 'clean'
                                              and r.get('program_executed')))


def run(args):
    prefix = BASE / 'install' / (args.version + '-asan')
    php = php_src_for(args.version) / 'sapi/cli/php'
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = BASE / 'evidence' / ('flowfusion-bridge-%s-%s-s%d' % (stamp, args.version, args.seed))
    gen_dir = root / 'fused'
    gen = subprocess.run([sys.executable, 'main.py', '--generate', str(args.count),
                          '--out', str(gen_dir), '--seed', str(args.seed),
                          '--php-src', str(php_src_for(args.version)), '--php', str(php)],
                         cwd=FF, capture_output=True, text=True, timeout=1800)
    (root / 'generate.log').parent.mkdir(parents=True, exist_ok=True)
    (root / 'generate.log').write_text(gen.stdout + '\n--stderr--\n' + gen.stderr)
    programs = [line.split('\t') for line in gen.stdout.splitlines() if '\t' in line]
    if gen.returncode != 0 or not programs:
        # Generator failure is not an empty clean run (issue #5-2).
        print(json.dumps(dict(error='generator failed', rc=gen.returncode,
                              programs=len(programs), out=str(root))))
        return 1
    results = []
    started = time.time()
    for n, row in enumerate(programs):
        phpt, strategy = row[0], row[1]
        code, ini = file_section(phpt)
        if code is None:
            results.append(dict(n=n, phpt=phpt, strategy=strategy, status='no_file_section',
                                **verdicts.flowfusion(False, [], [], '')))
            continue
        out = root / ('prog-%04d' % n)
        for item in Path(phpt).parent.iterdir():
            if item.is_file() and item.suffix != '.phpt':
                (out / 'docroot').mkdir(parents=True, exist_ok=True)
                shutil.copy(item, out / 'docroot' / item.name)
        observed, findings, states, log0 = run_program(code, prefix, out)
        v = verdicts.flowfusion(True, observed, states, log0)
        results.append(dict(n=n, phpt=phpt, strategy=strategy, parents=row[4:5],
                            ini_ignored=bool(ini), **v,
                            fused_response=(observed[0].get('response') if observed else None),
                            findings=[dict(sig=f['sig'], step=f['step']) for f in findings],
                            violations=sorted({v for s in observed for v in s.get('violations', [])
                                               if s.get('i', 0) > 0})))
        if args.time_limit and time.time() - started > args.time_limit:
            break
    counts = {}
    for r in results:
        counts[r.get('verdict', r.get('status'))] = counts.get(r.get('verdict', r.get('status')), 0) + 1
    sigs = {}
    for r in results:
        for f in r.get('findings', []):
            sigs.setdefault(f['sig'], dict(first=r['n'], steps=set()))['steps'].add(f['step'])
    summary = dict(scope='FlowFusion-generated programs executed as request 0 of a '
                         'lifecycle sequence; observation only',
                   version=args.version, seed=args.seed, generated=len(programs),
                   executed=len(results), wall_s=round(time.time() - started, 1),
                   verdicts=counts, denominators=summarize(results),
                   signatures={k: dict(first=v['first'], steps=sorted(v['steps']))
                               for k, v in sigs.items()},
                   strategies=sorted({r['strategy'] for r in results}),
                   limitations=['--INI-- sections not applied',
                                'CLI server only', 'exec/network functions disabled'])
    (root / 'results.jsonl').write_text('\n'.join(json.dumps(r) for r in results) + '\n')
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary | {'out': str(root)}, indent=2))
    bad = sum(1 for r in results if r.get('verdict') in ('harness_failed', 'not_reached'))
    return 2 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--ff-src', required=True)
    p.add_argument('--version', default='8.4.4')
    p.add_argument('--jobs', type=int, default=3)
    r = sub.add_parser('run')
    r.add_argument('--count', type=int, default=50)
    r.add_argument('--seed', type=int, default=1)
    r.add_argument('--version', default='8.4.4')
    r.add_argument('--time-limit', type=float, default=0)
    c = sub.add_parser('reclassify', help='re-derive verdicts of an existing run')
    c.add_argument('dir')
    args = parser.parse_args()
    if args.cmd == 'reclassify':
        rows = reclassify(args.dir)
        (Path(args.dir) / 'reclassified.jsonl').write_text(
            '\n'.join(json.dumps(r) for r in rows) + '\n')
        print(json.dumps(summarize(rows), indent=2))
        return 0
    return prepare(args) if args.cmd == 'prepare' else run(args)


if __name__ == '__main__':
    sys.exit(main())
