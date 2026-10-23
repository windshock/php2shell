#!/usr/bin/env python3
"""#3 CoreGuard Phase 5: ONE-TIME hold-out evaluation (pre-registration v1,
mapping addendum v1.1 in docs/coreguard/evaluation-preregistration.md).

Cases: docs/coreguard/holdout-v1.json (SHA-256 checked against the
registered value). Builds: B = 8.4.27-asanext, C = 8.4.27-coreguard-asanext
in modes disabled / observe / enforce, >= 3 independent repeats each, same
input, CLI (php -n + required extensions), same sandbox as run-repro.py.

Facts recorded per run: rc, signal, ASAN report, Zend heap panic, CoreGuard
event, CoreGuard fatal, case harm oracle, whether the script reached its end.
Verdict (fixed before the first run, v1.1):
  test_failed                      harness failure (binary missing, timeout)
  not_reached                      B does not show the harm -> case excluded
  not_protected                    harm observed, no CoreGuard event
  detected_only                    event AND harm (or ASAN) in the same run
  prevented_before_invalid_access  event, no harm, no ASAN, script ran to its end
  worker_contained                 event, no harm, no ASAN, the guard ended the
                                   unit of work (CLI: the request/process) early
  harm_absent_without_event        no event and no harm in a run although B
                                   showed it (flaky reproduction; never a success)
Harm oracles: R23 = GC runs stop increasing after the SOAP failure;
R46/R51 = memory error (ASAN report, zend_mm_panic, fatal signal).

Usage: holdout-eval.py --cases R23 [--repeats 3]
"""
import argparse
import hashlib
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
REGISTERED_SHA = 'acf426107a094cb3a410687b9962982d7d72451c7ef86826f4140681b8111f4a'
EVENT = 'COREGUARD event='
CG_FATAL = 'CoreGuard: '
END_MARK = '__HOLDOUT_END__'


def harm_r23(stdout):
    """GC runs do not increase after the SOAP failure (GH-10026 symptom)."""
    if 'Soap call failed' not in stdout:
        return False
    after = stdout.split('Soap call failed', 1)[1]
    before = [int(x) for x in re.findall(r'GC Runs: (\d+)', stdout.split('Soap call failed')[0])]
    runs = [int(x) for x in re.findall(r'GC Runs: (\d+)', after)]
    return bool(runs) and bool(before) and max(runs) <= max(before)


def run(php, code, needs, mode, workdir):
    script = workdir / 'case.php'
    # end marker: printed only if the script returns normally
    body = code.rstrip()
    if body.endswith('?>'):
        body += "\n<?php echo '%s';\n" % END_MARK
    else:
        body += "\necho '%s';\n" % END_MARK
    script.write_text(body)
    asan_dir = workdir / ('asan-%s-%d' % (mode, time.time_ns()))
    asan_dir.mkdir()
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % asan_dir,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    if mode != 'B':
        env['COREGUARD_MODE'] = mode
    extra = rr.opcache_args(php) if 'opcache' in needs else []
    args = [str(php), '-n'] + extra + rr.SANDBOX + [
        '-d', 'sys_temp_dir=%s' % workdir, '-d', 'session.save_path=%s' % workdir, str(script)]
    t0 = time.time()
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=120, cwd=workdir, env=env)
    except subprocess.TimeoutExpired:
        return dict(harness='timeout')
    asan = None
    for p in asan_dir.glob('asan.*'):
        t = p.read_text(errors='replace')
        if 'AddressSanitizer' in t:
            frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', t)[:3]
            kind = re.search(r'AddressSanitizer: ([\w-]+)', t)
            asan = '%s:%s' % (kind.group(1) if kind else '?', '>'.join(frames))
    out = res.stdout + res.stderr
    return dict(rc=res.returncode, signal=-res.returncode if res.returncode < 0 else None,
                seconds=round(time.time() - t0, 2), asan=asan,
                zend_mm_panic='zend_mm_panic' in out or 'zend_mm_heap corrupted' in out,
                event=EVENT in res.stderr, cg_fatal=CG_FATAL in out,
                reached_end=END_MARK in res.stdout,
                stdout=res.stdout[-800:], stderr=res.stderr[-800:])


def harm(rid, r):
    if rid == 'R23':
        return harm_r23(r['stdout'])
    return bool(r['asan'] or r['zend_mm_panic'] or r['signal'] or r['rc'] in (134, 139))


def verdict(rid, r, b_harm):
    if 'harness' in r:
        return 'test_failed'
    if not b_harm:
        return 'not_reached'
    h = harm(rid, r)
    if not r['event']:
        return 'not_protected' if h else 'harm_absent_without_event'
    if h or r['asan']:
        return 'detected_only'
    return 'prevented_before_invalid_access' if r['reached_end'] else 'worker_contained'


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--cases', nargs='+', required=True,
                        help='hold-out records to evaluate now (one-time per case, v1.1)')
    args = parser.parse_args()
    sha = hashlib.sha256(HOLDOUT.read_bytes()).hexdigest()
    if sha != REGISTERED_SHA:
        print(json.dumps(dict(error='hold-out list changed', sha=sha)))
        return 2
    holdout = [h for h in json.loads(HOLDOUT.read_text())['holdout'] if h['record'] in args.cases]
    if sorted(h['record'] for h in holdout) != sorted(set(args.cases)):
        print(json.dumps(dict(error='not a hold-out record', cases=args.cases)))
        return 2
    cases = json.loads((HERE.parent / 'corpus/h2-cases.json').read_text())['cases']
    b_php = BASE / 'install/8.4.27-asanext/bin/php'
    c_php = BASE / 'install/8.4.27-coreguard-asanext/bin/php'
    c_manifest = json.loads((c_php.parents[1] / 'build-manifest.json').read_text())
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-holdout-%s' % stamp)
    out.mkdir(parents=True)
    rows = {}
    for h in holdout:
        rid = h['record']
        code, ini, needs, _ = rr.case_source(cases[rid])
        if ini:
            code = '<?php\n' + ''.join("ini_set(%r, %r);\n" % tuple(l.split('=', 1)) for l in ini) \
                + '?>' + code
        rows[rid] = dict(pattern=h['pattern'], runs={})
        for mode in ('B', 'disabled', 'observe', 'enforce'):
            php = b_php if mode == 'B' else c_php
            reps = []
            for _ in range(args.repeats):
                with tempfile.TemporaryDirectory(dir=out) as tmp:
                    reps.append(run(php, code, needs, mode, Path(tmp)))
            rows[rid]['runs'][mode] = reps
        b_harm = all(harm(rid, r) for r in rows[rid]['runs']['B'] if 'harness' not in r)
        rows[rid]['b_harm_all_repeats'] = b_harm
        rows[rid]['verdicts'] = {m: [verdict(rid, r, b_harm) for r in reps]
                                 for m, reps in rows[rid]['runs'].items() if m != 'B'}
        print('%s %-26s B_harm=%s %s' % (rid, h['pattern'], b_harm, json.dumps(rows[rid]['verdicts'])))
    summary = dict(scope='CoreGuard Phase 5 one-time hold-out evaluation (pre-registration v1/v1.1)',
                   holdout_sha256=sha, cases_evaluated=sorted(args.cases),
                   repeats=args.repeats, c_build=c_manifest.get('patches'),
                   c_binary_sha256=c_manifest.get('binary_sha256'), rows=rows,
                   **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('out=%s citable=%s' % (out, summary['citable']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
