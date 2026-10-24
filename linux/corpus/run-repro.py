#!/usr/bin/env python3
"""#4 H2: run historical reproducers against the lab builds (plan §13.4).

For each case of h2-cases.json and each version (default 8.4.4 / 8.4.27,
flavor asan) the reproducer runs once in the CLI with:
  php -n (no php.ini) + the PHPT --INI-- lines, exec/network functions
  disabled, temp/session paths inside the run dir, ASAN with a log path.
Verdict per run (fail-closed, R1/R2):
  capability_gap   a required extension is not in this build (never a pass)
  harness_failed   the binary is missing or the run could not start
  reproduced       oracle hit: ASAN report / fatal signal (memory_error),
                   PHPT expectation mismatch (expect), or the custom check
  not_reproduced   the run completed and the oracle did not fire
  no_reproducer    the source has no script (recorded, never run)
  excluded_weaponized  the only code is a weaponized exploit (never run)
A not_reproduced on one build is NOT a safety verdict for that build.
Every summary carries provenance (R12).

Usage: run-repro.py [--cases R26 R35 ...] [--versions 8.4.4 8.4.27] [--flavor asan]
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
SANDBOX = ['-d', 'disable_functions=exec,shell_exec,system,passthru,proc_open,popen,'
           'pcntl_exec,mail,fsockopen,pfsockopen,stream_socket_client,socket_connect,'
           'curl_exec,putenv,dl', '-d', 'allow_url_fopen=0', '-d', 'max_execution_time=30']


def phpt_sections(text):
    sections, current = {}, None
    for line in text.splitlines(keepends=True):
        m = re.match(r'^--([A-Z_]+)--\s*$', line)
        if m:
            current = m.group(1)
            sections[current] = ''
        elif current:
            sections[current] += line
    return sections


def extract_php(text):
    """bugs.php.net blocks mix prose and code: keep from the first '<?' up
    to the next tracker section marker."""
    start = text.find('<?')
    if start < 0:
        return text
    code = text[start:]
    cut = re.search(r'\n\s*(Expected result|Actual result|Patches|History|Backtrace)\s*:', code)
    return code[:cut.start()] if cut else code


def opcache_args(php):
    """opcache is a shared zend_extension: load it explicitly under -n."""
    found = sorted(Path(php).parents[1].glob('lib/php/extensions/*/opcache.so'))
    return (['-d', 'zend_extension=%s' % found[0], '-d', 'opcache.enable_cli=1']
            if found else [])


def modules(php, extra=()):
    res = subprocess.run([str(php), '-n', *extra, '-m'], capture_output=True, text=True)
    names = {line.strip().lower() for line in res.stdout.splitlines() if line.strip()}
    if 'zend opcache' in names:
        names.add('opcache')
    return names


def expect_matches(expected, actual, fmt):
    expected, actual = expected.strip(), actual.strip()
    if fmt == 'EXPECT':
        return expected == actual
    rx = re.escape(expected)
    for token, pattern in (('%s', r'[^\r\n]+'), ('%d', r'\d+'), ('%a', r'.+'),
                           ('%A', r'.*'), ('%w', r'\s*'), ('%i', r'[+-]?\d+'),
                           ('%f', r'[+-]?\.?\d+\.?\d*(?:[Ee][+-]?\d+)?'), ('%c', r'.')):
        rx = rx.replace(re.escape(token), pattern)
    return re.fullmatch(rx, actual, re.S) is not None


CUSTOM = {
    # GH-24361: after a compile error caught by opcache_compile_file() the
    # cycle collector must not stay protected. The script dumps three bools:
    # protected-before, the compile result, protected-after (checked against
    # a real run's output, R5) - the bug is present when protected-after is
    # true.
    'gc_protected_after_compile_error':
        lambda out: re.findall(r'bool\((true|false)\)', out)[2:3] == ['true'],
}


def case_source(case):
    """Script text of a case as run: (code, ini lines, needs, expect)."""
    text = (HERE / 'repro' / case['script']).read_text(encoding='utf-8')
    if text.lstrip().startswith('diff --git'):
        # A test file quoted as a patch: keep the added lines without '+'.
        text = '\n'.join(l[1:] for l in text.splitlines()
                         if l.startswith('+') and not l.startswith('+++')) + '\n'
    ini, expect = [], None
    if case['format'] == 'phpt':
        sec = phpt_sections(text)
        code = sec.get('FILE', '')
        ini = [l.strip() for l in sec.get('INI', '').splitlines() if '=' in l]
        needs = [l.strip().lower() for l in sec.get('EXTENSIONS', '').splitlines() if l.strip()]
        for fmt in ('EXPECT', 'EXPECTF'):
            if fmt in sec:
                expect = (fmt, sec[fmt])
    else:
        code = extract_php(text) if case.get('extract') else text
        needs = []
    needs = sorted(set(needs) | {n.lower() for n in case.get('needs', [])})
    return code, ini, needs, expect


def run_case(rid, case, version, flavor, root):
    out = root / rid / version
    out.mkdir(parents=True, exist_ok=True)
    rec = dict(record=rid, version=version, flavor=flavor, source=case.get('source'))
    if case.get('status') in ('no_reproducer', 'excluded_weaponized'):
        # Never run: no script, or the only code is a weaponized exploit
        # (outside the safety boundary).
        rec.update(verdict=case['status'], note=case.get('note'))
        return rec
    php = BASE / 'install' / ('%s-%s' % (version, flavor)) / 'bin/php'
    if not php.exists():
        rec.update(verdict='harness_failed', reason='binary missing: %s' % php)
        return rec
    code, ini, needs, expect = case_source(case)
    extra = opcache_args(php) if 'opcache' in needs else []
    have = modules(php, extra)
    missing = [n for n in needs if n not in have]
    rec['needs'] = needs
    if missing:
        rec.update(verdict='capability_gap', missing_extensions=missing)
        return rec
    script = out / 'repro.php'
    script.write_text(code, encoding='utf-8')
    args = [str(php), '-n'] + extra + SANDBOX + ['-d', 'sys_temp_dir=%s' % out,
                                         '-d', 'session.save_path=%s' % out]
    for line in ini:
        args += ['-d', line]
    args.append(str(script))
    env = dict(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer', USE_ZEND_ALLOC='1',
               PATH='/usr/bin:/bin')
    started = time.time()
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=120, cwd=out, env=env)
    except subprocess.TimeoutExpired as exc:
        # #5 P1-D: a timeout is an unobserved run, never evidence of
        # non-reproduction. Keep whatever partial output the child produced.
        rec.update(verdict='timeout', reason='timeout 120 s',
                   partial_output=bool(exc.stdout or exc.stderr))
        if exc.stdout or exc.stderr:
            sep = bytes([10]) + b'--stderr--' + bytes([10])
            (out / 'timeout-partial.txt').write_bytes(
                (exc.stdout or b'')[-20000:] + sep + (exc.stderr or b'')[-20000:])
        return rec
    (out / 'stdout.txt').write_text(res.stdout)
    (out / 'stderr.txt').write_text(res.stderr)
    reports = sorted(out.glob('asan.*'))
    asan = None
    for r in reports:
        t = r.read_text(errors='replace')
        if 'AddressSanitizer' in t:
            kind = re.search(r'AddressSanitizer: ([\w-]+)', t)
            frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', t)[:3]
            asan = '%s:%s' % (kind.group(1) if kind else '?', '>'.join(frames))
            break
    rec.update(rc=res.returncode, seconds=round(time.time() - started, 1), asan=asan,
               signal=-res.returncode if res.returncode < 0 else None)
    oracle = case['oracle']
    if oracle == 'memory_error':
        hit = bool(asan) or res.returncode < 0 or res.returncode in (134, 139)
        if hit:
            rec['outcome_class'] = 'memory_error'
    elif oracle == 'expect':
        hit = expect is not None and not expect_matches(expect[1], res.stdout, expect[0])
        rec['expect_format'] = expect[0] if expect else None
        if hit:
            # #4 H2: an EXPECT/EXPECTF mismatch is a functional divergence,
            # not by itself a memory-safety violation.
            rec['outcome_class'] = 'functional_regression'
    else:
        hit = CUSTOM[case['custom']](res.stdout)
        if hit:
            rec['outcome_class'] = 'gc_state_stuck' if oracle == 'gc' else 'custom'
    if not hit:
        # Separate clean completion from abnormal-exit-with-no-oracle so the
        # denominators stay honest (#4 H2).
        rec['outcome_class'] = ('completed_no_oracle' if res.returncode == 0
                                else 'abnormal_exit_no_oracle')
    rec['verdict'] = 'reproduced' if hit else 'not_reproduced'
    rec['oracle'] = oracle
    return rec


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cases', nargs='*')
    parser.add_argument('--versions', nargs='+', default=['8.4.4', '8.4.27'])
    parser.add_argument('--flavor', default='asan')
    args = parser.parse_args()
    cases = json.loads((HERE / 'h2-cases.json').read_text(encoding='utf-8'))['cases']
    chosen = args.cases or sorted(cases)
    root = BASE / 'evidence' / ('corpus-h2-%s-%s' % (time.strftime('%Y%m%dT%H%M%S',
                                                                    time.gmtime()), args.flavor))
    root.mkdir(parents=True)
    rows = [run_case(rid, cases[rid], v, args.flavor, root) for rid in chosen
            for v in args.versions]
    report = dict(scope='#4 H2 reproduction (not a safety verdict for any build)',
                  **provenance.provenance(), flavor=args.flavor, results=rows)
    (root / 'summary.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(out=str(root), citable=report['citable'], results=[
        dict(record=r['record'], version=r['version'], verdict=r['verdict'],
             asan=r.get('asan'), signal=r.get('signal'), missing=r.get('missing_extensions'))
        for r in rows]), indent=2))
    return 0 if all(r['verdict'] != 'harness_failed' for r in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
