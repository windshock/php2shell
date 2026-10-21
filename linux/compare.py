#!/usr/bin/env python3
"""Run an explicitly supplied PHPT on two builds; never infer a CVE from smoke."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

BASE = Path('/home/phplab/php-lab')
parser = argparse.ArgumentParser()
parser.add_argument('--before', required=True, help='e.g. 8.4.4-asan')
parser.add_argument('--after', required=True, help='officially confirmed fixed build')
parser.add_argument('--test', type=Path, required=True)
parser.add_argument('--advisory', type=Path, required=True,
                    help='JSON: cve, official_url, affected_version, fixed_version, regression_source')
args = parser.parse_args()
metadata = json.loads(args.advisory.read_text())
for key in ('cve', 'official_url', 'affected_version', 'fixed_version', 'regression_source'):
    if not metadata.get(key):
        raise SystemExit('Missing advisory field: ' + key)
if not str(metadata['official_url']).startswith(('https://www.php.net/', 'https://github.com/php/php-src/')):
    raise SystemExit('Use the official PHP advisory/commit URL')
if args.before == args.after:
    raise SystemExit('Before/after builds must differ')
if metadata['cve'] != 'HARNESS-CONTROL-NOT-A-CVE':
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', metadata['cve']):
        raise SystemExit('Expected a CVE ID, or the explicit local harness control ID')
    if args.before.rsplit('-', 1)[-1] != args.after.rsplit('-', 1)[-1]:
        raise SystemExit('CVE comparison requires matching build flavors')
out = BASE / 'evidence' / ('comparison-' + time.strftime('%Y%m%dT%H%M%S', time.gmtime()))
out.mkdir(parents=True)
result = dict(advisory=metadata, test=str(args.test.resolve()), runs=[],
              verdict='inconclusive', reason='Official applicability and regression provenance require review')
for label, build in (('before', args.before), ('after', args.after)):
    if not re.fullmatch(r'8\.[0-9]+\.[0-9]+-(asan|normal)', build):
        raise SystemExit('Invalid build name')
    prefix = BASE / 'install' / build
    manifest = json.loads((prefix / 'build-manifest.json').read_text())
    expected = metadata['affected_version' if label == 'before' else 'fixed_version']
    if manifest['version'] != expected:
        raise SystemExit('Advisory/build version mismatch')
    work = out / label
    work.mkdir()
    # Separate copies prevent before-run generated artifacts affecting after-run.
    case_dir = args.test.resolve().parent
    if (work / 'case').resolve().is_relative_to(case_dir):
        raise SystemExit('Test fixtures must be outside the comparison output directory')
    shutil.copytree(case_dir, work / 'case')
    test = work / 'case' / args.test.name
    php = str(prefix / 'bin/php')
    env = {**os.environ, 'NO_INTERACTION': '1', 'REPORT_EXIT_STATUS': '1',
           'USE_ZEND_ALLOC': '0', 'USE_TRACKED_ALLOC': '1',
           'ASAN_OPTIONS': 'detect_leaks=0:symbolize=1:log_path=' + str(work / 'asan')}
    command = [php, '-n', str(BASE / 'sources' / ('php-' + manifest['version']) / 'run-tests.php'),
               '-n', '-q', '--offline', '-p', php, str(test)]
    try:
        run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or b'') + (exc.stderr or b'')
        (work / 'runner.log').write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        result['runs'].append(dict(label=label, build=manifest, exit_code=None,
                                   passed=False, failed=False, skipped_or_invalid=True, timeout=True))
        continue
    (work / 'runner.log').write_text(run.stdout + run.stderr)
    output = re.sub(r'\x1b\[[0-9;]*m', '', run.stdout).replace('\r', '\n')
    passed = bool(re.search(r'^PASS ', output, re.M))
    failed = bool(re.search(r'^FAIL ', output, re.M))
    skipped = bool(re.search(r'^(SKIP|BORK|XFAIL|WARN) ', output, re.M))
    result['runs'].append(dict(label=label, build=manifest, exit_code=run.returncode,
                               passed=passed, failed=failed, skipped_or_invalid=skipped))
before, after = result['runs']
if before['failed'] and not before['skipped_or_invalid'] and after['passed'] and after['exit_code'] == 0 and not after['skipped_or_invalid']:
    result['verdict'] = 'regression_difference_observed'
    result['reason'] = 'Review allocation/free/use stacks and official CVE mapping before declaring vulnerable/fixed'
(out / 'result.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
raise SystemExit(0 if result['verdict'] == 'regression_difference_observed' else 2)
