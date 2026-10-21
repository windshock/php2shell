#!/usr/bin/env python3
"""Check environment deliverables from real build/test artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

BASE = Path('/home/phplab/php-lab')
summary = dict(time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               scope='environment readiness, not a vulnerability verdict',
               builds=[], matrices=[], calibrations=[], cve_verdict='not_run',
               official_fixed_version='not_confirmed')
for build in ('8.4.4-normal', '8.4.4-asan', '8.5.4-asan'):
    prefix = BASE / 'install' / build
    data = json.loads((prefix / 'build-manifest.json').read_text())
    for name, expected in data['binary_sha256'].items():
        assert hashlib.sha256((prefix / name).read_bytes()).hexdigest() == expected, build
    source = BASE / 'sources' / ('php-' + data['version'])
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    summary['builds'].append(data)
    matrix_path = BASE / 'evidence' / ('matrix-' + build + '.json')
    matrix = json.loads(matrix_path.read_text())
    assert len(matrix['runs']) == 6
    assert {(r['allocator'], r['buffering']) for r in matrix['runs']} == {
        (a, b) for a in ('zend', 'system', 'tracked') for b in ('on', 'off')}
    for run in matrix['runs']:
        assert run['status'] == 'passed' and run['servers_stopped'] and run['same_worker_reused']
        assert not run['asan_reports']
        assert run['worker_allocator_env']['USE_ZEND_ALLOC'] == ('1' if run['allocator'] == 'zend' else '0')
    summary['matrices'].append(dict(build=build, configurations=6, result=str(matrix_path)))
for version in ('8.4.4', '8.5.4'):
    folder = BASE / 'evidence' / ('calibration-' + version)
    calibration = json.loads((folder / 'result.json').read_text())
    assert calibration['probe_exit_code'] != 0 and calibration['php_gdb_exit_code'] == 0
    assert 'heap-use-after-free' in (folder / 'asan-probe.log').read_text()
    assert 'main.c:' in (folder / 'php-gdb.log').read_text()
    summary['calibrations'].append(calibration)
controls = [json.loads(p.read_text()) for p in (BASE / 'evidence').glob('comparison-*/result.json')]
assert any(c['advisory']['cve'] == 'HARNESS-CONTROL-NOT-A-CVE'
           and c['test'].endswith('debug-build.phpt') and c['verdict'] == 'regression_difference_observed'
           for c in controls)
assert any(c['test'].endswith('skip.phpt') and c['verdict'] == 'inconclusive'
           and all(r['skipped_or_invalid'] for r in c['runs']) for c in controls)
repo = Path(__file__).resolve().parents[1]
health = json.loads((repo / 'var/logs/wsl-fpm-health-from-windows.json').read_text())
assert health['sapi'] == 'fpm-fcgi' and health['debug']
summary['windows_to_linux_http'] = health
summary['comparison_controls'] = 'difference recognized; skip remained inconclusive'
listeners = subprocess.check_output(['ss', '-ltnH'], text=True)
assert not any(line.split()[3].rsplit(':', 1)[-1] in ('18085', '19084') for line in listeners.splitlines())
summary['lab_servers_stopped'] = True
summary['status'] = 'ready_for_analysis_and_regression_execution'
path = BASE / 'evidence/environment-status.json'
path.write_text(json.dumps(summary, indent=2))
print(json.dumps(dict(status=summary['status'], builds=len(summary['builds']),
                     configurations=sum(m['configurations'] for m in summary['matrices']),
                     cve_verdict=summary['cve_verdict'], result=str(path)), indent=2))
