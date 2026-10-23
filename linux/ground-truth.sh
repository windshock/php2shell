#!/usr/bin/env bash
# Phase 5 v2 Stage 0: ground-truth regression set. For the three reproduced
# paths (P15/P16/P17) separates, per version:
#   reached          - the trigger request actually reached the vulnerable code
#   error_triggered  - the fatal/OOM the path requires occurred
#   memory_error     - the memory error itself was observed (ASAN teardown
#                      consumption for P15, UAF for P16/P17)
#   expectation      - vulnerable versions must reproduce, fixed versions must
#                      extinguish (error_trigger or memory_error absent)
# Exits non-zero when any expectation is unmet. This is the MVP criterion of
# issue #2 Stage 0: the known paths must be distinguishable by the harness
# before new-path exploration results can be trusted.
# Usage: ground-truth.sh <version> [port]
set -u
cd /mnt/c/Users/user/Downloads/php
version=${1:-8.4.4}
port=${2:-18088}
base=/home/phplab/php-lab
stamp=$(date -u +%Y%m%dT%H%M%S)
outdir="$base/evidence/ground-truth-$stamp-$version"
mkdir -p "$outdir"
export GROUND_TRUTH_OUT="$outdir"

case "$version" in
  8.4.27|8.5.12) expect=extinct ;;
  *) expect=reproduce ;;
esac

# P15 - Path A (HashTable partial init): crash config + pre-counter control.
bash linux/apache-patha-matrix.sh "$version" 1 "$port" >/dev/null 2>&1
patha_summary=$(ls -t "$base"/evidence/poc-patha-*-matrix/summary.json 2>/dev/null | head -1)
cp "$patha_summary" "$outdir/patha-summary.json" 2>/dev/null || echo '[]' > "$outdir/patha-summary.json"

# P16 - Path B (stale PS globals).
bash linux/apache-pathb-matrix.sh "$version" 1 "$port" >/dev/null 2>&1
pathb_summary=$(ls -t "$base"/evidence/poc-pathb-*-matrix/summary.json 2>/dev/null | head -1)
cp "$pathb_summary" "$outdir/pathb-summary.json" 2>/dev/null || echo '[]' > "$outdir/pathb-summary.json"

# P17 - Path C (post-RINIT BG(unserialize) on FPM).
python3 linux/poc-pathc.py --version "$version" --iterations 1 >/dev/null 2>&1
pathc_summary=$(ls -t "$base"/evidence/poc-pathc-summary-*.json 2>/dev/null | head -1)
cp "$pathc_summary" "$outdir/pathc-summary.json" 2>/dev/null || echo '{"runs":[]}' > "$outdir/pathc-summary.json"

python3 - "$outdir" "$version" "$expect" <<'PY'
import glob, json, sys
outdir, version, expect = sys.argv[1:4]
rows = []
problems = []

patha = json.load(open(outdir + '/patha-summary.json'))
patha_runs = patha.get('entries', [])
a_crash = next((r for r in patha_runs if str(r.get('label', '')).startswith('crash')), None)
a_control = next((r for r in patha_runs if r.get('label') == 'control'), None)
if a_crash is None:
    problems.append('P15 crash-config result missing')
else:
    rows.append(dict(
        path='P15_path_a', version=version, expectation=expect,
        reached=a_crash.get('oom_tried_bytes') is not None or 'fatal' in str(a_crash.get('verdict')),
        error_triggered='fatal' in str(a_crash.get('verdict')),
        memory_error=a_crash.get('verdict') == 'fatal_and_teardown_memory_error',
        teardown_frames=a_crash.get('teardown_frames'),
        control_pre_counter=(a_control or {}).get('pre_counter_crossing', False)))
if a_control is not None and a_control.get('verdict') == 'fatal_and_teardown_memory_error':
    problems.append('P15 control config crashed (differential control broken)')

pathb = json.load(open(outdir + '/pathb-summary.json'))
b_rows = pathb.get('entries', [])
b_ok = next((r for r in b_rows if r.get('status') == 'ok'), None)
if not b_ok:
    problems.append('P16 result missing')
else:
    detail = b_ok.get('detail') or {}
    rows.append(dict(
        path='P16_path_b', version=version, expectation=expect,
        reached=bool(detail.get('a') is not None),
        error_triggered=bool(detail.get('oom_logged') if 'oom_logged' in detail
                             else detail.get('a') == 500),
        memory_error=b_ok.get('reproduced', 0) > 0,
        worker_survived_a=detail.get('worker_alive_after_a')))

pathc = json.load(open(outdir + '/pathc-summary.json'))
c_run = next((r for r in pathc.get('runs', [])), None)
if c_run is None:
    problems.append('P17 result missing')
else:
    rows.append(dict(
        path='P17_path_c', version=version, expectation=expect,
        reached=bool(c_run.get('request_a_status')),
        error_triggered=bool(c_run.get('fatal_in_unserialize')),
        memory_error=c_run.get('result') == 'path_c_reproduced',
        worker_survived_a=c_run.get('worker_survived_a')))

# Expectation check: on vulnerable versions every path must show
# reached+error+memory_error; on fixed versions memory_error must be absent.
for row in rows:
    if row['expectation'] == 'reproduce':
        row['expectation_met'] = bool(row['reached'] and row['error_triggered']
                                      and row['memory_error'])
        if not row['expectation_met']:
            problems.append('%s: expected full reproduction, got %s' % (row['path'], row))
    else:
        row['expectation_met'] = not row['memory_error']
        if not row['expectation_met']:
            problems.append('%s: expected extinction, observed memory error' % row['path'])

# Stage 0 metric definitions recorded alongside every ground-truth run:
# reached / error_triggered / memory_error above, plus the exploration
# metrics that Phase 5 v2 stages report: error_site_coverage,
# request_transition_coverage, invariant_violations, time_to_first_valid_finding.
summary = dict(scope='Phase 5 v2 Stage 0 ground-truth regression',
               version=version, expectation=expect, paths=rows,
               problems=problems,
               metrics_definitions=dict(
                   reached='trigger request reached the vulnerable code',
                   error_triggered='the required fatal/OOM occurred',
                   memory_error='ASAN-confirmed memory error observed',
                   error_site_coverage='(v2 stages) fraction of enumerated fault sites exercised',
                   request_transition_coverage='(v2 stages) fraction of modeled request transitions exercised',
                   invariant_violations='(v2 stages) state-oracle candidate violations',
                   time_to_first_valid_finding='(v2 stages) wall time to first confirmed new-path error'),
               ok=not problems)
open(outdir + '/ground-truth.json', 'w').write(json.dumps(summary, indent=2))
print(json.dumps(dict(version=version, expectation=expect,
                      paths=[dict(path=r['path'], met=r['expectation_met'],
                                  memory_error=r['memory_error']) for r in rows],
                      problems=problems, ok=summary['ok']), indent=2))
sys.exit(0 if summary['ok'] else 2)
PY
