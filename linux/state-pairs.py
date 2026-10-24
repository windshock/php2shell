#!/usr/bin/env python3
"""#7 P0 (plan 15.2): offline, READ-ONLY aggregation of same-fingerprint /
different-prefix pairs over existing explorer campaign evidence.

Schema frozen in docs/state-pair-schema.md: fingerprint = the explorer's
normalize_state semantics (imported, never reimplemented) over the step's
startup snapshot + explicit suffix modules_activated,gc_enabled,gc_active,
gc_protected (gc_runs excluded: history counter). Pairs need the same
build context (version/flavor/sapi/binary) and the same fault/limit class;
carried-marked fingerprints are isolated (address-reuse fake identity).
Campaign evidence is only read; output goes to --out (default: a fresh
evidence dir). Go gate (>=20 confirmed pairs, query contract, budget
estimate) is evaluated and reported.

Usage: state-pairs.py <run_dir> [<run_dir> ...] | --self-test
"""
import importlib.util
import json
import re
import sys
import time
from itertools import combinations
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

_spec = importlib.util.spec_from_file_location('lexp', HERE / 'lifecycle-explore.py')
lexp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lexp)
BASE = Path('/home/phplab/php-lab')
STEP_RE = re.compile(r'[?&]step=(\d+)')


def fingerprint(snap, prev_startup):
    norm = lexp.normalize_state(snap, [prev_startup] if prev_startup else [])
    suffix = ',mod=%d,gc_e=%d,gc_a=%d,gc_p=%d' % (
        snap.get('modules_activated', 0), snap.get('gc_enabled', 0),
        snap.get('gc_active', 0), snap.get('gc_protected', 0))
    return norm + suffix


def parse_exec(exec_dir, seq_row):
    """Per-step (fingerprint, prefix, completeness) for one exec."""
    obs = exec_dir / 'observer.log'
    startups, shutdowns = {}, {}
    if obs.exists():
        for line in obs.read_text(errors='replace').splitlines():
            if not line.startswith('STATE '):
                continue
            try:
                st = json.loads(line[6:])
            except ValueError:
                continue
            m = STEP_RE.search(st.get('uri') or '')
            if not m:
                continue  # readiness probe etc.
            step = int(m.group(1))
            if st.get('tag') == 'startup':
                startups[step] = st
            elif st.get('tag') == 'shutdown':
                shutdowns[step] = st
    steps = seq_row.get('steps') or []
    planned = seq_row.get('planned') or [s.get('a') for s in
                                         (json.loads(seq_row['seq'])['steps']
                                          if isinstance(seq_row.get('seq'), str)
                                          else seq_row['seq']['steps'])]
    limit_fault = ''
    try:
        sq = json.loads(seq_row['seq']) if isinstance(seq_row['seq'], str) else seq_row['seq']
        limit_fault = '|limit=%s,fault=%s' % (sq.get('limit'), sq.get('fault', 0))
    except (ValueError, KeyError, TypeError):
        pass
    rows, actions = [], []
    for i in range(len(planned)):
        action = planned[i]
        executed = any(s.get('i') == i for s in steps)
        if not executed:
            rows.append(dict(step=i, completeness='missing'))
            continue
        snap = startups.get(i)
        if snap is None:
            rows.append(dict(step=i, completeness='partial',
                             prefix='>'.join(actions) + limit_fault))
        else:
            fp = fingerprint(snap, startups.get(i - 1))
            rows.append(dict(step=i, completeness='complete', fingerprint=fp,
                             carried_involved='carried' in fp,
                             prefix='>'.join(actions) + limit_fault,
                             boundary_only=True, pid=snap.get('pid')))
        actions.append(action)
    return rows


def load_run(run_dir):
    run_dir = Path(run_dir)
    summary_p = run_dir / 'summary.json'
    if not summary_p.exists():
        return None
    s = json.loads(summary_p.read_text())
    note = run_dir / 'provenance-note.json'
    source_commit = s.get('source_commit') or (
        json.loads(note.read_text()).get('effective_commit') if note.exists() else None)
    ctx = dict(version=s.get('version'), flavor=s.get('flavor'), sapi=s.get('sapi'),
               binary=s.get('binary_sha256'), source_commit=source_commit,
               feedback=s.get('feedback'), run=run_dir.name)
    execs = {}
    for line in (run_dir / 'execs.jsonl').read_text(errors='replace').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        execs[row['exec']] = row
    out = []
    for exec_dir in sorted(run_dir.glob('exec-*')):
        n = int(exec_dir.name.split('-')[1])
        row = execs.get(n)
        if row is None:
            continue
        for r in parse_exec(exec_dir, row):
            r['exec'] = n
            out.append(r)
    return ctx, out


def aggregate(runs):
    groups = {}   # (ctx-key, limit_fault-class inside prefix, fingerprint) -> [entries]
    for ctx, rows in runs:
        key = (ctx['version'], ctx['flavor'], ctx['sapi'], ctx['binary'])
        for r in rows:
            if r['completeness'] != 'complete':
                continue
            lf = r['prefix'].rsplit('|', 1)[-1] if '|' in r['prefix'] else 'limit=?,fault=0'
            gkey = key + (lf, r['fingerprint'])
            groups.setdefault(gkey, []).append(
                dict(prefix=r['prefix'], run=ctx['run'], exec=r.get('exec'),
                     step=r['step'], carried=r['carried_involved']))
    candidates, confirmed_pairs, carried_groups = [], 0, 0
    for gkey, entries in sorted(groups.items()):
        prefixes = {e['prefix'] for e in entries}
        if len(prefixes) < 2:
            continue
        any_carried = any(e['carried'] for e in entries)
        if any_carried:
            carried_groups += 1
        else:
            confirmed_pairs += sum(1 for _ in combinations(sorted(prefixes), 2))
        candidates.append(dict(
            context=dict(version=gkey[0], flavor=gkey[1], sapi=gkey[2],
                         binary=gkey[3][:8], limit_fault=gkey[4]),
            fingerprint=gkey[5], prefixes=sorted(prefixes), n_entries=len(entries),
            carried_involved=any_carried,
            sample=entries[:3]))
    return candidates, confirmed_pairs, carried_groups


def self_test():
    import tempfile
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    def snap(**kw):
        base = dict(tag='startup', pid=1, uri='/x?step=0', ser_level=0, ser_data=0,
                    unser_level=0, unser_data=0, lock=0, ps_id=0, ps_mod=0, ps_status=1,
                    ps_vars_type=0, ps_session_vars=0, url_hosts=0, modules_activated=0,
                    gc_enabled=1, gc_active=0, gc_protected=0, gc_runs=0)
        base.update(kw)
        return base

    fp_clean = fingerprint(snap(), None)
    check('gc suffix included', 'gc_p=0' in fp_clean and 'ser=0' in fp_clean)
    check('gc_runs excluded', 'gc_runs' not in fp_clean and 'runs' not in fp_clean)
    check('gc_protected changes the fingerprint',
          fingerprint(snap(gc_protected=1), None) != fp_clean)
    fp_carried = fingerprint(snap(unser_data=99), snap(unser_data=99))
    check('carried marker detected', 'carried' in fp_carried)
    with tempfile.TemporaryDirectory() as tmp:
        def mk_exec(run, n, seq, states):
            d = Path(tmp) / run / ('exec-%04d' % n)
            d.mkdir(parents=True)
            (d / 'observer.log').write_text(
                ''.join('STATE %s\n' % json.dumps(s) for s in states))
            return dict(exec=n, seq=json.dumps(seq), steps=states and [
                dict(i=i, response='s200') for i in range(len(seq['steps']))] or [])
        # same fingerprint (pristine state), different prefixes, same class
        rows_a = [mk_exec('r1', 0, dict(limit='8M', steps=[{'a': 'health'}]), [snap()]),
                  mk_exec('r1', 1, dict(limit='8M', steps=[{'a': 'upload_nofile'},
                                                           {'a': 'health'}]),
                          [snap(), snap(uri='/x?step=1')])]
        r0 = rows_a[0]
        r0['steps'] = [dict(i=0, response='s200')]
        r1 = rows_a[1]
        r1['steps'] = [dict(i=0, response='s200'), dict(i=1, response='s200')]
        # different fault class must not pair
        rows_b = [mk_exec('r1', 2, dict(limit='8M', fault=3, steps=[{'a': 'health'}]),
                          [snap(uri='/x?step=0')])]
        rows_b[0]['steps'] = [dict(i=0, response='s200')]
        parsed = []
        for row in (r0, r1, rows_b[0]):
            parsed.extend(parse_exec(Path(tmp) / 'r1' / ('exec-%04d' % row['exec']), row))
        cands, confirmed, carried = aggregate([
            (dict(version='8.4.27', flavor='asanext', sapi='cli', binary='deadbeef',
                  run='r1'), parsed)])
        check('one multi-prefix fingerprint found', len(cands) == 1)
        check('confirmed pair count 1 (fault=3 excluded)', confirmed == 1)
        check('carried groups isolated', carried == 0)
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    runs = [a for a in sys.argv[1:] if not a.startswith('--')]
    out_dir = None
    if '--out' in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index('--out') + 1])
    if not runs:
        print('usage: state-pairs.py <run_dir> [...] [--out DIR]')
        return 2
    loaded, failed, completeness = [], [], {'complete': 0, 'partial': 0, 'missing': 0}
    for r in runs:
        got = load_run(r)
        if got is None:
            failed.append(r)
        else:
            loaded.append(got)
            for row in got[1]:
                completeness[row['completeness']] = completeness.get(row['completeness'], 0) + 1
    candidates, confirmed, carried = aggregate(loaded)
    go_gate = dict(confirmed_pairs=confirmed, threshold=20, passed=confirmed >= 20,
                   note='P1 needs >=20 confirmed pairs + the p1+q/p2+q replay '
                        'contract + a per-pair budget (~6 execs incl. self-contrast)')
    summary = dict(scope='#7 P0 read-only state-pair aggregation '
                   '(schema frozen: docs/state-pair-schema.md)',
                   runs=[c for c, _ in loaded], failed_runs=failed,
                   completeness_distribution=completeness,
                   fingerprints_with_multiple_prefixes=len(candidates),
                   confirmed_pairs=confirmed, carried_isolated_groups=carried,
                   go_gate=go_gate, **provenance.provenance())
    if out_dir is None:
        out_dir = BASE / 'evidence' / ('state-pairs-%s' %
                                       time.strftime('%Y%m%dT%H%M%S', time.gmtime()))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'model-candidates.json').write_text(json.dumps(candidates, indent=2))
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(dict(out=str(out_dir), confirmed=confirmed, carried=carried,
                          candidates=len(candidates), go=go_gate['passed'],
                          citable=summary['citable']), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
