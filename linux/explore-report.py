#!/usr/bin/env python3
"""Gate evidence from lifecycle-explore.py campaign logs (plan §12.6.4).

  g1    generated sequences: grammar-checked, distinct, outside the fixed
        8-combination regression matrix
  g2    closed loop: a sequence that produced new feedback was stored, later
        selected as a parent, and its mutated child was executed (lineage
        chains, with the keys each link added)
  g4    feedback ON vs OFF across campaign directories at equal budget:
        unique state transitions, failure sites, ASAN signatures, cost per
        confirmed finding

  g3    hold-out rediscovery of the known paths, with miss causes split
        into generation / reach / oracle

Usage: explore-report.py g1|g2 <campaign-dir>
       explore-report.py g3 DIR...
       explore-report.py g4 --on DIR... --off DIR...
       explore-report.py g5 DIR... --cutoff SECONDS   (SAPI profiles, same budget)
"""
import argparse
import json
import statistics
import sys
from pathlib import Path


def load_execs(path):
    return [json.loads(line) for line in (Path(path) / 'execs.jsonl').read_text().splitlines()
            if line.strip()]


def g1(d):
    execs = load_execs(d)
    ran = [e for e in execs if e.get('grammar_ok')]
    generated = [e for e in ran if e['origin'] != 'seed']
    distinct = {json.dumps(e['seq'], sort_keys=True) for e in generated}
    novel = [e for e in generated if e.get('novel_vs_fixed_matrix')]
    lengths = {}
    for e in generated:
        lengths[len(e['seq']['steps'])] = lengths.get(len(e['seq']['steps']), 0) + 1
    rejected = [e for e in execs if not e.get('grammar_ok')]
    examples = [dict(exec=e['exec'], op=e.get('op'), parent=e.get('parent'),
                     limit=e['seq']['limit'], steps=[s['a'] for s in e['seq']['steps']])
                for e in novel[:8]]
    return dict(gate='G1', executed=len(ran), generated=len(generated),
                distinct_generated=len(distinct), outside_fixed_matrix=len(novel),
                grammar_rejected_before_run=len(rejected), length_histogram=lengths,
                examples=examples,
                passed=len(novel) > 0 and len(distinct) == len(generated))


def g2(d):
    execs = {e['id']: e for e in load_execs(d) if e.get('grammar_ok')}
    corpus = json.loads((Path(d) / 'corpus.json').read_text())
    sched = [json.loads(line) for line in (Path(d) / 'scheduler.jsonl').read_text().splitlines()
             if line.strip()]
    by_id = {c['id']: c for c in corpus}
    chains = []
    for entry in corpus:
        chain = [entry]
        while chain[-1].get('parent') in by_id:
            chain.append(by_id[chain[-1]['parent']])
        if len(chain) >= 3:
            chains.append(list(reversed(chain)))
    chains.sort(key=len, reverse=True)

    def describe(c):
        e = execs.get(c['id'], {})
        return dict(id=c['id'], depth=c['depth'], op=e.get('op'),
                    steps=[s['a'] for s in c['seq']['steps']], limit=c['seq']['limit'],
                    new_keys=len(e.get('new_keys', [])),
                    new_key_examples=[k[:110] for k in e.get('new_keys', [])
                                      if k.startswith(('T:', 'A:', 'F:'))][:3])
    # Selection changed by feedback: entries added mid-run (depth>0) that the
    # scheduler then picked as parents.
    added_then_picked = sorted({s['parent'] for s in sched
                                if by_id.get(s['parent'], {}).get('depth', 0) > 0})
    return dict(gate='G2', corpus_size=len(corpus),
                max_depth=max((c['depth'] for c in corpus), default=0),
                selections=len(sched),
                generated_entries_reselected_as_parents=len(added_then_picked),
                longest_chains=[[describe(c) for c in chain] for chain in chains[:2]],
                passed=bool(chains) and bool(added_then_picked))


def campaign_metrics(d):
    summary = json.loads((Path(d) / 'summary.json').read_text())
    execs = [e for e in load_execs(d) if e.get('grammar_ok')]
    keys = set()
    for e in execs:
        keys.update(e.get('new_keys', []))
    trans = {k for k in keys if k.startswith('T:')}
    states = {k for k in keys if k.startswith('S:')}
    sites = {k for k in keys if k.startswith('F:')}
    sigs = {k for k in keys if k.startswith('A:')}
    confirmed_execs = sum(1 for e in execs
                          if any(s.get('oracle') == 'memory_error_confirmed'
                                 for s in e.get('steps', [])))
    return dict(dir=str(d), feedback=summary['feedback'], seed=summary['seed'],
                execs=summary['execs'], wall_s=summary['wall_s'],
                code_edges=summary.get('code_edge_coverage'),
                transitions=len(trans), states=len(states), failure_sites=len(sites),
                asan_signatures=len(sigs), confirmed_execs=confirmed_execs,
                execs_per_signature=(round(summary['execs'] / len(sigs), 1) if sigs else None),
                time_to_first_valid_finding=summary.get('time_to_first_valid_finding'),
                signatures=sorted(s[2:] for s in sigs))


# Known ground-truth paths: the consecutive action pair that is their answer
# and the ASAN function that identifies their consumer.
KNOWN = {
    'P16_path_b': dict(pair=('parse_oom', 'upload_nofile'), func='ps_files_close'),
    'BugS_bg_serialize': dict(pair=('parse_oom', 'upload_small'), func='php_add_var_hash'),
    'P17_path_c': dict(pair=('runtime_oom', 'upload_small'), func='tmp_var'),
}


def g3(dirs):
    """Hold-out rediscovery: for each known path, when (if ever) did a run
    observe its consumer signature, and if not, where did it fail:
      generation - the answer pair was never generated
      reach      - generated, but the producer step never fataled there
      oracle     - producer fataled and the consumer ran, yet no signature
    """
    rows = []
    for d in dirs:
        summary = json.loads((Path(d) / 'summary.json').read_text())
        execs = [e for e in load_execs(d) if e.get('grammar_ok')]
        for name, spec in KNOWN.items():
            first = None
            generated = reached = consumed = 0
            for e in execs:
                acts = [s['a'] for s in e['seq']['steps']]
                steps = e.get('steps', [])
                hit = any(spec['func'] in ((s.get('asan') or {}).get('sig') or '') for s in steps)
                if hit and first is None:
                    first = dict(exec=e['exec'], t=e['t'], seq=acts, limit=e['seq']['limit'],
                                 seed_origin=e['origin'])
                for i in range(len(acts) - 1):
                    if (acts[i], acts[i + 1]) != spec['pair']:
                        continue
                    generated += 1
                    if i < len(steps) and steps[i].get('failure_sites'):
                        reached += 1
                        if i + 1 < len(steps):
                            consumed += 1
            cause = (None if first else 'generation' if not generated else
                     'reach' if not reached else 'oracle' if consumed else 'reach')
            rows.append(dict(run=Path(d).name, feedback=summary['feedback'],
                             seed=summary['seed'], path=name,
                             excluded_from_seeds='>'.join(spec['pair']) in summary.get(
                                 'excluded_pairs', []),
                             rediscovered=first is not None, first=first,
                             pair_generated=generated, producer_landed=reached,
                             consumer_ran_after_landing=consumed, miss_cause=cause))
    space = None
    if dirs:
        space = json.loads((Path(dirs[0]) / 'summary.json').read_text())['grammar']
    return dict(gate='G3', grammar=space, rows=rows,
                passed=any(r['rediscovered'] and r['excluded_from_seeds']
                           and r['feedback'] == 'on' for r in rows))


def profile_metrics(d, cutoff=None):
    """Per-campaign metrics restricted to executions started before cutoff
    seconds (so 900 s CLI runs compare with 600 s SAPI runs)."""
    summary = json.loads((Path(d) / 'summary.json').read_text())
    execs = [e for e in load_execs(d) if e.get('grammar_ok')
             and (cutoff is None or e['t'] <= cutoff)]
    keys = set()
    for e in execs:
        keys.update(e.get('new_keys', []))
    sigs = sorted(k[2:] for k in keys if k.startswith('A:'))
    found = {name: next((e['t'] for e in execs for s in e.get('steps', [])
                         if spec['func'] in ((s.get('asan') or {}).get('sig') or '')), None)
             for name, spec in KNOWN.items()}
    harness = sum(1 for e in execs if any('harness_error' in s for s in e.get('steps', [])))
    hangs = sum(1 for e in execs if any(s.get('hung') for s in e.get('steps', [])))
    replaced = sum(1 for e in execs for s in e.get('steps', [])
                   if s.get('alive_after') is False and not s.get('asan'))
    return dict(dir=Path(d).name, sapi=summary.get('sapi', 'cli'),
                feedback=summary['feedback'], cutoff_s=cutoff, execs=len(execs),
                transitions=len({k for k in keys if k.startswith('T:')}),
                failure_sites=len({k for k in keys if k.startswith('F:')}),
                asan_signatures=sigs, known_paths_first_t=found,
                hangs=hangs, worker_lost_without_asan=replaced,
                harness_errors=harness, aborted=summary.get('aborted', False))


def g5(dirs, cutoff):
    rows = [profile_metrics(d, cutoff) for d in dirs]
    return dict(gate='G5', cutoff_s=cutoff, profiles=rows,
                passed=all(not r['aborted'] and r['harness_errors'] == 0 for r in rows)
                and len({r['sapi'] for r in rows}) >= 3)


def g4(on_dirs, off_dirs):
    on = [campaign_metrics(d) for d in on_dirs]
    off = [campaign_metrics(d) for d in off_dirs]

    def agg(rows, key):
        vals = [r[key] for r in rows if r[key] is not None]
        if not vals:
            return None
        return dict(mean=round(statistics.mean(vals), 2),
                    min=min(vals), max=max(vals), n=len(vals))
    keys = ('execs', 'code_edges', 'transitions', 'states', 'failure_sites', 'asan_signatures',
            'execs_per_signature', 'time_to_first_valid_finding')
    return dict(gate='G4', on=on, off=off,
                aggregate={k: dict(on=agg(on, k), off=agg(off, k)) for k in keys})


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('gate', choices=('g1', 'g2', 'g3', 'g4', 'g5'))
    parser.add_argument('--cutoff', type=float, default=None)
    parser.add_argument('dir', nargs='*')
    parser.add_argument('--on', nargs='*', default=[])
    parser.add_argument('--off', nargs='*', default=[])
    args = parser.parse_args()
    if args.gate == 'g1':
        result = g1(args.dir[0])
    elif args.gate == 'g2':
        result = g2(args.dir[0])
    elif args.gate == 'g3':
        result = g3(args.dir)
    elif args.gate == 'g5':
        result = g5(args.dir, args.cutoff)
    else:
        result = g4(args.on, args.off)
    print(json.dumps(result, indent=2))
    return 0 if result.get('passed', True) else 2


if __name__ == '__main__':
    sys.exit(main())
