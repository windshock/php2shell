#!/usr/bin/env python3
"""#4 H2: re-classify existing corpus H2 results with the fixed judges.

The recorded per-run facts (rc, asan, expect mismatch, oracle) are enough to
re-derive outcome classes without re-running PHP: memory_error /
functional_regression / gc_state_stuck / completed_no_oracle /
abnormal_exit_no_oracle / timeout. Writes a differential report
(old verdict counts -> new outcome classes) next to each summary and one
aggregate table for the findings diff.

Usage: reclassify-results.py [--evidence-root /home/phplab/php-lab/evidence]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

CASES = Path(__file__).resolve().parent / 'h2-cases.json'


def outcome_class(row):
    if row.get('verdict') == 'timeout':
        return 'timeout'
    if row.get('verdict') in ('no_reproducer', 'excluded_weaponized',
                              'capability_gap'):
        return row['verdict']
    oracle = row.get('oracle')
    hit = row.get('verdict') == 'reproduced'
    if hit:
        if oracle == 'memory_error':
            return 'memory_error'
        if oracle == 'expect':
            return 'functional_regression'
        return 'gc_state_stuck' if oracle == 'gc' else 'custom'
    return 'completed_no_oracle' if row.get('rc') == 0 else 'abnormal_exit_no_oracle'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path,
                        default=Path('/home/phplab/php-lab/evidence'))
    args = parser.parse_args()
    summaries = sorted(args.evidence_root.glob('corpus-h2-*/summary.json'))
    if not summaries:
        print('no corpus-h2 summaries found')
        return 1
    aggregate = Counter()
    per_run = []
    for path in summaries:
        data = json.loads(path.read_text())
        rows = data.get('results', [])
        old = Counter(r.get('verdict') for r in rows)
        for r in rows:
            r['outcome_class'] = outcome_class(r)
        new = Counter(r['outcome_class'] for r in rows)
        data['reclassification'] = dict(
            scheme='#4 H2 outcome classes (plan 14.2)', old_verdicts=dict(old),
            new_outcome_classes=dict(new))
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        aggregate.update(new)
        per_run.append(dict(run=path.parent.name, old=dict(old), new=dict(new)))
    report = dict(scope='#4 H2 re-classification of existing evidence (no PHP re-run)',
                  runs=per_run, aggregate=dict(aggregate))
    out = args.evidence_root / 'corpus-h2-reclassification.json'
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(dict(aggregate=report['aggregate'], runs=len(per_run),
                          out=str(out)), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
