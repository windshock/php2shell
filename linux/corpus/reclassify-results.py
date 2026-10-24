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


def verify_outcome_class(row):
    """Derive the class from RECORDED FACTS (rc, asan, oracle, verdict)
    rather than trusting the stored verdict label alone (#4 H2 review).
    Contradictions between facts and label are surfaced, not smoothed."""
    if row.get('verdict') == 'timeout':
        return 'timeout'
    if row.get('verdict') in ('no_reproducer', 'excluded_weaponized',
                              'capability_gap'):
        return row['verdict']
    oracle = row.get('oracle')
    rc = row.get('rc')
    asan = bool(row.get('asan'))
    hit = row.get('verdict') == 'reproduced'

    # Cross-check the stored verdict against facts
    if hit and oracle == 'memory_error' and not asan and rc not in (134, 139)             and (rc is None or rc >= 0):
        return 'verdict_label_contradicted'  # says reproduced, no evidence
    if hit:
        if oracle == 'memory_error':
            return 'memory_error' if (asan or rc in (134, 139)) else 'custom'
        if oracle == 'expect':
            return 'functional_regression'
        return 'gc_state_stuck' if oracle == 'gc' else 'custom'
    if rc is None:
        return 'rc_missing'
    return 'completed_no_oracle' if rc == 0 else 'abnormal_exit_no_oracle' 


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
    import hashlib
    for path in summaries:
        data = json.loads(path.read_text())
        rows = data.get('results', [])
        old = Counter(r.get('verdict') for r in rows)
        new_rows = []
        for r in rows:
            cls = verify_outcome_class(r)
            new_rows.append(dict(record=r.get('record'), version=r.get('version'),
                                 stored_verdict=r.get('verdict'), oracle=r.get('oracle'),
                                 rc=r.get('rc'), asan=bool(r.get('asan')),
                                 outcome_class=cls))
        new = Counter(nr['outcome_class'] for nr in new_rows)
        # Write a SEPARATE file; the original summary.json is never modified.
        out_path = path.parent / 'reclassified.json'
        out_path.write_text(json.dumps(dict(
            scheme='#4 H2 outcome classes (plan 14.2)', source_summary=path.name,
            source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            old_verdicts=dict(old), new_outcome_classes=dict(new),
            rows=new_rows), indent=2, ensure_ascii=False))
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
