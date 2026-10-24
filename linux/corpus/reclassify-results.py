#!/usr/bin/env python3
"""#4 H2: re-classify existing corpus H2 results with the fixed judges.

The recorded per-run facts (rc, asan, expect mismatch, oracle) are enough to
re-derive outcome classes without re-running PHP: memory_error /
functional_regression / gc_state_stuck / completed_no_oracle /
abnormal_exit_no_oracle / timeout. Writes a differential report
(old verdict counts -> new outcome classes) next to each summary and one
aggregate table for the findings diff.

Usage: reclassify-results.py [--evidence-root /home/phplab/php-lab/evidence]
       reclassify-results.py --restore [--reference-manifest <v22 snapshot>]

--restore reverses the 0b3a020 in-place mutation bug (this script's pre-
95c41cd run wrote 'reclassification'/'outcome_class' keys INTO corpus-h2
summary.json originals). It strips the injected keys and rewrites the file
ONLY when the stripped serialization hash-matches the pre-mutation
reference manifest; any file that cannot be matched aborts without write.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

CASES = Path(__file__).resolve().parent / 'h2-cases.json'
REPO = Path(__file__).resolve().parents[2]
DEFAULT_REFERENCE = REPO / 'docs' / 'evidence-manifest-20261024-v22.sha256'


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


def strip_injected(data):
    """Remove the keys the 0b3a020 in-place run added; True if any removed."""
    changed = False
    if 'reclassification' in data:
        del data['reclassification']
        changed = True
    for r in data.get('results', []):
        if 'outcome_class' in r:
            del r['outcome_class']
            changed = True
    return changed


def restore(evidence_root, reference_manifest):
    reference = {}
    for line in reference_manifest.read_text().splitlines():
        digest, _, rel = line.partition('  ')
        if rel.startswith('evidence/corpus-h2-') and rel.endswith('/summary.json'):
            reference[rel] = digest
    if not reference:
        print('reference manifest has no corpus-h2 summary entries: %s'
              % reference_manifest, file=sys.stderr)
        return 1
    restored = clean = 0
    for path in sorted(evidence_root.glob('corpus-h2-*/summary.json')):
        rel = 'evidence/%s' % path.relative_to(evidence_root).as_posix()
        data = json.loads(path.read_text())
        if not strip_injected(data):
            clean += 1
            continue
        blob = json.dumps(data, indent=2).encode()
        digest = hashlib.sha256(blob).hexdigest()
        if reference.get(rel) != digest:
            print('NOT RESTORABLE (stripped form does not match the '
                  'reference): %s' % rel, file=sys.stderr)
            return 1
        path.write_bytes(blob)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            print('write verification failed: %s' % rel, file=sys.stderr)
            return 1
        restored += 1
        print('restored %s' % rel)
    print(json.dumps(dict(restored=restored, already_clean=clean,
                          reference=str(reference_manifest))))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path,
                        default=Path('/home/phplab/php-lab/evidence'))
    parser.add_argument('--restore', action='store_true',
                        help='undo the 0b3a020 in-place mutation (see above)')
    parser.add_argument('--reference-manifest', type=Path,
                        default=DEFAULT_REFERENCE,
                        help='pre-mutation manifest for --restore verification')
    args = parser.parse_args()
    if args.restore:
        return restore(args.evidence_root, args.reference_manifest)
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
