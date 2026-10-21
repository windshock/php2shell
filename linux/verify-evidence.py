#!/usr/bin/env python3
"""Audit lab evidence: per-iteration ASAN attribution, GDB verdict indexes,
and the SHA-256 manifest. Fails closed on any inconsistency.

Usage:
  python3 linux/verify-evidence.py [--root var/linux-evidence]
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def latest(pattern, root):
    matches = sorted(root.glob(pattern))
    return matches[-1] if matches else None


def check_poc(root):
    results = []
    by_target = {}
    for path in sorted(root.glob('evidence/poc-*/result.json')):
        data = json.loads(path.read_text())
        target = data.get('target', 'cli-server')
        by_target[target] = (path, data)  # sorted() keeps the newest per target
    if not by_target:
        return dict(status='not_run', reason='no poc result.json')
    problems_all = []
    for target, (path, data) in sorted(by_target.items()):
        problems = []
        seen_files = set()
        rows = []
        for item in data.get('results', []):
            asan = item.get('asan') or {}
            row = dict(iteration=item.get('iteration'),
                       process_pid=item.get('process_pid'),
                       asan_pid=asan.get('asan_pid'),
                       file=Path(asan['file']).name if asan.get('file') else None,
                       is_uaf=asan.get('is_uaf'))
            rows.append(row)
            if item.get('result') == 'uaf_reproduced':
                if not asan.get('file'):
                    problems.append('iteration %s claims uaf without a report' % item.get('iteration'))
                    continue
                if not Path(asan['file']).exists():
                    problems.append('iteration %s report missing: %s' % (item.get('iteration'), asan['file']))
                if item.get('process_pid') and asan.get('asan_pid') \
                        and item['process_pid'] != asan['asan_pid']:
                    problems.append('iteration %s pid mismatch: process %s vs asan %s'
                                    % (item.get('iteration'), item['process_pid'], asan['asan_pid']))
                if asan.get('file') in seen_files:
                    problems.append('iteration %s reused report %s' % (item.get('iteration'), asan['file']))
                seen_files.add(asan.get('file'))
                if not asan.get('is_uaf'):
                    problems.append('iteration %s report is not heap-use-after-free' % item.get('iteration'))
        claimed = data.get('reproduced')
        counted = len([row for row in rows if row['is_uaf']])
        if claimed != counted:
            problems.append('claimed reproduced=%s but %s reports verified' % (claimed, counted))
        results.append(dict(target=target, status='passed' if not problems else 'failed',
                            result=str(path), claimed=claimed, verified=counted,
                            rows=rows, problems=problems))
        problems_all.extend(problems)
    return dict(status='passed' if not problems_all else 'failed', targets=results)


def check_gdb(root):
    path = latest('evidence/probe-gdb-*/result.json', root)
    if not path:
        return dict(status='not_run', reason='no gdb result.json')
    data = json.loads(path.read_text())
    verdict = data.get('verdict', {})
    levels = verdict.get('request_levels') or []
    oom = verdict.get('oom_request_index')
    reuse = verdict.get('reuse_request_index')
    problems = []
    if oom is None:
        problems.append('oom request not identified from recorded transitions')
    else:
        if not (0 <= oom < len(levels)):
            problems.append('oom index out of range')
        if reuse is not None and reuse != oom + 1:
            problems.append('reuse index is not the request after the oom request')
        if reuse is not None and not (0 <= reuse < len(levels)):
            problems.append('reuse index out of range')
        if reuse is not None and levels and levels[reuse] != verdict.get('residue_level_at_next_request_start'):
            problems.append('residue level field does not match recorded request levels')
        if not any(index > oom for index in
                   verdict.get('serialize_context_reuse_request_indexes', [])) \
                and data.get('asan_reports'):
            problems.append('asan report present but no post-oom reuse recorded')
    return dict(status='passed' if not problems else 'failed', result=str(path),
                oom_request_index=oom, reuse_request_index=reuse, levels=levels,
                problems=problems)


def check_manifest(root):
    manifest = root / 'evidence-manifest.sha256'
    if not manifest.exists():
        return dict(status='not_run', reason='no manifest')
    raw = manifest.read_bytes()
    problems = []
    if raw.startswith(b'\xef\xbb\xbf'):
        problems.append('manifest has a UTF-8 BOM')
    checked = missing = 0
    for line in raw.decode('utf-8-sig').splitlines():
        match = re.match(r'^([0-9a-f]{64})  (.+)$', line)
        if not match:
            continue
        digest, rel = match.groups()
        path = root / rel
        if not path.exists():
            missing += 1
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append('hash mismatch: ' + rel)
        checked += 1
    if missing:
        problems.append('%d manifest entries are missing on disk' % missing)
    return dict(status='passed' if not problems else 'failed', manifest=str(manifest),
                checked=checked, missing=missing, problems=problems)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=REPO / 'var/linux-evidence')
    args = parser.parse_args()
    summary = dict(scope='evidence audit; fails on inconsistency',
                   poc=check_poc(args.root), gdb=check_gdb(args.root),
                   manifest=check_manifest(args.root))
    summary['status'] = ('passed' if all(part['status'] in ('passed', 'not_run')
                                         for part in (summary['poc'], summary['gdb'], summary['manifest']))
                         else 'failed')
    print(json.dumps(summary, indent=2))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
