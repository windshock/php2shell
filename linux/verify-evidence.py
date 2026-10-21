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


def _result_paths(root, pattern):
    """Support both the exported layout (<root>/evidence/...) and the live one (<root>/...)."""
    return (sorted(root.glob('evidence/%s/result.json' % pattern))
            + sorted(root.glob('%s/result.json' % pattern)))


def check_poc(root, since=None):
    results = []
    by_target = {}
    for path in _result_paths(root, 'poc-*'):
        if since is not None and path.parent.stat().st_mtime < since:
            continue
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


def check_gdb(root, since=None):
    by_mode = {}
    for path in _result_paths(root, 'probe-gdb-*'):
        if since is not None and path.parent.stat().st_mtime < since:
            continue
        data = json.loads(path.read_text())
        mode = data.get('verdict', {}).get('mode', 'serialize')
        by_mode[mode] = (path, data)  # newest per mode wins
    if not by_mode:
        return dict(status='not_run', reason='no gdb result.json')
    results = []
    problems_all = []
    for mode, (path, data) in sorted(by_mode.items()):
        verdict = data.get('verdict', {})
        levels = verdict.get('request_levels') or []
        oom = verdict.get('oom_request_index')
        reuse = verdict.get('reuse_request_index')
        reuse_key = ('unserialize_reuse_request_indexes' if mode == 'unserialize'
                     else 'serialize_context_reuse_request_indexes')
        problems = []
        if oom is None:
            # No OOM inside the serialize/unserialize window is a legitimate
            # negative (e.g. fixed build), unless reuse or ASAN is still present.
            if data.get('asan_reports'):
                problems.append('asan report present but no oom request was identified')
            if verdict.get(reuse_key):
                problems.append('context reuse recorded without an identified oom request')
        else:
            if not (0 <= oom < len(levels)):
                problems.append('oom index out of range')
            if reuse is not None and reuse != oom + 1:
                problems.append('reuse index is not the request after the oom request')
            if reuse is not None and not (0 <= reuse < len(levels)):
                problems.append('reuse index out of range')
            if reuse is not None and levels and levels[reuse] != verdict.get('residue_level_at_next_request_start'):
                problems.append('residue level field does not match recorded request levels')
            if not any(index > oom for index in verdict.get(reuse_key, [])) \
                    and data.get('asan_reports'):
                problems.append('asan report present but no post-oom reuse recorded')
        results.append(dict(mode=mode, status='passed' if not problems else 'failed',
                            result=str(path),
                            build_version=(data.get('build') or {}).get('version'),
                            oom_request_index=oom,
                            reuse_request_index=reuse, levels=levels, problems=problems))
        problems_all.extend(problems)
    return dict(status='passed' if not problems_all else 'failed', modes=results)


def check_manifest(root, skip=False):
    if skip:
        return dict(status='not_run', reason='manifest check skipped (fresh-evidence mode)')
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
    parser.add_argument('--since', type=float, default=None,
                        help='only audit evidence created after this unix timestamp '
                             '(used by phase4 to prove this run produced its own evidence)')
    parser.add_argument('--skip-manifest', action='store_true',
                        help='skip the SHA-256 manifest check (live evidence directory has no manifest)')
    args = parser.parse_args()
    summary = dict(scope='evidence audit; fails on inconsistency',
                   since=args.since,
                   poc=check_poc(args.root, args.since), gdb=check_gdb(args.root, args.since),
                   manifest=check_manifest(args.root, args.skip_manifest))
    parts = (summary['poc'], summary['gdb'], summary['manifest'])
    if args.since is not None:
        # Phase 4 mode: this run must have produced both PoC and GDB evidence.
        fresh_ok = (summary['poc']['status'] == 'passed'
                    and summary['gdb']['status'] == 'passed'
                    and summary['manifest']['status'] in ('passed', 'not_run'))
        summary['status'] = 'passed' if fresh_ok else 'failed'
        if not fresh_ok:
            summary['reason'] = 'evidence from this run is missing or invalid (--since)'
    else:
        checked = [part for part in parts if part['status'] != 'not_run']
        if not checked:
            summary['status'] = 'not_run'
            summary['reason'] = 'no evidence was found to audit'
        elif any(part['status'] == 'failed' for part in parts):
            summary['status'] = 'failed'
        else:
            summary['status'] = 'passed'
    print(json.dumps(summary, indent=2))
    if summary['status'] == 'passed':
        return 0
    if summary['status'] == 'not_run':
        return 2
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
