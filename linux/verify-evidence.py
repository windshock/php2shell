#!/usr/bin/env python3
"""Audit lab evidence: per-iteration ASAN attribution, GDB verdict indexes,
and the SHA-256 manifest. Fails closed on any inconsistency.

Usage:
  python3 linux/verify-evidence.py [--root var/linux-evidence]
"""
import argparse
import hashlib
import json
import os
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


# sha256sum emits "digest  path" (text mode) or "digest *path" (binary mode);
# anything else on a non-empty line is a manifest defect, not a skip.
_MANIFEST_LINE = re.compile(r'^([0-9a-f]{64})(?:  | \*)(.+)$')


def check_manifest(root, skip=False, incremental=False):
    if skip:
        return dict(status='not_run', reason='manifest check skipped (fresh-evidence mode)')
    manifest = root / 'evidence-manifest.sha256'
    if not manifest.exists():
        return dict(status='not_run', reason='no manifest')
    raw = manifest.read_bytes()
    problems = []
    if raw.startswith(b'\xef\xbb\xbf'):
        problems.append('manifest has a UTF-8 BOM')
    entries = checked = missing = mismatched = stat_unchanged = 0
    # --incremental (plan §13.9): trust entries whose size/mtime still match
    # the evidence-sync cache with the same digest; everything else is
    # hashed. A speed device for routine checks - snapshot commits need the
    # full mode (mtime-preserving tampering is only caught there).
    cache = {}
    if incremental and (root / '.manifest-cache.json').exists():
        cache = json.loads((root / '.manifest-cache.json').read_text())
    # Windows-native runs open paths case-insensitively: entries that differ
    # only by case (e.g. fuzz corpus lab-references-r / -R, kept apart by
    # WSL) cannot be told apart there and are deferred to a WSL run.
    deferred = []
    collide = set()
    if os.name == 'nt':
        seen = {}
        for line in raw.decode('utf-8-sig').splitlines():
            m = _MANIFEST_LINE.match(line)
            if m:
                seen.setdefault(m.group(2).lower(), []).append(m.group(2))
        collide = {r for group in seen.values() if len(group) > 1 for r in group}
    for lineno, line in enumerate(raw.decode('utf-8-sig').splitlines(), 1):
        if not line.strip():
            continue
        match = _MANIFEST_LINE.match(line)
        if not match:
            problems.append('manifest line %d is not a sha256sum entry: %r' % (lineno, line[:60]))
            continue
        entries += 1
        digest, rel = match.groups()
        if rel in collide:
            deferred.append(rel)
            continue
        path = root / rel
        if not path.exists():
            missing += 1
            continue
        entry = cache.get(rel)
        if entry and entry[2] == digest:
            st = path.stat()
            if entry[0] == st.st_size and entry[1] == st.st_mtime_ns:
                stat_unchanged += 1
                checked += 1
                continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            mismatched += 1
            problems.append('hash mismatch: ' + rel)
        checked += 1
    if missing:
        problems.append('%d manifest entries are missing on disk' % missing)
    if entries == 0:
        problems.append('manifest contains no parseable entries')
    elif checked == 0:
        problems.append('manifest verification matched 0 files (entries=%d)' % entries)
    if incremental and not cache:
        problems.append('incremental mode requested but no evidence-sync cache')
    ok_status = 'passed_incremental' if incremental else 'passed'
    return dict(status=ok_status if not problems else 'failed', manifest=str(manifest),
                mode='incremental' if incremental else 'full',
                entries=entries, checked=checked, hashed=checked - stat_unchanged,
                stat_unchanged=stat_unchanged, missing=missing,
                mismatched=mismatched, deferred_to_wsl=deferred, problems=problems)


def run_self_test():
    """Fixture cases for check_manifest: text and binary sha256sum notation,
    an unparseable line, zero parseable entries, a hash mismatch and a
    missing entry. A manifest that verifies zero files can never pass."""
    import tempfile
    digest_hello = hashlib.sha256(b'hello').hexdigest()
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'a.bin').write_bytes(b'hello')
        (tmp / 'b.bin').write_bytes(b'world')
        fixtures = {
            'text-notation-pass': ('%s  a.bin\n' % digest_hello, 'passed'),
            'binary-notation-pass': ('%s *a.bin\n' % digest_hello, 'passed'),
            'unparseable-line-fails': ('%s  a.bin\nnot a sha256 line\n' % digest_hello, 'failed'),
            'zero-entries-fails': ('\n\n', 'failed'),
            'hash-mismatch-fails': ('%s  b.bin\n' % digest_hello, 'failed'),
            'missing-entry-fails': ('%s  nope.bin\n' % digest_hello, 'failed'),
        }
        for name, (content, expect) in fixtures.items():
            (tmp / 'evidence-manifest.sha256').write_text(content)
            result = check_manifest(tmp)
            got = result['status']
            ok = got == expect and not (expect == 'passed' and result['checked'] == 0)
            cases.append(dict(case=name, expect=expect, got=got, ok=ok,
                              checked=result.get('checked'),
                              problems=result.get('problems', [])[:2]))
    passed = sum(1 for case in cases if case['ok'])
    print(json.dumps(dict(scope='check_manifest self-test', cases=cases,
                          passed=passed, total=len(cases)), indent=2))
    return 0 if passed == len(cases) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true',
                        help='run the check_manifest fixture tests and exit')
    parser.add_argument('--root', type=Path, default=REPO / 'var/linux-evidence')
    parser.add_argument('--since', type=float, default=None,
                        help='only audit evidence created after this unix timestamp '
                             '(used by phase4 to prove this run produced its own evidence)')
    parser.add_argument('--manifest-only', action='store_true',
                        help='check only the manifest (e.g. from Windows-native Python, '
                             'where NTFS stat is fast; PoC/GDB checks need WSL paths)')
    parser.add_argument('--incremental', action='store_true',
                        help='hash only entries whose size/mtime changed since evidence-sync '
                             '(routine checks; snapshot commits need the full mode)')
    parser.add_argument('--skip-manifest', action='store_true',
                        help='skip the SHA-256 manifest check (live evidence directory has no manifest)')
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    summary = dict(scope='evidence audit; fails on inconsistency',
                   since=args.since,
                   poc=(dict(status='not_run', reason='--manifest-only') if args.manifest_only
                        else check_poc(args.root, args.since)),
                   gdb=(dict(status='not_run', reason='--manifest-only') if args.manifest_only
                        else check_gdb(args.root, args.since)),
                   manifest=check_manifest(args.root, args.skip_manifest, args.incremental))
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
        elif summary['manifest']['status'] == 'passed_incremental':
            summary['status'] = 'passed_incremental'   # not a snapshot-grade result
        else:
            summary['status'] = 'passed'
    print(json.dumps(summary, indent=2))
    if summary['status'] in ('passed', 'passed_incremental'):
        return 0
    if summary['status'] == 'not_run':
        return 2
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
