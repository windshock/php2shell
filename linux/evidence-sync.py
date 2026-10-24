#!/usr/bin/env python3
"""Incremental evidence export + manifest (replaces export.py + a full
sha256sum pass; plan §13.9).

export.py copied every file and the manifest re-hashed every file across
drvfs on each run (46k files, tens of minutes). This tool:

  1. copies only files whose size or mtime differ from the Windows copy
     (evidence/, logs/, build manifests - the same scope as export.py),
     reading each changed file ONCE, writing it and hashing the same bytes
     (so the recorded digest is exactly what was written);
  2. keeps var/linux-evidence/.manifest-cache.json  {rel: [size, mtime_ns,
     sha256, src_size, src_mtime_ns]} and re-hashes only destination files missing from the cache
     or whose size/mtime changed;
  3. rewrites evidence-manifest.sha256 for the whole tree from the cache.

Full verification stays `verify-evidence.py` (default mode). The cache is a
speed device, not evidence: before a manifest snapshot is committed, run the
full verification.

Usage: evidence-sync.py [--dest var/linux-evidence] [--full-rehash] | --self-test
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
CACHE = '.manifest-cache.json'
MANIFEST = 'evidence-manifest.sha256'


def sources(base):
    """(source path, relative destination) pairs - same scope as export.py."""
    for name in ('evidence', 'logs'):
        root = base / name
        if root.exists():
            for path in root.rglob('*'):
                if path.is_file():
                    yield path, Path(name) / path.relative_to(root)
    for manifest in (base / 'install').glob('*/build-manifest.json'):
        yield manifest, Path('builds') / manifest.parent.name / 'build-manifest.json'


def sync(base, dest, full_rehash=False, audit_dest=False, allow_shrink=False):
    dest.mkdir(parents=True, exist_ok=True)
    cache_path = dest / CACHE
    cache = {} if full_rehash or not cache_path.exists() else json.loads(cache_path.read_text())
    if audit_dest and not allow_shrink:
        # shrink guard (2026-10-24 review): a filesystem incident can lose
        # ORIGINAL files; audit mode would then drop the mirror copies too
        # (second loss). Refuse until the loss is verified as intended.
        # Only entries recorded FROM A SOURCE count (5-element cache rows);
        # destination-only rows from an earlier audit walk (3-element) have
        # no original to lose (23:33 review: the first version counted them
        # and broke the self-test at s5).
        missing = [k for k, entry in cache.items()
                   if (k.startswith('evidence/') or k.startswith('logs/'))
                   and isinstance(entry, list) and len(entry) >= 5
                   and not (base / k).exists()]
        if missing:
            raise SystemExit('originals missing vs the last snapshot (%d, e.g. %s): '
                             'refusing --audit-dest (it would delete the mirror copies '
                             'too) - verify the loss, then pass --allow-shrink'
                             % (len(missing), missing[:3]))
    stats = dict(copied=0, unchanged=0, hashed=0, cache_hits=0, removed_from_cache=0)
    started = time.time()
    pairs = list(sources(base))
    # NTFS destinations are case-insensitive: two source paths differing only
    # by case would silently overwrite each other and the manifest could then
    # never verify (seen 2026-10-24 with corpus seeds lab-references-r/-R).
    # Refuse to sync instead; rename one of the colliding source files.
    seen_fold = {}
    for _, rel in pairs:
        folded = rel.as_posix().lower()
        if folded in seen_fold and seen_fold[folded] != rel.as_posix():
            raise SystemExit('case-insensitive destination collision: %s vs %s '
                             '- rename one source file' % (seen_fold[folded], rel.as_posix()))
        seen_fold[folded] = rel.as_posix()
    for src, rel in pairs:
        target = dest / rel
        st = src.stat()
        key = rel.as_posix()
        entry = cache.get(key)
        # drvfs refuses utime for the lab user, so source and destination
        # mtimes never match; "unchanged" = the source stat recorded in the
        # cache at the last copy still holds. The destination is NOT stat'ed
        # here (each drvfs stat costs milliseconds x 46k files); copy
        # integrity is checked by verify-evidence (incremental: stat, full:
        # hash) and by --audit-dest.
        same = (entry is not None and len(entry) >= 5
                and entry[3] == st.st_size and entry[4] == st.st_mtime_ns)
        if same:
            stats['unchanged'] += 1
            continue
        data = src.read_bytes()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        dt = target.stat()
        cache[key] = [dt.st_size, dt.st_mtime_ns, hashlib.sha256(data).hexdigest(),
                      st.st_size, st.st_mtime_ns]
        stats['copied'] += 1
        stats['hashed'] += 1
    # Destination files not produced by this sync (older exports, Windows-side
    # writes) still belong to the manifest: --audit-dest walks the
    # destination and hashes them when not cached (slow over drvfs; run it
    # before snapshots). Without it the manifest covers the cached entries.
    present = set(cache) if not audit_dest else set()
    for path in (dest.rglob('*') if audit_dest else ()):
        if not path.is_file() or path.name in (CACHE, MANIFEST):
            continue
        rel = path.relative_to(dest).as_posix()
        present.add(rel)
        dt = path.stat()
        entry = cache.get(rel)
        if entry and entry[0] == dt.st_size and entry[1] == dt.st_mtime_ns:
            stats['cache_hits'] += 1
            continue
        cache[rel] = [dt.st_size, dt.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()]
        stats['hashed'] += 1
    for rel in [r for r in cache if audit_dest and r not in present]:
        del cache[rel]
        stats['removed_from_cache'] += 1
    lines = ['%s  %s' % (cache[rel][2], rel) for rel in sorted(cache)]
    (dest / MANIFEST).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    cache_path.write_text(json.dumps(cache))
    stats.update(entries=len(lines), audit_dest=audit_dest,
                 seconds=round(time.time() - started, 1))
    return stats


def self_test():
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    with tempfile.TemporaryDirectory() as tmp:
        base, dest = Path(tmp) / 'base', Path(tmp) / 'dest'
        (base / 'evidence' / 'run1').mkdir(parents=True)
        (base / 'evidence' / 'run1' / 'a.json').write_text('{"a": 1}')
        (base / 'logs').mkdir()
        (base / 'logs' / 'b.log').write_text('log')
        s1 = sync(base, dest)
        check('first sync copies and hashes everything', s1['copied'] == 2 and s1['entries'] == 2)
        s2 = sync(base, dest)
        check('second sync copies nothing and hashes nothing',
              s2['copied'] == 0 and s2['hashed'] == 0 and s2['unchanged'] == 2)
        time.sleep(1.1)
        (base / 'evidence' / 'run1' / 'a.json').write_text('{"a": 22}')
        s3 = sync(base, dest)
        manifest = (dest / MANIFEST).read_text()
        digest = hashlib.sha256(b'{"a": 22}').hexdigest()
        check('changed file re-copied and re-hashed', s3['copied'] == 1 and s3['hashed'] == 1
              and digest in manifest)
        (dest / 'evidence' / 'extra.txt').write_text('windows side')
        s4 = sync(base, dest, audit_dest=True)
        check('destination-only file hashed into the manifest', s4['hashed'] == 1
              and 'evidence/extra.txt' in (dest / MANIFEST).read_text())
        (dest / 'evidence' / 'extra.txt').unlink()
        s5 = sync(base, dest, audit_dest=True)
        check('deleted destination file leaves the manifest', s5['removed_from_cache'] == 1
              and 'extra.txt' not in (dest / MANIFEST).read_text())
        (base / 'evidence' / 'run1' / 'a.json').unlink()
        try:
            sync(base, dest, audit_dest=True)
            check('missing original blocks --audit-dest (shrink guard)', False)
        except SystemExit:
            check('missing original blocks --audit-dest (shrink guard)', True)
        sync(base, dest, audit_dest=True, allow_shrink=True)
        check('--allow-shrink keeps the mirror copy of a lost original',
              'evidence/run1/a.json' in (dest / MANIFEST).read_text())
        (base / 'evidence' / 'run1' / 'a.json').write_text('{"a": 22}')
        sync(base, dest)
        s6 = sync(base, dest, full_rehash=True)
        check('--full-rehash re-copies and re-hashes every source file',
              s6['copied'] == 2 and s6['unchanged'] == 0)
        s7 = sync(base, dest)
        check('fast path: unchanged sources are not copied', s7['copied'] == 0
              and s7['unchanged'] == 2)
        (base / 'evidence' / 'run1' / 'lab-r').write_text('r')
        (base / 'evidence' / 'run1' / 'lab-R').write_text('R')
        try:
            sync(base, dest)
            check('case-colliding source pair aborts the sync', False)
        except SystemExit:
            check('case-colliding source pair aborts the sync', True)
        (base / 'evidence' / 'run1' / 'lab-R').unlink()
        s8 = sync(base, dest)
        check('sync resumes after the collision is resolved',
              s8['copied'] == 1 and 'lab-r' in (dest / MANIFEST).read_text())
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dest', type=Path, default=REPO / 'var/linux-evidence')
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--full-rehash', action='store_true')
    parser.add_argument('--audit-dest', action='store_true',
                        help='walk the destination too (destination-only/deleted files)')
    parser.add_argument('--allow-shrink', action='store_true',
                        help='let --audit-dest proceed even when original files '
                             'went missing (verified loss, e.g. intentional removal)')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    print(json.dumps(sync(args.base, args.dest, args.full_rehash, args.audit_dest,
                          args.allow_shrink), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
