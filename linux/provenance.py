#!/usr/bin/env python3
"""Evidence provenance (lab-engineering-rules R12).

provenance() returns the fields every evidence summary must carry:
  source_commit   HEAD of the repository at run time
  source_dirty    True if linux/ has uncommitted changes (not citable)
  argv            the exact command line
  citable         False when dirty or the commit is unknown
preserve_inputs() copies replay/re-derivation inputs into the evidence dir.
"""
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _git(*args):
    # safe.directory: WSL git refuses the /mnt/c checkout (other owner) otherwise.
    res = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(REPO), *args],
                         capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else None


def provenance(argv=None):
    commit = _git('rev-parse', 'HEAD')
    status = _git('status', '--porcelain', '--', 'linux')
    dirty = None if status is None else bool(status)
    return dict(source_commit=commit, source_dirty=dirty,
                argv=list(argv if argv is not None else sys.argv),
                citable=bool(commit) and dirty is False)


def disk_gate(mount='/mnt/c', expect_gb=5.0, label='campaign'):
    """Fail closed when the host drive backing the WSL vhdx AND the
    evidence mirror is low: every evidence GB costs ~2GB there (vhdx +
    var/linux-evidence). The 2026-10-24 ext4 remount-ro incident came from
    a full C:. Returns the free MB when the gate passes."""
    try:
        out = subprocess.check_output(['df', '-B1M', mount], text=True)
        avail_mb = int(out.splitlines()[1].split()[3])
    except (OSError, ValueError, IndexError):
        return None  # df unavailable: unmeasurable, do not block
    need_mb = int(expect_gb * 2 * 1024 + 10240)
    if avail_mb < need_mb:
        raise SystemExit('disk_gate: %s free %dMB < required %dMB (evidence x2 '
                         '+ 10GB) - refusing (%s)' % (mount, avail_mb, need_mb, label))
    return avail_mb


def preserve_inputs(paths, evidence_dir):
    """Copy input files into <evidence_dir>/inputs/; returns the copies."""
    dest = Path(evidence_dir) / 'inputs'
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for p in paths:
        if p and Path(p).is_file():
            target = dest / Path(p).name
            shutil.copy(p, target)
            out.append(str(target))
    return out


def write_note(evidence_dir, effective_commit, reason, check_paths, until=None):
    """Provenance note for evidence produced without a recorded commit:
    verifies that no commit after `effective_commit` touched the files the
    run loaded (check_paths) and records the reconstruction."""
    import json
    # Only commits made while the run was executing matter (until = run end).
    log = _git('log', '--format=%H %cI %s', *(['--until=%s' % until] if until else []),
               '%s..HEAD' % effective_commit, '--', *check_paths)
    note = dict(effective_commit=_git('rev-parse', effective_commit), reason=reason,
                run_end=until,
                loaded_paths=list(check_paths),
                later_commits_touching_loaded_paths=[line for line in (log or '').splitlines()
                                                     if line],
                written_by=provenance())
    note['reconstruction_valid'] = log is not None and not note[
        'later_commits_touching_loaded_paths']
    Path(evidence_dir, 'provenance-note.json').write_text(json.dumps(note, indent=2))
    return note


if __name__ == '__main__':
    import json
    if len(sys.argv) > 1 and sys.argv[1] == '--note':
        # --note <evidence_dir> <effective_commit> <run_end_iso> <reason> <loaded paths...>
        print(json.dumps(write_note(sys.argv[2], sys.argv[3], sys.argv[5], sys.argv[6:],
                                    until=sys.argv[4]), indent=2))
    else:
        print(json.dumps(provenance(), indent=2))
