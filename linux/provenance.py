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
    res = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else None


def provenance(argv=None):
    commit = _git('rev-parse', 'HEAD')
    status = _git('status', '--porcelain', '--', 'linux')
    dirty = None if status is None else bool(status)
    return dict(source_commit=commit, source_dirty=dirty,
                argv=list(argv if argv is not None else sys.argv),
                citable=bool(commit) and dirty is False)


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


if __name__ == '__main__':
    import json
    print(json.dumps(provenance(), indent=2))
