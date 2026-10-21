#!/usr/bin/env python3
"""Copy lab evidence and provenance into the Windows workspace."""
from pathlib import Path
import shutil

base = Path('/home/phplab/php-lab')
dest = Path(__file__).resolve().parents[1] / 'var/linux-evidence'
dest.mkdir(parents=True, exist_ok=True)
for name in ('evidence', 'logs'):
    if (base / name).exists():
        for source in (base / name).rglob('*'):
            target = dest / name / source.relative_to(base / name)
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif source.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                # DrvFS does not guarantee Linux ownership/mode preservation.
                shutil.copyfile(source, target)
for manifest in (base / 'install').glob('*/build-manifest.json'):
    target = dest / 'builds' / manifest.parent.name
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(manifest, target / manifest.name)
print(dest)
