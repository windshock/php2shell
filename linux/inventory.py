#!/usr/bin/env python3
"""Record only selected runtime facts, without phpinfo environment variables."""
import json
from pathlib import Path
import subprocess

base = Path('/home/phplab/php-lab')
inventory = {}
for prefix in (base / 'install').iterdir():
    php = prefix / 'bin/php'
    if not php.exists():
        continue
    modules = subprocess.check_output([str(php), '-n', '-m'], text=True)
    code = 'echo json_encode(["opcache.enable"=>ini_get("opcache.enable"),"opcache.enable_cli"=>ini_get("opcache.enable_cli"),"opcache.jit"=>ini_get("opcache.jit"),"memory_limit"=>ini_get("memory_limit")]);'
    settings = json.loads(subprocess.check_output([str(php), '-n', '-r', code], text=True))
    inventory[prefix.name] = dict(modules=modules.splitlines(), compiled_defaults=settings)
(base / 'evidence/runtime-inventory.json').write_text(json.dumps(inventory, indent=2))
print('Runtime inventory recorded for', len(inventory), 'builds')
