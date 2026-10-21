#!/usr/bin/env python3
"""Verify each allocator/buffering path and summarize without a vulnerability claim."""
import json
import sys
from pathlib import Path
from run import BASE, verify

version = sys.argv[1] if len(sys.argv) > 1 else '8.4.4'
flavor = sys.argv[2] if len(sys.argv) > 2 else 'asan'
if flavor not in ('asan', 'normal'):
    raise SystemExit('Expected asan or normal')
results = []
for allocator in ('zend', 'system', 'tracked'):
    for buffering in ('on', 'off'):
        results.append(verify(version, flavor, allocator, buffering))
path = BASE / 'evidence' / ('matrix-' + version + '-' + flavor + '.json')
path.write_text(json.dumps({'scope': 'environment only', 'runs': results}, indent=2))
print('Matrix passed:', len(results), path)
