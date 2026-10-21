#!/usr/bin/env python3
"""Structural validation for the detection rules shipped in this repo.

Checks (not a full sigma-cli conversion):
  - YAML parses; every rule has title/id/status/logsource/detection/level
  - id is a UUIDv4
  - condition only references defined selections and uses valid operators
  - a list of *mappings* under one selection key is rejected: in Sigma a list is
    OR, so a list of different fields silently weakens the rule
  - ModSecurity rule file: every non-comment line starts with Sec*/Include and
    rule ids are unique

Usage: python3 linux/validate-rules.py [rules-dir]
"""
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit('pyyaml is required: python3 -m pip install --user pyyaml')

UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
COND_TOKEN = re.compile(r'\b(and|or|not|all|any|of|them|\d+)\b|\(|\)')


def validate_sigma(path):
    problems = []
    docs = list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
    rules = [d for d in docs if isinstance(d, dict)]
    if not rules:
        return ['no rules found']
    for index, rule in enumerate(rules, start=1):
        label = rule.get('title', 'rule#%d' % index)
        for field in ('title', 'id', 'status', 'logsource', 'detection', 'level'):
            if field not in rule:
                problems.append('%s: missing %s' % (label, field))
        rule_id = str(rule.get('id', ''))
        if not UUID4.match(rule_id):
            problems.append('%s: id is not a UUIDv4 (%s)' % (label, rule_id))
        detection = rule.get('detection') or {}
        condition = detection.get('condition')
        if not condition:
            problems.append('%s: detection.condition missing' % label)
            continue
        selections = {k: v for k, v in detection.items() if k != 'condition'}
        tokens = set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', COND_TOKEN.sub(' ', condition)))
        for token in tokens:
            if token not in selections:
                problems.append('%s: condition references undefined selection %s' % (label, token))
        for name, value in selections.items():
            if isinstance(value, list) and any(isinstance(item, dict) for item in value):
                problems.append('%s: selection %s is a list of mappings '
                                '(Sigma evaluates a list as OR; use a mapping for AND)'
                                % (label, name))
            if isinstance(value, list) and any(isinstance(item, str) for item in value) \
                    and any(f'|' in str(item) for item in value):
                problems.append('%s: selection %s mixes field strings in a list' % (label, name))
    return problems


def validate_modsecurity(path):
    problems = []
    ids = []
    text = path.read_text(encoding='utf-8').replace('\\\n', ' ')
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if not re.match(r'^(Sec[A-Za-z]+|Include|#)', line):
            problems.append('line %d: unexpected directive %r' % (number, line[:40]))
        for match in re.findall(r'id:(\d+)', line):
            ids.append(match)
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        problems.append('duplicate rule ids: %s' % sorted(dupes))
    return problems


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / 'detect-rules'
    total = 0
    failed = 0
    for path in sorted(root.glob('*.yml')) + sorted(root.glob('*.yaml')):
        total += 1
        problems = validate_sigma(path)
        print(('FAIL' if problems else 'PASS'), path.name)
        for problem in problems:
            print('   -', problem)
        failed += bool(problems)
    for path in sorted(root.glob('*.conf')):
        total += 1
        problems = validate_modsecurity(path)
        print(('FAIL' if problems else 'PASS'), path.name)
        for problem in problems:
            print('   -', problem)
        failed += bool(problems)
    print('checked=%d failed=%d' % (total, failed))
    return 0 if total and not failed else 1


if __name__ == '__main__':
    raise SystemExit(main())
