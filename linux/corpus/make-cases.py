#!/usr/bin/env python3
"""#4 H2: add h2-cases.json entries for fetched records that have no case.

For each record directory under linux/corpus/repro/ without a case, pick the
reproducer block: a PHPT test file (from a PR) first, then a block whose text
says "reduced"/"test case", then the first block containing '<?'. The case
gets oracle memory_error, the record's required extensions from
reachability.json, and 'extract' for tracker blocks that mix prose and
code. Blocks are listed for manual reading; nothing is run here.

Usage: make-cases.py [--dry-run]
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXT_WORDS = ('soap', 'mbstring', 'exif', 'xmlreader', 'xmlwriter', 'filter', 'simplexml',
             'opcache', 'dom', 'xml')
RISKY = re.compile(r'\b(exec|shell_exec|system|passthru|proc_open|popen|fsockopen|curl_|'
                   r'stream_socket_client|mail|unlink|rmdir)\s*\(|https?://(?!127\.0\.0\.1)')


def pick(blocks):
    texts = {b: b.read_text(encoding='utf-8', errors='replace') for b in blocks}
    phpt = [b for b, t in texts.items() if '--FILE--' in t]
    if phpt:
        return phpt[0], 'phpt'
    with_code = [b for b, t in texts.items() if '<?' in t]
    reduced = [b for b in with_code if re.search(r'reduced|test ?case|test script', texts[b], re.I)]
    chosen = (reduced or with_code or [None])[0]
    return chosen, 'php'


def main():
    cases_path = HERE / 'h2-cases.json'
    data = json.loads(cases_path.read_text(encoding='utf-8'))
    reach = json.loads((HERE / 'reachability.json').read_text(encoding='utf-8'))['records']
    added = []
    for d in sorted((HERE / 'repro').iterdir()):
        rid = d.name
        if rid in data['cases'] or not d.is_dir():
            continue
        blocks = sorted(d.glob('*.txt'))
        chosen, fmt = pick(blocks)
        category, reason = reach.get(rid, ['unassessed', ''])
        needs = [w for w in EXT_WORDS if category == 'needs_extension'
                 and re.search(r'\b%s\b' % w, reason, re.I)]
        if chosen is None:
            data['cases'][rid] = dict(status='no_reproducer',
                                      note='no PHP code block in the fetched sources')
        else:
            text = chosen.read_text(encoding='utf-8', errors='replace')
            data['cases'][rid] = dict(
                source=json.loads((d / 'source.json').read_text(encoding='utf-8'))['label'][:80],
                script='%s/%s' % (rid, chosen.name), format=fmt, oracle='memory_error',
                extract=(fmt == 'php'), needs=needs,
                risky_calls=sorted(set(m.group(0) for m in RISKY.finditer(text))))
        added.append((rid, data['cases'][rid].get('script'), data['cases'][rid].get('risky_calls')))
    if '--dry-run' not in sys.argv:
        cases_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n',
                              encoding='utf-8')
    for row in added:
        print(*row)
    return 0


if __name__ == '__main__':
    sys.exit(main())
