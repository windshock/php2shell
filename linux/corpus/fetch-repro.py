#!/usr/bin/env python3
"""#4 H2: fetch the reproducer of a corpus record from its primary source.

  github issue   fenced code blocks of the issue body (```php / ```)
  github PR      the .phpt test files the PR adds (from the PR file list)
  bugs.php.net   the "Test script" block of the bug page

Everything is saved verbatim under linux/corpus/repro/<RID>/ (source.json
with the URL and fetch time, the raw blocks, and candidate scripts) so the
inputs of every reproduction run are committed (rules R12). Reproducers are
third-party code: they are read before they are run, and run only in the
isolated lab with exec/network functions disabled (run-repro.py).

Usage: fetch-repro.py RID [RID...]
"""
import html
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECORDS = HERE / 'records.json'
OUT = HERE / 'repro'


def gh(path, raw=False):
    args = ['gh', 'api', path] + (['-H', 'Accept: application/vnd.github.raw'] if raw else [])
    res = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip()[:200])
    return res.stdout if raw else json.loads(res.stdout)


def fenced_blocks(text):
    return [m.group(2) for m in re.finditer(r'```(\w*)\s*\n(.*?)```', text or '', re.S)]


def from_issue(num):
    issue = gh('repos/php/php-src/issues/%d' % num)
    blocks = fenced_blocks(issue.get('body'))
    comments = gh('repos/php/php-src/issues/%d/comments?per_page=100' % num)
    for c in comments:
        blocks += fenced_blocks(c.get('body'))
    return dict(kind='issue', title=issue.get('title')), blocks


def from_pr(num):
    pr = gh('repos/php/php-src/pulls/%d' % num)
    files = gh('repos/php/php-src/pulls/%d/files?per_page=100' % num)
    blocks = []
    for f in files:
        if f['filename'].endswith('.phpt') and f.get('status') in ('added', 'modified'):
            ref = pr['head']['sha']
            try:
                content = gh('repos/%s/contents/%s?ref=%s' % (
                    pr['head']['repo']['full_name'], f['filename'], ref), raw=True)
            except RuntimeError:
                content = '\n'.join(line[1:] for line in (f.get('patch') or '').splitlines()
                                    if line.startswith('+') and not line.startswith('+++'))
            blocks.append('// %s\n%s' % (f['filename'], content))
    return dict(kind='pr', title=pr.get('title'), head=pr['head']['sha']), blocks


def from_bug(num):
    req = urllib.request.Request('https://bugs.php.net/bug.php?id=%d' % num,
                                 headers={'User-Agent': 'php2shell-corpus/1.0'})
    page = urllib.request.urlopen(req, timeout=30).read().decode('utf-8', 'replace')
    blocks = []
    for m in re.finditer(r'<pre class=[\'"]note[\'"]>(.*?)</pre>', page, re.S):
        blocks.append(html.unescape(re.sub(r'<[^>]+>', '', m.group(1))))
    title = re.search(r'<title>(.*?)</title>', page, re.S)
    return dict(kind='bug', title=title.group(1).strip() if title else None), blocks


def main():
    records = {r['id']: r for r in json.loads(RECORDS.read_text(encoding='utf-8'))['records']}
    for rid in sys.argv[1:]:
        rec = records[rid]
        dest = OUT / rid
        dest.mkdir(parents=True, exist_ok=True)
        fetched = []
        for link in rec['links']:
            url = link['url']
            m = re.match(r'https://github\.com/php/php-src/(issues|pull)/(\d+)', url)
            b = re.match(r'https://bugs\.php\.net/bug\.php\?id=(\d+)', url)
            try:
                if m and m.group(1) == 'issues':
                    meta, blocks = from_issue(int(m.group(2)))
                elif m:
                    meta, blocks = from_pr(int(m.group(2)))
                elif b:
                    meta, blocks = from_bug(int(b.group(1)))
                else:
                    continue
            except Exception as exc:
                fetched.append(dict(url=url, error=str(exc)))
                continue
            stem = re.sub(r'\W+', '_', url.split('//')[1])[-40:]
            for i, block in enumerate(blocks):
                (dest / ('%s.block%02d.txt' % (stem, i))).write_text(block, encoding='utf-8')
            fetched.append(dict(url=url, blocks=len(blocks), **meta))
        (dest / 'source.json').write_text(json.dumps(dict(
            record=rid, label=rec['label'], fetched_at=time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                                     time.gmtime()),
            sources=fetched), indent=2, ensure_ascii=False), encoding='utf-8')
        print(rid, json.dumps(fetched, ensure_ascii=False)[:300])
    return 0


if __name__ == '__main__':
    sys.exit(main())
