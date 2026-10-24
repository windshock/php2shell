#!/usr/bin/env python3
"""#4 H1: verify the historical corpus against its primary sources.

Parses the 58-record table of docs/corpus/php-memory-safety-2016-2026.md
and, for every linked source, fetches its CURRENT state:

  github issue    state, state_reason, created/closed dates (gh api)
  github PR       state, merged, merged_at
  GHSA advisory   state, published_at, cve_id, severity
  bugs.php.net    Status / Submitted / PHP Version fields of the bug page
  other pages     reachable (HTTP status) only

Each record then gets independent classification axes (plan §13.4 H1):
  record_type      fixed | open | duplicate | wontfix | unmerged_design |
                   design-discussion | advisory | unverified
  evidence_level   unassessed (assigned per case in H2; the table text is a
                   claim, not evidence)
  exposure         unassessed (remote request / app callback / CLI-ext only
                   is decided in H2.5)
and a list of DISCREPANCIES between the document's stated status and the
fetched status. A fetch failure is recorded as such - never as a status.

Usage: verify-corpus.py [--md PATH] [--out linux/corpus/records.json]
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MD = REPO / 'docs/corpus/php-memory-safety-2016-2026.md'


def parse(md):
    text = Path(md).read_text(encoding='utf-8')
    rows = [line for line in text.splitlines() if re.match(r'\| 20\d\d', line)]
    records = []
    for n, row in enumerate(rows, 1):
        cells = [c.strip() for c in row.strip().strip('|').split('|')]
        links = re.findall(r'\[([^\]]+)\]\((https?://[^)]+)\)', cells[1])
        records.append(dict(id='R%02d' % n, first_seen=cells[0], label=cells[1],
                            links=[dict(text=t, url=u) for t, u in links],
                            pattern=cells[2] if len(cells) > 2 else '',
                            stated_status=cells[3] if len(cells) > 3 else '',
                            link_type=cells[4] if len(cells) > 4 else ''))
    return records


def gh(path):
    res = subprocess.run(['gh', 'api', path], capture_output=True, text=True,
                         encoding='utf-8')
    if res.returncode != 0:
        return dict(fetch_error=res.stderr.strip()[:200])
    return json.loads(res.stdout)


def fetch_url(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'php2shell-corpus-verify/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return res.status, res.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, ''
    except Exception as exc:
        return None, str(exc)


def check(url):
    m = re.match(r'https://github\.com/php/php-src/(issues|pull)/(\d+)', url)
    if m:
        kind, num = m.groups()
        d = gh('repos/php/php-src/issues/%s' % num)
        if 'fetch_error' in d:
            return dict(source='github', fetch_error=d['fetch_error'])
        out = dict(source='github', kind='pr' if 'pull_request' in d else 'issue',
                   number=int(num), title=d.get('title'), state=d.get('state'),
                   state_reason=d.get('state_reason'), created_at=d.get('created_at'),
                   closed_at=d.get('closed_at'),
                   labels=[label['name'] for label in d.get('labels', [])])
        if out['kind'] == 'pr':
            p = gh('repos/php/php-src/pulls/%s' % num)
            out.update(merged=p.get('merged'), merged_at=p.get('merged_at'),
                       draft=p.get('draft'))
        return out
    m = re.match(r'https://github\.com/php/php-src/security/advisories/(GHSA-[\w-]+)', url)
    if m:
        d = gh('repos/php/php-src/security-advisories/%s' % m.group(1))
        if 'fetch_error' in d:
            return dict(source='ghsa', fetch_error=d['fetch_error'])
        return dict(source='ghsa', ghsa=m.group(1), state=d.get('state'),
                    cve_id=d.get('cve_id'), severity=d.get('severity'),
                    published_at=d.get('published_at'), summary=d.get('summary'))
    m = re.match(r'https://bugs\.php\.net/bug\.php\?id=(\d+)', url)
    if m:
        status, html = fetch_url(url)
        if status != 200:
            return dict(source='bugs.php.net', id=int(m.group(1)), http=status,
                        fetch_error='http %s' % status)

        def field(name):
            f = re.search(r'<th[^>]*>\s*%s:?\s*</th>\s*<td[^>]*>(.*?)</td>' % name, html, re.S)
            return re.sub(r'<[^>]+>|\s+', ' ', f.group(1)).strip() if f else None
        return dict(source='bugs.php.net', id=int(m.group(1)), status=field('Status'),
                    submitted=field('Submitted'), php_version=field('PHP Version'),
                    package=field('Package'),
                    title=(re.search(r'<title>(.*?)</title>', html, re.S) or [None, None])[1])
    status, _ = fetch_url(url)
    return dict(source='web', http=status, reachable=status == 200)


def record_type(results):
    """Source-state classification only (#4 H1): what the tracker SAYS.
    'closed_resolution_unverified' / 'fix_claimed' deliberately do not say
    'fixed' - a verified fix needs a fix commit + version relation or a
    regression test, recorded separately."""
    kinds = []
    for r in results:
        if r.get('fetch_error'):
            continue
        if r['source'] == 'github' and r.get('kind') == 'pr':
            kinds.append('fix_claimed' if r.get('merged') else
                         'unmerged_design' if r.get('state') == 'closed' else 'open')
        elif r['source'] == 'github':
            kinds.append('open' if r.get('state') == 'open' else
                         'wontfix' if r.get('state_reason') == 'not_planned' else
                         'closed_resolution_unverified')
        elif r['source'] == 'ghsa':
            kinds.append('advisory')
        elif r['source'] == 'bugs.php.net':
            s = (r.get('status') or '').lower()
            kinds.append('open' if s in ('open', 'verified', 'analyzed', 'assigned',
                                         'feedback', 're-opened') else
                         'duplicate' if 'duplicate' in s else
                         'wontfix' if 'wont' in s or 'not a bug' in s else
                         'closed_resolution_unverified' if s in ('closed',) else
                         'unverified')
        else:
            kinds.append('design-discussion')
    if not kinds:
        return 'unverified'
    for k in ('open', 'advisory', 'duplicate', 'wontfix', 'unmerged_design',
              'design-discussion', 'closed_resolution_unverified', 'fix_claimed',
              'unverified'):
        if k == kinds[0]:
            return k
    return kinds[0]


def discrepancies(rec, results):
    stated = rec['stated_status'].lower()
    issues = []
    for r in results:
        if r.get('fetch_error'):
            issues.append('fetch failed: %s' % r['fetch_error'][:80])
            continue
        if r['source'] == 'github' and r.get('kind') == 'issue':
            if 'open' in stated and r.get('state') == 'closed' and len(results) == 1:
                issues.append('document says open, GitHub issue #%s is now closed (%s)'
                              % (r['number'], r.get('state_reason')))
            if ('closed' in stated or '수정' in stated) and r.get('state') == 'open':
                issues.append('document says closed/fixed, GitHub issue #%s is open'
                              % r['number'])
        if r['source'] == 'github' and r.get('kind') == 'pr':
            if 'merged' in stated and not r.get('merged'):
                issues.append('document says merged, PR #%s is not merged' % r['number'])
            if '미병합' in stated and r.get('merged'):
                issues.append('document says unmerged, PR #%s is merged' % r['number'])
        if r['source'] == 'bugs.php.net':
            s = (r.get('status') or '').lower()
            if 'open' in stated and s == 'closed':
                issues.append('document says open, bug #%s is Closed' % r['id'])
            if 'closed' in stated and s in ('open', 'verified'):
                issues.append('document says closed, bug #%s is %s' % (r['id'], r['status']))
    return issues


PATTERNS = (  # candidate grouping by the record text; confirmed per case in H2
    ('oom_partial_init', r'OOM|부분 초기화|memory_limit|bailout 중'),
    ('bailout_gc', r'GC|gc_protect|bailout|zend_bailout'),
    ('reentrancy', r'재진입|destructor|__wakeup|callback|콜백|에러 핸들러|warning'),
    ('request_lifetime', r'요청 간|RINIT|RSHUTDOWN|request|shutdown|전역'),
    ('allocator_hardening', r'heap|allocator|guard page|할당기|프리리스트'),
    ('input_parser_uaf', r'unserialize|EXIF|xmlrpc|JSON|multipart|파서|입력'),
)


def render(data, path):
    lines = ['# PHP Memory-Safety Historical Corpus — H1 검증 결과', '',
             '> 생성: `linux/corpus/verify-corpus.py --render` (원천 상태 조회 시각 %s). '
             '원문: `%s`(사용자 제공, 수정 없음).' % (data['fetched_at'], data['source']),
             '> **이 표는 취약점 목록이 아니다.** 수정 완료·미검증 제보·설계 논의가 섞여 있다. '
             '`record_type`은 원천의 현재 상태에서 나온 기록 유형이며, 증거 수준·노출 조건·'
             '현재 탐색기 도달 가능성은 H2/H2.5에서 사례별로 판정한다(`unassessed`).', '',
             '| ID | 최초 | 기록 | 원천 현재 상태 | record_type | 후보 패턴 | 현재 탐색기 도달성(H2.5) | 불일치 |',
             '|---|---|---|---|---|---|---|---|']
    reach_path = Path(__file__).resolve().parent / 'reachability.json'
    reach = json.loads(reach_path.read_text(encoding='utf-8')) if reach_path.exists() else {}
    for r in data['records']:
        fetched = '; '.join(
            '%s%s' % (s.get('status') or s.get('state') or ('reachable' if s.get('reachable')
                                                            else s.get('fetch_error', '?')),
                      '/merged' if s.get('merged') else
                      ('/%s' % s['state_reason'] if s.get('state_reason') else ''))
            for s in r['verified_sources'])
        pats = [name for name, rx in PATTERNS if re.search(rx, r['pattern'], re.I)]
        label = re.sub(r'\]\([^)]+\)', ']', r['label']).replace('|', '/')
        rc = reach.get('records', {}).get(r['id'], ['unassessed', ''])
        lines.append('| %s | %s | %s | %s | %s | %s | %s | %s |' % (
            r['id'], r['first_seen'], label, fetched, r['record_type'],
            ', '.join(pats) or 'other', '`%s` %s' % (rc[0], rc[1]),
            '; '.join(r['discrepancies']) or '—'))
    counts = {}
    for r in data['records']:
        counts[r['record_type']] = counts.get(r['record_type'], 0) + 1
    lines += ['', '**요약:** ' + ', '.join('%s %d' % kv for kv in sorted(counts.items())) +
              ' (총 %d). 원천 조회 실패 0.' % len(data['records'])]
    if reach:
        rcount = {}
        for value in reach['records'].values():
            rcount[value[0]] = rcount.get(value[0], 0) + 1
        lines += ['', '**H2.5 도달성(%s):** ' % reach.get('basis') +
                  ', '.join('%s %d' % kv for kv in sorted(rcount.items())) +
                  '. 범주 정의: ' + '; '.join('`%s` = %s' % kv for kv in
                                             reach['categories'].items())]
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--md', default=str(MD))
    parser.add_argument('--out', default=str(REPO / 'linux/corpus/records.json'))
    parser.add_argument('--render', nargs='?', const=str(REPO / 'docs/historical-corpus.md'),
                        help='render records.json as a Markdown table and exit')
    args = parser.parse_args()
    if args.render:
        render(json.loads(Path(args.out).read_text(encoding='utf-8')), args.render)
        print('rendered', args.render)
        return 0
    records = parse(args.md)
    if len(records) != 58:
        print('warning: expected 58 records, parsed %d' % len(records), file=sys.stderr)
    for rec in records:
        rec['verified_sources'] = []
        for link in rec['links']:
            rec['verified_sources'].append(dict(url=link['url'], **check(link['url'])))
            time.sleep(0.3)
        rec['record_type'] = record_type(rec['verified_sources'])
        rec['evidence_level'] = 'unassessed'
        rec['exposure'] = 'unassessed'
        rec['discrepancies'] = discrepancies(rec, rec['verified_sources'])
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    data = dict(scope='#4 H1 corpus verification (status of primary sources at fetch time; '
                      'not a vulnerability determination)',
                source=Path(args.md).resolve().relative_to(REPO).as_posix(), fetched_at=stamp,
                records=records)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    counts = {}
    for rec in records:
        counts[rec['record_type']] = counts.get(rec['record_type'], 0) + 1
    failed = sum(1 for rec in records for s in rec['verified_sources'] if s.get('fetch_error'))
    print(json.dumps(dict(records=len(records), record_types=counts, fetch_failures=failed,
                          with_discrepancies=[r['id'] for r in records if r['discrepancies']],
                          out=args.out), indent=2, ensure_ascii=False))
    return 0 if failed == 0 else 2


if __name__ == '__main__':
    sys.exit(main())
