#!/usr/bin/env python3
"""WAF vs PHP parsing comparison (WAFFLED-style, local lab only).

Sends multipart requests whose progress-field part header is written in several
syntactically different ways. For each variant we record:
  - the WAF decision (HTTP 403 from ModSecurity)
  - whether PHP actually treated it as the upload-progress field
    (session file contains upload_progress_<value>; the lab php.ini uses
    cleanup=Off so the entry persists)

Classification:
  blocked_not_reached : WAF blocked and PHP never saw it
  passed_and_reached  : WAF allowed and PHP parsed it  (rule gap for this form)
  passed_not_reached  : WAF allowed, PHP rejected the syntax
  blocked_but_reached : WAF blocked but PHP still parsed it (worst case)

Local loopback only. No external target, no attempt to evade a third-party WAF.
"""
import argparse
import http.cookiejar
import json
import os
import re
import secrets
import socket
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
RUN = BASE / 'evidence/waf-lab'
PROGRESS = 'PHP_SESSION_UPLOAD_PROGRESS'

VARIANTS = [
    ('baseline', 'Content-Disposition: form-data; name="%s"' % PROGRESS),
    ('unquoted', 'Content-Disposition: form-data; name=%s' % PROGRESS),
    ('spaces_around_eq', 'Content-Disposition: form-data; name = "%s"' % PROGRESS),
    ('filename_first', 'Content-Disposition: form-data; filename="x.bin"; name="%s"' % PROGRESS),
    ('lowercase_name', 'Content-Disposition: form-data; name="%s"' % PROGRESS.lower()),
    ('duplicate_name', 'Content-Disposition: form-data; name="foo"; name="%s"' % PROGRESS),
    ('rfc2231', "Content-Disposition: form-data; name*=UTF-8''%s" % PROGRESS),
    ('trailing_tab', 'Content-Disposition: form-data; name="%s"\t' % PROGRESS),
    ('trailing_semicolon', 'Content-Disposition: form-data; name="%s";' % PROGRESS),
    ('extra_param_first', 'Content-Disposition: form-data; foo="bar"; name="%s"' % PROGRESS),
]


def send(port, cookie, header_line, value, payload=b'F' * 1024):
    boundary = 'WafBnd' + secrets.token_hex(8)
    body = b''
    body += ('--%s\r\n%s\r\n\r\n%s\r\n' % (boundary, header_line, value)).encode()
    body += ('--%s\r\nContent-Disposition: form-data; name="file"; filename="f.bin"\r\n'
             'Content-Type: application/octet-stream\r\n\r\n' % boundary).encode()
    body += payload + b'\r\n'
    body += ('--%s--\r\n' % boundary).encode()
    sock = socket.create_connection(('127.0.0.1', port), timeout=8)
    try:
        head = ('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                'Content-Type: multipart/form-data; boundary=%s\r\n'
                'Content-Length: %d\r\nConnection: close\r\nCookie: PHPSESSID=%s\r\n\r\n'
                % (boundary, len(body), cookie))
        sock.sendall(head.encode() + body)
        data = b''
        while True:
            block = sock.recv(65536)
            if not block:
                break
            data += block
    finally:
        sock.close()
    match = re.match(rb'HTTP/1\.[01] (\d+)', data)
    return int(match.group(1)) if match else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18090)
    args = parser.parse_args()

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    with opener.open('http://127.0.0.1:%d/session' % args.port, timeout=5) as res:
        assert json.load(res).get('visits') == 1
    sid = next((c.value for c in jar if c.name == 'PHPSESSID'), None)
    if not sid:
        raise SystemExit('no session cookie from /session')

    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('waf-compare-%s' % stamp)
    out.mkdir(parents=True)
    rows = []
    for index, (name, header) in enumerate(VARIANTS, start=1):
        value = 'w%d' % index
        status = send(args.port, sid, header, value)
        time.sleep(0.2)
        session_file = RUN / 'sessions' / ('sess_' + sid)
        text = session_file.read_text(errors='replace') if session_file.exists() else ''
        reached = ('upload_progress_' + value) in text
        if status == 403 and not reached:
            verdict = 'blocked_not_reached'
        elif status == 403 and reached:
            verdict = 'blocked_but_reached'
        elif status == 200 and reached:
            verdict = 'passed_and_reached'
        else:
            verdict = 'passed_not_reached'
        rows.append(dict(variant=name, header=header, progress_value=value,
                         http_status=status, php_reached=reached, verdict=verdict))
    waf_log = RUN / 'error.log'
    log_text = waf_log.read_text(errors='replace') if waf_log.exists() else ''
    summary = dict(scope='local WAF vs PHP parsing comparison; observation only',
                   port=args.port, variants=len(rows), rows=rows,
                   waf_blocks=sum(1 for r in rows if r['http_status'] == 403),
                   php_reached=sum(1 for r in rows if r['php_reached']),
                   rule_gaps=[r for r in rows if r['verdict'] == 'passed_and_reached'],
                   modsecurity_hits=len(re.findall(r'progress field blocked', log_text)),
                   evidence=str(out))
    (out / 'result.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('variants', 'waf_blocks', 'php_reached',
                                              'modsecurity_hits', 'evidence')}, indent=2))
    for row in rows:
        print('%-22s status=%-4s php_reached=%-5s %s'
              % (row['variant'], row['http_status'], row['php_reached'], row['verdict']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
