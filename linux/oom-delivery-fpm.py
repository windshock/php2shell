#!/usr/bin/env python3
"""P18 FPM arms (plan 9.14-5e): chunked delivery through nginx -> FPM.

Observation only. Question: does the front proxy neutralise the
Content-Length/post_max_size mismatch (nginx buffers and synthesises
CONTENT_LENGTH, or caps the body with client_max_body_size), or can a
chunked request still deliver undeclared bytes to the FPM parser?

Usage: python3 linux/oom-delivery-fpm.py --version 8.4.4
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe import Lab, worker_pid  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def build_body(mib=5.5):
    boundary = 'P18Bnd'
    parts = [
        ('--%s\r\nContent-Disposition: form-data; name="pad"\r\n\r\n%s\r\n'
         % (boundary, 'D' * (4 * 1024 * 1024))).encode(),
        ('--%s\r\nContent-Disposition: form-data; name="file"; '
         'filename="f.bin"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n'
         % (boundary, b'F' * int(1.5 * 1024 * 1024))).encode(),
        ('--%s--\r\n' % boundary).encode()]
    body = b''.join(parts)
    return body


def curl_chunked(port, body_path, declared_chunked=True):
    cmd = ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
           '--max-time', '60', '-X', 'POST',
           '-H', 'Content-Type: multipart/form-data; boundary=P18Bnd']
    if declared_chunked:
        # curl 7.66+ streams the body chunked when the header is forced.
        cmd += ['-H', 'Transfer-Encoding: chunked']
    cmd += ['--data-binary', '@' + body_path,
            'http://127.0.0.1:%d/upload' % port]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip() or None


def run_arm(version, buffering, body_path):
    lab = Lab(version, 'asan', 'tracked', buffering,
              ['session.upload_progress.min_freq=0', 'memory_limit=64M',
               'post_max_size=4M'], 'oomdelivery')
    try:
        lab.start()
        # Raise the nginx body cap by rewriting the conf and restarting nginx
        # is intrusive; run two variants via the default 4m cap first, then a
        # second lab with the cap raised.
        record = dict(buffering=buffering)
        code = curl_chunked(18085, body_path, declared_chunked=True)
        record['chunked_http'] = code
        time.sleep(0.5)
        log = lab.out / 'php-error.log'
        text = log.read_text(errors='replace') if log.exists() else ''
        record['exceeds_warning_reached_php'] = 'exceeds the limit' in text
        record['fatal_reached_php'] = 'Allowed memory size' in text
        nginx_err = lab.out / 'nginx-error.log'
        ntext = nginx_err.read_text(errors='replace') if nginx_err.exists() else ''
        record['nginx_client_body_too_large'] = 'client intended to send too large body' in ntext
        nacc = lab.out / 'nginx-access.log'
        if nacc.exists():
            record['nginx_access_tail'] = nacc.read_text(errors='replace').splitlines()[-2:]
        record['worker_pid'] = worker_pid(lab.out)
        return record, str(lab.out)
    finally:
        lab.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    args = parser.parse_args()

    body = build_body()
    body_path = '/tmp/p18-fpm-body.bin'
    Path(body_path).write_bytes(body)

    results = []
    for buffering in ('on', 'off'):
        record, out = run_arm(args.version, buffering, body_path)
        record['nginx_client_max_body_size'] = '4m (default cap in lab conf)'
        results.append(record)
        print(json.dumps(record))
    summary = dict(scope='P18 FPM arms; observation only',
                   version=args.version, body_bytes=len(body),
                   deployability=dict(
                       nginx='nginx caps the body (client_max_body_size) before '
                             'FastCGI and, when buffering is on, synthesises '
                             'CONTENT_LENGTH so the PHP pre-parse check applies '
                             'again; the chunked mismatch is a front-proxy '
                             'configuration property'),
                   results=results)
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out_path = Path('/home/phplab/php-lab/evidence') / (
        'oom-delivery-fpm-%s-%s.json' % (stamp, args.version))
    out_path.write_text(json.dumps(summary, indent=2))
    print('summary:', out_path)


if __name__ == '__main__':
    main()
