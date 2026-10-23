#!/usr/bin/env python3
"""GDB instrumentation for CVE-2026-109618 Path A (Apache mod_php).

Runs the crash-config request (filename="" empty uploads, nested names) under
gdb with a breakpoint on zend_mm_safe_error, capturing the allocation
backtrace at the moment of the memory_limit fatal. The site must be the key
zend_string_init inside _zend_hash_str_add_or_update_i (zend_hash.c:955-958,
8.4.4) — after nNumUsed++ and before the bucket is initialized — and not the
resize path, for the observation to count as CVE-2026-109618's specific
partially-initialized-bucket trigger.

Observation only: no exploitation attempt, no heap grooming.
"""
import argparse
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location('poc_patha_mod', HERE / 'poc-patha.py')
poc_patha = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(poc_patha)
build_body, send_request = poc_patha.build_body, poc_patha.send_request
REPO = Path(__file__).resolve().parents[1]
BASE = Path('/home/phplab/php-lab')
PORT = 18088

GDB_TEMPLATE = '''set pagination off
set confirm off
set breakpoint pending on
add-auto-load-safe-path /home/phplab/php-lab
set environment LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:log_path={asan}/asan
set environment ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
set environment USE_ZEND_ALLOC=0
set environment USE_TRACKED_ALLOC=1

break zend_mm_safe_error
commands
  silent
  printf "===OOM_FATAL_BEGIN===\\n"
  bt 16
  printf "===OOM_FATAL_END===\\n"
  python
import gdb
print("===BUCKET_BEGIN===")
try:
    frame = gdb.newest_frame()
    target = None
    while frame is not None:
        if '_zend_hash_str_add_or_update_i' in (frame.name() or ''):
            target = frame
            break
        frame = frame.older()
    if target is None:
        print("hash_frame=not-found")
    else:
        target.select()
        ht = gdb.parse_and_eval('ht')
        nused = int(ht['nNumUsed'])
        print('hash_frame=%s nNumUsed=%d nNumOfElements=%d' %
              (target.name(), nused, int(ht['nNumOfElements'])))
        try:
            bucket = ht['arData'][nused - 1]
            key = int(bucket['key'])
            vtype = int(bucket['val']['u1']['v']['type'])
            print('counted_bucket_idx=%d key_ptr=0x%x val_type=%d' %
                  (nused - 1, key, vtype))
        except gdb.Error as exc:
            print('bucket_read_error=%s' % exc)
except Exception as exc:
    print('observer_error=%s' % exc)
print("===BUCKET_END===")
  end
  continue
end

file /usr/sbin/apache2
set args -X -f {conf}
run
'''


def classify_backtrace(bt_text):
    has_add_or_update = '_zend_hash_str_add_or_update_i' in bt_text
    has_key_line = bool(re.search(r'zend_hash\.c:9[5-8]\d', bt_text))
    has_string_alloc = ('zend_string_init' in bt_text or 'zend_string_alloc' in bt_text)
    # Resize/init paths are identified by the callee name, not by line ranges:
    # callers of _zend_hash_str_add_or_update_i also live at zend_hash.c:10xx.
    has_resize = ('zend_hash_do_resize' in bt_text or 'zend_hash_rehash' in bt_text
                  or 'zend_hash_real_init' in bt_text or 'zend_hash_packed_to_hash' in bt_text
                  or '_zend_new_array' in bt_text)
    if has_add_or_update and (has_key_line or has_string_alloc) and not has_resize:
        return 'key_alloc_in_hash_add_or_update'
    if has_resize:
        return 'hash_resize'
    if has_add_or_update:
        return 'hash_add_or_update_other_frame'
    return 'other'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--parts', type=int, default=1000)
    parser.add_argument('--nest', type=int, default=60)
    parser.add_argument('--shared-chain', action='store_true')
    parser.add_argument('--seg-pad', type=int, default=0)
    args = parser.parse_args()

    run = BASE / 'evidence' / ('apache-lab-%s-patha-gdb' % args.version)
    prefix = BASE / 'install' / (args.version + '-apache')
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('probe-gdb-patha-%s-%s' % (stamp, args.version))
    out.mkdir(parents=True)

    env = os.environ.copy()
    env.update(APACHE_LAB_PREFIX=str(prefix), APACHE_LAB_RUN=str(run),
               APACHE_LAB_MEMORY_LIMIT=os.environ.get('POC_MEMORY_LIMIT', '64M'))
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'stop', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)
    # Generate conf/ini with our memory limit, then stop; gdb launches httpd.
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'start', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)
    subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), 'stop', str(PORT)],
                   env=env, capture_output=True)
    time.sleep(0.5)

    (out / 'gdb.cmd').write_text(GDB_TEMPLATE.format(asan=out, conf=run / 'httpd.conf'))
    log_handle = (out / 'gdb.log').open('w')
    gdb = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')],
                           stdout=log_handle, stderr=subprocess.STDOUT,
                           start_new_session=True)

    report = dict(scope='GDB Path A OOM-site confirmation; observation only',
                  version=args.version, parts=args.parts, nest=args.nest,
                  memory_limit=env['APACHE_LAB_MEMORY_LIMIT'], evidence=str(out))
    try:
        deadline = time.time() + 60
        ready = False
        while time.time() < deadline:
            if gdb.poll() is not None:
                raise RuntimeError('gdb exited before httpd was ready')
            try:
                with socket.create_connection(('127.0.0.1', PORT), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.4)
        if not ready:
            raise RuntimeError('httpd startup timeout under gdb')
        boundary = 'PathAGdb' + secrets.token_hex(8)
        body = build_body(args.parts, args.nest, boundary,
                          shared_chain=args.shared_chain,
                          seg_pad=args.seg_pad)
        response = send_request(PORT, body, boundary, timeout=120)
        report['request'] = response
        time.sleep(2.0)
    finally:
        if gdb.poll() is None:
            os.killpg(gdb.pid, signal.SIGTERM)
            try:
                gdb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(gdb.pid, signal.SIGKILL)
                gdb.wait()
        log_handle.close()

    log_text = (out / 'gdb.log').read_text(errors='replace')
    match = re.search(r'===OOM_FATAL_BEGIN===(.*?)===OOM_FATAL_END===',
                      log_text, re.S)
    bt_text = match.group(1).strip() if match else ''
    report['oom_backtrace'] = bt_text.splitlines()[:16]
    report['oom_site_class'] = classify_backtrace(bt_text)
    bucket_match = re.search(r'===BUCKET_BEGIN===(.*?)===BUCKET_END===',
                             log_text, re.S)
    bucket = {}
    if bucket_match:
        for line in bucket_match.group(1).splitlines():
            for item in line.strip().split():
                key, _, val = item.partition('=')
                if key in ('nNumUsed', 'nNumOfElements', 'counted_bucket_idx',
                           'key_ptr', 'val_type', 'hash_frame'):
                    bucket[key] = val
        if 'observer_error' in bucket_match.group(1) or 'bucket_read_error' in bucket_match.group(1):
            bucket['notes'] = [line.strip() for line in bucket_match.group(1).splitlines()
                               if 'error' in line][:2]
    report['bucket_observation'] = bucket
    # The counted-but-uninitialized claim requires: fatal at the key
    # allocation (:958) AND a bucket slot at nNumUsed-1 with a garbage key.
    report['counted_uninitialized_bucket_observed'] = bool(
        report['oom_site_class'] == 'key_alloc_in_hash_add_or_update'
        and bucket.get('nNumUsed')
        and bucket.get('key_ptr') not in (None, '0x0'))
    report['gdb_errors'] = [line.strip() for line in log_text.splitlines()
                            if 'Error in sourced' in line or 'No symbol table' in line][:3]
    asan_reports = sorted(str(p) for p in out.glob('asan.*') if p.is_file())
    report['asan_reports'] = asan_reports
    (out / 'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'evidence': report['evidence'],
                      'oom_site_class': report['oom_site_class'],
                      'bucket': bucket,
                      'counted_uninitialized_bucket_observed':
                          report['counted_uninitialized_bucket_observed'],
                      'asan_reports': asan_reports}))
    print(json.dumps(report.get('request', {}), ))


if __name__ == '__main__':
    sys.exit(main())
