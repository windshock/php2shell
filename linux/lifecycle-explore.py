#!/usr/bin/env python3
"""Phase 5 v2 Stage 1b-1f: feedback-driven request-lifecycle explorer.

Closes the loop Generate -> Execute -> Observe -> Select -> Mutate ->
Replay/Validate (plan §12.6.4) over HTTP request SEQUENCES sent to one PHP
CLI-server process (worker state is preserved inside a sequence; every
sequence starts a fresh process).

  Generate   sequences from an action grammar (grammar check before run)
  Execute    one ASAN php -S process per sequence, optionally under gdb
  Observe    per request: response class, failure site (fatal log delta),
             ASAN signature (pid-attributed), and - with the gdb observer -
             the normalized request-boundary state (BG serialize/unserialize,
             PS id/mod_data/vars, url_adapt hosts) at php_request_startup
  Select     corpus scheduler: sequences that produced new feedback keys are
             kept and re-selected as parents (selection log = lineage)
  Mutate     insert/delete/replace/swap/duplicate/param/splice
  Validate   replay, step-wise minimization, fixed-version differential

State ids are normalized, never raw addresses: a pointer is null / fresh /
carried (same address seen during the previous request). Oracle levels:
state_change_observed -> invariant_violation_candidate (request-owned state
carried into the next request's startup) -> memory_error_confirmed (ASAN
report of this process during this step).

--feedback off generates every sequence from the grammar at random with the
same executor and budget (G4 baseline). --exclude-pairs (G3 hold-out) drops
seeds containing the given consecutive action pairs from the initial corpus
only; generation may still rediscover them.

SAPI scope: --sapi cli (default; gdb state observer available), apache
(prefork mod_php, httpd -X) or fpm (nginx + single-worker FPM; a replaced
worker ends the sequence). See explore_sapi.py.
Observation only: no heap grooming, no pointer control, no RCE attempt.
New memory-error signatures stay in the local evidence tree; they are not
published (plan §11.2 D1).
"""
import argparse
import hashlib
import http.cookiejar
import json
import math
import os
import random
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from probe import multipart  # noqa: E402
import explore_sapi  # noqa: E402
import verdicts  # noqa: E402

REPO = HERE.parent
BASE = Path('/home/phplab/php-lab')
CLI_PORT = 18090
PORT = CLI_PORT  # rebound per execution to the active SAPI's port
SESSION_FIELD = 'PHPSESSID'
PROGRESS_FIELD = 'PHP_SESSION_UPLOAD_PROGRESS'
FIXED_VERSIONS = ('8.4.27', '8.5.12')
MAX_LEN = 6

# ---------------------------------------------------------------- grammar
ACTIONS = {
    'health': {},
    'session': {},
    'upload_small': {},
    'upload_nofile': {},
    'upload_cookie': {},
    'unser_small': {},
    'parse_oom': {},
    'runtime_oom': {'mb': (2, 6, 14)},
    'abort_upload': {},
    'abort_big': {},
}
FUSED_POOL = None  # set by --fused-pool: directory made by linux/fused-pool.py
OPCACHE = False  # set by --opcache: load the shared opcache zend_extension
FUSED_SANDBOX = ('disable_functions=exec,shell_exec,system,passthru,proc_open,popen,'
                 'pcntl_exec,mail,fsockopen,pfsockopen,stream_socket_client,'
                 'stream_socket_server,socket_create,socket_connect,curl_exec,'
                 'curl_multi_exec,putenv,dl\nallow_url_fopen=Off\nallow_url_include=Off\n'
                 'max_execution_time=10\n')


def enable_fused(pool_dir):
    """#4 H2.5: the `fused` action runs program p of a FlowFusion pool as one
    request of the sequence (CLI server only)."""
    global FUSED_POOL
    pool = json.loads((Path(pool_dir) / 'pool.json').read_text())
    FUSED_POOL = Path(pool_dir)
    ACTIONS['fused'] = {'p': tuple(range(len(pool['programs'])))}
    return pool


LIMITS = ('8M', '16M')
# Stage 2 connection: ZEND_MM_MAX_ALLOCS (8.4.27+, tracked allocator) fails
# the n-th allocation of every request after startup. putenv() from userland
# is restored at RSHUTDOWN, so the knob is per sequence (process env), not
# per request; pre-RINIT parsing stays outside it (main.c:1914, §12.3).
FAULTS = (0, 30, 120, 500, 2000)
POST_MAX_MB = 64


def validate(seq):
    """Grammar check run before every execution (G1 evidence)."""
    problems = []
    if seq.get('limit') not in LIMITS:
        problems.append('limit %r not in %s' % (seq.get('limit'), LIMITS))
    if seq.get('fault', 0) not in FAULTS:
        problems.append('fault %r not in %s' % (seq.get('fault'), FAULTS))
    extra_keys = set(seq) - {'limit', 'steps', 'fault'}
    if extra_keys:
        problems.append('unexpected sequence keys %s' % sorted(extra_keys))
    steps = seq.get('steps') or []
    if not 1 <= len(steps) <= MAX_LEN:
        problems.append('length %d outside 1..%d' % (len(steps), MAX_LEN))
    for i, step in enumerate(steps):
        action = step.get('a')
        if action not in ACTIONS:
            problems.append('step %d: unknown action %r' % (i, action))
            continue
        for key, domain in ACTIONS[action].items():
            if step.get(key) not in domain:
                problems.append('step %d: %s=%r not in %s' % (i, key, step.get(key), domain))
        extra = set(step) - {'a'} - set(ACTIONS[action])
        if extra:
            problems.append('step %d: unexpected params %s' % (i, sorted(extra)))
        if action == 'runtime_oom' and step.get('mb', 0) >= POST_MAX_MB:
            problems.append('step %d: body exceeds post_max_size' % i)
    return problems


def make_step(rng, action=None):
    action = action or rng.choice(sorted(ACTIONS))
    step = {'a': action}
    for key, domain in ACTIONS[action].items():
        step[key] = rng.choice(domain)
    return step


def random_sequence(rng, faults=False):
    seq = dict(limit=rng.choice(LIMITS),
               steps=[make_step(rng) for _ in range(rng.randint(1, MAX_LEN))])
    if faults:
        seq['fault'] = rng.choice(FAULTS)
    return seq


def seq_key(seq):
    return json.dumps(seq, sort_keys=True)


def seq_hash(seq):
    return hashlib.sha1(seq_key(seq).encode()).hexdigest()[:12]


def pairs(seq):
    acts = [s['a'] for s in seq['steps']]
    return set(zip(acts, acts[1:]))


def mutate(rng, parent, corpus, faults=False):
    child = json.loads(json.dumps(parent))
    steps = child['steps']
    ops = ['insert', 'replace', 'param', 'swap', 'delete', 'duplicate', 'splice', 'limit']
    if faults:
        ops.append('fault')
    for _ in range(20):
        op = rng.choice(ops)
        if op == 'insert' and len(steps) < MAX_LEN:
            steps.insert(rng.randint(0, len(steps)), make_step(rng))
        elif op == 'replace' and steps:
            steps[rng.randrange(len(steps))] = make_step(rng)
        elif op == 'param':
            idx = [i for i, s in enumerate(steps) if ACTIONS[s['a']]]
            if not idx:
                continue
            i = rng.choice(idx)
            steps[i] = make_step(rng, steps[i]['a'])
        elif op == 'swap' and len(steps) > 1:
            i = rng.randrange(len(steps) - 1)
            steps[i], steps[i + 1] = steps[i + 1], steps[i]
        elif op == 'delete' and len(steps) > 1:
            del steps[rng.randrange(len(steps))]
        elif op == 'duplicate' and 0 < len(steps) < MAX_LEN:
            i = rng.randrange(len(steps))
            steps.insert(i, json.loads(json.dumps(steps[i])))
        elif op == 'splice' and len(corpus) > 1:
            other = rng.choice(corpus)['seq']['steps']
            cut_a = rng.randint(1, len(steps)) if steps else 0
            cut_b = rng.randint(0, len(other) - 1)
            child['steps'] = steps = (steps[:cut_a] + json.loads(json.dumps(other[cut_b:])))[:MAX_LEN]
        elif op == 'limit':
            child['limit'] = rng.choice([l for l in LIMITS if l != child['limit']])
        elif op == 'fault':
            child['fault'] = rng.choice([f for f in FAULTS if f != child.get('fault', 0)])
        else:
            continue
        if seq_key(child) != seq_key(parent) and not validate(child):
            return child, op
        child = json.loads(json.dumps(parent))
        steps = child['steps']
    return None, None


# --------------------------------------------------------------- executor
GDB_TEMPLATE = r'''set pagination off
set confirm off
set breakpoint pending on
add-auto-load-safe-path /home/phplab/php-lab
handle SIGPIPE nostop noprint pass
handle SIGSEGV nostop noprint pass
handle SIGBUS nostop noprint pass
handle SIGABRT nostop noprint pass
handle SIGINT nostop noprint pass
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:log_path={asan}/asan
set environment ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
set environment USE_ZEND_ALLOC=0
set environment USE_TRACKED_ALLOC=1
python
import gdb, json, sys

def _ptr(v):
    try:
        return int(v)
    except Exception:
        return None

class StateBP(gdb.Breakpoint):
    def __init__(self, loc, tag):
        super().__init__(loc, internal=True)
        self.tag = tag
    def stop(self):
        out = dict(tag=self.tag, pid=gdb.selected_inferior().pid)
        try:
            bg = gdb.parse_and_eval('basic_globals')
            ps = gdb.parse_and_eval('ps_globals')
            pg = gdb.parse_and_eval('core_globals')
            sg = gdb.parse_and_eval('sapi_globals')
            uri = sg['request_info']['request_uri']
            out['uri'] = uri.string() if _ptr(uri) else ''
            out.update(ser_level=int(bg['serialize']['level']),
                       ser_data=_ptr(bg['serialize']['data']),
                       unser_level=int(bg['unserialize']['level']),
                       unser_data=_ptr(bg['unserialize']['data']),
                       lock=int(bg['serialize_lock']),
                       ps_id=_ptr(ps['id']), ps_mod=_ptr(ps['mod_data']),
                       ps_status=int(ps['session_status']),
                       ps_vars_type=int(ps['http_session_vars']['u1']['v']['type']),
                       ps_session_vars=_ptr(ps['session_vars']),
                       url_hosts=int(bg['url_adapt_session_hosts_ht']['nNumOfElements']),
                       modules_activated=int(pg['modules_activated']))
        except Exception as exc:
            out['error'] = str(exc)[:200]
        try:
            gc = gdb.parse_and_eval("'zend_gc.c'::gc_globals")
            out.update(gc_enabled=int(gc['gc_enabled']), gc_active=int(gc['gc_active']),
                       gc_protected=int(gc['gc_protected']), gc_runs=int(gc['gc_runs']))
        except Exception as exc:
            out['gc_error'] = str(exc)[:120]
        print('STATE ' + json.dumps(out))
        sys.stdout.flush()
        return False

class EventBP(gdb.Breakpoint):
    # Instrumentation events for verified block points (issue #5-9): the
    # producer's (un)serialize context destroyed, the 8.4.27 early reset.
    def __init__(self, loc):
        super().__init__(loc, internal=True)
        self.name = loc
    def stop(self):
        out = dict(name=self.name)
        try:
            uri = gdb.parse_and_eval('sapi_globals')['request_info']['request_uri']
            out['uri'] = uri.string() if _ptr(uri) else ''
        except Exception as exc:
            out['error'] = str(exc)[:120]
        try:
            out['gc_protected'] = int(gdb.parse_and_eval("'zend_gc.c'::gc_globals")['gc_protected'])
            out['in_shutdown'] = int(gdb.parse_and_eval('executor_globals')['flags']) & 1
        except Exception:
            pass
        if self.name == '_zend_bailout':
            frames, f = [], gdb.selected_frame().older()
            while f is not None and len(frames) < 6:
                frames.append(f.name() or '?')
                f = f.older()
            out['frames'] = frames
        print('EVENT ' + json.dumps(out))
        sys.stdout.flush()
        return False

StateBP('php_request_startup', 'startup')
StateBP('php_request_shutdown', 'shutdown')
for _loc in ('php_var_unserialize_destroy', 'php_var_serialize_destroy', 'php_basic_early_rinit',
             '_zend_bailout', 'zend_mm_delayed_error'):
    try:
        EventBP(_loc)
    except Exception:
        pass
end
file {php}
set args -c {ini} -S 127.0.0.1:{port} -t {docroot} {router}
run
'''

FATAL_RE = re.compile(r'PHP (Fatal error|Warning|Notice|Parse error):\s+(.*?)(?: in (\S+) on line (\d+))?$')
AT_RE = re.compile(r'exhausted at (\S+):(\d+)')
TRIED_RE = re.compile(r'Allowed memory size of \d+ bytes exhausted(?: at \S+)? '
                      r'\(tried to allocate (\d+) bytes\)')
POINTER_FIELDS = ('ser_data', 'unser_data', 'ps_id', 'ps_mod', 'ps_session_vars')


def failure_sites(text, injected=False):
    """Normalized failure-site ids from a php-error.log delta. The debug
    build reports the failing allocation's C location ('exhausted at
    file:line'); 'file:0' (no location) is dropped. With fault injection
    armed the id is prefixed 'inj:' (injected vs natural failure)."""
    sites = []
    for line in text.splitlines():
        match = FATAL_RE.search(line.strip())
        if not match or match.group(1) != 'Fatal error':
            continue
        message, file_, lineno = match.group(2), match.group(3), match.group(4)
        tried = TRIED_RE.search(line)
        if tried:
            bucket = int(math.log2(max(int(tried.group(1)), 1)))
            kind = 'oom:2^%d' % bucket
        else:
            kind = re.sub(r'\d+', 'N', message)[:60]
        where = '%s:%s' % (Path(file_ or 'Unknown').name, lineno or '0')
        at = AT_RE.search(line)
        if at and at.group(1) != 'file':
            where += '<%s:%s' % (Path(at.group(1)).name, at.group(2))
        sites.append('%s%s@%s' % ('inj:' if injected else '', kind, where))
    return sites


def asan_signature(path):
    text = Path(path).read_text(errors='replace')
    if 'AddressSanitizer' not in text:
        return None
    kind = re.search(r'AddressSanitizer: ([\w-]+)', text)
    funcs = []
    for line in text.splitlines():
        frame = re.match(r'\s*#\d+ 0x[0-9a-f]+ in (\S+)', line)
        if frame:
            funcs.append(frame.group(1))
        if len(funcs) == 3:
            break
    pid = re.match(r'asan\.(\d+)', Path(path).name)
    return dict(sig='%s:%s' % (kind.group(1) if kind else 'unknown', '>'.join(funcs)),
                pid=int(pid.group(1)) if pid else None, file=str(path),
                summary=next((l for l in text.splitlines() if 'SUMMARY' in l), ''))


SANCOV_MAGIC64 = 0xC0BFFFFFFFFFFF64


def read_sancov(cov_dir):
    """Covered edge-guard PCs (module offsets) of the php binary, plus the
    collection state (issue #5-6): coverage_not_collected (no file),
    coverage_invalid (files but none with a valid header/payload),
    coverage_valid. Returns (pcs, valid_files, status)."""
    pcs = set()
    files = sorted(Path(cov_dir).glob('php.*.sancov')) if Path(cov_dir).exists() else []
    valid = 0
    for path in files:
        data = path.read_bytes()
        if len(data) < 16 or int.from_bytes(data[:8], 'little') != SANCOV_MAGIC64:
            continue
        valid += 1
        for i in range(8, len(data) - 7, 8):
            pcs.add(int.from_bytes(data[i:i + 8], 'little'))
    status = ('coverage_not_collected' if not files else
              'coverage_invalid' if not valid else 'coverage_valid')
    return pcs, valid, status


def normalize_state(state, previous):
    """Abstract state id: levels bucketed, pointers null/fresh/carried."""
    if state is None:
        return 'unobserved'
    if 'error' in state:
        return 'observer_error'
    seen = set()
    for prev in previous:
        seen.update(prev.get(f) for f in POINTER_FIELDS if prev.get(f))
    parts = ['ser=%d' % min(state['ser_level'], 2), 'unser=%d' % min(state['unser_level'], 2)]
    for field in POINTER_FIELDS:
        value = state.get(field)
        parts.append('%s=%s' % (field, 'null' if not value else
                                'carried' if value in seen else 'fresh'))
    parts.append('ps_status=%d' % state['ps_status'])
    parts.append('vars=%d' % state['ps_vars_type'])
    parts.append('hosts=%d' % min(state['url_hosts'], 1))
    parts.append('lock=%d' % min(state['lock'], 1))
    return ','.join(parts)


def gc_state(state):
    """GC state at request shutdown: normal = enabled, not running, not
    protected. Anything else is unexpected at the end of a request."""
    if not state or 'gc_protected' not in state:
        return 'gc_unobserved'
    odd = [name for name, bad in (('protected', state['gc_protected']),
                                  ('active', state['gc_active']),
                                  ('disabled', not state['gc_enabled'])) if bad]
    return 'gc_' + '+'.join(odd) if odd else 'gc_normal'


# Feedback 'state' (plan §13.3a): weight per new key kind. Code edges and
# step-outcome text are not rewarded beyond 1.
STATE_WEIGHTS = dict(G=4, R=4, A=4, H=2)


def feedback_gain(mode, rec):
    new = rec.get('new_keys', [])
    if mode == 'state':
        return sum(STATE_WEIGHTS.get(k[0], 3 if k[0] == 'S' and 'carried' in k else 1)
                   for k in new)
    return len(new) + (rec.get('new_edges', 0) and 1 + int(math.log2(rec['new_edges'])))


def carried_request_state(norm):
    """Invariant: request-owned state must not be live at the next startup."""
    if norm in ('unobserved', 'observer_error'):
        return []
    found = []
    for item in norm.split(','):
        key, _, val = item.partition('=')
        if key in ('ser', 'unser') and val != '0':
            found.append('%s_level>0' % key)
        if val == 'carried':
            found.append('%s carried' % key)
    return found


class Process:
    def __init__(self, prefix, out, limit, observer, fault=0, docroot=None, router=None,
                 cov=False):
        self.fault = fault
        self.ready_state = None
        # docroot/router default to the lab app; flowfusion-bridge.py
        # serves a fused program next to it.
        docroot = docroot or REPO / 'web'
        router = router or REPO / 'web/index.php'
        self.out, self.observer = out, observer
        for name in ('sessions', 'uploads'):
            (out / name).mkdir(parents=True, exist_ok=True)
        ini = (REPO / 'config/php.ini').read_text() + '\n'
        ini += ('session.upload_progress.min_freq=0\n'
                'memory_limit=%s\npost_max_size=%dM\n'
                'session.save_path=%s\nupload_tmp_dir=%s\nerror_log=%s\n'
                % (limit, POST_MAX_MB, out / 'sessions', out / 'uploads',
                   out / 'php-error.log'))
        if OPCACHE:
            so = sorted(prefix.glob('lib/php/extensions/*/opcache.so'))
            if not so:
                raise SystemExit('--opcache: no opcache.so under %s' % prefix)
            ini += 'zend_extension=%s\nopcache.enable=1\nopcache.enable_cli=1\n' % so[0]
        (out / 'php.ini').write_text(ini)
        php = prefix / 'bin/php'
        self.env = os.environ.copy()
        self.env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:'
                        'log_path=%s/asan' % out,
                        ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer',
                        USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
        self.env.pop('ZEND_MM_MAX_ALLOCS', None)
        self.cov = cov
        self.cov_dir = out / 'cov'
        if cov:
            # Stage 1c: SanitizerCoverage edge guards (cov build); each php
            # process writes php.<pid>.sancov when it exits normally.
            self.cov_dir.mkdir(parents=True, exist_ok=True)
            self.env['ASAN_OPTIONS'] += ':coverage=1:coverage_dir=%s' % self.cov_dir
        fault_line = ''
        if fault:
            self.env['ZEND_MM_MAX_ALLOCS'] = str(fault)
            fault_line = 'set environment ZEND_MM_MAX_ALLOCS=%d\n' % fault
        if observer == 'gdb':
            (out / 'gdb.cmd').write_text(GDB_TEMPLATE.format(
                asan=out, php=php, ini=out / 'php.ini', port=PORT,
                docroot=docroot, router=router).replace(
                    'log_path={0}/asan\n'.format(out),
                    'log_path={0}/asan{1}\n'.format(
                        out, ':coverage=1:coverage_dir=%s' % self.cov_dir if cov else '')).replace(
                    'set environment USE_TRACKED_ALLOC=1\n',
                    'set environment USE_TRACKED_ALLOC=1\n' + fault_line))
            self.cmd = ['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')]
        else:
            self.cmd = [str(php), '-c', str(out / 'php.ini'), '-S', '127.0.0.1:%d' % PORT,
                        '-t', str(docroot), str(router)]
        self.proc = None
        self.port = PORT
        self.sessions = out / 'sessions'
        self.error_log = out / 'php-error.log'
        self.asan_dir = out

    def worker_pid(self):
        # The php process itself (observer none) or the gdb inferior; None
        # only if it cannot be determined - attribution then stays unknown.
        return self.inferior_pid()

    def start(self):
        free_port()
        self.log = (self.out / 'observer.log').open('w')
        # cwd = the exec dir: programs that write relative files (fused
        # php-src tests) must never write into the repository.
        self.proc = subprocess.Popen(self.cmd, env=self.env, stdout=self.log, cwd=self.out,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('server/observer exited during startup')
            try:
                with urllib.request.urlopen('http://127.0.0.1:%d/health?step=ready' % PORT,
                                            timeout=3) as res:
                    if json.load(res).get('ok'):
                        self.ready_state = 'healthy'
                        return
            except urllib.error.HTTPError as exc:
                # Issue #5-7: an error answer is ready ONLY when fault
                # injection is armed (it may fail the health request itself).
                state = readiness_state(exc.code, self.fault)
                if state == 'fault_expected':
                    self.ready_state = state
                    return
                raise RuntimeError('warmup_unhealthy: health answered HTTP %d' % exc.code)
            except Exception:
                time.sleep(0.3)
        raise RuntimeError('startup timeout')

    def inferior_pid(self):
        if self.observer != 'gdb':
            return self.proc.pid if self.proc else None
        pid = None
        if (self.out / 'observer.log').exists():
            for line in (self.out / 'observer.log').read_text(errors='replace').splitlines():
                match = re.search(r'"pid": (\d+)', line)
                if line.startswith('STATE ') and match:
                    pid = int(match.group(1))
        return pid

    def stop(self):
        if self.cov and self.proc and self.proc.poll() is None:
            # Graceful CLI-server shutdown (SIGINT handler) so the coverage
            # dump runs at exit; SIGTERM would skip it.
            pid = self.inferior_pid()
            if pid:
                try:
                    os.kill(pid, signal.SIGINT)
                    self.proc.wait(timeout=15)
                except Exception:
                    pass
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        if getattr(self, 'log', None):
            self.log.close()

    def alive(self):
        # Process status only: an HTTP liveness probe would itself be a
        # normal request between steps and clear the very residue under
        # test (basic/session RINIT).
        return self.proc is not None and self.proc.poll() is None


def readiness_state(http_code, fault):
    """Warm-up verdict for an HTTP error answer (issue #5-7)."""
    return 'fault_expected' if fault and http_code >= 500 else 'unhealthy'


HANG_GRACE = 12.0
MAX_HARNESS_STREAK = 3


def responsive():
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health?step=hangprobe' % PORT,
                                    timeout=5) as res:
            return json.load(res).get('ok') is True
    except Exception:
        return False


def free_port(timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', PORT))
                return True
        except OSError:
            time.sleep(0.2)
    raise RuntimeError('port %d busy' % PORT)


def send(action, step, idx, ctx):
    """One HTTP request; returns a response class."""
    path_q = lambda p: '%s?step=%d' % (p, idx)  # noqa: E731
    try:
        if action == 'fused':
            url = 'http://127.0.0.1:%d/fused?p=%d&step=%d' % (PORT, step['p'], idx)
            # Read the whole body: closing after the status line makes the
            # program's next output write fail, and php_handle_aborted_connection
            # then bails out and cuts the program short (calibration, findings 11.5).
            try:
                with ctx['opener'].open(url, timeout=20) as res:
                    res.read()
                    return 's%d' % res.status
            except urllib.error.HTTPError as exc:
                exc.read()
                return 's%d' % exc.code
        if action in ('health', 'session'):
            try:
                with ctx['opener'].open('http://127.0.0.1:%d%s' % (PORT, path_q('/' + action)),
                                        timeout=10) as res:
                    return 's%d' % res.status
            except urllib.error.HTTPError as exc:
                return 's%d' % exc.code
        if action in ('unser_small', 'runtime_oom'):
            if action == 'unser_small':
                body = b'a:2:{i:0;s:3:"abc";i:1;a:1:{s:1:"k";i:7;}}'
            else:
                n = step['mb'] * 1024 * 1024
                body = ('s:%d:"%s";' % (n, 'B' * n)).encode()
            req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path_q('/unserialize')),
                                         data=body,
                                         headers={'Content-Type': 'application/octet-stream'})
            try:
                with ctx['opener'].open(req, timeout=30) as res:
                    return 's%d' % res.status
            except urllib.error.HTTPError as exc:
                return 's%d' % exc.code
        sid = ctx['sid_big'] if action in ('parse_oom', 'abort_big') else ctx['sid_small']
        cookie = None
        fields = [(SESSION_FIELD, sid), (PROGRESS_FIELD, 'ex%d' % idx)]
        if action == 'upload_cookie':
            jar_sid = next((c.value for c in ctx['jar'] if c.name == SESSION_FIELD), None)
            fields = [(PROGRESS_FIELD, 'ex%d' % idx)]
            cookie = (SESSION_FIELD + '=' + jar_sid) if jar_sid else None
        file_spec = {'upload_small': ('file', 'b.bin', b'L' * 16384),
                     'upload_cookie': ('file', 'c.bin', b'C' * 16384),
                     'upload_nofile': None,
                     'parse_oom': ('file', 'a.bin', b'K' * 32768),
                     'abort_upload': ('file', 'd.bin', b'D' * 262144),
                     'abort_big': ('file', 'e.bin', b'E' * 262144)}[action]
        abort_after = {'abort_upload': 2, 'abort_big': 1}.get(action)
        res = multipart(PORT, path_q('/upload'), fields=fields, file_spec=file_spec,
                        cookie=cookie, abort_after=abort_after, chunk_delay=0.02)
        if res.get('aborted'):
            return 'aborted'
        return 's%s' % res.get('status') if res.get('status') else 'no_status'
    except (ConnectionResetError, BrokenPipeError):
        return 'reset'
    except Exception as exc:
        return 'error:%s' % type(exc).__name__


def execute(seq, prefix, out, observer, sapi='cli', version=None, cov=False):
    """Run one sequence in one fresh process; return per-step observations."""
    global PORT
    out.mkdir(parents=True, exist_ok=True)
    ctx = dict(sid_big='exbig' + secrets.token_hex(6), sid_small='exsmall' + secrets.token_hex(6))
    uses_fused = any(s['a'] == 'fused' for s in seq['steps'])
    if uses_fused and (FUSED_POOL is None or sapi != 'cli'):
        return dict(steps=[dict(harness_error='fused action needs --fused-pool and the CLI '
                                              'server')], states=[], events=[], elapsed=0,
                    sapi=sapi, worker_pid=None, edges=set(), cov_files=0, cov_status=None,
                    ready_state=None)
    if sapi == 'cli':
        PORT = CLI_PORT
        proc = Process(prefix, out, seq['limit'], observer, seq.get('fault', 0), cov=cov,
                       docroot=FUSED_POOL if FUSED_POOL else None,
                       router=(FUSED_POOL / 'router.php') if FUSED_POOL else None)
        if FUSED_POOL:
            with (out / 'php.ini').open('a') as ini:
                ini.write(FUSED_SANDBOX)
    else:
        proc = explore_sapi.make_process(sapi, version, out, seq['limit'],
                                         seq.get('fault', 0), POST_MAX_MB)
        PORT = proc.port
    big = 'A' * (3 * 1024 * 1024)
    proc.sessions.mkdir(parents=True, exist_ok=True)
    (proc.sessions / ('sess_' + ctx['sid_big'])).write_text('big|s:%d:"%s";' % (len(big), big))
    (proc.sessions / ('sess_' + ctx['sid_small'])).write_text('small|a:1:{i:0;i:7;}')
    ctx['jar'] = http.cookiejar.CookieJar()
    ctx['opener'] = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(ctx['jar']))
    error_log = proc.error_log
    asan_dir = proc.asan_dir
    steps = []
    started = time.time()
    worker = None
    try:
        proc.start()
        worker = proc.worker_pid()
        for idx, step in enumerate(seq['steps']):
            before_log = error_log.stat().st_size if error_log.exists() else 0
            before_asan = {p.name for p in asan_dir.glob('asan.*')}
            response = send(step['a'], step, idx, ctx)
            time.sleep(0.25)
            log_text = ''
            if error_log.exists():
                with error_log.open('rb') as handle:
                    handle.seek(before_log)
                    log_text = handle.read().decode('utf-8', 'replace')
            asan = None
            deadline = time.time() + (3.0 if response in ('reset', 'no_status', 'aborted')
                                      or response.startswith('error') else 0.6)
            while time.time() < deadline and asan is None:
                for path in sorted(asan_dir.glob('asan.*')):
                    if path.name not in before_asan and path.is_file():
                        asan = asan_signature(path)
                        if asan:
                            break
                if asan is None:
                    time.sleep(0.2)
            alive = proc.alive()
            hung = False
            if alive and asan is None and (response in ('no_status', 'reset')
                                           or response.startswith('error')):
                # No answer from a live process: either a slow ASAN report
                # (symbolization) or a hang. Wait longer, then classify.
                deadline = time.time() + HANG_GRACE
                while time.time() < deadline and asan is None and proc.alive():
                    for path in sorted(asan_dir.glob('asan.*')):
                        if path.name not in before_asan and path.is_file():
                            asan = asan_signature(path)
                            if asan:
                                break
                    time.sleep(0.5)
                alive = proc.alive()
                # The probe is itself a normal request (it would clear
                # residue), so the sequence always ends after it.
                probed = alive and asan is None
                hung = probed and not responsive()
            else:
                probed = False
            steps.append(dict(i=idx, a=step['a'], response=response,
                              failure_sites=failure_sites(log_text, bool(seq.get('fault'))),
                              completed=('LAB-FUSED-END' in log_text
                                         if step['a'] == 'fused' else None),
                              asan=asan,
                              alive_after=alive, hung=hung, ended_by_probe=probed))
            if not alive or probed:
                break
    except Exception as exc:
        steps.append(dict(harness_error=str(exc)))
    finally:
        proc.stop()
    states, events = [], []
    if observer == 'gdb' and (out / 'observer.log').exists():
        for line in (out / 'observer.log').read_text(errors='replace').splitlines():
            if line.startswith('STATE ') or line.startswith('EVENT '):
                try:
                    (states if line.startswith('STATE ') else events).append(
                        json.loads(line[6:]))
                except ValueError:
                    pass
    edges, cov_files, cov_status = read_sancov(out / 'cov') if cov else (set(), 0, None)
    return dict(steps=steps, states=states, events=events,
                elapsed=round(time.time() - started, 2),
                sapi=sapi, worker_pid=worker, edges=edges, cov_files=cov_files,
                cov_status=cov_status, ready_state=getattr(proc, 'ready_state', None))


# ------------------------------------------------------------ observation
def observe(result, seq):
    """Derive per-step normalized state, outcome and feedback keys."""
    states = result['states']
    by_step, end_of = {}, {}
    for i, st in enumerate(states):
        match = re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'startup':
            by_step.setdefault(int(match.group(1)), (i, st))
        elif match and st.get('tag') == 'shutdown':
            end_of.setdefault(int(match.group(1)), st)
    bailouts = {}
    for ev in result.get('events') or ():
        match = re.search(r'[?&]step=(\d+)', ev.get('uri') or '')
        if match and ev.get('name') in ('_zend_bailout', 'zend_mm_delayed_error'):
            bailouts.setdefault(int(match.group(1)), []).append(ev)
    pids = {st.get('pid') for st in states if st.get('pid')}
    if result.get('worker_pid'):
        pids = {int(result['worker_pid'])}
    keys, steps = set(), []
    findings = []
    for step in result['steps']:
        if 'harness_error' in step:
            steps.append(step)
            continue
        idx = step['i']
        state_norm = 'unobserved'
        if idx in by_step:
            pos, st = by_step[idx]
            # "Carried" = address already seen during the previous request
            # (its startup..shutdown records) - never compared as raw values
            # across sequences.
            start = by_step[idx - 1][0] if idx - 1 in by_step else max(0, pos - 2)
            state_norm = normalize_state(st, states[start:pos])
        asan = step.get('asan')
        # Issue #5-7: no known pid means attribution_unknown, never confirmed.
        attributed = bool(asan and pids and asan.get('pid') in pids)
        unknown = bool(asan and not pids)
        site = '|'.join(step['failure_sites']) or '-'
        outcome = '%s/%s/%s' % (re.sub(r'\d\d$', 'xx', step['response']), site,
                                asan['sig'] if attributed else
                                'HANG' if step.get('hung') else '-')
        if step.get('hung'):
            keys.add('H:%s|%s' % (state_norm, step['a']))
        violations = carried_request_state(state_norm)
        level = ('memory_error_confirmed' if attributed else
                 'attribution_unknown' if unknown else
                 'invariant_violation_candidate' if violations else
                 'state_change_observed' if state_norm not in ('unobserved', 'observer_error')
                 and ('fresh' in state_norm or 'carried' in state_norm) else 'none')
        keys.add('S:' + state_norm)
        keys.add('T:%s|%s|%s' % (state_norm, step['a'], outcome))
        for s in step['failure_sites']:
            keys.add('F:' + s)
        gc = gc_state(end_of.get(idx))
        # _zend_bailout() always sets gc_protect(1): protected at shutdown is
        # expected after a terminating fatal. It is unexpected only when the
        # request ended normally (fused program returned, or no failure).
        ended_normally = bool(step.get('completed')) or not step['failure_sites']
        gc_odd = gc not in ('gc_unobserved', 'gc_normal') and \
            (ended_normally or gc != 'gc_protected')
        if gc_odd:
            keys.add('G:%s|%s' % (step['a'], gc))
        evs = bailouts.get(idx, [])
        bails = [ev for ev in evs if ev['name'] == '_zend_bailout']
        # Memory limit reached while GC protection is set outside shutdown:
        # the cycle collector could not run because a protection was left
        # set (invariant class of tuning case R49, plan 13.3a). A second
        # bailout under protection is NOT used: handlers that catch and
        # re-raise (soap_error_handler) and aborted connections produce it
        # normally (calibration, findings 11.5).
        oom_protected = any(ev['name'] == 'zend_mm_delayed_error' and ev.get('gc_protected')
                            and not ev.get('in_shutdown') for ev in evs)
        if oom_protected:
            keys.add('G:%s|oom_while_gc_protected' % step['a'])
        # Error recovery: a fatal/exception path after which execution went
        # on (caught bailout, handler, delayed OOM). For fused programs the
        # program must also have returned normally: a terminating fatal under
        # HTTP 200 is not recovery (state v1 over-rewarded it, findings 11.6).
        recovered = step['failure_sites'] and step['response'].startswith('s2') \
            and step.get('alive_after') and (step['a'] != 'fused' or step.get('completed'))
        if recovered:
            keys.add('R:%s|%s' % (step['a'], gc))
        if attributed:
            keys.add('A:' + asan['sig'])
            findings.append(dict(sig=asan['sig'], step=idx, summary=asan['summary'],
                                 file=asan['file']))
        steps.append(dict(step, state=state_norm, outcome=outcome, oracle=level,
                          violations=violations, gc_at_shutdown=gc, gc_unexpected=gc_odd,
                          bailouts=len(bails), oom_while_gc_protected=oom_protected))
    return keys, steps, findings


# ------------------------------------------------------------- campaign
def campaign(args):
    rng = random.Random(args.seed)
    prefix = BASE / 'install' / (args.version + ('-cov' if args.cov else '-' + args.flavor))
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    run_id = 'ex-%s-%s-%s-%s-s%d-%d' % (stamp, args.version, args.sapi, args.feedback,
                                        args.seed, os.getpid())
    out_base = Path(args.out) if args.out else BASE / 'evidence' / ('explore-' + run_id)
    out_base.mkdir(parents=True, exist_ok=True)
    execs_log = (out_base / 'execs.jsonl').open('a')
    sched_log = (out_base / 'scheduler.jsonl').open('a')
    exclude = {tuple(p.split('>')) for p in args.exclude_pairs}
    seeds = [json.loads(line) for line in Path(args.seeds).read_text().splitlines()
             if line.strip()] if args.seeds else DEFAULT_SEEDS
    seeds = [s for s in seeds if not (pairs(s) & exclude)]
    corpus, seen_keys, seen_seqs = [], {}, set()
    seen_edges = set()
    # Harness failures (the target never ran) are counted and stop the
    # campaign after MAX_HARNESS_STREAK in a row - a wedged lab must not be
    # reported as an exploration result.
    harness = dict(total=0, streak=0, aborted=False)
    findings = {}
    started = time.time()
    n = 0
    fixed_set = {('parse_oom', 'upload_small'), ('parse_oom', 'upload_nofile'),
                 ('runtime_oom', 'upload_small'), ('runtime_oom', 'upload_nofile')}

    def run_one(seq, parent=None, op=None, origin='generated'):
        nonlocal n
        problems = validate(seq)
        record = dict(exec=n, id=seq_hash(seq), seq=seq, parent=parent, op=op,
                      origin=origin, grammar_ok=not problems, grammar_problems=problems,
                      t=round(time.time() - started, 1))
        if problems:
            execs_log.write(json.dumps(record) + '\n')
            return record
        res = execute(seq, prefix, out_base / ('exec-%04d' % n), args.observer,
                      args.sapi, args.version, args.cov)
        keys, steps, found = observe(res, seq)
        new_edges = [e for e in res.get('edges', ()) if e not in seen_edges]
        seen_edges.update(new_edges)
        if any('harness_error' in st for st in steps):
            harness['total'] += 1
            harness['streak'] += 1
            if harness['streak'] >= MAX_HARNESS_STREAK:
                harness['aborted'] = True
        else:
            harness['streak'] = 0
        new = sorted(k for k in keys if k not in seen_keys)
        for k in new:
            seen_keys[k] = n
        for f in found:
            if f['sig'] not in findings:
                findings[f['sig']] = dict(first_exec=n, first_t=record['t'], seq=seq,
                                          step=f['step'], summary=f['summary'],
                                          evidence=f['file'])
        record.update(integrity=verdicts.integrity(seq, steps, res.get('states'),
                                                   args.observer)['status'],
                      worker_pid=res.get('worker_pid'))
        record.update(steps=steps, new_keys=new, elapsed=res['elapsed'],
                      new_edges=len(new_edges), edges=len(res.get('edges', ())),
                      cov_files=res.get('cov_files', 0),
                      cov_status=(None if not args.cov else
                                  'coverage_valid_no_new_edges'
                                  if res.get('cov_status') == 'coverage_valid' and not new_edges
                                  else res.get('cov_status')),
                      ready_state=res.get('ready_state'),
                      novel_vs_fixed_matrix=not (len(seq['steps']) == 2 and
                                                 tuple(s['a'] for s in seq['steps']) in fixed_set))
        execs_log.write(json.dumps(record) + '\n')
        execs_log.flush()
        n += 1
        return record

    if args.cov:
        # Coverage positive control (issue #5-6): a plain health request must
        # yield valid edges before any code-edge result is reported.
        control = run_one(dict(limit='16M', steps=[{'a': 'health'}]), origin='coverage_control')
        cov_ok = control.get('cov_status') in ('coverage_valid', 'coverage_valid_no_new_edges') \
            and control.get('edges', 0) > 0
        if not cov_ok:
            print(json.dumps(dict(error='coverage positive control failed',
                                  cov_status=control.get('cov_status'),
                                  edges=control.get('edges'))))
            return 3
    # Seeds always run first (both modes) so the budgets compare like for like.
    for seed in seeds:
        rec = run_one(seed, origin='seed')
        if args.feedback in ('on', 'state') and rec.get('grammar_ok'):
            corpus.append(dict(id=rec['id'], seq=seed,
                               new=(feedback_gain('state', rec) if args.feedback == 'state'
                                    else len(rec.get('new_keys', []))
                                    + (1 if rec.get('new_edges') else 0)),
                               picked=0, depth=0))
        seen_seqs.add(seq_key(seed))
    while (n < args.max_execs and time.time() - started < args.budget
           and not harness['aborted']):
        if args.feedback in ('on', 'state') and corpus:
            weights = [(1.0 + e['new']) / (1.0 + e['picked']) ** 0.5 for e in corpus]
            parent = rng.choices(corpus, weights=weights, k=1)[0]
            parent['picked'] += 1
            child, op = mutate(rng, parent['seq'], corpus, args.faults)
            sched_log.write(json.dumps(dict(
                exec=n, parent=parent['id'], parent_depth=parent['depth'], op=op,
                weight=round(weights[corpus.index(parent)], 3),
                corpus_size=len(corpus),
                top=sorted(((round(w, 3), e['id']) for w, e in zip(weights, corpus)),
                           reverse=True)[:3])) + '\n')
            sched_log.flush()
            if child is None or seq_key(child) in seen_seqs:
                continue
            seen_seqs.add(seq_key(child))
            rec = run_one(child, parent=parent['id'], op=op)
            gain = feedback_gain(args.feedback, rec)
            if gain:
                corpus.append(dict(id=rec['id'], seq=child, new=gain,
                                   picked=0, depth=parent['depth'] + 1,
                                   parent=parent['id']))
        else:
            seq = random_sequence(rng, args.faults)
            if seq_key(seq) in seen_seqs:
                continue
            seen_seqs.add(seq_key(seq))
            run_one(seq)
    execs_log.close()
    sched_log.close()
    kinds = {}
    for k in seen_keys:
        kinds[k[0]] = kinds.get(k[0], 0) + 1
    summary = dict(scope='Phase 5 v2 lifecycle explorer (CLI server); observation only',
                   run_id=run_id, version=args.version, flavor=args.flavor,
                   coreguard_mode=os.environ.get('COREGUARD_MODE'),
                   coreguard_log=os.environ.get('COREGUARD_LOG'), feedback=args.feedback,
                   observer=args.observer, sapi=args.sapi, seed=args.seed,
                   budget_s=args.budget,
                   max_execs=args.max_execs, execs=n, wall_s=round(time.time() - started, 1),
                   excluded_pairs=sorted('>'.join(p) for p in exclude),
                   faults=args.faults, opcache=OPCACHE,
                   fused_pool=(dict(dir=str(FUSED_POOL), programs=len(ACTIONS['fused']['p']),
                                    pool_json_sha256=hashlib.sha256(
                                        (FUSED_POOL / 'pool.json').read_bytes()).hexdigest())
                               if FUSED_POOL else None),
                   grammar=dict(actions=len(ACTIONS), max_len=MAX_LEN, limits=len(LIMITS),
                                faults=len(FAULTS) if args.faults else 1,
                                space_size=grammar_space(args.faults)),
                   unique_keys=kinds, corpus_size=len(corpus), cov=args.cov,
                   code_edge_coverage=len(seen_edges),
                   binary_sha256=(hashlib.sha256((prefix / 'bin/php').read_bytes()).hexdigest()
                                  if (prefix / 'bin/php').exists() else None),
                   cov_collection=({k: sum(1 for line in (out_base / 'execs.jsonl').read_text()
                                           .splitlines() if '"cov_status": "%s"' % k in line)
                                    for k in ('coverage_valid', 'coverage_valid_no_new_edges',
                                              'coverage_invalid', 'coverage_not_collected')}
                                   if args.cov else None),
                   harness_errors=harness['total'], aborted=harness['aborted'],
                   findings=findings, time_to_first_valid_finding=(
                       min((f['first_t'] for f in findings.values()), default=None)))
    (out_base / 'corpus.json').write_text(json.dumps(corpus, indent=2))
    (out_base / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('run_id', 'feedback', 'execs', 'wall_s',
                                              'unique_keys', 'corpus_size',
                                              'time_to_first_valid_finding',
                                              'harness_errors', 'aborted')}
                     | {'findings': sorted(findings), 'out': str(out_base)}, indent=2))
    return 3 if harness['aborted'] else 0


def grammar_space(faults=False):
    per_step = sum(math.prod(len(d) for d in params.values()) if params else 1
                   for params in ACTIONS.values())
    return (len(LIMITS) * (len(FAULTS) if faults else 1)
            * sum(per_step ** k for k in range(1, MAX_LEN + 1)))


DEFAULT_SEEDS = [dict(limit='8M', steps=[{'a': 'health'}]),
                 dict(limit='8M', steps=[{'a': 'session'}, {'a': 'upload_cookie'}]),
                 dict(limit='16M', steps=[{'a': 'upload_small'}]),
                 dict(limit='16M', steps=[{'a': 'unser_small'}])]


# -------------------------------------------------------- replay/minimize
def replay(args):
    """Replay a sequence N times, minimize it step-wise while the target
    ASAN signature persists, and run the minimal form on a second version."""
    seq = json.loads(Path(args.replay).read_text())
    target = args.signature
    prefix = BASE / 'install' / (args.version + '-asan')
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('explore-replay-%s-%s' % (stamp, args.version))
    report = dict(seq=seq, signature=target, version=args.version, replays=[], minimize=[])
    counter = [0]

    def run_once(s, version_prefix=prefix):
        """Signatures plus execution integrity (issue #5-1): a run that
        did not reach its steps can never vote for 'extinct'."""
        counter[0] += 1
        res = execute(s, version_prefix, out / ('run-%03d' % counter[0]), args.observer,
                      args.sapi, version_prefix.name.rsplit('-', 1)[0])
        _, steps, found = observe(res, s)
        integ = verdicts.integrity(s, steps, res.get('states'), args.observer)
        return sorted({f['sig'] for f in found}), steps, integ

    def sig_of(s, version_prefix=prefix):
        sigs, _, integ = run_once(s, version_prefix)
        # Minimization only accepts verified executions as votes.
        return sigs if integ['status'] == 'executed' else []

    replay_runs = []
    for _ in range(args.replays):
        sigs, steps, integ = run_once(seq)
        replay_runs.append(dict(sigs=sigs, steps=steps, integrity=integ))
        report['replays'].append(dict(signatures=sigs, integrity=integ['status']))
    stable = all(target in r['sigs'] and r['integrity']['status'] == 'executed'
                 for r in replay_runs)
    report['stable'] = stable
    current = seq
    if stable:
        changed = True
        while changed and len(current['steps']) > 1:
            changed = False
            for i in range(len(current['steps'])):
                cand = dict(current, steps=current['steps'][:i] + current['steps'][i + 1:])
                if validate(cand):
                    continue
                sigs = sig_of(cand)
                report['minimize'].append(dict(removed=i, steps=[s['a'] for s in cand['steps']],
                                               kept_signature=target in sigs))
                if target in sigs:
                    current = cand
                    changed = True
                    break
    report['minimal'] = current
    if args.diff_version:
        # Vulnerable reference run of the minimal form, then the fixed run.
        _, v_steps, v_int = run_once(current)
        dprefix = BASE / 'install' / (args.diff_version + '-asan')
        f_sigs, f_steps, f_int = run_once(current, dprefix)
        verdict = verdicts.differential(target, v_steps, v_int, f_steps, f_int)
        report['differential'] = dict(version=args.diff_version, signatures=f_sigs,
                                      **verdict,
                                      steps=[dict(a=s.get('a'), response=s.get('response'),
                                                  failure_sites=s.get('failure_sites'),
                                                  state=s.get('state'))
                                             for s in f_steps])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'replay.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(stable=stable, replays=report['replays'],
                          minimal=[s['a'] for s in current['steps']],
                          differential=report.get('differential', {}).get('verdict'),
                          extinct=report.get('differential', {}).get('extinct'),
                          out=str(out)), indent=2))
    diff = report.get('differential')
    if diff and diff.get('verdict') == 'harness_failed':
        return 1
    if not stable or (diff and not diff.get('extinct')):
        return 2
    return 0


# -------------------------------------------------------------- self-test
def self_test():
    rng = random.Random(1)
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))

    check('valid sequence passes grammar', not validate(DEFAULT_SEEDS[1]))
    check('unknown action rejected', validate(dict(limit='8M', steps=[{'a': 'rce'}])))
    check('bad param rejected', validate(dict(limit='8M', steps=[{'a': 'runtime_oom', 'mb': 99}])))
    check('too long rejected', validate(dict(limit='8M', steps=[{'a': 'health'}] * 7)))
    check('bad limit rejected', validate(dict(limit='1G', steps=[{'a': 'health'}])))
    kids = [mutate(rng, DEFAULT_SEEDS[1], [dict(seq=s) for s in DEFAULT_SEEDS])[0]
            for _ in range(50)]
    check('mutations are valid and differ from parent',
          all(k and not validate(k) and seq_key(k) != seq_key(DEFAULT_SEEDS[1]) for k in kids))
    prev = [dict(ser_data=0, unser_data=140000, ps_id=0, ps_mod=0, ps_session_vars=0)]
    st = dict(ser_level=0, ser_data=0, unser_level=1, unser_data=140000, lock=0, ps_id=0,
              ps_mod=0, ps_status=1, ps_vars_type=0, ps_session_vars=0, url_hosts=0,
              modules_activated=0)
    norm = normalize_state(st, prev)
    check('carried pointer normalized without address', 'unser_data=carried' in norm
          and '140000' not in norm)
    check('carried request state is an invariant candidate',
          set(carried_request_state(norm)) == {'unser_level>0', 'unser_data carried'})
    check('clean state has no violation',
          not carried_request_state(normalize_state(dict(st, unser_level=0, unser_data=0), prev)))
    sites = failure_sites('[x] PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted '
                          'at file:0 (tried to allocate 3149568 bytes) in Unknown on line 0')
    check('failure site normalized', sites == ['oom:2^21@Unknown:0'])
    inj = failure_sites('[x] PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted '
                        'at /src/Zend/zend_hash.c:281 (tried to allocate 56 bytes) in '
                        '/web/index.php on line 31', injected=True)
    check('injected site keeps C location', inj == ['inj:oom:2^5@index.php:31<zend_hash.c:281'])
    check('fault knob validated', validate(dict(limit='8M', fault=7, steps=[{'a': 'health'}]))
          and not validate(dict(limit='8M', fault=30, steps=[{'a': 'health'}])))
    check('grammar space is not enumerable within a budget', grammar_space() > 10 ** 6)
    check('fused action rejected without a pool',
          bool(validate(dict(limit='8M', steps=[{'a': 'fused', 'p': 0}]))))
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        blob = SANCOV_MAGIC64.to_bytes(8, 'little') + b''.join(
            x.to_bytes(8, 'little') for x in (0x1000, 0x2040, 0x1000))
        (Path(tmp) / 'php.123.sancov').write_bytes(blob)
        (Path(tmp) / 'php.9.sancov').write_bytes(b'garbage!')
        pcs, nfiles, _ = read_sancov(tmp)
    check('sancov parsed, bad magic ignored', pcs == {0x1000, 0x2040} and nfiles == 1)
    with tempfile.TemporaryDirectory() as tmp:
        check('sancov missing -> coverage_not_collected',
              read_sancov(Path(tmp) / 'none')[2] == 'coverage_not_collected')
        (Path(tmp) / 'php.1.sancov').write_bytes(b'')
        (Path(tmp) / 'php.2.sancov').write_bytes(b'notmagic' * 3)
        check('sancov zero-byte and bad magic -> coverage_invalid',
              read_sancov(tmp)[2] == 'coverage_invalid')
        (Path(tmp) / 'php.3.sancov').write_bytes(blob)
        check('sancov one valid file -> coverage_valid',
              read_sancov(tmp)[1:] == (1, 'coverage_valid'))
    check('readiness: 500 without fault is unhealthy', readiness_state(500, 0) == 'unhealthy')
    check('readiness: 500 with armed fault is fault_expected',
          readiness_state(500, 30) == 'fault_expected')
    _, steps_u, found_u = observe(dict(steps=[dict(i=0, a='health', response='no_status',
                                                   failure_sites=[], alive_after=False,
                                                   asan=dict(sig='x:y', pid=4242, summary='', file='f'))],
                                       states=[]), dict(steps=[{'a': 'health'}]))
    check('ASAN without known pid -> attribution_unknown, no finding',
          steps_u[0]['oracle'] == 'attribution_unknown' and not found_u)
    _, steps_k, found_k = observe(dict(steps=[dict(i=0, a='health', response='no_status',
                                                   failure_sites=[], alive_after=False,
                                                   asan=dict(sig='x:y', pid=4242, summary='', file='f'))],
                                       states=[], worker_pid=4242), dict(steps=[{'a': 'health'}]))
    check('ASAN with matching pid -> confirmed',
          steps_k[0]['oracle'] == 'memory_error_confirmed' and found_k)
    _, steps_o, found_o = observe(dict(steps=[dict(i=0, a='health', response='no_status',
                                                   failure_sites=[], alive_after=False,
                                                   asan=dict(sig='x:y', pid=1, summary='', file='f'))],
                                       states=[], worker_pid=4242), dict(steps=[{'a': 'health'}]))
    check('ASAN of another pid -> not confirmed', not found_o)
    check('gc state: normal / protected / unobserved',
          gc_state(dict(gc_enabled=1, gc_active=0, gc_protected=0)) == 'gc_normal'
          and gc_state(dict(gc_enabled=1, gc_active=0, gc_protected=1)) == 'gc_protected'
          and gc_state(dict(ser_level=0)) == 'gc_unobserved')
    keys_g, steps_g, _ = observe(dict(steps=[dict(i=0, a='fused', p=1, response='s200',
                                                  failure_sites=['x@f:1'], alive_after=True,
                                                  completed=True,
                                                  asan=None)],
                                      states=[dict(tag='shutdown', uri='/fused?p=1&step=0',
                                                   gc_enabled=1, gc_active=0, gc_protected=1)],
                                      worker_pid=1), dict(steps=[{'a': 'fused', 'p': 1}]))
    keys_b, _, _ = observe(dict(steps=[dict(i=0, a='parse_oom', response='s500',
                                            failure_sites=['oom@x:1'], alive_after=True,
                                            asan=None)],
                                states=[dict(tag='shutdown', uri='/x?step=0', gc_enabled=1,
                                             gc_active=0, gc_protected=1)], worker_pid=1),
                           dict(steps=[{'a': 'parse_oom'}]))
    check('protected GC after a terminating fatal is expected (no G key)',
          not any(k.startswith('G:') for k in keys_b))
    keys_r, steps_r, _ = observe(dict(steps=[dict(i=0, a='fused', response='s200',
                                                  failure_sites=['a@f:1', 'oom@f:2'],
                                                  alive_after=True, asan=None, completed=False)],
                                      states=[], worker_pid=1,
                                      events=[dict(name='_zend_bailout', uri='/fused?p=0&step=0',
                                                   gc_protected=0, in_shutdown=0),
                                              dict(name='zend_mm_delayed_error',
                                                   uri='/fused?p=0&step=0',
                                                   gc_protected=1, in_shutdown=0),
                                              dict(name='_zend_bailout', uri='/fused?p=0&step=0',
                                                   gc_protected=1, in_shutdown=0)]),
                                 dict(steps=[{'a': 'fused', 'p': 0}]))
    check('OOM under GC protection -> G oom_while_gc_protected',
          'G:fused|oom_while_gc_protected' in keys_r and steps_r[0]['bailouts'] == 2)
    keys_s, _, _ = observe(dict(steps=[dict(i=0, a='upload', response='s200',
                                            failure_sites=['oom@x:1'], alive_after=True,
                                            asan=None)], states=[], worker_pid=1,
                                events=[dict(name='_zend_bailout', uri='/upload?step=0',
                                             gc_protected=0, in_shutdown=0),
                                        dict(name='_zend_bailout', uri='/upload?step=0',
                                             gc_protected=1, in_shutdown=0)]),
                           dict(steps=[{'a': 'upload'}]))
    check('re-raised bailout under protection alone -> no G key',
          not any(k.startswith('G:') for k in keys_s))
    check('protected GC at shutdown -> G and R keys',
          'G:fused|gc_protected' in keys_g and 'R:fused|gc_protected' in keys_g
          and steps_g[0]['gc_at_shutdown'] == 'gc_protected')
    keys_t, _, _ = observe(dict(steps=[dict(i=0, a='fused', response='s200',
                                            failure_sites=['x@f:1'], alive_after=True,
                                            asan=None, completed=False)],
                                states=[], worker_pid=1), dict(steps=[{'a': 'fused', 'p': 0}]))
    check('terminating fatal under 200 in a fused program -> no R key',
          not any(k.startswith('R:') for k in keys_t))
    check('state gain weights G/R over T',
          feedback_gain('state', dict(new_keys=['G:x', 'T:y'])) == 5
          and feedback_gain('state', dict(new_keys=['S:ps_id=carried'])) == 3)
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--feedback', choices=('on', 'off', 'state'), default='on',
                        help="on = v2 key+edge gain; state = plan 13.3a redesign "
                             "(GC state, error recovery, carried ownership weighted)")
    parser.add_argument('--observer', choices=('gdb', 'none'), default='gdb')
    parser.add_argument('--sapi', choices=('cli', 'apache', 'fpm'), default='cli',
                        help='G5: worker model; apache/fpm use the fast observer only')
    parser.add_argument('--budget', type=float, default=600, help='seconds')
    parser.add_argument('--max-execs', type=int, default=10 ** 6)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--fused-pool', help='#4 H2.5: FlowFusion pool dir (fused action, CLI)')
    parser.add_argument('--opcache', action='store_true',
                        help='load the shared opcache zend_extension (asanext flavor)')
    parser.add_argument('--flavor', default='asan', help='build flavor (asan, asanext)')
    parser.add_argument('--cov', action='store_true',
                        help='Stage 1c: <version>-cov build, SanitizerCoverage edge feedback (CLI)')
    parser.add_argument('--faults', action='store_true',
                        help='Stage 2: allow ZEND_MM_MAX_ALLOCS per sequence (8.4.27+)')
    parser.add_argument('--seeds', help='JSONL of seed sequences (default: benign seeds)')
    parser.add_argument('--exclude-pairs', nargs='*', default=[],
                        help='hold-out: drop seeds containing these consecutive pairs, '
                             'e.g. parse_oom>upload_nofile')
    parser.add_argument('--out')
    parser.add_argument('--replay', help='sequence JSON to replay/minimize')
    parser.add_argument('--signature', help='target ASAN signature for --replay')
    parser.add_argument('--replays', type=int, default=2)
    parser.add_argument('--diff-version', help='second version for the differential')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.sapi != 'cli':
        args.observer = 'none'
        args.cov = False
    if getattr(args, 'fused_pool', None):
        if args.sapi != 'cli':
            parser.error('--fused-pool needs --sapi cli')
        enable_fused(args.fused_pool)
    global OPCACHE
    OPCACHE = bool(getattr(args, 'opcache', False))
    if args.replay:
        return replay(args)
    return campaign(args)


if __name__ == '__main__':
    sys.exit(main())
