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

SAPI scope: CLI built-in server only (G5 extends to mod_php/FPM).
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

REPO = HERE.parent
BASE = Path('/home/phplab/php-lab')
PORT = 18090
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
LIMITS = ('8M', '16M')
POST_MAX_MB = 64


def validate(seq):
    """Grammar check run before every execution (G1 evidence)."""
    problems = []
    if seq.get('limit') not in LIMITS:
        problems.append('limit %r not in %s' % (seq.get('limit'), LIMITS))
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


def random_sequence(rng):
    return dict(limit=rng.choice(LIMITS),
                steps=[make_step(rng) for _ in range(rng.randint(1, MAX_LEN))])


def seq_key(seq):
    return json.dumps(seq, sort_keys=True)


def seq_hash(seq):
    return hashlib.sha1(seq_key(seq).encode()).hexdigest()[:12]


def pairs(seq):
    acts = [s['a'] for s in seq['steps']]
    return set(zip(acts, acts[1:]))


def mutate(rng, parent, corpus):
    child = json.loads(json.dumps(parent))
    steps = child['steps']
    ops = ['insert', 'replace', 'param', 'swap', 'delete', 'duplicate', 'splice', 'limit']
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
        print('STATE ' + json.dumps(out))
        sys.stdout.flush()
        return False

StateBP('php_request_startup', 'startup')
StateBP('php_request_shutdown', 'shutdown')
end
file {php}
set args -c {ini} -S 127.0.0.1:{port} -t {docroot} {router}
run
'''

FATAL_RE = re.compile(r'PHP (Fatal error|Warning|Notice|Parse error):\s+(.*?)(?: in (\S+) on line (\d+))?$')
TRIED_RE = re.compile(r'Allowed memory size of \d+ bytes exhausted(?: at \S+)? '
                      r'\(tried to allocate (\d+) bytes\)')
POINTER_FIELDS = ('ser_data', 'unser_data', 'ps_id', 'ps_mod', 'ps_session_vars')


def failure_sites(text):
    """Normalized failure-site ids from a php-error.log delta."""
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
        sites.append('%s@%s' % (kind, where))
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
    def __init__(self, prefix, out, limit, observer):
        self.out, self.observer = out, observer
        for name in ('sessions', 'uploads'):
            (out / name).mkdir(parents=True, exist_ok=True)
        ini = (REPO / 'config/php.ini').read_text() + '\n'
        ini += ('session.upload_progress.min_freq=0\n'
                'memory_limit=%s\npost_max_size=%dM\n'
                'session.save_path=%s\nupload_tmp_dir=%s\nerror_log=%s\n'
                % (limit, POST_MAX_MB, out / 'sessions', out / 'uploads',
                   out / 'php-error.log'))
        (out / 'php.ini').write_text(ini)
        php = prefix / 'bin/php'
        self.env = os.environ.copy()
        self.env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:'
                        'log_path=%s/asan' % out,
                        ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer',
                        USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
        if observer == 'gdb':
            (out / 'gdb.cmd').write_text(GDB_TEMPLATE.format(
                asan=out, php=php, ini=out / 'php.ini', port=PORT,
                docroot=REPO / 'web', router=REPO / 'web/index.php'))
            self.cmd = ['gdb', '-q', '-batch', '-x', str(out / 'gdb.cmd')]
        else:
            self.cmd = [str(php), '-c', str(out / 'php.ini'), '-S', '127.0.0.1:%d' % PORT,
                        '-t', str(REPO / 'web'), str(REPO / 'web/index.php')]
        self.proc = None

    def start(self):
        free_port()
        self.log = (self.out / 'observer.log').open('w')
        self.proc = subprocess.Popen(self.cmd, env=self.env, stdout=self.log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('server/observer exited during startup')
            try:
                with urllib.request.urlopen('http://127.0.0.1:%d/health?step=ready' % PORT,
                                            timeout=3) as res:
                    if json.load(res).get('ok'):
                        return
            except Exception:
                time.sleep(0.3)
        raise RuntimeError('startup timeout')

    def stop(self):
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


HANG_GRACE = 12.0


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
        if action == 'health':
            with ctx['opener'].open('http://127.0.0.1:%d%s' % (PORT, path_q('/health')),
                                    timeout=10) as res:
                return 's%d' % res.status
        if action == 'session':
            with ctx['opener'].open('http://127.0.0.1:%d%s' % (PORT, path_q('/session')),
                                    timeout=10) as res:
                return 's%d' % res.status
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


def execute(seq, prefix, out, observer):
    """Run one sequence in one fresh process; return per-step observations."""
    out.mkdir(parents=True, exist_ok=True)
    ctx = dict(sid_big='exbig' + secrets.token_hex(6), sid_small='exsmall' + secrets.token_hex(6))
    proc = Process(prefix, out, seq['limit'], observer)
    big = 'A' * (3 * 1024 * 1024)
    (out / 'sessions' / ('sess_' + ctx['sid_big'])).write_text('big|s:%d:"%s";' % (len(big), big))
    (out / 'sessions' / ('sess_' + ctx['sid_small'])).write_text('small|a:1:{i:0;i:7;}')
    ctx['jar'] = http.cookiejar.CookieJar()
    ctx['opener'] = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(ctx['jar']))
    error_log = out / 'php-error.log'
    steps = []
    started = time.time()
    try:
        proc.start()
        server_pid = None
        for idx, step in enumerate(seq['steps']):
            before_log = error_log.stat().st_size if error_log.exists() else 0
            before_asan = {p.name for p in out.glob('asan.*')}
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
                for path in sorted(out.glob('asan.*')):
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
                    for path in sorted(out.glob('asan.*')):
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
                              failure_sites=failure_sites(log_text), asan=asan,
                              alive_after=alive, hung=hung, ended_by_probe=probed))
            if not alive or probed:
                break
    except Exception as exc:
        steps.append(dict(harness_error=str(exc)))
    finally:
        proc.stop()
    states = []
    if observer == 'gdb' and (out / 'observer.log').exists():
        for line in (out / 'observer.log').read_text(errors='replace').splitlines():
            if line.startswith('STATE '):
                try:
                    states.append(json.loads(line[6:]))
                except ValueError:
                    pass
    return dict(steps=steps, states=states, elapsed=round(time.time() - started, 2))


# ------------------------------------------------------------ observation
def observe(result, seq):
    """Derive per-step normalized state, outcome and feedback keys."""
    states = result['states']
    by_step = {}
    for i, st in enumerate(states):
        match = re.search(r'[?&]step=(\d+)', st.get('uri') or '')
        if match and st.get('tag') == 'startup':
            by_step.setdefault(int(match.group(1)), (i, st))
    pids = {st.get('pid') for st in states if st.get('pid')}
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
        attributed = bool(asan and (not pids or asan.get('pid') in pids))
        site = '|'.join(step['failure_sites']) or '-'
        outcome = '%s/%s/%s' % (re.sub(r'\d\d$', 'xx', step['response']), site,
                                asan['sig'] if attributed else
                                'HANG' if step.get('hung') else '-')
        if step.get('hung'):
            keys.add('H:%s|%s' % (state_norm, step['a']))
        violations = carried_request_state(state_norm)
        level = ('memory_error_confirmed' if attributed else
                 'invariant_violation_candidate' if violations else
                 'state_change_observed' if state_norm not in ('unobserved', 'observer_error')
                 and ('fresh' in state_norm or 'carried' in state_norm) else 'none')
        keys.add('S:' + state_norm)
        keys.add('T:%s|%s|%s' % (state_norm, step['a'], outcome))
        for s in step['failure_sites']:
            keys.add('F:' + s)
        if attributed:
            keys.add('A:' + asan['sig'])
            findings.append(dict(sig=asan['sig'], step=idx, summary=asan['summary'],
                                 file=asan['file']))
        steps.append(dict(step, state=state_norm, outcome=outcome, oracle=level,
                          violations=violations))
    return keys, steps, findings


# ------------------------------------------------------------- campaign
def campaign(args):
    rng = random.Random(args.seed)
    prefix = BASE / 'install' / (args.version + '-asan')
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    run_id = 'ex-%s-%s-%s-s%d-%d' % (stamp, args.version, args.feedback, args.seed, os.getpid())
    out_base = Path(args.out) if args.out else BASE / 'evidence' / ('explore-' + run_id)
    out_base.mkdir(parents=True, exist_ok=True)
    execs_log = (out_base / 'execs.jsonl').open('a')
    sched_log = (out_base / 'scheduler.jsonl').open('a')
    exclude = {tuple(p.split('>')) for p in args.exclude_pairs}
    seeds = [json.loads(line) for line in Path(args.seeds).read_text().splitlines()
             if line.strip()] if args.seeds else DEFAULT_SEEDS
    seeds = [s for s in seeds if not (pairs(s) & exclude)]
    corpus, seen_keys, seen_seqs = [], {}, set()
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
        res = execute(seq, prefix, out_base / ('exec-%04d' % n), args.observer)
        keys, steps, found = observe(res, seq)
        new = sorted(k for k in keys if k not in seen_keys)
        for k in new:
            seen_keys[k] = n
        for f in found:
            if f['sig'] not in findings:
                findings[f['sig']] = dict(first_exec=n, first_t=record['t'], seq=seq,
                                          step=f['step'], summary=f['summary'],
                                          evidence=f['file'])
        record.update(steps=steps, new_keys=new, elapsed=res['elapsed'],
                      novel_vs_fixed_matrix=not (len(seq['steps']) == 2 and
                                                 tuple(s['a'] for s in seq['steps']) in fixed_set))
        execs_log.write(json.dumps(record) + '\n')
        execs_log.flush()
        n += 1
        return record

    # Seeds always run first (both modes) so the budgets compare like for like.
    for seed in seeds:
        rec = run_one(seed, origin='seed')
        if args.feedback == 'on' and rec.get('grammar_ok'):
            corpus.append(dict(id=rec['id'], seq=seed, new=len(rec.get('new_keys', [])),
                               picked=0, depth=0))
        seen_seqs.add(seq_key(seed))
    while n < args.max_execs and time.time() - started < args.budget:
        if args.feedback == 'on' and corpus:
            weights = [(1.0 + e['new']) / (1.0 + e['picked']) ** 0.5 for e in corpus]
            parent = rng.choices(corpus, weights=weights, k=1)[0]
            parent['picked'] += 1
            child, op = mutate(rng, parent['seq'], corpus)
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
            if rec.get('new_keys'):
                corpus.append(dict(id=rec['id'], seq=child, new=len(rec['new_keys']),
                                   picked=0, depth=parent['depth'] + 1,
                                   parent=parent['id']))
        else:
            seq = random_sequence(rng)
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
                   run_id=run_id, version=args.version, feedback=args.feedback,
                   observer=args.observer, seed=args.seed, budget_s=args.budget,
                   max_execs=args.max_execs, execs=n, wall_s=round(time.time() - started, 1),
                   excluded_pairs=sorted('>'.join(p) for p in exclude),
                   grammar=dict(actions=len(ACTIONS), max_len=MAX_LEN, limits=len(LIMITS),
                                space_size=grammar_space()),
                   unique_keys=kinds, corpus_size=len(corpus),
                   findings=findings, time_to_first_valid_finding=(
                       min((f['first_t'] for f in findings.values()), default=None)))
    (out_base / 'corpus.json').write_text(json.dumps(corpus, indent=2))
    (out_base / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('run_id', 'feedback', 'execs', 'wall_s',
                                              'unique_keys', 'corpus_size',
                                              'time_to_first_valid_finding')}
                     | {'findings': sorted(findings), 'out': str(out_base)}, indent=2))
    return 0


def grammar_space():
    per_step = sum(math.prod(len(d) for d in params.values()) if params else 1
                   for params in ACTIONS.values())
    return len(LIMITS) * sum(per_step ** k for k in range(1, MAX_LEN + 1))


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

    def sig_of(s, version_prefix=prefix):
        counter[0] += 1
        res = execute(s, version_prefix, out / ('run-%03d' % counter[0]), args.observer)
        _, steps, found = observe(res, s)
        return sorted({f['sig'] for f in found}), steps

    for _ in range(args.replays):
        sigs, _ = sig_of(seq)
        report['replays'].append(sigs)
    stable = all(target in r for r in report['replays'])
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
                sigs, _ = sig_of(cand)
                report['minimize'].append(dict(removed=i, steps=[s['a'] for s in cand['steps']],
                                               kept_signature=target in sigs))
                if target in sigs:
                    current = cand
                    changed = True
                    break
    report['minimal'] = current
    if args.diff_version:
        dprefix = BASE / 'install' / (args.diff_version + '-asan')
        sigs, steps = sig_of(current, dprefix)
        report['differential'] = dict(version=args.diff_version, signatures=sigs,
                                      extinct=target not in sigs,
                                      steps=[dict(a=s.get('a'), response=s.get('response'),
                                                  failure_sites=s.get('failure_sites'),
                                                  state=s.get('state'))
                                             for s in steps])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'replay.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(stable=stable, replays=report['replays'],
                          minimal=[s['a'] for s in current['steps']],
                          differential=report.get('differential', {}).get('extinct'),
                          out=str(out)), indent=2))
    return 0 if stable else 2


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
    check('grammar space is not enumerable within a budget', grammar_space() > 10 ** 6)
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', default='8.4.4')
    parser.add_argument('--feedback', choices=('on', 'off'), default='on')
    parser.add_argument('--observer', choices=('gdb', 'none'), default='gdb')
    parser.add_argument('--budget', type=float, default=600, help='seconds')
    parser.add_argument('--max-execs', type=int, default=10 ** 6)
    parser.add_argument('--seed', type=int, default=1)
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
    if args.replay:
        return replay(args)
    return campaign(args)


if __name__ == '__main__':
    sys.exit(main())
