#!/usr/bin/env python3
"""#3 CoreGuard Phase 2 analysis: allocation-failure sweep on the official
fixed build (B = 8.4.27-asanext).

Question (plan §13.5 Phase 2): after 8.4.27's fallible allocation + delayed
soft OOM, do count-before-init / partial-initialization paths still reach a
memory error when an allocation fails? Failure injection: ZEND_MM_MAX_ALLOCS=N
(8.4.27 tracked allocator, armed at the end of request startup): the N-th
allocation fails - fallible callers get NULL, the others get memory and a
pending delayed OOM (zend_alloc.c tracked_max_allocs_error).

Workloads are synthetic, one per data-structure family on the request
surface (never hold-out or tuning reproducers). For each workload N sweeps
1..--dense one by one, then with --stride up to the first N at which the
script completes without hitting the limit.

Per run: ok (completed, limit not hit) / oom (delayed OOM fatal, no memory
error) / memory_error (ASAN report, zend_mm_panic, fatal signal) / hang
(timeout) / other. Memory-error signatures are grouped; any signature is
treated as a potential new finding under plan §11.2 D1: details stay in the
local evidence tree, reports carry counts and the workload name only.

Usage: phase2-fault-sweep.py [--build 8.4.27-asanext] [--dense 300]
                             [--stride 7] [--max-n 6000] [--jobs 4]
"""
import argparse
import collections
import concurrent.futures as cf
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
END = '__SWEEP_END__'
WORKLOADS = {
    'unserialize_nested': r'''
$p = serialize(['a' => [1, 2, [3, 'x' => str_repeat('s', 40)]], 'o' => (object)['k' => [1, 2, 3]],
                'r' => [str_repeat('t', 300), 1.5, true, null]]);
for ($i = 0; $i < 3; $i++) { $v = unserialize($p); }
var_dump(count($v));
''',
    'unserialize_refs': r'''
$a = [1, 2]; $a[] = &$a[0]; $o = new stdClass; $o->self = $o; $o->list = [$o, $o];
$p = serialize([$a, $o, $o]);
$v = unserialize($p); var_dump(is_array($v));
''',
    'session_codec': r'''
session_save_path(sys_get_temp_dir()); session_id('sweep' . getmypid());
@session_start();
$_SESSION['a'] = ['x' => str_repeat('q', 64), 'n' => [1, 2, 3]]; $_SESSION['o'] = new ArrayObject([1, 2]);
$enc = session_encode(); session_decode($enc); session_decode($enc);
var_dump(isset($_SESSION['a'])); session_write_close();
''',
    'array_ops': r'''
$a = range(1, 200); $b = array_fill(0, 150, 'v');
$c = array_merge($a, $b); $d = array_combine(range(0, 349), $c);
$e = array_map(fn($x) => [$x], array_slice($d, 0, 100));
$f = explode(',', implode(',', $a)); ksort($d); array_splice($c, 10, 20, $b);
var_dump(count($e) + count($f));
''',
    'string_ops': r'''
$s = str_repeat('abc', 500); $t = str_replace('b', 'BB', $s); $u = strtoupper($t);
$parts = str_split($u, 7); $j = implode('|', $parts); $w = wordwrap($j, 30, "\n", true);
$x = sprintf('%s-%d-%05.2f', $w, 42, 3.14159); var_dump(strlen($x) > 0);
''',
    'json_codec': r'''
$d = ['k' => range(1, 50), 'o' => ['x' => ['y' => ['z' => str_repeat('j', 80)]]], 's' => "\u{1F600}"];
$j = json_encode($d); $back = json_decode($j, true); $obj = json_decode($j);
var_dump(count($back['k']));
''',
    'objects_dtor': r'''
class D { public $p; function __construct($n) { $this->p = array_fill(0, $n, $n); }
          function __destruct() { $this->p = null; } }
$keep = []; for ($i = 0; $i < 60; $i++) { $keep[] = new D($i % 7); if ($i % 3 == 0) array_shift($keep); }
$keep = null; var_dump(gc_collect_cycles() >= 0);
''',
    'simplexml_dom': r'''
$x = '<r>' . str_repeat('<i a="1">t</i>', 40) . '<n><m>v</m></n></r>';
$s = simplexml_load_string($x); $c = 0; foreach ($s->i as $i) { $c += (int)$i['a']; }
$d = new DOMDocument(); $d->loadXML($x); $l = $d->getElementsByTagName('i');
var_dump($c + $l->length);
''',
    'mbstring': r'''
$s = str_repeat("한글abc", 100); $u = mb_strtoupper($s); $p = mb_substr($u, 3, 200);
$e = mb_convert_encoding($p, 'UTF-16', 'UTF-8'); $b = mb_convert_encoding($e, 'UTF-8', 'UTF-16');
var_dump(mb_strlen($b));
''',
    'var_export_closure': r'''
$f = function ($x) use (&$f) { return $x > 0 ? [$x, $f($x - 1)] : []; };
$r = $f(30); $e = var_export($r, true); $g = fn() => $e; var_dump(strlen($g()) > 0);
''',
}


def run_one(php, code, n, tmpdir, timeout=30):
    script = Path(tmpdir) / 'w.php'
    if not script.exists():
        script.write_text('<?php\n' + code + "\necho '%s';\n" % END)
    asan_dir = Path(tmpdir) / ('asan-%d' % n)
    asan_dir.mkdir()
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1',
               ZEND_MM_MAX_ALLOCS=str(n),
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/a' % asan_dir,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer')
    args = [str(php), '-n', '-d', 'memory_limit=256M', '-d', 'sys_temp_dir=%s' % tmpdir,
            '-d', 'disable_functions=exec,shell_exec,system,passthru,proc_open,popen',
            str(script)]
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                             cwd=tmpdir, env=env)
    except subprocess.TimeoutExpired:
        return dict(n=n, kind='hang')
    out = res.stdout + res.stderr
    sig = None
    for p in asan_dir.glob('a.*'):
        t = p.read_text(errors='replace')
        if 'AddressSanitizer' in t:
            kind = re.search(r'AddressSanitizer: ([\w-]+)', t)
            frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', t)[:4]
            sig = '%s:%s' % (kind.group(1) if kind else '?', '>'.join(frames))
            (Path(tmpdir).parent / ('asan-n%d.txt' % n)).write_text(t[:20000])
            break
    if sig or 'zend_mm_panic' in out or 'zend_mm_heap corrupted' in out \
            or res.returncode < 0 or res.returncode in (134, 139):
        return dict(n=n, kind='memory_error', rc=res.returncode,
                    sig=sig or ('zend_mm_panic' if 'zend_mm' in out else 'signal:%d' % res.returncode))
    if 'Allowed memory size' in out:
        return dict(n=n, kind='oom', rc=res.returncode)
    if END in res.stdout and res.returncode == 0:
        return dict(n=n, kind='ok')
    return dict(n=n, kind='other', rc=res.returncode, tail=out[-200:])


def sweep(name, code, php, args, out):
    wdir = out / name
    wdir.mkdir()
    rows = []
    ns = list(range(1, args.dense + 1))
    with tempfile.TemporaryDirectory(dir=wdir) as tmp:
        i, n, ok_streak = 0, 1, 0
        while n <= args.max_n:
            with tempfile.TemporaryDirectory(dir=tmp) as t:
                r = run_one(php, code, n, t)
            rows.append(r)
            # a fallible failure can also be handled cleanly ("ok"): stop only
            # after the dense range and --ok-streak consecutive clean completions
            ok_streak = ok_streak + 1 if r['kind'] == 'ok' else 0
            if ok_streak >= args.ok_streak and i >= len(ns) - 1:
                break
            i += 1
            n = ns[i] if i < len(ns) else n + args.stride
    kinds = collections.Counter(r['kind'] for r in rows)
    sigs = collections.Counter(r['sig'] for r in rows if r['kind'] == 'memory_error')
    (wdir / 'runs.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    first_ok = next((r['n'] for r in rows if r['kind'] == 'ok'), None)
    return dict(workload=name, runs=len(rows), first_ok_n=first_ok, completed_at_n=rows[-1]['n'] if rows and
                rows[-1]['kind'] == 'ok' else None, kinds=dict(kinds),
                memory_error_signatures=len(sigs), signature_counts=dict(sigs))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--build', default='8.4.27-asanext')
    parser.add_argument('--dense', type=int, default=300)
    parser.add_argument('--stride', type=int, default=7)
    parser.add_argument('--max-n', type=int, default=6000)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--ok-streak', type=int, default=25,
                        help='clean completions in a row that end a workload sweep')
    parser.add_argument('--workloads', nargs='*')
    args = parser.parse_args()
    php = BASE / 'install' / args.build / 'bin/php'
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    out = BASE / 'evidence' / ('coreguard-p2-sweep-%s-%s' % (stamp, args.build))
    out.mkdir(parents=True)
    names = args.workloads or list(WORKLOADS)
    # control: without injection every workload must complete
    controls = {}
    for name in names:
        with tempfile.TemporaryDirectory(dir=out) as t:
            r = run_one(php, WORKLOADS[name], 0, t)
        controls[name] = r['kind']
    bad = [k for k, v in controls.items() if v != 'ok']
    if bad:
        print(json.dumps(dict(error='control run failed (no injection)', workloads=bad,
                              controls=controls)))
        return 3
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        results = list(ex.map(lambda nm: sweep(nm, WORKLOADS[nm], php, args, out), names))
    summary = dict(scope='CoreGuard Phase 2 allocation-failure sweep (analysis; D1 for signatures)',
                   build=args.build, dense=args.dense, stride=args.stride, max_n=args.max_n,
                   ok_streak=args.ok_streak,
                   controls=controls, results=results, **provenance.provenance())
    (out / 'summary.json').write_text(json.dumps(summary, indent=2))
    for r in results:
        print('%-20s runs=%-5d complete_at=%-6s %s mem_sigs=%d' % (
            r['workload'], r['runs'], r['completed_at_n'], r['kinds'], r['memory_error_signatures']))
    print('out=%s citable=%s' % (out, summary['citable']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
