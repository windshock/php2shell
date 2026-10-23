#!/usr/bin/env python3
"""#4 H2.5: class-targeted PHP program grammar for the lifecycle explorer.

H3 (findings §11.7) showed that fused php-src tests never reach the hold-out
failure classes: the generator, not the signal, was the limit. This grammar
composes programs from building blocks taken from the failure-class
definitions of docs/coreguard/phase0-baseline.md §2, never from a hold-out
reproducer:
  bailout sources that a zend_try site catches (extension errors, compile
  errors), recovery (try/catch, error handlers), GC observation (cycles,
  gc_collect_cycles, gc_status), containers cleaned while user destructors
  run (unset, reassignment, array_splice, session_unset, ArrayObject),
  destructor behaviours (fatal, exception, container mutation, nested GC,
  serialize of the container), PHP 8.4 object-lifecycle API (lazy ghosts and
  proxies, reset), and generated serialization payloads (nested arrays,
  objects, references) fed to unserialize / session_decode.
Knowledge caveat: the author of these blocks knows the hold-out mechanisms;
a rediscovery with this grammar is weak evidence (reported as such).

Every program is deterministic for (seed, index), wraps each risky block in
try/catch, and ends with an echo. Output: a pool directory in the format of
linux/fused-pool.py (prog-NNNN.php, router.php, pool.json) so the explorer's
`fused` action runs it unchanged.

Usage: payload-grammar.py --out DIR [--count 300] [--seed 1] | --self-test
"""
import argparse
import importlib.util
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402

PRELUDE = r'''<?php
class GNode { public $peer; public $data; }
class GDtor {
    public static $mode = 'quiet';
    public static $box = null;
    public $id;
    function __construct($id) { $this->id = $id; }
    function __destruct() {
        switch (self::$mode) {
            case 'fatal': trigger_error("dtor {$this->id}", E_USER_ERROR); break;
            case 'throw': throw new RuntimeException("dtor {$this->id}");
            case 'mutate': if (is_array(self::$box)) { self::$box[] = new GNode; array_shift(self::$box); } break;
            case 'gc': gc_collect_cycles(); break;
            case 'serialize': @serialize(self::$box); break;
            case 'session': if (session_status() === PHP_SESSION_ACTIVE) { @session_encode(); } break;
        }
    }
}
function g_cycles($n) { for ($i = 0; $i < $n; $i++) { $a = new GNode; $b = new GNode; $a->peer = $b; $b->peer = $a; } }
function g_gc() { $r = gc_collect_cycles(); $s = gc_status(); echo "gc ", $r, " ", (int) $s['protected'], " ", $s['runs'], "\n"; }
'''


def payload(rng, depth=0):
    """A generated serialization payload (valid PHP serialize syntax)."""
    kind = rng.choice(['i', 's', 'b', 'd', 'N', 'a', 'a', 'O', 'r'] if depth < 3 else ['i', 's', 'N'])
    if kind == 'i':
        return 'i:%d;' % rng.randint(-5, 10 ** 6)
    if kind == 's':
        s = 'x' * rng.choice([0, 1, 7, 64])
        return 's:%d:"%s";' % (len(s), s)
    if kind == 'b':
        return 'b:%d;' % rng.randint(0, 1)
    if kind == 'd':
        return 'd:%s;' % rng.choice(['0.5', '-1', '1e10'])
    if kind == 'N':
        return 'N;'
    if kind == 'r':
        return '%s:%d;' % (rng.choice(['r', 'R']), rng.randint(1, 4))
    n = rng.randint(0, 4)
    items = ''.join('i:%d;%s' % (k, payload(rng, depth + 1)) for k in range(n))
    if kind == 'a':
        return 'a:%d:{%s}' % (n, items)
    cls = rng.choice(['GNode', 'GDtor', 'stdClass', 'ArrayObject'])
    props = ''.join('s:1:"%s";%s' % ('pqd'[k % 3], payload(rng, depth + 1)) for k in range(n))
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, n, props)


def php_str(s):
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'") + "'"


def block(rng, i):
    b = rng.choice(['caught_compile', 'caught_soap', 'cycles_gc', 'container_clean', 'dtor_mode',
                    'unserialize', 'session_cycle', 'lazy', 'error_handler', 'arrayobject'])
    if b == 'caught_compile':
        bad = rng.choice(['break 2;', 'function f(){} function f(){}', 'class A extends A {}',
                          'continue 3;', 'const X = $y;'])
        return ('$f = sys_get_temp_dir() . "/g%d.php"; file_put_contents($f, "<?php\\n%s\\n");\n'
                'try { var_dump(@opcache_compile_file($f)); } catch (Throwable $e) { echo "c\\n"; }\n'
                % (i, bad.replace('$', '\\$')))
    if b == 'caught_soap':
        junk = rng.choice(['not xml', '<definitions/>', '<?xml version="1.0"?><x>'])
        return ('$w = sys_get_temp_dir() . "/g%d.wsdl"; file_put_contents($w, %s);\n'
                'try { new SoapClient($w, ["cache_wsdl" => WSDL_CACHE_NONE]); } '
                'catch (Throwable $e) { echo "s\\n"; }\n' % (i, php_str(junk)))
    if b == 'cycles_gc':
        return 'g_cycles(%d); g_gc();\n' % rng.choice([10, 1000, 20000])
    if b == 'container_clean':
        n = rng.randint(1, 5)
        how = rng.choice(['unset($c);', '$c = [];', 'array_splice($c, 0, %d);' % rng.randint(1, n),
                          'array_pop($c);', '$c = null;'])
        return ('try { $c = []; for ($k = 0; $k < %d; $k++) { $c[] = new GDtor($k); } '
                'GDtor::$box = &$c; %s } catch (Throwable $e) { echo "t\\n"; }\n' % (n, how))
    if b == 'dtor_mode':
        return "GDtor::$mode = %s;\n" % php_str(rng.choice(['quiet', 'fatal', 'throw', 'mutate', 'gc',
                                                           'serialize', 'session']))
    if b == 'unserialize':
        return 'try { $u = @unserialize(%s); } catch (Throwable $e) { echo "u\\n"; }\n' % php_str(payload(rng))
    if b == 'session_cycle':
        op = rng.choice(['session_unset();', '$_SESSION = [];', 'session_destroy();',
                         '@session_decode(%s);' % php_str('k|' + payload(rng)), 'session_write_close();'])
        return ('if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }\n'
                'try { $_SESSION["o"] = new GDtor(9); $_SESSION["a"] = [new GNode]; %s } '
                'catch (Throwable $e) { echo "x\\n"; }\n' % op)
    if b == 'lazy':
        kind = rng.choice(['newLazyGhost', 'newLazyProxy'])
        init = ('function ($o) { $o->__construct(5); }' if kind == 'newLazyGhost'
                else 'function ($o) { return new GDtor(6); }')
        tail = rng.choice(['$l->id;', 'unset($l);', '$r->resetAsLazyGhost($l, function ($o) { $o->id = 7; });',
                           '$r->initializeLazyObject($l);', '$l = null;'])
        return ('try { $r = new ReflectionClass("GDtor"); $l = $r->%s(%s); %s } '
                'catch (Throwable $e) { echo "l\\n"; }\n' % (kind, init, tail))
    if b == 'error_handler':
        return ('set_error_handler(function ($no, $str) { %s return true; });\n'
                % rng.choice(['g_cycles(50);', 'gc_collect_cycles();', 'GDtor::$box = null;',
                              'restore_error_handler();', '']))
    return ('try { $ao = new ArrayObject([new GDtor(1), new GNode]); $ao->exchangeArray(%s); } '
            'catch (Throwable $e) { echo "o\\n"; }\n' % rng.choice(['[]', '[new GDtor(2)]', '$ao']))


def program(seed, index):
    rng = random.Random('%d/%d' % (seed, index))
    body = ''.join(block(rng, k) for k in range(rng.randint(4, 10)))
    return PRELUDE + body + 'g_gc();\necho "end\\n";\n'


def write_pool(out, count, seed):
    _spec = importlib.util.spec_from_file_location('fusedpool', HERE / 'fused-pool.py')
    fp = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(fp)
    out.mkdir(parents=True, exist_ok=True)
    programs = []
    for k in range(count):
        (out / ('prog-%04d.php' % k)).write_text(program(seed, k))
        programs.append(dict(p=k, generator='payload-grammar', seed=seed))
    (out / 'router.php').write_text(fp.ROUTER.format(app=fp.ff.ex.REPO / 'web/index.php'))
    pool = dict(scope='class-targeted grammar pool (H2.5); author knows hold-out mechanisms',
                generator='linux/payload-grammar.py', seed=seed, programs=programs,
                **provenance.provenance())
    (out / 'pool.json').write_text(json.dumps(pool, indent=2))
    return pool


def self_test():
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print('%s %s' % ('PASS' if cond else 'FAIL', name))
    check('deterministic per (seed, index)', program(1, 3) == program(1, 3))
    check('different indexes differ', program(1, 3) != program(1, 4))
    progs = [program(2, k) for k in range(200)]
    for name in ('opcache_compile_file', 'SoapClient', 'session_unset', 'newLazy', 'unserialize',
                 'gc_collect_cycles'):
        check('grammar reaches %s' % name, any(name in p for p in progs))
    rng = random.Random(5)
    check('payloads look serialized', all(payload(rng)[-1] in ';}' for _ in range(100)))
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--count', type=int, default=300)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.out:
        parser.error('--out is required')
    pool = write_pool(args.out, args.count, args.seed)
    print(json.dumps(dict(out=str(args.out), programs=len(pool['programs']),
                          citable=pool['citable']), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
