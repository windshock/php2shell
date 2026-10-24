#!/usr/bin/env python3
"""#3 CG-3: Phase 2b interrupt-hook lifetime across FPM requests (review
2026-10-24 16:45/17:11 design).

Patch 0001 installs its VM interrupt hook (cg_interrupt) LAZILY, at a
refused GC root after a caught bailout. The installed-hook pointer is
process-global (cg_prev_interrupt) while arming is per-request (cg_armed,
reset in gc_reset). On ONE FPM worker (pm.max_children=1, observe mode)
this harness proves:

  step1  an R49-shaped request installs+arms the hook -> exactly ONE
         gc_protected_after_caught_bailout event
  step2  normal requests: zero new events, healthy output
  step3  the R49-shaped request again: re-arms -> a SECOND event
  step4  a set_time_limit(2) request: the still-installed (unarmed) hook
         must pass the interrupt through - the ORIGINAL timeout fires at
         ~2s, no new event, the worker survives
  step5  the next request is healthy (process-global state does not
         poison the next request)

Events are aggregated BY NAME: counting lines alone conflated Phase 3
containment events with Phase 2b hook events (2026-10-24 review lesson).
Observation only, no hold-out cases (docs/coreguard/holdout-v1.json).
"""
import importlib.util
import json
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

_spec = importlib.util.spec_from_file_location('cg2', HERE / 'cg2-fpm-isolation.py')
cg2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cg2)
BASE = cg2.BASE
P2B_EVENT = 'gc_protected_after_caught_bailout'

ROUTER = '''<?php
$u = $_SERVER['REQUEST_URI'];
if ($u === '/r49arm') {
    $bad = sys_get_temp_dir() . "/p2blt.php"; file_put_contents($bad, "<?php\\nbreak 2;\\n");
    @opcache_compile_file($bad);
    class N { public $s; }
    $o = new N; $o->s = $o; unset($o);
    echo "armed";
    return true;
}
if ($u === '/timeout') {
    set_time_limit(2);
    $x = 0; while (true) { $x++; }
}
if ($u === '/health') { echo json_encode(['ok' => true, 'pid' => getmypid()]); return true; }
echo 'not-found';
return true;
'''


def events_by_name(out):
    names = {}
    cg = out / 'cg-events.log'
    if cg.exists():
        for ln in cg.read_text().splitlines():
            if 'COREGUARD event=' in ln:
                kind = ln.split('event=', 1)[1].split()[0]
                names[kind] = names.get(kind, 0) + 1
    return names


def timed_get(path, timeout=30):
    t0 = time.time()
    status, body = cg2.http_get(path, timeout=timeout)
    return status, body, round(time.time() - t0, 2)


def cell(build, mode, root):
    out = root / f'{build}-{mode}-mc1'
    out.mkdir(parents=True, exist_ok=True)
    record = dict(build=build, mode=mode)
    busy = [p for p in (cg2.HTTP_PORT, cg2.FPM_PORT) if not cg2.port_free(p)]
    if busy:
        record['error'] = 'port_in_use:%s' % ','.join(map(str, busy))
        return record
    procs, logs, _env = cg2.lab(build, mode, 1, out)
    try:
        (out / 'router.php').write_text(ROUTER)  # replace before startup
        deadline = time.time() + 20
        fpm_pid = ng_pid = None
        while time.time() < deadline:
            fpm_pid = cg2.pidfile_owner_ok(out, 'fpm')
            ng_pid = cg2.pidfile_owner_ok(out, 'nginx')
            if fpm_pid and ng_pid:
                break
            time.sleep(0.2)
        if not (fpm_pid and ng_pid):
            record['error'] = 'stack_identity_unverified'
            for name in ('fpm', 'nginx'):
                log = out / f'{name}-console.log'
                if log.exists():
                    record[f'{name}_console_tail'] = log.read_text()[-300:]
            return record
        deadline = time.time() + 20
        while time.time() < deadline:
            status, body = cg2.http_get(cg2.HEALTH_PATH, timeout=2)
            if status == 200 and b'"ok":true' in body:
                break
            time.sleep(0.2)
        else:
            record['error'] = 'startup timeout'
            return record
        master, workers = cg2.worker_pids(out)
        if master != fpm_pid or not workers:
            record['error'] = 'worker_pool_unverified'
            return record
        record['worker'] = workers
        # step1: arm the hook (R49 shape: caught compile bailout + refused root)
        s1, b1, t1 = timed_get('/r49arm')
        ev1 = events_by_name(out)
        # step2: normal requests in between - hook persists, no new events
        step2 = [timed_get(cg2.HEALTH_PATH) for _ in range(5)]
        ev2 = events_by_name(out)
        # step3: re-arm
        s3, b3, t3 = timed_get('/r49arm')
        ev3 = events_by_name(out)
        # step4: original timeout must fire THROUGH the installed hook
        s4, b4, t4 = timed_get('/timeout')
        ev4 = events_by_name(out)
        # step5: next request healthy on the same worker
        s5, b5, t5 = timed_get(cg2.HEALTH_PATH)
        _, workers_after = cg2.worker_pids(out)
        record.update(
            step1=dict(status=s1, body=b1.decode('utf-8', 'replace')[:40], seconds=t1,
                       events=ev1),
            step2=dict(statuses=[s for s, _, _ in step2],
                       max_ms=max(round(dt * 1000, 1) for _, _, dt in step2), events=ev2),
            step3=dict(status=s3, seconds=t3, events=ev3),
            step4=dict(status=s4, seconds=t4, events=ev4),
            step5=dict(status=s5, seconds=t5, events=events_by_name(out)),
            worker_after=workers_after,
            worker_survived=workers_after == workers,
        )
        record['checks'] = [
            ('step1 exactly one 2b event', ev1.get(P2B_EVENT) == 1),
            ('step2 no new events', ev2 == ev1),
            ('step2 all healthy', all(s == 200 for s in record['step2']['statuses'])),
            ('step3 second 2b event', ev3.get(P2B_EVENT) == 2),
            ('step4 timeout fired through installed hook (~2s, no hang)',
             1.5 <= t4 <= 10 and s4 is not None),
            ('step4 no new events', ev4 == ev3),
            ('step5 healthy', s5 == 200),
            ('worker survived (no replacements)', workers_after == workers),
        ]
    finally:
        for pidfile in ('fpm.pid', 'nginx.pid'):
            try:
                import os
                os.kill(int((out / pidfile).read_text().strip()), signal.SIGTERM)
            except (OSError, ValueError):
                pass
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
        for l in logs:
            l.close()
        import subprocess
        subprocess.run(['pkill', '-f', 'php-fpm.*%s' % out.name], capture_output=True)
        deadline = time.time() + 5
        while time.time() < deadline and not (cg2.port_free(cg2.HTTP_PORT)
                                              and cg2.port_free(cg2.FPM_PORT)):
            time.sleep(0.1)
    return record


def main():
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = BASE / 'evidence' / ('cg3-p2b-fpm-lifetime-%s' % stamp)
    root.mkdir(parents=True)
    rows = []
    ok = total = 0
    for build in ('8.4.27-coreguard-normalext', '8.4.27-coreguard-ztsnormalext'):
        row = cell(build, 'observe', root)
        rows.append(row)
        print(json.dumps(row), flush=True)
        for name, passed in row.get('checks', []):
            ok += bool(passed)
            total += 1
            if not passed:
                print('   FAIL', build, name, flush=True)
    summary = dict(scope='CG-3 Phase 2b interrupt-hook lifetime across FPM '
                   'requests (observation only, no hold-out)', rows=rows,
                   checks_ok=ok, checks_total=total,
                   **provenance.provenance())
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('checks=%d/%d out=%s citable=%s' % (ok, total, root, summary['citable']))
    return 0 if ok == total and total else 1


if __name__ == '__main__':
    sys.exit(main())
