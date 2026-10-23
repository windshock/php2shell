#!/usr/bin/env python3
"""Batch verdict for explore-g34.sh / explore-g5.sh (issue #5-5).

Each run of a batch is valid only if its runner exited 0, wrote a
summary.json, executed at least one sequence, did not abort and had no
harness errors. The batch exit code is non-zero when ANY run is invalid, and
batch.json keeps valid and failed runs apart so a failed campaign is never
read as a result.

Usage: batch-check.py <batch_root> <run_dir>=<rc> ...   (writes batch.json)
       batch-check.py --self-test
"""
import json
import sys
import tempfile
from pathlib import Path


def check_run(run_dir, rc):
    run_dir = Path(run_dir)
    out = dict(run=run_dir.name, rc=rc)
    summary = run_dir / 'summary.json'
    if rc != 0:
        out['status'] = 'runner_failed'
    elif not summary.exists():
        out['status'] = 'summary_missing'
    else:
        try:
            data = json.loads(summary.read_text())
        except ValueError:
            out['status'] = 'summary_unreadable'
            return out
        out.update(execs=data.get('execs'), aborted=data.get('aborted', False),
                   harness_errors=data.get('harness_errors', 0))
        if not data.get('execs'):
            out['status'] = 'zero_executions'
        elif data.get('aborted'):
            out['status'] = 'aborted'
        elif data.get('harness_errors'):
            out['status'] = 'harness_errors'
        else:
            out['status'] = 'valid'
    return out


def verdict(root, pairs):
    runs = [check_run(d, rc) for d, rc in pairs]
    report = dict(batch=str(root), runs=runs,
                  valid=[r['run'] for r in runs if r['status'] == 'valid'],
                  failed=[r['run'] for r in runs if r['status'] != 'valid'])
    report['ok'] = bool(runs) and not report['failed']
    Path(root, 'batch.json').write_text(json.dumps(report, indent=2))
    return report


def self_test():
    ok = total = 0
    with tempfile.TemporaryDirectory() as tmp:
        def mk(name, summary):
            d = Path(tmp) / name
            d.mkdir()
            if summary is not None:
                (d / 'summary.json').write_text(json.dumps(summary))
            return d
        good = mk('good', dict(execs=5, aborted=False, harness_errors=0))
        cases = [
            ('all valid -> ok', [(good, 0)], True),
            ('runner exit 3 -> failed', [(good, 0), (mk('rc3', dict(execs=5)), 3)], False),
            ('missing summary -> failed', [(mk('nosum', None), 0)], False),
            ('zero executions -> failed', [(mk('zero', dict(execs=0)), 0)], False),
            ('aborted campaign -> failed', [(mk('abort', dict(execs=4, aborted=True)), 0)],
             False),
            ('harness errors -> failed', [(mk('harn', dict(execs=4, harness_errors=2)), 0)],
             False),
            ('empty batch -> failed', [], False),
        ]
        for name, pairs, want in cases:
            got = verdict(tmp, pairs)['ok']
            total += 1
            ok += got == want
            print('%s %s' % ('PASS' if got == want else 'FAIL', name))
    print('self_test=%d/%d' % (ok, total))
    return 0 if ok == total else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    root, items = sys.argv[1], sys.argv[2:]
    pairs = []
    for item in items:
        d, _, rc = item.rpartition('=')
        pairs.append((d, int(rc)))
    report = verdict(root, pairs)
    print(json.dumps(dict(ok=report['ok'], valid=len(report['valid']),
                          failed=report['failed']), indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
