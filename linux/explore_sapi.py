"""G5 SAPI profiles for lifecycle-explore.py (plan §12.6.4).

Each profile runs ONE PHP worker for one sequence and exposes the same
interface as the CLI-server Process: port, sessions, error_log, asan_dir,
start(), stop(), alive(), worker_pid().

  apache  Apache prefork + mod_php, `httpd -X` (single process; a fatal
          request is followed by the next request on the same process)
  fpm     nginx + PHP-FPM with pm.max_children=1. A crashed worker is
          REPLACED by the master: residue does not survive that, so a
          worker change ends the sequence and is recorded as
          worker_replaced (the worker-replacement control of §12.3 Stage 1)

Observation is the fast tier only (failure sites, pid-attributed ASAN,
hang classification); the gdb state observer stays CLI-only.
"""
import os
import re
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BASE = Path('/home/phplab/php-lab')
APACHE_PORT = 18088


def _ini_extra(limit, post_max_mb):
    return ('memory_limit=%s\npost_max_size=%dM\nupload_max_filesize=8M\n'
            'session.upload_progress.min_freq=0\n' % (limit, post_max_mb))


class ApacheProcess:
    def __init__(self, version, out, limit, fault, post_max_mb):
        self.out = out
        self.run = out / 'apache'
        self.port = APACHE_PORT
        self.sessions = self.run / 'sessions'
        self.error_log = self.run / 'php-error.log'
        self.asan_dir = self.run
        self.sessions.mkdir(parents=True, exist_ok=True)
        self.env = os.environ.copy()
        self.env.update(APACHE_LAB_PREFIX=str(BASE / 'install' / (version + '-apache')),
                        APACHE_LAB_RUN=str(self.run), APACHE_LAB_MEMORY_LIMIT=limit,
                        # apache-lab.sh writes memory_limit/post_max_size first;
                        # later INI lines override them.
                        APACHE_LAB_INI_EXTRA=_ini_extra(limit, post_max_mb))
        self.env.pop('ZEND_MM_MAX_ALLOCS', None)
        if fault:
            self.env['ZEND_MM_MAX_ALLOCS'] = str(fault)
        self._pid = None

    def _lab(self, action):
        return subprocess.run(['bash', str(REPO / 'linux/apache-lab.sh'), action,
                               str(self.port)], env=self.env, capture_output=True,
                              text=True, timeout=60)

    def start(self):
        self._lab('stop')
        res = self._lab('start')
        if res.returncode != 0:
            raise RuntimeError('apache start failed: ' + res.stdout[-300:])
        self._pid = int((self.run / 'httpd.pid').read_text().strip())

    def stop(self):
        self._lab('stop')
        # A request blocked in the kernel (e.g. the Path B flock self-
        # deadlock) ignores the graceful stop; a survivor keeps the port and
        # every later start fails, so escalate.
        deadline = time.time() + 5
        while self.alive() and time.time() < deadline:
            time.sleep(0.2)
        if self.alive():
            try:
                os.kill(self._pid, 9)
            except OSError:
                pass
        subprocess.run(['pkill', '-9', '-f', 'apache2 -X -f %s/httpd.conf' % self.run],
                       capture_output=True)
        deadline = time.time() + 10
        while time.time() < deadline:
            res = subprocess.run(['bash', '-c', 'exec 3<>/dev/tcp/127.0.0.1/%d' % self.port],
                                 capture_output=True)
            if res.returncode != 0:
                break
            time.sleep(0.3)

    def worker_pid(self):
        return self._pid

    def alive(self):
        try:
            os.kill(self._pid, 0)
            return True
        except (OSError, TypeError):
            return False


class FpmProcess:
    def __init__(self, version, out, limit, fault, post_max_mb):
        import probe  # linux/probe.py (path set by the caller)
        self.lab = probe.Lab(version, 'asan', 'tracked', 'on', [], 'explore')
        lab_out = self.lab.out
        # The Lab picks its own evidence directory; link it from the exec dir.
        out.mkdir(parents=True, exist_ok=True)
        (out / 'fpm-lab').write_text(str(lab_out) + '\n')
        ini = (lab_out / 'php.ini').read_text() + _ini_extra(limit, post_max_mb)
        (lab_out / 'php.ini').write_text(ini)
        conf = (lab_out / 'nginx.conf').read_text().replace(
            'client_max_body_size 4m', 'client_max_body_size %dm' % post_max_mb)
        (lab_out / 'nginx.conf').write_text(conf)
        self.lab.env.pop('ZEND_MM_MAX_ALLOCS', None)
        if fault:
            self.lab.env['ZEND_MM_MAX_ALLOCS'] = str(fault)
        self.out = out
        self.port = probe.HTTP_PORT
        self.sessions = lab_out / 'sessions'
        self.error_log = lab_out / 'php-error.log'
        self.asan_dir = lab_out
        self._probe = probe
        self._worker = None

    def start(self):
        self.lab.start()
        self._worker = self.worker_pid()

    def stop(self):
        self.lab.stop()

    def worker_pid(self):
        try:
            return self._probe.worker_pid(self.lab.out)
        except Exception:
            return None

    def alive(self):
        # The same worker must still be serving: a respawned worker has
        # fresh globals, so the sequence's residue is gone.
        current = self.worker_pid()
        return current is not None and current == self._worker


def make_process(sapi, version, out, limit, fault, post_max_mb):
    if sapi == 'apache':
        return ApacheProcess(version, out, limit, fault, post_max_mb)
    if sapi == 'fpm':
        return FpmProcess(version, out, limit, fault, post_max_mb)
    raise ValueError('unknown sapi %r' % sapi)


def asan_pid(path):
    match = re.match(r'asan\.(\d+)', Path(path).name)
    return int(match.group(1)) if match else None


def wait_ready(port, timeout=30):
    import json
    import urllib.error
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:%d/health?step=ready' % port,
                                        timeout=3) as res:
                return json.load(res).get('ok') is True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.3)
    return False
