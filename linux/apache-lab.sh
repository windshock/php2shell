#!/usr/bin/env bash
# Apache prefork + mod_php lab (single process, loopback only).
# Usage: apache-lab.sh start|stop|status [port]
set -euo pipefail
action=${1:-start}
port=${2:-18088}
base=/home/phplab/php-lab
prefix="$base/install/8.4.4-apache"
run="$base/evidence/apache-lab"
mkdir -p "$run"
ini="$run/php.ini"
conf="$run/httpd.conf"

cat > "$ini" <<INI
[PHP]
display_errors=Off
log_errors=On
error_reporting=E_ALL
expose_php=Off
memory_limit=8M
max_execution_time=30
file_uploads=On
upload_max_filesize=2M
post_max_size=4M
allow_url_include=Off
[Session]
session.save_handler=files
session.serialize_handler=php
session.use_only_cookies=On
session.use_strict_mode=On
session.upload_progress.enabled=On
session.upload_progress.cleanup=On
session.upload_progress.min_freq=0
session.save_path=$run/sessions
upload_tmp_dir=$run/uploads
error_log=$run/php-error.log
INI
mkdir -p "$run/sessions" "$run/uploads"

cat > "$conf" <<CONF
ServerRoot $run
PidFile $run/httpd.pid
Listen 127.0.0.1:$port
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module $prefix/modules/libphp.so
PHPIniDir $run
User phplab
Group phplab
ServerName localhost
TypesConfig /etc/mime.types
DocumentRoot /mnt/c/Users/user/Downloads/php/web
FallbackResource /index.php
ErrorLog $run/error.log
LogFormat "%h %l %u %t \"%r\" %>s %b" common
CustomLog $run/access.log common
LogLevel warn
<Directory />
    AllowOverride None
    Require all granted
</Directory>
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
CONF

asan=$(ls /usr/lib/x86_64-linux-gnu/libasan.so.8 2>/dev/null || true)
[[ -n "$asan" ]] || { echo 'libasan.so.8 not found'; exit 1; }

case "$action" in
  start)
    if [[ -f "$run/httpd.pid" ]] && kill -0 "$(cat "$run/httpd.pid")" 2>/dev/null; then
      echo "already running: $(cat "$run/httpd.pid")"; exit 0
    fi
    : > "$run/asan" 2>/dev/null || true
    LD_PRELOAD="$asan" \
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:log_path=$run/asan" \
    ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer \
    USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
    nohup /usr/sbin/apache2 -X -f "$conf" > "$run/httpd-console.log" 2>&1 &
    for _ in $(seq 1 40); do
      if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
        echo "started pid $(cat "$run/httpd.pid" 2>/dev/null) port $port"; exit 0
      fi
      sleep 0.25
    done
    echo 'start failed'; tail -20 "$run/httpd-console.log" "$run/error.log" 2>/dev/null; exit 1
    ;;
  stop)
    if [[ -f "$run/httpd.pid" ]]; then kill "$(cat "$run/httpd.pid")" 2>/dev/null || true; sleep 0.5; fi
    pkill -f "apache2 -X -f $conf" 2>/dev/null || true
    echo stopped ;;
  status)
    curl -fsS "http://127.0.0.1:$port/health" || echo 'not running' ;;
esac
