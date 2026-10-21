#!/usr/bin/env bash
# Local WAF lab: Apache prefork + mod_php + ModSecurity, loopback only.
# Purpose: compare what the WAF blocks against what PHP actually parses.
# Usage: waf-lab.sh start|stop|status [port]
set -euo pipefail
action=${1:-start}
port=${2:-18090}
base=/home/phplab/php-lab
prefix="$base/install/8.4.4-apache"
run="$base/evidence/waf-lab"
mkdir -p "$run/tmp" "$run/data" "$run/sessions" "$run/uploads"

cat > "$run/php.ini" <<INI
[PHP]
display_errors=Off
log_errors=On
error_reporting=E_ALL
expose_php=Off
memory_limit=64M
max_execution_time=30
file_uploads=On
upload_max_filesize=2M
post_max_size=4M
allow_url_include=Off
[Session]
session.save_handler=files
session.serialize_handler=php
session.use_only_cookies=On
session.use_strict_mode=Off
session.upload_progress.enabled=On
session.upload_progress.cleanup=Off
session.upload_progress.min_freq=0
session.save_path=$run/sessions
upload_tmp_dir=$run/uploads
error_log=$run/php-error.log
INI

cat > "$run/httpd.conf" <<CONF
ServerRoot $run
PidFile $run/httpd.pid
Listen 127.0.0.1:$port
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule unique_id_module /usr/lib/apache2/modules/mod_unique_id.so
LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so
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
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 8388608
SecRequestBodyNoFilesLimit 1048576
SecTmpDir $run/tmp
SecDataDir $run/data
SecAuditEngine Off
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" "id:1001,phase:2,deny,status:403,log,msg:'progress field blocked'"
CONF

asan=$(ls /usr/lib/x86_64-linux-gnu/libasan.so.8 2>/dev/null || true)
case "$action" in
  start)
    if [[ -f "$run/httpd.pid" ]] && kill -0 "$(cat "$run/httpd.pid")" 2>/dev/null; then
      echo "already running: $(cat "$run/httpd.pid")"; exit 0
    fi
    LD_PRELOAD="$asan" \
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:log_path=$run/asan" \
    ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer \
    USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
    nohup /usr/sbin/apache2 -X -f "$run/httpd.conf" > "$run/httpd-console.log" 2>&1 &
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
    pkill -f "apache2 -X -f $run/httpd.conf" 2>/dev/null || true
    echo stopped ;;
  status)
    curl -fsS "http://127.0.0.1:$port/health" || echo 'not running' ;;
esac
