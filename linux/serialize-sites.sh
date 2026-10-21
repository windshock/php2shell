#!/usr/bin/env bash
# Static survey: which code can (un)serialize before module RINIT?
set -u
cd /home/phplab/php-lab/sources/php-8.4.4 || exit 1
echo '=== php_var_serialize call sites'
grep -rn 'php_var_serialize(' ext main --include='*.c' --include='*.re' | grep -v tests | head -12
echo '=== php_var_unserialize call sites'
grep -rn 'php_var_unserialize(' ext main --include='*.c' --include='*.re' | grep -v tests | head -12
echo '=== url_scanner request-startup state'
grep -n 'early_rinit\|http_session_vars' ext/standard/url_scanner_ex.c | head -8
echo '=== 8.5 fatal_error_backtraces'
grep -rn 'fatal_error_backtraces' /home/phplab/php-lab/sources/php-8.5.4 --include='*.c' | head -6
