#!/usr/bin/env bash
# Phase 5 A2: stale-state candidate scan.
# The residue class is bounded by a key fact from A1: only state CONSUMED
# BEFORE RINIT matters (everything else is reset by the module RINITs that
# always run for a normally-started request). So enumerate the globals the
# request-startup parse path (php_hash_environment and its callees) touches,
# plus runtime-fatal producers whose INIT/DESTROY pairing a bailout can skip.
set -euo pipefail
base=/home/phplab/php-lab
src=${1:-$base/sources/php-8.4.4}
out="$base/evidence/state-sites"
mkdir -p "$out"

# 1) globals written/read before RINIT: walk the php_hash_environment tree.
{
  echo '== php_hash_environment direct callees (main/php_variables.c) =='
  grep -n 'php_treat_data\|sapi_module.default_treat_data\|zend_activate_auto_globals\|php_default_treat_data' "$src/main/php_variables.c" | head -20
  echo
  echo '== treat_data -> rfc1867_post_handler / php_std_post_handler chain =='
  grep -n 'sapi_handle_post\|treat_data' "$src/main/php_variables.c" | head -20
  echo
  echo '== rfc1867 parse path: SG()/PG() globals touched =='
  grep -n 'SG(\|PG(' "$src/main/rfc1867.c" | grep -v 'SG(sapi_headers)\|SG(request_info)' | head -25
  echo
  echo '== session progress callback globals (pre-RINIT) =='
  grep -n 'PS(\|BG(\|php_url_scanner' "$src/ext/session/session.c" | sed -n '/rfc1867/,$p' | head -5
  awk '/php_session_rfc1867_callback|php_session_rfc1867_update|php_session_rfc1867_cleanup|php_rinit_session\(/{show=1} show && /PS\(|BG\(|php_url_scanner|php_rinit_session_globals/{print NR": "$0}' "$src/ext/session/session.c" | head -40
  echo
  echo '== url scanner registration entry (session.c reset_id) =='
  grep -n 'php_url_scanner_add_session_var\|php_url_scanner_reset_session_var\|php_url_scanner_reset' "$src/ext/session/session.c"
  echo
  echo '== url_scanner_ex state fields (request-lifetime pointers) =='
  sed -n '/typedef struct.*smart_str/,+8p' "$src/ext/standard/url_scanner_ex.h" 2>/dev/null || true
  grep -n 'url_adapt\|char \*.*sess\|smart_str' "$src/ext/standard/url_scanner_ex.h" | head -15
  echo
  echo '== ZEND_DECLARE_MODULE_GLOBALS across tree (request-global structs) =='
  grep -rn 'ZEND_DECLARE_MODULE_GLOBALS(' "$src/ext" "$src/main" --include='*.c' | grep -v TSRM | head -40
} > "$out/pre-rinit-globals.txt" 2>&1 || true

# 2) INIT/DESTROY pairings a bailout can skip (manual-pair contexts).
{
  echo '== PHP_VAR_SERIALIZE_INIT / DESTROY call pairs (var.c users) =='
  grep -rn 'PHP_VAR_SERIALIZE_INIT\|PHP_VAR_SERIALIZE_DESTROY' "$src/ext" "$src/main" --include='*.c' --include='*.re' | head -30
  echo
  echo '== PHP_VAR_UNSERIALIZE_INIT / DESTROY call pairs =='
  grep -rn 'PHP_VAR_UNSERIALIZE_INIT\|PHP_VAR_UNSERIALIZE_DESTROY' "$src/ext" "$src/main" --include='*.c' --include='*.re' | head -30
} > "$out/init-destroy-pairs.txt" 2>&1 || true

# 3) S9 checklist anchors (Calif php-unserialize-audit methodology).
{
  echo '== C:Serializable userland unserialize during decode (reentrancy anchor) =='
  grep -n 'ce->unserialize\|zend_call_function\|unserialize_callback\|__wakeup\|PHP_SANITIZED' "$src/ext/standard/var_unserializer.re" | head -20
  echo
  echo '== wakeup/destructor deferral (var_push_dtor) =='
  grep -n 'var_push_dtor\|var_destroy\|var_hash->rtmp_var' "$src/ext/standard/var_unserializer.re" | head -20
  echo
  echo '== session decoder differences: zend_try coverage per handler =='
  awk '/ps_srlzr_decode_php|ps_srlzr_decode_php_binary|ps_srlzr_decode_php_serialize|php_session_decode/{print NR": "$0}' "$src/ext/session/session.c" | head -10
  sed -n '/static zend_result php_session_decode/,/^}/p' "$src/ext/session/session.c"
  grep -n -A20 'static const ps_serializer ps_srlzr_handlers' "$src/ext/session/session.c" | head -25
} > "$out/s9-checklist-anchors.txt" 2>&1 || true

wc -l "$out"/*.txt
echo "outdir: $out"
