#!/usr/bin/env bash
# Phase 4: build an officially fixed PHP version and re-run identical inputs.
#
# Usage: phase4.sh <fixed-version> <official-advisory.json> [asan|normal]
# Env: SKIP_BUILD=1 reuses an existing build manifest.
#
# The advisory MUST come from official PHP sources; placeholder or incomplete
# advisories are refused, so a difference can never be labelled a regression
# without an official mapping.
#
# Exit codes: 0 determinate verdict, 2 inconclusive, 1 harness failure.
set -u
ver=${1:?usage: phase4.sh <fixed-version> <advisory.json> [asan|normal]}
advisory=${2:?usage: phase4.sh <fixed-version> <advisory.json> [asan|normal]}
flavor=${3:-asan}
cd /mnt/c/Users/user/Downloads/php || exit 1
stamp=$(date -u +%Y%m%dT%H%M%S)
out="/home/phplab/php-lab/evidence/phase4-$stamp"
mkdir -p "$out"
log="$out/phase4.log"
exec > >(tee -a "$log") 2>&1

fail() { echo "PHASE4_FAILED: $1"; echo "LOG=$log"; exit 1; }

# ---------- advisory validation (official only) ----------
[ -f "$advisory" ] || fail "advisory file not found: $advisory"
python3 - "$advisory" "$ver" <<'PY' || exit 1
import json, re, sys
path, ver = sys.argv[1], sys.argv[2]
data = json.loads(open(path, encoding='utf-8-sig').read())
need = ('cve', 'official_url', 'affected_version', 'fixed_version')
missing = [k for k in need if not str(data.get(k, '')).strip()]
if missing:
    sys.exit('advisory missing fields: ' + ','.join(missing))
if not re.fullmatch(r'CVE-\d{4}-\d{4,}', data['cve']):
    sys.exit('advisory cve is not an official CVE id')
if not data['official_url'].startswith(('https://www.php.net/', 'https://github.com/php/php-src/')):
    sys.exit('advisory official_url must be a php.net or php-src URL')
if data['fixed_version'] != ver:
    sys.exit('advisory fixed_version %s does not match requested %s' % (data['fixed_version'], ver))
if data['affected_version'] == data['fixed_version']:
    sys.exit('affected and fixed versions are identical')
PY
echo "advisory OK: $(python3 -c "import json,sys;d=json.load(open(sys.argv[1],encoding='utf-8-sig'));print(d['cve'],d['affected_version'],'->',d['fixed_version'])" "$advisory")"

# ---------- steps with aggregation ----------
declare -A STEP_RC
run_step() {
  local name=$1; shift
  echo "=== [$name] $*"
  "$@" 2>&1 | tee -a "$log"
  STEP_RC[$name]=${PIPESTATUS[0]}
  echo "--- [$name] rc=${STEP_RC[$name]}"
}

T0=$(date +%s)
if [ "${SKIP_BUILD:-0}" = "1" ] && [ -f "/home/phplab/php-lab/install/$ver-$flavor/build-manifest.json" ]; then
  echo "=== [build] skipped (existing manifest for $ver-$flavor)"
  STEP_RC[build]=0
else
  run_step build bash linux/build.sh "$ver" "$flavor"
fi
[ "${STEP_RC[build]}" -eq 0 ] || fail "build failed"

run_step probe_standard python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile standard
run_step probe_oom      python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile oom
run_step probe_parts    python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile parts
run_step probe_cleanup  python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile cleanup
run_step probe_oomparse python3 linux/probe.py --version "$ver" --flavor "$flavor" --allocator tracked --buffering off --profile oomparse

# PoC "not reproduced" is a legitimate patched outcome, so its rc is recorded but not fatal.
run_step poc python3 linux/poc-bgserialize.py --version "$ver" --iterations 5
run_step gdb_serialize   python3 linux/gdb-probe.py --version "$ver" --flavor "$flavor" --allocator tracked --memory-limit 8M
run_step gdb_unserialize python3 linux/gdb-unserialize.py --version "$ver" --flavor "$flavor" --allocator tracked --memory-limit 5M

affected=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1],encoding='utf-8-sig'))['affected_version'])" "$advisory")
run_step compare_progress python3 linux/http-compare.py --before "$affected-$flavor" --after "$ver-$flavor" \
  --scenario progress-lifecycle --advisory "$advisory"
run_step compare_oom python3 linux/http-compare.py --before "$affected-$flavor" --after "$ver-$flavor" \
  --scenario oom-residue --advisory "$advisory"

run_step verify python3 linux/verify-evidence.py --root /home/phplab/php-lab/evidence --since "$T0" --skip-manifest
[ "${STEP_RC[verify]}" -eq 0 ] || fail "verify-evidence failed"

# ---------- aggregate verdict ----------
python3 - "$out" "$ver" "$flavor" "$advisory" "${STEP_RC[poc]}" "${STEP_RC[gdb_serialize]}" \
         "${STEP_RC[gdb_unserialize]}" "${STEP_RC[compare_progress]}" "${STEP_RC[compare_oom]}" \
         "${STEP_RC[probe_standard]}" "${STEP_RC[probe_oom]}" "${STEP_RC[probe_parts]}" \
         "${STEP_RC[probe_cleanup]}" "${STEP_RC[probe_oomparse]}" "$T0" <<'PY'
import glob, json, os, sys
(out, ver, flavor, advisory, poc_rc, gdbs_rc, gdbu_rc, cmp1_rc, cmp2_rc,
 p_std, p_oom, p_parts, p_cleanup, p_parse, t0) = sys.argv[1:]
t0 = float(t0)
probe_rcs = dict(standard=int(p_std), oom=int(p_oom), parts=int(p_parts),
                 cleanup=int(p_cleanup), oomparse=int(p_parse))
adv = json.load(open(advisory, encoding='utf-8-sig'))
summary = dict(verdict='inconclusive', advisory=adv, steps={}, probes={})

def fresh(pattern):
    items = [p for p in glob.glob(pattern) if os.path.getmtime(os.path.dirname(p) if p.endswith('result.json') else p) >= t0]
    return sorted(items)[-1] if items else None

def load(path):
    return json.load(open(path, encoding='utf-8-sig')) if path and os.path.exists(path) else None

summary['probes'] = probe_rcs
summary['steps']['poc_rc'] = int(poc_rc)
poc = load(fresh('/home/phplab/php-lab/evidence/poc-*-%s-tracked/result.json' % ver))
poc_valid = bool(poc and poc.get('iterations') == 5
                 and len(poc.get('results', [])) == 5
                 and all('result' in item for item in poc.get('results', [])))
summary['poc_valid'] = poc_valid
if poc:
    summary['poc_reproduced'] = poc.get('reproduced')
    summary['poc_iterations'] = poc.get('iterations')

summary['steps']['gdb_serialize_rc'] = int(gdbs_rc)
gdb = None
for path in sorted(glob.glob('/home/phplab/php-lab/evidence/probe-gdb-*-%s-asan-tracked/result.json' % ver), reverse=True):
    data = load(path)
    if data and data.get('verdict', {}).get('mode', 'serialize') == 'serialize' \
            and os.path.getmtime(os.path.dirname(path)) >= t0:
        gdb = data
        break
if gdb:
    summary['serialize_residue_level'] = gdb['verdict'].get('residue_level_at_next_request_start')
    summary['serialize_memory_error'] = gdb['verdict'].get('memory_error_observed')

summary['steps']['gdb_unserialize_rc'] = int(gdbu_rc)
gu = load(fresh('/home/phplab/php-lab/evidence/probe-gdb-unser-*-%s-tracked/result.json' % ver))
if gu:
    summary['unserialize_residue_level'] = gu['verdict'].get('residue_level_at_next_request_start')
    summary['unserialize_memory_error'] = gu['verdict'].get('memory_error_observed')

def cmp_status(suffix):
    for path in sorted(glob.glob('/home/phplab/php-lab/evidence/http-compare-*-%s/result.json' % suffix), reverse=True):
        if os.path.getmtime(os.path.dirname(path)) >= t0:
            return (load(path) or {}).get('status')
    return None

summary['steps']['compare_progress_rc'] = int(cmp1_rc)
summary['steps']['compare_oom_rc'] = int(cmp2_rc)
summary['compare_progress'] = cmp_status('progress-lifecycle')
summary['compare_oom'] = cmp_status('oom-residue')

statuses = (summary['compare_progress'], summary['compare_oom'])
# Every required step must have run: probes, gdb modes, verify (already fatal), comparisons.
all_probes_ok = all(rc == 0 for rc in probe_rcs.values())
comparisons_ok = (int(cmp1_rc) in (0, 2) and int(cmp2_rc) in (0, 2)
                  and all(statuses) and 'inconclusive' not in statuses)
harness_ok = (all_probes_ok and int(gdbs_rc) == 0 and int(gdbu_rc) == 0 and comparisons_ok
              and poc_valid)
summary['steps']['all_probes_ok'] = all_probes_ok
summary['steps']['comparisons_ok'] = comparisons_ok

if not harness_ok:
    summary['verdict'] = 'inconclusive'
    summary['reason'] = ('probe or comparison step did not complete: probes=%s '
                         'gdbs=%s gdbu=%s poc_valid=%s compare=%s/%s' %
                         (probe_rcs, gdbs_rc, gdbu_rc, poc_valid,
                          summary['compare_progress'], summary['compare_oom']))
elif 'regression_difference_observed' in statuses or 'difference_observed' in statuses:
    summary['verdict'] = 'regression_difference_observed'
else:
    summary['verdict'] = 'no_difference_observed'

if (summary.get('poc_reproduced') == 0
        and summary.get('serialize_memory_error') is False
        and summary.get('unserialize_memory_error') is False):
    summary['patch_effect_signal'] = ('memory error no longer reproduced in this lab '
                                      '(poc 0/%s, no ASAN residue)' % summary.get('poc_iterations'))

summary['note'] = ('regression_difference_observed only reflects a difference under an official advisory; '
                   'patch_effect_confirmed still requires the official diff review and manual sign-off.')
print(json.dumps(summary, indent=2))
json.dump(summary, open(os.path.join(out, 'summary.json'), 'w'), indent=2)
PY

rc=$?
if [ "$rc" -ne 0 ]; then fail "aggregation failed"; fi

verdict=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1],encoding='utf-8-sig'))['verdict'])" "$out/summary.json")
echo "step rc: $(for k in "${!STEP_RC[@]}"; do printf '%s=%s ' "$k" "${STEP_RC[$k]}"; done)"
case "$verdict" in
  no_difference_observed|regression_difference_observed)
    echo "PHASE4_DONE verdict=$verdict log=$log"; echo "LOG=$log"; exit 0 ;;
  inconclusive)
    echo "PHASE4_INCONCLUSIVE log=$log"; echo "LOG=$log"; exit 2 ;;
  *)
    fail "unexpected verdict: $verdict" ;;
esac
