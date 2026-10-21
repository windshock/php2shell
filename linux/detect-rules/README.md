# PHP2Shell detection rules

Local, defensive detection artifacts derived from the lab measurements in
`docs/php2shell-analysis-findings.md` (§4.10, §6). They are **not** a virtual
patch and were not validated against production traffic.

## What is validated (ModSecurity 2.9.7, Apache 2.4.58, PHP 8.4.4)

`linux/waf-compare.py` sends ten `Content-Disposition` variants and checks both
the WAF decision and whether PHP actually wrote the upload-progress entry.

| Rule set | Blocked | PHP reached |
|---|---|---|
| naive `ARGS_NAMES @streq` (original) | 5/10 | 2 (duplicate name, extra parameter) |
| `modsecurity-php2shell.conf` (this directory) | **6/10** | 2 (same two) |

`FILES_NAMES` closed the `filename="x"; name="…"` variant. The duplicate-name
and extra-parameter variants still bypass ModSecurity 2.9.7's multipart name
resolution while PHP's rfc1867 parser uses the last `name` parameter.

## Gap and recommended placement

ModSecurity 2.9.x does not expose the raw multipart part headers reliably enough
to match the field name when extra parameters precede or duplicate it. Close the
gap where the raw bytes are still visible:

- reverse proxy / API gateway body inspection on the raw `Content-Type:
  multipart/form-data` part headers (e.g. Envoy/Lua, NGINX `ngx_http_lua`, Cloudflare
  Enterprise `http.request.body.multipart.names[*][0]` with `names[*]` iteration),
- or disable the feature: `session.upload_progress.enabled=0` before workers start.

## Sigma rules

`sigma-php2shell.yml` contains log-side rules (OOM fatal, worker exit, progress
field in request logs). They are `status: experimental` and were **not executed
in a SIEM**; field names follow common nginx/Apache and PHP-FPM templates and
must be mapped to your pipeline.

## Files

| File | Purpose |
|---|---|
| `modsecurity-php2shell.conf` | Blocking rules (validated 6/10) |
| `sigma-php2shell.yml` | Log detection rules (experimental, untested in SIEM) |
| `../waf-lab.sh`, `../waf-compare.py` | Lab used to measure the above |

## Limits

- Body-size limits, `SecRequestBodyLimit`, and non-standard multipart encodings
  can hide the field from any name-based rule.
- Detection of the memory error itself is not possible at the WAF; use PHP-FPM
  logs (worker exit signal/70), OOM fatals, and 5xx bursts.
- Re-measure after any engine upgrade; the numbers above are for 2.9.7.
