# PHP2Shell detection rules

Defensive detection artifacts derived from the lab measurements
(`docs/php2shell-analysis-findings.md` §4.10, §6.4). **They are not a control
and not a virtual patch.**

## Measured effect (ModSecurity 2.9.7, PHP 8.4.4, 10 `Content-Disposition` shapes)

| Rule set | Blocked | PHP-reachable bypasses |
|---|---|---|
| naive `ARGS_NAMES @streq` | 5/10 | **2** (duplicate `name`, extra parameter) |
| `modsecurity-php2shell.example.conf` (this dir) | 6/10 | **2** (same) |

The sixth block is the `filename="x"; name="…"` shape, which PHP **never** used
as the progress field. So the change adds a block but **removes no verified
risk**. `@contains` was replaced by `@streq` to avoid false positives on longer
field names that merely contain the substring.

The two shapes that reach PHP:

```
Content-Disposition: form-data; name="foo"; name="PHP_SESSION_UPLOAD_PROGRESS"
Content-Disposition: form-data; foo="bar"; name="PHP_SESSION_UPLOAD_PROGRESS"
```

ModSecurity 2.9.7 does not expose the last `name` parameter in a matchable form
(`MULTIPART_PART_HEADERS` and `REQUEST_BODY` were both measured ineffective; see
the comments in the .conf). Close this at a layer that sees raw multipart bytes,
or disable the feature:

```ini
session.upload_progress.enabled=0   ; apply before workers start, then restart
```

## Sigma rules

`sigma-php2shell.yml` has four rules:

1. progress field with duplicate/extra parameters (requires raw body logging),
2. PHP memory-limit fatal (needs correlation with a POST),
3. FPM worker termination (signal / exit 70),
4. multipart POST to a `.php` endpoint — correlation counterpart for rule 3.

Sigma cannot express joins, so rules 3 and 4 must be correlated in the SIEM on
host+pool within a short window.

Validation performed: `linux/validate-rules.py` (YAML parses, UUIDv4 ids,
condition references defined selections, no list-of-mappings OR traps).
**Not performed:** `sigma-cli` conversion and SIEM execution.

## Files

| File | Purpose |
|---|---|
| `modsecurity-php2shell.example.conf` | Example blocking rules (5→6/10, gap unchanged). **Do not deploy**: loading it blocks traffic |
| `sigma-php2shell.yml` | 4 experimental log rules |
| `../validate-rules.py` | Structural validator (run after every edit) |
| `../waf-lab.sh`, `../waf-compare.py` | Lab used to measure the numbers above |

## Limits

- Body-size and `SecRequestBodyLimit` settings can hide the field from name-based rules.
- The memory error itself is invisible to a WAF; use FPM worker-exit logs, OOM
  fatals and 5xx bursts.
- Re-measure after any engine upgrade; numbers are for 2.9.7.
- `SecRequestBodyLimit 8388608` may reject legitimate uploads; tune per service.
