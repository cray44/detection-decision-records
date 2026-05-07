# DDR Spec v0.4

**Status:** Released  
**Date:** 2026-05-06  
**Schema:** `spec/ddr-v0.4.schema.json`  
**Changelog:** `spec/CHANGELOG.md`

---

## Changes from v0.3

`ddr_version` pattern now accepts `"0.4"` (`^0\.[1234]$`). All other schema fields are
unchanged. v0.1, v0.2, and v0.3 records validate without modification.

---

## §6 SPL Canonicalization Algorithm v1

Used by `target.query_ref.query_hash` to produce a stable hash of a Splunk savedsearch
SPL query. The algorithm answers one question: *"has this savedsearch's SPL been edited
since the DDR was authored?"* — not whether two SPLs are semantically equivalent.

### Inputs

Raw SPL string extracted from the `search =` key of a `savedsearches.conf` stanza.

### Steps

1. **UTF-8 decode, strip BOM.** If the string begins with U+FEFF, strip it.
2. **CRLF → LF.** Replace `\r\n` with `\n`, then any remaining `\r` with `\n`.
3. **Join backslash-continued lines.** For each physical line ending with `\`, remove
   the trailing `\` and append the next physical line with a space separator. Repeat
   until no continuation remains.
4. **Drop comment lines.** Remove any logical line whose first non-whitespace character
   is `#`. Note: Splunk only honors `#` comments at the start of a line; mid-line `#`
   is treated as data and is preserved.
5. **Collapse whitespace.** Replace any run of whitespace characters (space, tab, `\n`,
   `\r`) with a single space character.
6. **Trim.** Remove leading and trailing whitespace from the result.

### Hash

Compute SHA-256 of the canonicalized string encoded as UTF-8. Prefix the 64-character
lowercase hex digest with `sha256:`.

**No keyword lowercasing.** Splunk SPL commands are case-insensitive but field values
are not. DDR cannot safely distinguish them, so case is preserved verbatim.

### Example

Raw `search` value from conf:
```
index=auth sourcetype=linux_secure action=failure \
  | stats count by src_ip, user \
  | where count > 50
```

After canonicalization:
```
index=auth sourcetype=linux_secure action=failure | stats count by src_ip, user | where count > 50
```

Hash: `sha256:9f67aa9e2f7e15b2a9a62c694e9d1af4d685cddb7a09290575643157e5ffc06e`

### Idempotency

`canon(canon(x)) == canon(x)` for all inputs. Whitespace-only edits to the SPL produce
the same hash. Semantic changes (field names, filter values, pipe stages) produce a
different hash.

---

## §7 savedsearches.conf Parsing

DDR's conf parser handles the following Splunk INI dialect quirks:

| Case | Handling |
|---|---|
| BOM-prefixed file | Stripped before parse (`utf-8-sig` decode) |
| CRLF line endings | Normalized to LF |
| Backslash continuation | Physical lines joined into one logical line |
| `#` at line start | Treated as comment; line skipped |
| `#` mid-line | Treated as data (Splunk behavior) |
| `[default]` stanza | Skipped — never a DDR target |
| Duplicate keys in one stanza | Last-wins (Splunk behavior) |
| Stanza name absent from file | Error; available stanza names listed |
| `disabled = 1` | Allowed; CLI warns |
| Empty `search` value | Error |
| Multiple stanzas, no `--name` | Error unless exactly one non-default stanza |

### App inference

If `path_or_url` matches `.../etc/apps/<app>/(local|default)/savedsearches.conf`,
DDR infers `app = <app>`. Otherwise `app` defaults to `"search"` and can be set with
`--app`.

---

## §8 query_hash Drift

`ddr validate --strict` checks for query_hash drift when:
- `target.kind == "splunk"`
- `target.query_ref.query_hash` is present
- `target.query_ref.path_or_url` is a local path that resolves

Drift is a **warning**, not a validation failure — it signals the SPL may have changed
since the DDR was authored but does not indicate the DDR is invalid. Use
`ddr refresh-hash` to update the hash after confirming the change is cosmetic-only.

If `path_or_url` is an `http(s)://` URL, drift cannot be verified and a note is emitted
instead of a warning.
