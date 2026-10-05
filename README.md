# google-otp-extract

Offline decoder for Google Authenticator export URIs (`otpauth-migration://offline?data=...`) that yields per-account Base32 secrets and ready-to-paste `otpauth://totp/...` URIs, plus a small local TOTP checker.

## Why

Bitwarden's vault TOTP field only accepts `otpauth://` URIs or bare Base32 secrets. Pasting the migration URI — or its raw `data` payload — into Bitwarden produces wrong codes, because the payload is a URL-encoded, URL-safe Base64 wrapper around a protobuf container that holds the **raw (not Base32) secret bytes**. This tool decodes that container offline and emits secrets and URIs in the form Bitwarden expects.

## Security

- 100 % offline. Python standard library only, no third-party dependencies, no network calls of any kind.
- Exported secrets are full 2FA credentials. Never paste them into an online "decoder" — this tool exists precisely so you don't have to.

## Usage

### Extractor

```bash
python3 extract_ga_otp.py "<URI>"
python3 extract_ga_otp.py @/path/to/uri.txt
```

The second form reads the URI from a file (leading/trailing whitespace and surrounding quotes are tolerated). Example output:

```
Konto 1: Issuer='TestIssuer'  Name='Test:user@example.com'
  Secret (Base32): JBSWY3DPEHPK3PXP
  Für Bitwarden einfügen:
    otpauth://totp/TestIssuer:Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestIssuer
```

Non-default parameters are emitted only when relevant (`algorithm=`, `digits=`). HOTP accounts produce a `otpauth://hotp/...` URI plus a warning (Bitwarden does not support HOTP).

### TOTP checker

```bash
python3 totp_check.py "<secret-or-otpauth-uri>"
python3 totp_check.py "<uri>" --digits 8 --period 30 --algo SHA256
python3 totp_check.py "<key>" --time 59      # fix a timestamp (testing)
```

Prints a header with the resolved parameters and a table of codes for time-window offsets −3..+3, marking the current window:

```
  Offset | Fensterstart (UTC)     | noch(s) | Code
  -------+------------------------+---------+----------
      -1 | 2026-10-05 11:41:00    |       - | 404836
       0 | 2026-10-05 11:41:30    |      10 | 182259  <-- aktuell
       1 | 2026-10-05 11:42:00    |       - | 288386
```

**Cross-check workflow:** if your authenticator app's code appears at offset −1 or +1, the other device's clock drifts.

## Export format notes

The migration export is a `MigrationPayload` protobuf:

- Field 1 (repeated) — `OtpParameters` messages, one per account.
- `OtpParameters`: field 1 = secret (raw bytes), 2 = name, 3 = issuer, 4 = algorithm, 5 = digits, 6 = type, 7 = counter (HOTP only).
- The whole payload is URL-safe Base64, then URL-encoded, inside the `data` query parameter.
- One export can contain several accounts (batch processing with `batch_size` / `batch_index`).
- Secrets are raw bytes and must be Base32-encoded for use in authenticator apps.

**Enum values (they start at 1 — a common off-by-one trap):**

| Enum | 0 (UNSPECIFIED) | 1 | 2 | 3 | 4 |
|------|-----------------|---|---|---|---|
| algorithm | → SHA1 (fallback) | SHA1 | SHA256 | SHA512 | MD5 |
| digits | → 6 (fallback) | SIX (6) | EIGHT (8) | SEVEN (7) | — |
| type | → TOTP (fallback) | HOTP | TOTP | — | — |

Unknown enum values fall back to the defaults with a warning on stderr.

## Limitations

- **Bitwarden** (vault and Authenticator app) does not support HOTP → the extractor warns on HOTP accounts.
- **Battle.net / Blizzard** uses a proprietary 8-digit scheme — the raw seed alone is not sufficient there.
- Issuer/name from the export are preserved in the generated URI label.

## Tests

```bash
python3 tests/run_all.py
```

Runs the extractor tests plus the RFC 6238 test vectors for `totp_check.py`.

## Requirements

- Python 3.8+ (nothing else).

## License

MIT — see [LICENSE](LICENSE).

## References / credits

- [scito/extract_otp_secrets](https://github.com/scito/extract_otp_secrets) — related tool
- [qistoph/otp_export](https://github.com/qistoph/otp_export) — `OtpMigration.proto` source
- [alexbakker.me — "Parsing the Google Authenticator export QR code"](https://alexbakker.me/post/parsing-google-authenticator-qr-codes/)
- [GoogleAuthExtractor](https://github.com/GoogleAuthExtractor/GoogleAuthExtractor)