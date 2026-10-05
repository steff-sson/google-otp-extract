# AGENTS.md

Guidance for coding agents working in this repository.

## Purpose & file map

- `extract_ga_otp.py` — offline decoder for Google Authenticator `otpauth-migration://offline?data=...` export URIs → per-account Base32 secrets and `otpauth://totp/...` URIs.
- `totp_check.py` — local TOTP checker (RFC 6238 / HOTP RFC 4226) for diagnosing wrong codes (bad secret, clock drift, algorithm/digits).
- `tests/` — `test_extract_ga_otp.py`, `test_totp_check.py`, and `run_all.py` (aggregates both as subprocesses; exit 0 only if all green).

## Hard constraints

- **Python stdlib only.** No third-party dependencies, no package installs.
- **Offline always.** No network calls of any kind — ever.
- Secrets may appear **only** in the tool's intended output. Never log secrets, never include them in tracebacks, never write them to auxiliary files.
- No telemetry of any kind.
- All user-facing output and code comments must be in English.

## Enum authority

The `MigrationPayload` / `OtpParameters` enum mappings must match the `qistoph/otp_export` proto and the alexbakker.me post (see README references):

- `algorithm`: 0=UNSPECIFIED→SHA1, 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5
- `digits`: 0=UNSPECIFIED→6, 1=SIX(6), 2=EIGHT(8), 3=SEVEN(7)
- `type`: 0=UNSPECIFIED→TOTP, 1=HOTP, 2=TOTP

Beware the **off-by-one trap**: enums start at 1, and 0 is UNSPECIFIED (fallback), not the first real value. Only change proto mappings with an explicit source citation; unknown values must fall back to the default with a warning on stderr.

## totp_check.py is RFC 6238-validated

The HOTP core is verified against the RFC 6238 test vectors in `tests/test_totp_check.py`. Do not touch the HOTP core. Any change requires the tests to stay green.

## Workflow

Before every commit:

```
python3 tests/run_all.py
python3 -m py_compile extract_ga_otp.py totp_check.py
```

All checks must be green.

Keep input tolerance (whitespace/quotes in extractor, Base32 normalization in checker), clear stderr error messages, and exit codes. Docs are in English; keep README.md in sync with any behavior change.