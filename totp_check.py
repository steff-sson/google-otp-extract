#!/usr/bin/env python3
# Local TOTP calculator for cross-checking authenticator codes.
# Recomputes TOTP codes per RFC 6238 / HOTP per RFC 4226 locally,
# to diagnose "wrong code in Bitwarden" (secret correct? clock drift?
# algorithm/digits?).
# Runs offline, without a network. Python standard library only.

import argparse
import base64
import hashlib
import hmac
import struct
import sys
import time
import urllib.parse

ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}
OFFSETS = range(-3, 4)


def normalize_base32(raw):
    """Removes spaces/hyphens/URL-safe chars, uppercases, pads."""
    cleaned = (
        raw.replace(" ", "").replace("-", "").replace("_", "")
        .replace("\t", "").replace("\n", "").replace("\r", "")
    ).upper()
    return cleaned + "=" * ((8 - len(cleaned) % 8) % 8)


def decode_secret(raw):
    try:
        return base64.b32decode(normalize_base32(raw))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid Base32 secret: {exc}") from exc


def parse_uri(uri):
    """Parses an otpauth://totp/... or otpauth://hotp/... URI."""
    parts = urllib.parse.urlparse(uri)
    if parts.scheme != "otpauth":
        raise ValueError("Not a valid otpauth:// URI")
    params = urllib.parse.parse_qs(parts.query)
    if "secret" not in params or not params["secret"][0]:
        raise ValueError('Parameter "secret" is missing in the otpauth URI')

    def _int(name, default):
        try:
            return int(params.get(name, [default])[0])
        except (TypeError, ValueError) as exc:
            raise ValueError(f'Parameter "{name}" is not a valid number: '
                             f'{params.get(name, [default])[0]!r}') from exc

    algo = params.get("algorithm", ["SHA1"])[0].upper()
    if algo not in ALGOS:
        raise ValueError(f"Unknown algorithm {algo!r} "
                         f"(allowed: {', '.join(ALGOS)})")

    cfg = {
        "secret_raw": params["secret"][0],
        "digits": _int("digits", 6),
        "period": _int("period", 30),
        "algo": algo,
        "schema": parts.netloc.lower(),
        "source": "otpauth URI",
    }
    if cfg["schema"] == "hotp":
        cfg["counter"] = _int("counter", 0)
    return cfg


def hotp(secret, counter, digits, algo):
    """HOTP per RFC 4226 (HMAC + dynamic truncation)."""
    digest = hmac.new(secret, struct.pack(">Q", counter & 0xFFFFFFFFFFFFFFFF),
                      ALGOS[algo]).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24
              | (digest[offset + 1] & 0xFF) << 16
              | (digest[offset + 2] & 0xFF) << 8
              | (digest[offset + 3] & 0xFF))
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret, ts, period, digits, algo):
    """TOTP per RFC 6238: HOTP with counter = floor(t / period)."""
    return hotp(secret, int(ts) // period, digits, algo)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="totp_check.py",
        description="Recomputes TOTP codes (RFC 6238) locally and shows them "
                    "for time-window offsets -3..+3.",
        epilog="KEY = bare Base32 secret OR otpauth://totp/...-URI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("key", help="Base32 secret or otpauth://totp/...-URI")
    parser.add_argument("--digits", type=int, default=None,
                        help="number of digits (default: 6, or from URI)")
    parser.add_argument("--period", type=int, default=None,
                        help="window length in seconds (default: 30, or from URI)")
    parser.add_argument("--algo", type=str.upper, default=None,
                        choices=sorted(ALGOS),
                        help="hash algorithm (default: SHA1, or from URI)")
    parser.add_argument("--time", type=int, default=None,
                        help="Unix timestamp to evaluate at "
                             "(default: current time; useful for tests)")
    args = parser.parse_args(argv)

    try:
        if args.key.startswith("otpauth://"):
            cfg = parse_uri(args.key)
        else:
            cfg = {"secret_raw": args.key, "digits": 6, "period": 30,
                   "algo": "SHA1", "schema": "", "source": "bare Base32 secret"}

        # apply overrides (only when explicitly set)
        cfg["algo"] = (args.algo or cfg["algo"]).upper()
        if cfg["algo"] not in ALGOS:
            raise ValueError(f"Unknown algorithm {cfg['algo']!r} "
                             f"(allowed: {', '.join(ALGOS)})")
        if args.digits is not None:
            cfg["digits"] = args.digits
        if args.period is not None:
            cfg["period"] = args.period
        if args.digits is not None and args.digits < 1:
            raise ValueError("--digits must be >= 1")
        if args.period is not None and args.period < 1:
            raise ValueError("--period must be >= 1")

        secret = decode_secret(cfg["secret_raw"])
        cfg["secret"] = secret
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # HOTP schema: no TOTP time comparison possible, but print a counter-based code
    if cfg["schema"] == "hotp":
        print("Warning: HOTP schema detected — a TOTP time comparison is not "
              "possible this way. (Bitwarden does not support HOTP either.)",
              file=sys.stderr)
        code = hotp(secret, cfg["counter"], cfg["digits"], cfg["algo"])
        print(f"Parameters: algorithm={cfg['algo']}, digits={cfg['digits']}, "
              f"secret length={len(secret)} bytes (source: {cfg['source']})")
        print(f"HOTP code for counter={cfg['counter']}: {code}")
        return 0

    now = float(args.time) if args.time is not None else time.time()
    period = cfg["period"]
    digits = cfg["digits"]
    algo = cfg["algo"]

    # Header line
    print(f"Parameters: algorithm={algo}, digits={digits}, period={period}s, "
          f"secret length={len(secret)} bytes (source: {cfg['source']})")
    print(f"Evaluation time (UTC): "
          f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))}  "
          f"(Unix {int(now)})")
    print()

    # Table of time windows
    print("  Offset | Window start (UTC)    | left(s) | Code")
    print("  -------+------------------------+---------+----------")
    current_window = int(now) // period
    for off in OFFSETS:
        counter = current_window + off
        start = counter * period
        code = hotp(secret, counter, digits, algo)
        left = period - (int(now) % period) if off == 0 else ""
        marker = "  <-- current" if off == 0 else ""
        start_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(start))
        left_str = f"{left}" if left != "" else "-"
        print(f"  {off:>6} | {start_utc:<22} | {left_str:>7} | {code}{marker}")
    print()
    print("Note: If your authenticator app's code appears at offset -1 or +1, "
          "the other device's clock drifts.")

    return 0


if __name__ == "__main__":
    sys.exit(main())