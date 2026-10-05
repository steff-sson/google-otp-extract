#!/usr/bin/env python3
# Lokaler TOTP-Rechner zum Abgleich von Authenticator-Codes.
# Rechnet TOTP-Codes nach RFC 6238 / HOTP nach RFC 4226 lokal nach,
# um bei "falscher Zahlenfolge in Bitwarden" die Ursache zu finden
# (Secret korrekt? Zeitabweichung? Algorithmus/Stellen?).
# Läuft offline, ohne Netzwerk. Nur Python-Standardbibliothek.

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
    """Entfernt Leerzeichen/Bindestriche/URL-safe-Zeichen, uppercase, Padding ergänzen."""
    cleaned = (
        raw.replace(" ", "").replace("-", "").replace("_", "")
        .replace("\t", "").replace("\n", "").replace("\r", "")
    ).upper()
    return cleaned + "=" * ((8 - len(cleaned) % 8) % 8)


def decode_secret(raw):
    try:
        return base64.b32decode(normalize_base32(raw))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Ungültiger Base32-Secret: {exc}") from exc


def parse_uri(uri):
    """Parst eine otpauth://totp/... oder otpauth://hotp/...-URI."""
    parts = urllib.parse.urlparse(uri)
    if parts.scheme != "otpauth":
        raise ValueError("Keine gültige otpauth://-URI")
    params = urllib.parse.parse_qs(parts.query)
    if "secret" not in params or not params["secret"][0]:
        raise ValueError('Parameter "secret" fehlt in der otpauth-URI')

    def _int(name, default):
        try:
            return int(params.get(name, [default])[0])
        except (TypeError, ValueError) as exc:
            raise ValueError(f'Parameter "{name}" ist keine gültige Zahl: '
                             f'{params.get(name, [default])[0]!r}') from exc

    algo = params.get("algorithm", ["SHA1"])[0].upper()
    if algo not in ALGOS:
        raise ValueError(f"Unbekannter Algorithmus {algo!r} "
                         f"(erlaubt: {', '.join(ALGOS)})")

    cfg = {
        "secret_raw": params["secret"][0],
        "digits": _int("digits", 6),
        "period": _int("period", 30),
        "algo": algo,
        "schema": parts.netloc.lower(),
        "source": "otpauth-URI",
    }
    if cfg["schema"] == "hotp":
        cfg["counter"] = _int("counter", 0)
    return cfg


def hotp(secret, counter, digits, algo):
    """HOTP nach RFC 4226 (HMAC + dynamische Truncation)."""
    digest = hmac.new(secret, struct.pack(">Q", counter & 0xFFFFFFFFFFFFFFFF),
                      ALGOS[algo]).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24
              | (digest[offset + 1] & 0xFF) << 16
              | (digest[offset + 2] & 0xFF) << 8
              | (digest[offset + 3] & 0xFF))
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret, ts, period, digits, algo):
    """TOTP nach RFC 6238: HOTP mit Counter = floor(t / period)."""
    return hotp(secret, int(ts) // period, digits, algo)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="totp_check.py",
        description="Rechnet TOTP-Codes (RFC 6238) lokal nach und zeigt sie "
                    "für Zeitfenster-Offsets -3..+3 an.",
        epilog="KEY = nackter Base32-Secret ODER otpauth://totp/...-URI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("key", help="Base32-Secret oder otpauth://totp/...-URI")
    parser.add_argument("--digits", type=int, default=None,
                        help="Anzahl der Ziffern (Default: 6 bzw. aus URI)")
    parser.add_argument("--period", type=int, default=None,
                        help="Fensterlänge in Sekunden (Default: 30 bzw. aus URI)")
    parser.add_argument("--algo", type=str.upper, default=None,
                        choices=sorted(ALGOS),
                        help="Hash-Algorithmus (Default: SHA1 bzw. aus URI)")
    parser.add_argument("--time", type=int, default=None,
                        help="Unix-Zeitstempel für die Auswertung "
                             "(Default: aktuelle Zeit; nützlich für Tests)")
    args = parser.parse_args(argv)

    try:
        if args.key.startswith("otpauth://"):
            cfg = parse_uri(args.key)
        else:
            cfg = {"secret_raw": args.key, "digits": 6, "period": 30,
                   "algo": "SHA1", "schema": "", "source": "nackter Base32-Secret"}

        # Overrides anwenden (nur wenn explizit gesetzt)
        cfg["algo"] = (args.algo or cfg["algo"]).upper()
        if cfg["algo"] not in ALGOS:
            raise ValueError(f"Unbekannter Algorithmus {cfg['algo']!r} "
                             f"(erlaubt: {', '.join(ALGOS)})")
        if args.digits is not None:
            cfg["digits"] = args.digits
        if args.period is not None:
            cfg["period"] = args.period
        if args.digits is not None and args.digits < 1:
            raise ValueError("--digits muss >= 1 sein")
        if args.period is not None and args.period < 1:
            raise ValueError("--period muss >= 1 sein")

        secret = decode_secret(cfg["secret_raw"])
        cfg["secret"] = secret
    except ValueError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

    # HOTP-Schema: TOTP-Zeitvergleich nicht möglich, aber Counter-Code ausgeben
    if cfg["schema"] == "hotp":
        print("Warnung: HOTP-Schema erkannt – ein TOTP-Zeitvergleich ist so "
              "nicht möglich. (Bitwarden unterstützt zudem kein HOTP.)",
              file=sys.stderr)
        code = hotp(secret, cfg["counter"], cfg["digits"], cfg["algo"])
        print(f"Parameter: Algorithmus={cfg['algo']}, Ziffern={cfg['digits']}, "
              f"Secret-Länge={len(secret)} Bytes (Quelle: {cfg['source']})")
        print(f"HOTP-Code für counter={cfg['counter']}: {code}")
        return 0

    now = float(args.time) if args.time is not None else time.time()
    period = cfg["period"]
    digits = cfg["digits"]
    algo = cfg["algo"]

    # Kopfzeile
    print(f"Parameter: Algorithmus={algo}, Ziffern={digits}, Periode={period}s, "
          f"Secret-Länge={len(secret)} Bytes (Quelle: {cfg['source']})")
    print(f"Auswertungszeit (UTC): "
          f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))}  "
          f"(Unix {int(now)})")
    print()

    # Tabelle der Zeitfenster
    print("  Offset | Fensterstart (UTC)     | noch(s) | Code")
    print("  -------+------------------------+---------+----------")
    current_window = int(now) // period
    for off in OFFSETS:
        counter = current_window + off
        start = counter * period
        code = hotp(secret, counter, digits, algo)
        noch = period - (int(now) % period) if off == 0 else ""
        marker = "  <-- aktuell" if off == 0 else ""
        start_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(start))
        noch_str = f"{noch}" if noch != "" else "-"
        print(f"  {off:>6} | {start_utc:<22} | {noch_str:>7} | {code}{marker}")
    print()
    print("Hinweis: Wenn der Code deiner Authenticator-App zu Offset -1 oder +1 "
          "auftaucht, weicht die Uhr des anderen Geräts ab.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
