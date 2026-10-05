#!/usr/bin/env python3
# Offline-Decoder für Google Authenticator Export (otpauth-migration). Läuft ohne Netzwerk.
#
# Dekodiert eine Export-URI der Form
#   otpauth-migration://offline?data=<urlencoded-urlsafe-base64-protobuf>
# offline und gibt pro Konto den Base32-Secret sowie eine fertige
# otpauth://totp/...-URI aus, die man z. B. in Bitwarden einfügen kann.
#
# Aufruf:
#   python3 extract_ga_otp.py "<URI>"
#   python3 extract_ga_otp.py @/pfad/zur/datei.txt
#
# Nur Python-Standardbibliothek, keinerlei Netzwerkzugriff.

import base64
import binascii
import os
import sys
import urllib.parse

# Enum-Zuordnungen aus dem Google-otpauth-Migration-Protobuf.
# WICHTIG: 0 = UNSPECIFIED -> Default (SHA1 / 6 Stellen / TOTP).
# algorithm: 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5
# digits:    1=SIX(6), 2=EIGHT(8), 3=SEVEN(7)
# type:      1=HOTP, 2=TOTP
ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8, 3: 7}
TYPES = {0: "TOTP", 1: "HOTP", 2: "TOTP"}


def usage(stream=sys.stderr):
    print("Aufruf:", file=stream)
    print('  python3 extract_ga_otp.py "<URI>"', file=stream)
    print("  python3 extract_ga_otp.py @/pfad/zur/datei.txt", file=stream)
    print("Die URI ist ein Google-Authenticator-Export der Form", file=stream)
    print("  otpauth-migration://offline?data=<urlencoded-urlsafe-base64>", file=stream)


def read_input(arg):
    """Liefert den Rohtext der URI – aus dem Argument oder aus einer Datei."""
    if arg.startswith("otpauth-migration://"):
        return arg
    # "@pfad" erzwingt Datei-Behandlung; sonst: wenn das Argument eine
    # existierende Datei ist, ebenfalls als Datei behandeln.
    if arg.startswith("@"):
        path = arg[1:]
    elif os.path.isfile(arg):
        path = arg
    else:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def clean_uri(raw):
    """Entfernt führendes/trailing Whitespace und umschließende Anführungszeichen."""
    raw = raw.strip()
    while len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
        raw = raw[1:-1].strip()
    return raw


def extract_data(uri):
    """Zerlegt die URI und liefert den (bereits URL-dekodierten) data-Wert."""
    parts = urllib.parse.urlparse(uri)
    if parts.scheme != "otpauth-migration":
        raise ValueError("Keine gültige otpauth-migration://-URI")
    params = urllib.parse.parse_qs(parts.query)
    if "data" not in params:
        raise ValueError('Parameter "data" fehlt in der URI')
    return params["data"][0]


def decode_data(data):
    """URL-safe Base64 -> Standard-Base64 -> Bytes (mit Fehlerprüfung)."""
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Ungültige Base64-Daten: {exc}") from exc


class Reader:
    """Minimaler Byte-Reader für einen handgeschriebenen Protobuf-Parser."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def eof(self):
        return self.pos >= len(self.data)

    def read_byte(self):
        if self.pos >= len(self.data):
            raise ValueError("Protobuf-Daten unerwartet zu Ende (truncated)")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_varint(self):
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
            if shift > 63:
                raise ValueError("Varint zu lang")

    def read_bytes(self, length):
        if self.pos + length > len(self.data):
            raise ValueError("Length-delimited Feld überschreitet Datenende")
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    def read_tag(self):
        return self.read_varint()

    def skip(self, wire_type):
        """Überspringt ein unbekanntes Feld anhand seines Wire Type."""
        if wire_type == 0:      # varint
            self.read_varint()
        elif wire_type == 2:    # length-delimited
            self.read_bytes(self.read_varint())
        elif wire_type == 5:    # fixed32
            self.read_bytes(4)
        elif wire_type == 1:    # fixed64
            self.read_bytes(8)
        else:
            raise ValueError(f"Unbekannter Wire Type {wire_type}")


def parse_otp_parameters(data):
    """Parst eine OtpParameters-Message (Feld 1 der MigrationPayload)."""
    r = Reader(data)
    account = {
        "secret": b"",
        "name": "",
        "issuer": "",
        "algorithm": 0,   # SHA1
        "digits": 0,      # 6
        "type": 0,        # TOTP
        "counter": None,  # nur für HOTP relevant
    }
    while not r.eof():
        tag = r.read_tag()
        field = tag >> 3
        wire = tag & 7
        if field == 1 and wire == 2:
            account["secret"] = r.read_bytes(r.read_varint())
        elif field == 2 and wire == 2:
            account["name"] = r.read_bytes(r.read_varint()).decode("utf-8")
        elif field == 3 and wire == 2:
            account["issuer"] = r.read_bytes(r.read_varint()).decode("utf-8")
        elif field == 4 and wire == 0:
            account["algorithm"] = r.read_varint()
        elif field == 5 and wire == 0:
            account["digits"] = r.read_varint()
        elif field == 6 and wire == 0:
            account["type"] = r.read_varint()
        elif field == 7 and wire == 0:
            account["counter"] = r.read_varint()
        else:
            r.skip(wire)
    return account


def parse_payload(data):
    """Parst die MigrationPayload: Feld 1 (repeated) = OtpParameters."""
    r = Reader(data)
    accounts = []
    while not r.eof():
        tag = r.read_tag()
        field = tag >> 3
        wire = tag & 7
        if field == 1 and wire == 2:
            accounts.append(parse_otp_parameters(r.read_bytes(r.read_varint())))
        else:
            r.skip(wire)  # unbekannte Top-Level-Felder überspringen
    return accounts


def build_otpauth(account):
    """Erzeugt die otpauth-URI (nur Nicht-Default-Parameter)."""
    algo = ALGORITHMS.get(account["algorithm"])
    if algo is None:
        print(f"  Warnung: Unbekannter Algorithmus-Wert "
              f"{account['algorithm']}; verwende Default SHA1.", file=sys.stderr)
        algo = "SHA1"
    digits = DIGITS.get(account["digits"])
    if digits is None:
        print(f"  Warnung: Unbekannter digits-Wert {account['digits']}; "
              f"verwende Default 6.", file=sys.stderr)
        digits = 6
    typ = TYPES.get(account["type"])
    if typ is None:
        print(f"  Warnung: Unbekannter type-Wert {account['type']}; "
              f"verwende Default TOTP.", file=sys.stderr)
        typ = "TOTP"

    issuer = (account["issuer"] or "").strip()
    name = (account["name"] or "").strip()
    label = f"{issuer}:{name}" if issuer else name
    label_q = urllib.parse.quote(label, safe=":@")

    scheme = "hotp" if typ == "HOTP" else "totp"
    params = {"secret": base64.b32encode(account["secret"]).decode("ascii").rstrip("=")}
    if issuer:
        params["issuer"] = issuer
    if algo != "SHA1":
        params["algorithm"] = algo
    if digits != 6:
        params["digits"] = str(digits)
    if typ == "HOTP":
        params["counter"] = str(account["counter"] if account["counter"] is not None else 0)

    uri = f"otpauth://{scheme}/{label_q}?" + urllib.parse.urlencode(params)
    return uri, typ, algo, digits, issuer, name


def main(argv):
    if len(argv) < 2:
        usage()
        return 2

    raw = read_input(argv[1])
    if raw is None:
        print(f'Fehler: Kein Argument, keine otpauth-migration://-URI und keine '
              f'Datei "{argv[1]}" gefunden.', file=sys.stderr)
        usage()
        return 2

    uri = clean_uri(raw)
    try:
        payload_bytes = decode_data(extract_data(uri))
        accounts = parse_payload(payload_bytes)
    except ValueError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

    if not accounts:
        print("Fehler: Keine Konten in der MigrationPayload gefunden. "
              "Die URI könnte unvollständig oder beschädigt sein.",
              file=sys.stderr)
        return 1

    for idx, acc in enumerate(accounts, start=1):
        uri_out, typ, algo, digits, issuer, name = build_otpauth(acc)
        secret = base64.b32encode(acc["secret"]).decode("ascii").rstrip("=")
        print(f"Konto {idx}: Issuer='{issuer}'  Name='{name}'")
        print(f"  Secret (Base32): {secret}")
        print("  Für Bitwarden einfügen:")
        print(f"    {uri_out}")
        if typ == "HOTP":
            print("  Warnung: Bitwarden unterstützt kein HOTP! "
                  "Diese Konto-Daten lassen sich nicht importieren.", file=sys.stderr)
        if idx < len(accounts):
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
