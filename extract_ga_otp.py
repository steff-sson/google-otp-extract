#!/usr/bin/env python3
# Offline decoder for Google Authenticator export (otpauth-migration). Runs without a network.
#
# Decodes an export URI of the form
#   otpauth-migration://offline?data=<urlencoded-urlsafe-base64-protobuf>
# offline and prints, per account, the Base32 secret plus a ready-to-paste
# otpauth://totp/... URI (e.g. for Bitwarden).
#
# Usage:
#   python3 extract_ga_otp.py "<URI>"
#   python3 extract_ga_otp.py @/path/to/file.txt
#
# Python standard library only, no network access of any kind.

import base64
import binascii
import os
import sys
import urllib.parse

# Enum mappings from the Google otpauth-migration protobuf.
# IMPORTANT: 0 = UNSPECIFIED -> default (SHA1 / 6 digits / TOTP).
# algorithm: 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5
# digits:    1=SIX(6), 2=EIGHT(8), 3=SEVEN(7)
# type:      1=HOTP, 2=TOTP
ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8, 3: 7}
TYPES = {0: "TOTP", 1: "HOTP", 2: "TOTP"}


def usage(stream=sys.stderr):
    print("Usage:", file=stream)
    print('  python3 extract_ga_otp.py "<URI>"', file=stream)
    print("  python3 extract_ga_otp.py @/path/to/file.txt", file=stream)
    print("The URI is a Google Authenticator export of the form", file=stream)
    print("  otpauth-migration://offline?data=<urlencoded-urlsafe-base64>", file=stream)


def read_input(arg):
    """Returns the raw URI text — from the argument or from a file."""
    if arg.startswith("otpauth-migration://"):
        return arg
    # "@path" forces file handling; otherwise, if the argument is an existing
    # file, treat it as a file too.
    if arg.startswith("@"):
        path = arg[1:]
    elif os.path.isfile(arg):
        path = arg
    else:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def clean_uri(raw):
    """Strips leading/trailing whitespace and surrounding quotes."""
    raw = raw.strip()
    while len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
        raw = raw[1:-1].strip()
    return raw


def extract_data(uri):
    """Splits the URI and returns the (already URL-decoded) data value."""
    parts = urllib.parse.urlparse(uri)
    if parts.scheme != "otpauth-migration":
        raise ValueError("Not a valid otpauth-migration:// URI")
    params = urllib.parse.parse_qs(parts.query)
    if "data" not in params:
        raise ValueError('Parameter "data" is missing in the URI')
    return params["data"][0]


def decode_data(data):
    """URL-safe Base64 -> standard Base64 -> bytes (with validation)."""
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid Base64 data: {exc}") from exc


class Reader:
    """Minimal byte reader for the hand-written protobuf parser."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def eof(self):
        return self.pos >= len(self.data)

    def read_byte(self):
        if self.pos >= len(self.data):
            raise ValueError("Protobuf data ended unexpectedly (truncated)")
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
                raise ValueError("Varint too long")

    def read_bytes(self, length):
        if self.pos + length > len(self.data):
            raise ValueError("Length-delimited field exceeds end of data")
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    def read_tag(self):
        return self.read_varint()

    def skip(self, wire_type):
        """Skips an unknown field based on its wire type."""
        if wire_type == 0:      # varint
            self.read_varint()
        elif wire_type == 2:    # length-delimited
            self.read_bytes(self.read_varint())
        elif wire_type == 5:    # fixed32
            self.read_bytes(4)
        elif wire_type == 1:    # fixed64
            self.read_bytes(8)
        else:
            raise ValueError(f"Unknown wire type {wire_type}")


def parse_otp_parameters(data):
    """Parses an OtpParameters message (field 1 of the MigrationPayload)."""
    r = Reader(data)
    account = {
        "secret": b"",
        "name": "",
        "issuer": "",
        "algorithm": 0,   # SHA1
        "digits": 0,      # 6
        "type": 0,        # TOTP
        "counter": None,  # only relevant for HOTP
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
    """Parses the MigrationPayload: field 1 (repeated) = OtpParameters."""
    r = Reader(data)
    accounts = []
    while not r.eof():
        tag = r.read_tag()
        field = tag >> 3
        wire = tag & 7
        if field == 1 and wire == 2:
            accounts.append(parse_otp_parameters(r.read_bytes(r.read_varint())))
        else:
            r.skip(wire)  # skip unknown top-level fields
    return accounts


def build_otpauth(account):
    """Builds the otpauth URI (only non-default parameters)."""
    algo = ALGORITHMS.get(account["algorithm"])
    if algo is None:
        print(f"  Warning: Unknown algorithm value "
              f"{account['algorithm']}; falling back to SHA1.", file=sys.stderr)
        algo = "SHA1"
    digits = DIGITS.get(account["digits"])
    if digits is None:
        print(f"  Warning: Unknown digits value {account['digits']}; "
              f"falling back to 6.", file=sys.stderr)
        digits = 6
    typ = TYPES.get(account["type"])
    if typ is None:
        print(f"  Warning: Unknown type value {account['type']}; "
              f"falling back to TOTP.", file=sys.stderr)
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
        print(f'Error: No argument, no otpauth-migration:// URI and no '
              f'file "{argv[1]}" found.', file=sys.stderr)
        usage()
        return 2

    uri = clean_uri(raw)
    try:
        payload_bytes = decode_data(extract_data(uri))
        accounts = parse_payload(payload_bytes)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not accounts:
        print("Error: No accounts found in the MigrationPayload. "
              "The URI might be incomplete or corrupted.",
              file=sys.stderr)
        return 1

    for idx, acc in enumerate(accounts, start=1):
        uri_out, typ, algo, digits, issuer, name = build_otpauth(acc)
        secret = base64.b32encode(acc["secret"]).decode("ascii").rstrip("=")
        print(f"Account {idx}: Issuer='{issuer}'  Name='{name}'")
        print(f"  Secret (Base32): {secret}")
        print("  Paste into Bitwarden:")
        print(f"    {uri_out}")
        if typ == "HOTP":
            print("  Warning: Bitwarden does not support HOTP! "
                  "These credentials cannot be imported.", file=sys.stderr)
        if idx < len(accounts):
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))