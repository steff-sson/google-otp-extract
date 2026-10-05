#!/usr/bin/env python3
"""Verifikation für extract_ga_otp.py (aus dem Repo-Root lauffähig)."""
import base64
import subprocess
import sys
import urllib.parse
from pathlib import Path

# Repo-relativ: tests/ -> Repo-Wurzel (../)
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "extract_ga_otp.py"
TOTP_CHECK = REPO_ROOT / "totp_check.py"
failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f"  ({detail})" if detail else ""))
    if not cond:
        failures.append(name)


# ---------- Mini-Protobuf-Encoder (nur für den Test) ----------
def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def field_varint(num, value):
    return varint((num << 3) | 0) + varint(value)


def field_bytes(num, data):
    return varint((num << 3) | 2) + varint(len(data)) + data


def otp_params(secret, name="", issuer="", algorithm=0, digits=0, typ=0, counter=None):
    m = b""
    if secret:
        m += field_bytes(1, secret)
    if name:
        m += field_bytes(2, name.encode("utf-8"))
    if issuer:
        m += field_bytes(3, issuer.encode("utf-8"))
    if algorithm is not None:
        m += field_varint(4, algorithm)
    if digits is not None:
        m += field_varint(5, digits)
    if typ is not None:
        m += field_varint(6, typ)
    if counter is not None:
        m += field_varint(7, counter)
    return m


def payload(accounts, extra=None):
    m = b""
    for acc in accounts:
        m += field_bytes(1, acc)
    if extra:
        for num, val in extra:   # unbekannte Top-Level-Felder
            m += field_varint(num, val)
    return m


def make_uri(proto_bytes):
    b64 = base64.urlsafe_b64encode(proto_bytes).decode("ascii")
    return "otpauth-migration://offline?data=" + urllib.parse.quote(b64)


def run(script, args):
    return subprocess.run([sys.executable, str(script)] + args,
                          capture_output=True, text=True)


# ---------- Basis-Verifikation: Base32 der Test-Secret-Bytes ----------
SECRET = b"Hello!\xde\xad\xbe\xef"
expected_b32 = base64.b32encode(SECRET).decode("ascii").rstrip("=")
check("Base32(secret) == JBSWY3DPEHPK3PXP", expected_b32 == "JBSWY3DPEHPK3PXP",
      f"actual={expected_b32}")

# ---------- Test 1 (REALWERTE): ein Konto algorithm=1, digits=1, type=2 ----------
# Erwartung: SHA1 / 6 Stellen / TOTP -> URI ohne digits- und algorithm-Parameter
name = "Test:user@example.com"
issuer = "TestIssuer"
proto = payload([otp_params(SECRET, name=name, issuer=issuer,
                            algorithm=1, digits=1, typ=2)])
uri = make_uri(proto)

r = run(SCRIPT, [uri])
check("Test1: Exit-Code 0", r.returncode == 0, f"rc={r.returncode}")
check("Test1: Base32-Secret korrekt", "JBSWY3DPEHPK3PXP" in r.stdout, r.stdout)
check("Test1: Name korrekt", f"Name='{name}'" in r.stdout, r.stdout)
check("Test1: Issuer korrekt", f"Issuer='{issuer}'" in r.stdout, r.stdout)
check("Test1: URI ohne digits/algorithm (Defaults SHA1/6/TOTP)",
      "otpauth://totp/TestIssuer:Test%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestIssuer" in r.stdout
      or "otpauth://totp/TestIssuer:Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestIssuer" in r.stdout,
      r.stdout)
check("Test1: kein 'digits=' und kein 'algorithm=' in URI",
      "digits=" not in r.stdout and "algorithm=" not in r.stdout, r.stdout)
check("Test1: KEINE Hotp-Warnung bei type=2 (TOTP)",
      "Bitwarden unterstützt kein HOTP" not in r.stderr, r.stderr)
# konserviere die erzeugte otpauth-URI für den Chain-Test
chain_uri = None
for line in r.stdout.splitlines():
    s = line.strip()
    if s.startswith("otpauth://totp/") or s.startswith("otpauth://hotp/"):
        chain_uri = s

# ---------- Test 1b: digits=2 -> digits=8 ; digits=3 -> digits=7 ----------
r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="d", issuer="I",
                                              algorithm=1, digits=2, typ=2)]))])
check("digits=2 -> digits=8 in URI",
      "digits=8" in r.stdout and "digits=7" not in r.stdout, r.stdout)

r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="d", issuer="I",
                                              algorithm=1, digits=3, typ=2)]))])
check("digits=3 -> digits=7 in URI",
      "digits=7" in r.stdout, r.stdout)

# ---------- Test 1c: algorithm=2 -> SHA256 ; algorithm=3 -> SHA512 ----------
r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="a", issuer="I",
                                              algorithm=2, digits=1, typ=2)]))])
check("algorithm=2 -> algorithm=SHA256 in URI",
      "algorithm=SHA256" in r.stdout, r.stdout)

r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="a", issuer="I",
                                              algorithm=3, digits=1, typ=2)]))])
check("algorithm=3 -> algorithm=SHA512 in URI",
      "algorithm=SHA512" in r.stdout, r.stdout)

# ---------- Test 1d: type=1 -> hotp-Schema + Warnung + counter ----------
r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="h", issuer="I",
                                              algorithm=1, digits=1, typ=1, counter=42)]))])
check("type=1 -> hotp-Schema + counter + Warnung",
      r.returncode == 0 and "otpauth://hotp/" in r.stdout and "counter=42" in r.stdout
      and "Bitwarden unterstützt kein HOTP" in r.stderr,
      f"rc={r.returncode} out={r.stdout.strip()} err={r.stderr.strip()}")

# ---------- Test 1e: unbekannte Enum-Werte -> Warnung + Default ----------
r = run(SCRIPT, [make_uri(payload([otp_params(SECRET, name="u", issuer="I",
                                              algorithm=99, digits=99, typ=99)]))])
check("unbekannte Enums: Defaults + Warnung auf stderr",
      r.returncode == 0 and "otpauth://totp/" in r.stdout
      and "digits=" not in r.stdout and "algorithm=" not in r.stdout
      and "Unbekannter Algorithmus" in r.stderr
      and "Unbekannter digits" in r.stderr
      and "Unbekannter type" in r.stderr,
      f"out={r.stdout.strip()} err={r.stderr.strip()}")

# ---------- Test 2: zwei Konten + unbekanntes varint-Feld (batch_index) ----------
secret2 = b"secret-two-1234567890"
proto2 = payload([
    otp_params(SECRET, name="user1@example.com", issuer="A", algorithm=1, digits=1, typ=2),
    otp_params(secret2, name="user2@example.com", issuer="B",
               algorithm=2, digits=2, typ=2),
], extra=[(2, 0)])  # batch_index = Feld 2, varint
uri2 = make_uri(proto2)

r2 = run(SCRIPT, [uri2])
check("Test2: Exit-Code 0", r2.returncode == 0, f"rc={r2.returncode}")
check("Test2: zwei Konto-Blöcke", r2.stdout.count("Konto ") == 2, r2.stdout)
check("Test2: Konto1-Secret", "JBSWY3DPEHPK3PXP" in r2.stdout, r2.stdout)
exp2 = base64.b32encode(secret2).decode().rstrip("=")
check("Test2: Konto2-Secret", exp2 in r2.stdout, f"exp={exp2}")
check("Test2: Konto2 algorithm=SHA256 & digits=8 im URI",
      "algorithm=SHA256&digits=8" in r2.stdout, r2.stdout)

# ---------- Test 3: kaputte Base64 -> Fehler, Exit-Code 1 ----------
r3 = run(SCRIPT, ["otpauth-migration://offline?data=!!!not-base64!!!"])
check("Test3: Exit-Code 1", r3.returncode == 1, f"rc={r3.returncode}")
check("Test3: Fehlermeldung auf stderr", "Fehler" in r3.stderr, r3.stderr)

# ---------- Zusatz: Datei-Eingabe (@file und Plain-File), Whitespace/Quotes ----------
tmp_uri_file = REPO_ROOT / "tests" / ".test_uri.txt"
tmp_uri_file.write_text(f'  "{uri}"  \n', encoding="utf-8")

r4 = run(SCRIPT, ["@" + str(tmp_uri_file)])
check("Datei (@): Exit 0 & korrekt", r4.returncode == 0 and "JBSWY3DPEHPK3PXP" in r4.stdout,
      f"rc={r4.returncode}")

r5 = run(SCRIPT, [str(tmp_uri_file)])
check("Datei (plain): Exit 0 & korrekt", r5.returncode == 0 and "JBSWY3DPEHPK3PXP" in r5.stdout,
      f"rc={r5.returncode}")

# ---------- Zusatz: kein Argument -> Usage ----------
r6 = run(SCRIPT, [])
check("Kein Argument: Usage auf stderr", r6.returncode != 0 and "Aufruf" in r6.stderr,
      f"rc={r6.returncode}")

# ---------- Zusatz: 0 Konten -> Fehler ----------
r7 = run(SCRIPT, [make_uri(field_varint(2, 0))])  # nur unbekanntes Feld, keine Konten
check("0 Konten: Exit 1 + Hinweis", r7.returncode == 1 and "unvollständig" in r7.stderr,
      f"rc={r7.returncode} stderr={r7.stderr.strip()}")

# ---------- CHAIN-Test: erzeugte otpauth-URI an totp_check.py verfüttern ----------
check("Chain-Vorbereitung: otpauth-URI erzeugt", chain_uri is not None, r.stdout)
if chain_uri:
    rc = run(TOTP_CHECK, [chain_uri])
    check("Chain: totp_check Exit 0", rc.returncode == 0, f"rc={rc.returncode}")
    check("Chain: Kopfzeile SHA1/6/30",
          "Algorithmus=SHA1" in rc.stdout and "Ziffern=6" in rc.stdout
          and "Periode=30s" in rc.stdout,
          rc.stdout.splitlines()[0] if rc.stdout else "")
    check("Chain: ein Code erscheint",
          any(c.isdigit() and len(c) == 6 for c in rc.stdout.replace("|", " ").split()),
          rc.stdout)

print()
if failures:
    print(f"{len(failures)} CHECK(S) FEHLGESCHLAGEN: {failures}")
    sys.exit(1)
print("ALLE CHECKS BESTANDEN.")