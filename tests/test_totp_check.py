#!/usr/bin/env python3
"""Verifikation für totp_check.py – RFC 6238-Testvektoren (aus dem Repo-Root lauffähig)."""
import base64
import subprocess
import sys
import urllib.parse
from pathlib import Path

# Repo-relativ: tests/ -> Repo-Wurzel (../)
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "totp_check.py"
failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f"  ({detail})" if detail else ""))
    if not cond:
        failures.append(name)


def run(args):
    return subprocess.run([sys.executable, str(SCRIPT)] + args,
                          capture_output=True, text=True)


def offset0_code(out):
    """Extracts the code of the offset-0 line (marked with <-- current)."""
    for line in out.splitlines():
        if "<-- current" in line:
            # Columns: Offset | Window start | left | Code <-- current
            return line.split("|")[3].split()[0]
    return None


# RFC-6238-Secrets
SEC_SHA1 = b"12345678901234567890"                       # 20 Bytes
SEC_SHA256 = b"12345678901234567890123456789012"         # 32 Bytes
SEC_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"  # 64 Bytes
B32_SHA1 = base64.b32encode(SEC_SHA1).decode().rstrip("=")          # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
B32_SHA256 = base64.b32encode(SEC_SHA256).decode().rstrip("=")
B32_SHA512 = base64.b32encode(SEC_SHA512).decode().rstrip("=")

check("Base32(SHA1-Secret) == GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      B32_SHA1 == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", B32_SHA1)

# ---------- Test 1: SHA1, T=59, 8 Ziffern -> 94287082; 6 Ziffern -> 287082 ----------
r = run([B32_SHA1, "--time", "59", "--digits", "8"])
check("Test1 SHA1 d8: Exit 0", r.returncode == 0, f"rc={r.returncode}")
check("Test1 SHA1 d8: Offset-0-Code == 94287082",
      offset0_code(r.stdout) == "94287082", offset0_code(r.stdout))

r = run([B32_SHA1, "--time", "59", "--digits", "6"])
check("Test1 SHA1 d6: Offset-0-Code == 287082",
      offset0_code(r.stdout) == "287082", offset0_code(r.stdout))

# ---------- Test 2: SHA256, T=59 -> 46119246 ----------
r = run([B32_SHA256, "--time", "59", "--digits", "8", "--algo", "SHA256"])
check("Test2 SHA256: Offset-0-Code == 46119246",
      offset0_code(r.stdout) == "46119246", offset0_code(r.stdout))
check("Test2 SHA256: Kopfzeile zeigt SHA256/8/30",
      "algorithm=SHA256" in r.stdout and "digits=8" in r.stdout
      and "period=30s" in r.stdout, r.stdout.splitlines()[0])

# ---------- Test 3: SHA512, T=59 -> 90693936 ----------
r = run([B32_SHA512, "--time", "59", "--digits", "8", "--algo", "SHA512"])
check("Test3 SHA512: Offset-0-Code == 90693936",
      offset0_code(r.stdout) == "90693936", offset0_code(r.stdout))

# ---------- Test 4: nackter Base32 lowercase + Leerzeichen + ohne Padding ----------
messy = B32_SHA1.lower()          # lowercase
messy = messy[:16] + " " + messy[16:24] + " - " + messy[24:]  # Leerzeichen + Bindestrich
messy = messy.rstrip("=")         # Padding entfernt (war eh keins, aber zur Sicherheit)
r = run([messy, "--time", "59", "--digits", "8"])
check("Test4 Normalisierung: Offset-0-Code == 94287082 (kanonische Form)",
      offset0_code(r.stdout) == "94287082", f"input={messy!r} -> {offset0_code(r.stdout)}")
check("Test4: Quelle = nackter Base32-Secret",
      "bare Base32 secret" in r.stdout, r.stdout.splitlines()[0])

# ---------- Test 5: otpauth-URI mit digits=8&period=30&algorithm=SHA256 ----------
uri = ("otpauth://totp/Test:user@example.com?secret=" + B32_SHA256 +
       "&digits=8&period=30&algorithm=SHA256&issuer=Test")
r = run([uri, "--time", "59"])
check("Test5 URI: Exit 0", r.returncode == 0, f"rc={r.returncode}")
check("Test5 URI: Kopfzeile zeigt SHA256/8/30",
      "algorithm=SHA256" in r.stdout and "digits=8" in r.stdout
      and "period=30s" in r.stdout, r.stdout.splitlines()[0])
check("Test5 URI: Quelle = otpauth-URI",
      "source: otpauth URI" in r.stdout, r.stdout.splitlines()[0])
check("Test5 URI: Offset-0-Code == 46119246",
      offset0_code(r.stdout) == "46119246", offset0_code(r.stdout))

# ---------- Zusatz: ungültiger Base32 -> Fehler, Exit 1 ----------
r = run(["!!!kein-base32!!!", "--time", "59"])
check("Ungültiger Base32: Exit 1 + Fehlermeldung",
      r.returncode == 1 and "Error" in r.stderr, f"rc={r.returncode} stderr={r.stderr.strip()}")

# ---------- Zusatz: URI ohne secret -> Fehler, Exit 1 ----------
r = run(["otpauth://totp/x?digits=6"])
check("URI ohne secret: Exit 1", r.returncode == 1 and "secret" in r.stderr,
      f"rc={r.returncode} stderr={r.stderr.strip()}")

# ---------- Zusatz: HOTP-URI -> Warnung + counter-Code ----------
r = run(["otpauth://hotp/x?secret=" + B32_SHA1 + "&counter=42&digits=6"])
check("HOTP-URI: Warnung + Counter-Code",
      r.returncode == 0 and "HOTP code for counter=42" in r.stdout
      and "TOTP time comparison" in r.stderr,
      f"rc={r.returncode} out={r.stdout.strip()} err={r.stderr.strip()}")

# ---------- Zusatz: Kopfzeile enthält Secret-Länge (20 Bytes) ----------
r = run([B32_SHA1, "--time", "59"])
check("Kopfzeile: Secret-Länge 20 Bytes",
      "secret length=20 bytes" in r.stdout, r.stdout.splitlines()[0])

# ---------- Zusatz: Hinweiszeile Zeitabweichung vorhanden ----------
r = run([B32_SHA1, "--time", "59"])
check("Hinweiszeile Zeitabweichung",
      "offset -1 or +1" in r.stdout and "clock drifts" in r.stdout,
      "ok")

print()
if failures:
    print(f"{len(failures)} CHECK(S) FEHLGESCHLAGEN: {failures}")
    sys.exit(1)
print("ALLE CHECKS BESTANDEN.")