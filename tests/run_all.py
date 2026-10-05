#!/usr/bin/env python3
"""Führt alle Repo-Tests als Subprozesse aus und fasst die Ergebnisse zusammen.

Exit-Code 0 nur, wenn alle Test-Dateien grün sind.
Aufruf:  python3 tests/run_all.py
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent

TEST_FILES = [
    TESTS_DIR / "test_extract_ga_otp.py",
    TESTS_DIR / "test_totp_check.py",
]


def main():
    results = []
    overall = 0
    print(f"=== google-otp-extract: Testlauf (Repo-Root: {REPO_ROOT}) ===\n")
    for tf in TEST_FILES:
        print(f"--- {tf.name} ---")
        proc = subprocess.run([sys.executable, str(tf)],
                              capture_output=True, text=True)
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        ok = proc.returncode == 0
        results.append((tf.name, ok, proc.returncode))
        if not ok:
            overall = 1
        print()
    print("=== Zusammenfassung ===")
    for name, ok, rc in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name} (rc={rc})")
    if overall == 0:
        print("ALLE TESTS BESTANDEN.")
    else:
        print("TESTS FEHLGESCHLAGEN.")
    return overall


if __name__ == "__main__":
    sys.exit(main())