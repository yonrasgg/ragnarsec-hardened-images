#!/usr/bin/env python3
"""Check the Jenkins key against the approved public key before registry access."""

import os
from pathlib import Path
import subprocess
import tempfile

APPROVED_PUBLIC_KEY = Path(__file__).resolve().parents[1] / "cosign.pub"


def verify_signing_key(key_path, approved_path=APPROVED_PUBLIC_KEY):
    if not key_path or not Path(key_path).is_file():
        raise ValueError("signing-key-not-configured")
    if not approved_path.is_file():
        raise ValueError("approved-signing-key-missing")
    approved = approved_path.read_bytes().strip().replace(b"\r\n", b"\n")
    if not approved:
        raise ValueError("approved-signing-key-missing")
    with tempfile.TemporaryDirectory(prefix="release-signing-") as temporary:
        derived = Path(temporary) / "public.pem"
        subprocess.run(["cosign", "public-key", "--key", key_path, "--outfile", str(derived)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not derived.is_file() or derived.read_bytes().strip().replace(b"\r\n", b"\n") != approved:
            raise ValueError("signing-key-does-not-match-approved-public-key")


if __name__ == "__main__":
    try:
        verify_signing_key(os.environ.get("COSIGN_KEY"))
    except ValueError as error:
        raise SystemExit(str(error)) from None
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit("signing-key-check-failed") from None
    print("Approved release signing key verified.")
