#!/usr/bin/env python3
"""
Forged-receipt / key-resolution attack PoC  (acceptance gate for FIRST_TASKS T1).

The attack: an attacker ships a forged receipt AND their own signing_pubkey.json
in the SAME folder. If `railcall verify` will load a key from the receipt's own
directory, the forged receipt "verifies" against the attacker's key -> self-attesting.

SECURE behavior (what this asserts):
  - verifying the forged receipt WITHOUT --key, on a machine with no install key,
    must NOT print SIGNATURE VALID. It should refuse / say it can't find a trusted key.
  - (documented, not attacked here) passing --key <dir> is the only way to trust an
    external key, and the output must attribute it as user-supplied.

Exit 0 = loophole closed (secure).  Exit 1 = VULNERABLE.
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.normpath(os.path.join(HERE, "..", "..", "cli", "railcall_cli.py"))


def main():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("SKIP: pip install cryptography to run this PoC")
        return 0

    sk = Ed25519PrivateKey.generate()
    pub_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    with tempfile.TemporaryDirectory() as d:
        integrity = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        sig = sk.sign(integrity.encode("utf-8")).hex()
        forged = {
            "schema": "railcall_workflow_receipt.v1", "workflow_id": "attacker",
            "integrity_root": integrity, "artifact": "x.html", "spec": {"name": "x", "steps": []},
            "signature": {"alg": "ed25519", "sig": sig, "key_id": "attacker1"},
        }
        rp = os.path.join(d, "forged_receipt.json")
        json.dump(forged, open(rp, "w"))
        # the attacker's key, sitting right next to the receipt:
        json.dump({"public_key_hex": pub_hex, "key_id": "attacker1"},
                  open(os.path.join(d, "signing_pubkey.json"), "w"))

        # Clean env: a scratch HOME with NO ~/.railcall, no RAILCALL_WS -> the only key
        # available to a vulnerable CLI is the attacker's, adjacent to the receipt.
        env = dict(os.environ)
        env["HOME"] = os.path.join(d, "fakehome")
        os.makedirs(env["HOME"], exist_ok=True)
        env.pop("RAILCALL_WS", None)

        out = subprocess.run([sys.executable, CLI, "verify", rp],
                             capture_output=True, text=True, env=env).stdout.upper()

    if "SIGNATURE VALID" in out or ("VALID" in out and "INVALID" not in out):
        print("VULNERABLE: forged receipt verified via an adjacent attacker key.")
        print("Fix (T1): remove the receipt-dir fallback from the pubkey search; add --key for explicit trust.")
        return 1
    print("SECURE: adjacent attacker key was refused. Loophole closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
