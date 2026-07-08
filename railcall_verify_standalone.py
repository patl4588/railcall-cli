#!/usr/bin/env python3
"""RailCall standalone offline receipt verifier.

This single file proves a claim RailCall makes about every receipt it emits:

    Receipts verify offline against a public key — you never need the
    RailCall engine (or any RailCall install) to trust one.

A third-party auditor can drop this file next to a receipt and its install's
pinned `signing_pubkey.json`, run one command, and cryptographically confirm
the Ed25519 signature. No RailCall code, no network, no daemon.

Security posture (a real audit finding drove this):
  * The public key you trust MUST be chosen consciously by the auditor via
    an explicit `--key <path>`. This tool NEVER auto-loads a key sitting in
    the receipt's own directory, because a receipt that ships its own key is
    self-attestation and proves nothing.
  * A signature that verifies under a DIFFERENT key_id is reported as
    "signed by a different install" — that is a distinct, honest verdict, not
    the same thing as an invalid or unsigned receipt.

Dependencies: Python 3 stdlib + `cryptography`.

Usage:
    python3 railcall_verify_standalone.py <receipt.json> --key <signing_pubkey.json>
    python3 railcall_verify_standalone.py <receipt.json> --key <key.json> --json

Exit code: 0 = signature valid, 1 = invalid / mismatch / error.
"""

import argparse
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Receipt shapes RailCall emits. Each verifies a different integrity field,
# but the contract is identical: sign target = raw UTF-8 of str(<field>).
# Order matters only for reporting; a receipt carries exactly one of these.
INTEGRITY_FIELDS = ("integrity_hash", "integrity", "integrity_root")


def load_json(path):
    """Read a UTF-8 JSON file, raising a clear error on failure."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def extract_signature(receipt):
    """Return (integrity_field_name, integrity_value, sig_hex, key_id).

    Handles both receipt families:
      * flat CLI audit  -> signature_hex + public_key_hex over the body
      * nested Studio/Workflow -> integrity* field + signature{alg,sig,key_id}
    Raises ValueError if the receipt carries no recognizable signature.
    """
    # Family 1: flat CLI audit receipt. The signature covers the canonical
    # body (the receipt minus its own signature/public_key fields).
    if "signature_hex" in receipt:
        body = {k: v for k, v in receipt.items()
                if k not in ("signature_hex", "public_key_hex")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return ("<canonical body>", canonical,
                receipt["signature_hex"], receipt.get("key_id"))

    # Family 2: nested signature block over a single integrity field.
    sig = receipt.get("signature")
    if not isinstance(sig, dict) or "sig" not in sig:
        raise ValueError("receipt has no signature_hex and no signature{} block")
    for field in INTEGRITY_FIELDS:
        if field in receipt:
            # Sign target is the raw UTF-8 string of the field value.
            return (field, str(receipt[field]), sig["sig"], sig.get("key_id"))
    raise ValueError(
        "signature present but no integrity field "
        f"(one of {', '.join(INTEGRITY_FIELDS)})")


def verify(receipt_path, key_path):
    """Verify one receipt against one explicitly-chosen public key.

    Returns a result dict with a boolean `valid` and human-readable detail.
    Never raises for a normal invalid signature — only for malformed input.
    """
    receipt = load_json(receipt_path)
    key_doc = load_json(key_path)

    pub_hex = key_doc.get("public_key_hex")
    pinned_key_id = key_doc.get("key_id")
    if not pub_hex:
        raise ValueError(f"{key_path}: missing public_key_hex")

    field, message, sig_hex, receipt_key_id = extract_signature(receipt)

    result = {
        "receipt": receipt_path,
        "key_source": key_path,
        "integrity_field": field,
        "pinned_key_id": pinned_key_id,
        "receipt_key_id": receipt_key_id,
        "valid": False,
        "verdict": "",
    }

    # Honest cross-install check: if the receipt names a key_id and it differs
    # from the pinned key, say so plainly — the auditor may be holding the
    # wrong install's key, which is not the same as a forged receipt.
    if receipt_key_id and pinned_key_id and receipt_key_id != pinned_key_id:
        result["verdict"] = (
            f"KEY MISMATCH — receipt key_id '{receipt_key_id}' != pinned "
            f"'{pinned_key_id}'; this receipt was signed by a DIFFERENT "
            "install. Supply that install's public key to verify it.")
        return result

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), message.encode("utf-8"))
    except InvalidSignature:
        result["verdict"] = (
            f"SIGNATURE INVALID — {field} does not verify under key_id "
            f"'{pinned_key_id}'. Receipt is tampered or wrongly keyed.")
        return result
    except ValueError as exc:
        # Malformed hex in the receipt/key is a hard failure, not a valid sig.
        result["verdict"] = f"SIGNATURE INVALID — malformed key or signature bytes: {exc}"
        return result

    result["valid"] = True
    result["verdict"] = (
        f"SIGNATURE VALID — field '{field}' verifies under key_id "
        f"'{pinned_key_id}'. Receipt is authentic and unmodified.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline Ed25519 verifier for RailCall receipts.")
    parser.add_argument("receipt", help="path to the receipt .json to verify")
    parser.add_argument(
        "--key", required=True, metavar="signing_pubkey.json",
        help="pinned public key you choose to trust (never auto-loaded)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of prose")
    args = parser.parse_args(argv)

    try:
        result = verify(args.receipt, args.key)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"valid": False, "error": str(exc)}))
        else:
            print(f"ERROR — {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["verdict"])
        print(f"  receipt : {result['receipt']}")
        print(f"  key     : {result['key_source']}  (explicitly supplied)")
        print(f"  field   : {result['integrity_field']}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
