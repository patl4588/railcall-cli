#!/usr/bin/env python3
"""
Verified-Builder bot skeleton (T2). Fill in verify_receipt() against RECEIPT_FORMATS.md.
Secrets come from env only:  DISCORD_BOT_TOKEN,  RAILCALL_TRUSTED_KEYS (path to a JSON
list of {public_key_hex, key_id} you trust). Never read a key from the uploaded message.
"""
import json, os


def verify_receipt(receipt: dict, trusted_keys: list) -> tuple[bool, str]:
    """
    Return (ok, reason). Implement per ../RECEIPT_FORMATS.md:
      1. pick integrity = first present of integrity_hash / integrity / integrity_root
      2. read receipt['signature'] = {alg, sig, key_id}
      3. find the trusted key whose key_id matches; if none -> (False, "unknown signer")
      4. Ed25519-verify sig over str(integrity).encode('utf-8') against that key
      5. (False, "signature invalid") on failure, else (True, "signed by <key_id>")
    NOTE: `trusted_keys` is YOUR configured list — never a key from the message.
    """
    raise NotImplementedError("implement against RECEIPT_FORMATS.md")


def load_trusted_keys() -> list:
    p = os.environ.get("RAILCALL_TRUSTED_KEYS")
    return json.load(open(p)) if p and os.path.isfile(p) else []


# --- Discord wiring (pseudocode; use discord.py) ---
# on_message: if attachment/JSON in a watched channel ->
#   ok, reason = verify_receipt(receipt, load_trusted_keys())
#   ok  -> add "Verified Builder" role, reply f"verified: {reason}"
#   else-> reply f"rejected: {reason}"   (never grant on failure)
if __name__ == "__main__":
    print("stub — see README.md for the acceptance criteria")
