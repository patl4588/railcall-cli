#!/usr/bin/env python3
"""
Tamper-fuzz the standalone offline verifier (railcall_verify_standalone.py).

The claim RailCall makes is absolute: a receipt verifies OFFLINE against a public
key, and ONLY if it is authentic and unmodified. This suite tries to break that
claim by force — it mints a genuine, correctly-signed receipt for EACH of the four
receipt families, confirms the pristine receipt verifies, then mutates the receipt
thousands of ways and asserts the verifier NEVER returns VALID for any mutation.

A red result here beats a green one that lies: a single mutation that verifies is a
forged-receipt hole, so a failure prints the exact mutation that slipped through.

Determinism: every keypair, message, and mutation is derived from a fixed seed
(_SEED). The Ed25519 private key is loaded from a constant 32-byte seed and the RNG
is `random.Random(_SEED)`, so a failure replays byte-for-byte on the next run — no
real randomness sources that would make a finding un-reproducible.

Scope of a "mutation": we fuzz the cryptographically-bound surface — the signed
message (the canonical body for the flat family; the integrity string for the nested
families), the signature bytes, and the key binding (key_id / pinned pubkey). Every
mutation below is constructed to genuinely alter that surface, so "never VALID" is an
honest invariant. (Re-ordering JSON keys that are NOT part of the signed message is
correctly a no-op on authenticity, so it is asserted as its own positive control
rather than smuggled in as a tamper that "must fail".)

Dependencies: Python 3 stdlib + `cryptography`. Skips cleanly if `cryptography` is
absent — no fake-green.
"""
import copy
import importlib.util
import json
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
STANDALONE = os.path.join(REPO, "railcall_verify_standalone.py")

# A fixed seed makes the whole fuzz replayable: same keys, same messages, same
# mutations on every run and on CI.
_SEED = 0x5A11CA11
# Two constant Ed25519 private seeds (32 bytes each) — the "install" key and a
# distinct "other" key used to prove a wrong pubkey never validates.
_INSTALL_SEED = bytes(range(1, 33))
_OTHER_SEED = bytes(range(101, 133))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False


def _load_standalone():
    """Import railcall_verify_standalone.py by path so this runs from qa/ on any Python."""
    spec = importlib.util.spec_from_file_location("railcall_verify_standalone", STANDALONE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Signer(object):
    """A deterministic Ed25519 identity: sign raw bytes, publish {public_key_hex, key_id}."""

    def __init__(self, seed_bytes):
        self._sk = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        import hashlib
        # key_id convention in the wild: first 16 hex chars of a digest of the raw key.
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    def sign_str(self, s):
        """Nested families sign the raw UTF-8 of the integrity string."""
        return self._sk.sign(str(s).encode("utf-8")).hex()

    def sign_body(self, body):
        """Flat family signs the canonical body, byte-identical to receipt_signer.canonical_bytes."""
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
        return self._sk.sign(canonical).hex()


# --- pristine receipt builders (one per family) -----------------------------------
# Each returns (receipt_dict, pubkey_doc_dict). The pubkey_doc is what an auditor
# passes with --key. An em-dash (—) is deliberately embedded in a value so the fuzz
# also covers the non-ASCII canonicalization path that a naive verifier gets wrong.


def _build_flat(signer):
    """Family 1 — flat CLI-audit receipt: top-level signature_hex over the canonical body."""
    body = {
        "schema": "railcall_audit_receipt.v1",
        "ran_at": "2026-07-07T00:00:00",
        "file": {"name": "metrics.csv", "sha256": "sha256:" + "00" * 32, "bytes": 128},
        "audit": {"rows": 3, "columns": 4, "import_breakers": 0, "pii_columns": 0,
                  "findings": [{"severity": "info", "detail": "lsof -P tree — absolute paths"}]},
        "network_audit": {"external_sockets_open": 0, "note": "measured via lsof — not asserted"},
        "result": "audited",
    }
    receipt = dict(body)
    receipt["signer_alg"] = "ed25519"
    receipt["public_key_hex"] = signer.public_key_hex
    receipt["signature_hex"] = signer.sign_body(body)
    return receipt, {"public_key_hex": signer.public_key_hex}


def _build_nested(signer, schema, field):
    """Families 2-4 — nested signature block over a single integrity field STRING."""
    integrity = "sha256:" + "ab" * 32
    receipt = {
        "schema": schema,
        "workflow_id": "scheduled_qa_workflow",
        field: integrity,
        "artifact": "scheduled_qa_workflow.html",
        "network_audit": {"external_sockets_open": 0},
        "signature": {"alg": "ed25519", "sig": signer.sign_str(integrity),
                      "key_id": signer.key_id},
    }
    return receipt, {"public_key_hex": signer.public_key_hex, "key_id": signer.key_id}


def _families(signer):
    """The four receipt shapes, keyed by a human label -> (receipt, pubkey_doc)."""
    return {
        "flat-cli-audit": _build_flat(signer),
        "studio-build (integrity_hash)": _build_nested(signer, "railcall_build_receipt.v0", "integrity_hash"),
        "studio-run (integrity)": _build_nested(signer, "railcall_composed_dryrun.v0", "integrity"),
        "workflow (integrity_root)": _build_nested(signer, "railcall_workflow_receipt.v1", "integrity_root"),
    }


# --- family-aware accessors -------------------------------------------------------


def _is_flat(receipt):
    return "signature_hex" in receipt


def _get_sig(receipt):
    return receipt["signature_hex"] if _is_flat(receipt) else receipt["signature"]["sig"]


def _set_sig(receipt, hexstr):
    if _is_flat(receipt):
        receipt["signature_hex"] = hexstr
    else:
        receipt["signature"]["sig"] = hexstr


def _integrity_field(receipt):
    for k in ("integrity_hash", "integrity", "integrity_root"):
        if k in receipt:
            return k
    return None


def _flip_hex_char(rng, hexstr):
    """Return `hexstr` with one position changed to a DIFFERENT hex digit (guaranteed change)."""
    if not hexstr:
        return "0"
    i = rng.randrange(len(hexstr))
    alphabet = "0123456789abcdef"
    cur = hexstr[i].lower()
    choices = [ch for ch in alphabet if ch != cur]
    return hexstr[:i] + rng.choice(choices) + hexstr[i + 1:]


# --- mutators ---------------------------------------------------------------------
# Each mutator takes (rng, receipt, keydoc, other_signer) and returns a
# (mutated_receipt, mutated_keydoc) pair whose signed surface is genuinely altered,
# so the verifier MUST NOT return VALID. `applies(receipt)` filters by family where a
# mutation would otherwise be a semantic no-op (and thus legitimately still valid).


def _m_sig_flip_char(rng, r, k, other):
    _set_sig(r, _flip_hex_char(rng, _get_sig(r)))
    return r, k


def _m_sig_bit_flip(rng, r, k, other):
    raw = bytearray(bytes.fromhex(_get_sig(r)))
    if raw:
        i = rng.randrange(len(raw))
        raw[i] ^= 1 << rng.randrange(8)
    _set_sig(r, raw.hex())
    return r, k


def _m_sig_truncate(rng, r, k, other):
    _set_sig(r, _get_sig(r)[:-2])          # drop a byte -> wrong length
    return r, k


def _m_sig_extend(rng, r, k, other):
    _set_sig(r, _get_sig(r) + "ab")        # extra byte -> wrong length
    return r, k


def _m_sig_zeroed(rng, r, k, other):
    _set_sig(r, "00" * 64)                 # all-zero 64-byte signature
    return r, k


def _m_sig_odd_len(rng, r, k, other):
    _set_sig(r, _get_sig(r) + "a")         # odd hex length -> malformed bytes
    return r, k


def _m_sig_nonhex(rng, r, k, other):
    _set_sig(r, "zz" + _get_sig(r)[2:])    # non-hex -> malformed bytes
    return r, k


def _m_sig_from_other_key(rng, r, k, other):
    """Replace the signature with a VALID signature made by a different key over the
    same message. It verifies under `other` but must NOT verify under the pinned key."""
    if _is_flat(r):
        body = {kk: v for kk, v in r.items()
                if kk not in ("signer_alg", "signature_hex", "public_key_hex")}
        _set_sig(r, other.sign_body(body))
    else:
        _set_sig(r, other.sign_str(r[_integrity_field(r)]))
        r["signature"]["key_id"] = k.get("key_id")   # keep key_id matching so it reaches the crypto check
    return r, k


def _m_wrong_pubkey(rng, r, k, other):
    """Pin the wrong public key: the authentic signature cannot verify under it."""
    k = dict(k)
    k["public_key_hex"] = other.public_key_hex
    return r, k


def _m_content_flip(rng, r, k, other):
    if _is_flat(r):
        r["result"] = r["result"] + "_TAMPERED"       # body byte-changes -> canonical differs
    else:
        f = _integrity_field(r)
        r[f] = _flip_hex_char(rng, r[f])
    return r, k


def _m_content_truncate(rng, r, k, other):
    if _is_flat(r):
        del r["result"]                                # drop a signed field
    else:
        f = _integrity_field(r)
        r[f] = r[f][:-1]                               # shorten the signed string
    return r, k


def _m_content_swap(rng, r, k, other):
    if _is_flat(r):
        r["schema"], r["result"] = r["result"], r["schema"]   # swap two signed values
    else:
        f = _integrity_field(r)
        r[f] = r["schema"]                             # integrity now holds the schema string
    return r, k


def _m_content_reorder_chars(rng, r, k, other):
    """A 'reorder' that DOES alter the signed message: reverse the integrity string /
    a signed scalar (guaranteed different because these values are not palindromes)."""
    if _is_flat(r):
        r["result"] = r["result"][::-1] + "!"
    else:
        f = _integrity_field(r)
        r[f] = r[f][::-1]
    return r, k


def _m_keyid_mismatch(rng, r, k, other):
    """Nested only: change the receipt's key_id so it no longer matches the pinned key
    -> honest KEY MISMATCH verdict, which is NOT valid."""
    r["signature"]["key_id"] = "deadbeefdeadbeef"
    return r, k


def _m_inject_second_signature(rng, r, k, other):
    if _is_flat(r):
        # A second signature copied into the body is an extra signed-over field the
        # verifier does not strip -> canonical body changes -> invalid.
        r["signature_hex_backup"] = r["signature_hex"]
    else:
        # Turning the signature into a list of two blocks makes it un-extractable
        # (not a dict) -> the verifier refuses it rather than returning VALID.
        r["signature"] = [dict(r["signature"]), dict(r["signature"])]
    return r, k


# (mutator, applies-predicate). A mutator whose predicate is False for a family is a
# semantic no-op there (would legitimately still verify), so it is excluded — keeping
# the "never VALID" invariant honest rather than trivially satisfiable.
_MUTATORS = [
    (_m_sig_flip_char, lambda r: True),
    (_m_sig_bit_flip, lambda r: True),
    (_m_sig_truncate, lambda r: True),
    (_m_sig_extend, lambda r: True),
    (_m_sig_zeroed, lambda r: True),
    (_m_sig_odd_len, lambda r: True),
    (_m_sig_nonhex, lambda r: True),
    (_m_sig_from_other_key, lambda r: True),
    (_m_wrong_pubkey, lambda r: True),
    (_m_content_flip, lambda r: True),
    (_m_content_truncate, lambda r: True),
    (_m_content_swap, lambda r: True),
    (_m_content_reorder_chars, lambda r: True),
    (_m_keyid_mismatch, lambda r: not _is_flat(r)),
    (_m_inject_second_signature, lambda r: True),
]

# Total mutations = _ITER_PER_FAMILY * 4 families. Kept in the thousands so the fuzz
# has real coverage while staying fast (each iteration is one in-process verify()).
_ITER_PER_FAMILY = 750


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed — cannot sign/verify receipts")
class TamperFuzz(unittest.TestCase):
    """Every test is hermetic: receipts + keys are written into a throwaway tempdir and
    verified in-process by the standalone verifier. No network, no shared state."""

    @classmethod
    def setUpClass(cls):
        cls.sv = _load_standalone()
        cls.signer = _Signer(_INSTALL_SEED)
        cls.other = _Signer(_OTHER_SEED)
        cls.tmp = tempfile.mkdtemp(prefix="rc_fuzz_")
        cls.rp = os.path.join(cls.tmp, "receipt.json")
        cls.kp = os.path.join(cls.tmp, "signing_pubkey.json")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _verify(self, receipt, keydoc):
        """Write the pair to disk and return the verifier's boolean verdict. An exception
        (malformed receipt/key) is NOT a VALID verdict — report it as False, honestly."""
        with open(self.rp, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh)
        with open(self.kp, "w", encoding="utf-8") as fh:
            json.dump(keydoc, fh)
        try:
            return bool(self.sv.verify(self.rp, self.kp)["valid"])
        except Exception:
            return False

    def test_pristine_each_family_verifies(self):
        """Positive control: an untouched, correctly-signed receipt for EACH family MUST
        verify — otherwise a later 'never VALID' would be vacuously (and dishonestly) true."""
        for label, (receipt, keydoc) in _families(self.signer).items():
            self.assertTrue(self._verify(receipt, keydoc),
                            "pristine %s receipt failed to verify — the fuzz baseline is broken" % label)

    def test_reordered_keys_stay_valid_positive_control(self):
        """Honesty control: re-ordering JSON keys that are NOT part of the signed message
        is not tampering and MUST stay valid — so the suite never pretends a semantic
        no-op is a caught forgery."""
        receipt, keydoc = _build_nested(self.signer, "railcall_workflow_receipt.v1", "integrity_root")
        reordered = dict(reversed(list(receipt.items())))   # same content, different key order
        self.assertTrue(self._verify(reordered, keydoc),
                        "re-ordering non-signed keys must not change authenticity")

    def test_fuzz_never_validates_any_mutation(self):
        """The core invariant: across thousands of seeded, family-aware mutations of the
        cryptographically-bound surface, the verifier returns VALID for NONE of them."""
        rng = random.Random(_SEED)
        families = _families(self.signer)
        total, checked = 0, 0
        for label, (base_receipt, base_keydoc) in families.items():
            usable = [(m, ap) for (m, ap) in _MUTATORS if ap(base_receipt)]
            for _ in range(_ITER_PER_FAMILY):
                mutator, _ap = rng.choice(usable)
                receipt = copy.deepcopy(base_receipt)
                keydoc = copy.deepcopy(base_keydoc)
                receipt, keydoc = mutator(rng, receipt, keydoc, self.other)
                total += 1
                if self._verify(receipt, keydoc):
                    self.fail("VERIFIER ACCEPTED A MUTATION — forged-receipt hole.\n"
                              "  family:  %s\n  mutator: %s\n  receipt: %s\n  keydoc:  %s"
                              % (label, mutator.__name__, json.dumps(receipt), json.dumps(keydoc)))
                checked += 1
        self.assertEqual(total, checked)
        self.assertGreaterEqual(checked, 2000,
                                "expected thousands of mutations exercised, got %d" % checked)

    def test_named_attack_cases(self):
        """The specific mutations the task calls out, asserted by name so a regression in
        any single one is obvious: integrity byte-flip, field swap, reorder, truncation,
        second-signature injection, and key_id change."""
        cases = []
        # integrity byte-flip (nested)
        r, k = _build_nested(self.signer, "railcall_workflow_receipt.v1", "integrity_root")
        r["integrity_root"] = _flip_hex_char(random.Random(1), r["integrity_root"])
        cases.append(("integrity byte-flip", r, k))
        # field swap (flat)
        r, k = _build_flat(self.signer)
        r["schema"], r["result"] = r["result"], r["schema"]
        cases.append(("flat field swap", r, k))
        # reorder signed string (nested)
        r, k = _build_nested(self.signer, "railcall_composed_dryrun.v0", "integrity")
        r["integrity"] = r["integrity"][::-1]
        cases.append(("integrity reorder", r, k))
        # truncated signature (flat)
        r, k = _build_flat(self.signer)
        r["signature_hex"] = r["signature_hex"][:-2]
        cases.append(("signature truncation", r, k))
        # injected second signature (flat)
        r, k = _build_flat(self.signer)
        r["signature_hex_backup"] = r["signature_hex"]
        cases.append(("second-signature injection", r, k))
        # changed key_id (nested)
        r, k = _build_nested(self.signer, "railcall_build_receipt.v0", "integrity_hash")
        r["signature"]["key_id"] = "0000000000000000"
        cases.append(("key_id change", r, k))
        for name, receipt, keydoc in cases:
            self.assertFalse(self._verify(receipt, keydoc),
                             "%s must NOT verify" % name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
