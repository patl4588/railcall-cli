#!/usr/bin/env python3
"""
Regression suite for cli/railcall_cli.py — each test pins a bug the contest surfaced
so it can never silently come back. Pure stdlib unittest; only extra dep is
`cryptography` (already required to sign/verify receipts). No network: every test
runs the real CLI as a subprocess in a throwaway HOME/RAILCALL_WS.

Contest-finder → test map
-------------------------
  F1  key-resolution self-attestation loophole (a forged receipt shipping its own
      adjacent signing_pubkey.json must NOT self-verify; --key is the ONLY explicit
      trust path and the output must attribute it):
        test_forged_receipt_adjacent_key_refused
        test_forged_receipt_with_key_flag_attributes_user_key
  F2  run-receipt integrity binding (railcall_composed_dryrun.v0, `integrity` field):
        test_run_receipt_valid_then_tampered
  F3  workflow-receipt integrity_root binding (railcall_workflow_receipt.v1):
        test_workflow_receipt_valid_then_tampered
  F4  flat CLI-audit receipt binding (top-level signature_hex/public_key_hex):
        test_flat_audit_receipt_valid_then_tampered
  F5  foreign receipt (key_id ≠ this install) must report "different install",
      NOT "unsigned" and NOT crash:
        test_foreign_receipt_reports_different_install
  F6  `railcall backup` on an empty workspace must exit 0 (scripts depend on it):
        test_backup_empty_workspace_exits_zero
  F7  `railcall audit` on a non-CSV (.json) input must WARN, not silently pretend:
        test_audit_non_csv_input_warns
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CLI_DIR = os.path.join(REPO, "cli")
CLI = os.path.join(CLI_DIR, "railcall_cli.py")

# The CLI imports railcall_companion_daemon + receipt_signer (its runtime siblings,
# shipped alongside it by install.sh). They are NOT vendored into cli/, so locate a
# directory that holds both and stage a self-contained install for the subprocess.
_SRC_CANDIDATES = [
    os.environ.get("RAILCALL_SRC"),
    CLI_DIR,
    os.path.join(HERE, "..", "..", "core-fixes"),
]
_RUNTIME_DEPS = ("railcall_companion_daemon.py", "receipt_signer.py")


def _find_src():
    for cand in _SRC_CANDIDATES:
        if cand and all(os.path.isfile(os.path.join(cand, f)) for f in _RUNTIME_DEPS):
            return os.path.abspath(cand)
    return None


try:
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    _HAVE_CRYPTO = True
    # The subprocess runs under a throwaway HOME (so ~/.railcall resolves empty). If
    # cryptography lives in the *user* site-packages (keyed off the real HOME, as it does
    # in this dev env), that temp HOME would hide it. Pin the exact site-packages dir here,
    # while the parent still sees the real HOME, and add it to the child's PYTHONPATH.
    _CRYPTO_SITE = os.path.dirname(os.path.dirname(os.path.abspath(cryptography.__file__)))
except ImportError:
    _HAVE_CRYPTO = False
    _CRYPTO_SITE = None

_SRC = _find_src()


def _canonical(payload):
    """Byte-identical to receipt_signer.canonical_bytes — the flat CLI-audit contract."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class _Keypair(object):
    """A throwaway Ed25519 identity: sign raw bytes, publish {public_key_hex, key_id}."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        # key_id convention in the wild is the first 16 hex chars of a digest of the key
        import hashlib
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    def sign_str(self, s):
        return self._sk.sign(str(s).encode("utf-8")).hex()

    def sign_body(self, body):
        return self._sk.sign(_canonical(body)).hex()

    def pubkey_doc(self):
        return {"public_key_hex": self.public_key_hex, "key_id": self.key_id}


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed — cannot forge/verify receipts")
@unittest.skipUnless(_SRC is not None,
                     "runtime deps (railcall_companion_daemon.py + receipt_signer.py) not found; "
                     "set RAILCALL_SRC to their directory")
class RailCallRegressions(unittest.TestCase):
    """Every test is hermetic: a fresh temp HOME + RAILCALL_WS, no network, no shared state."""

    @classmethod
    def setUpClass(cls):
        # Stage a self-contained install so the subprocess can import the CLI's siblings
        # and so daemon.ROOT (where `audit` writes its receipt) is a throwaway dir.
        cls.install = tempfile.mkdtemp(prefix="rc_install_")
        shutil.copy2(CLI, os.path.join(cls.install, "railcall_cli.py"))
        for f in _RUNTIME_DEPS:
            shutil.copy2(os.path.join(_SRC, f), os.path.join(cls.install, f))
        cls.cli = os.path.join(cls.install, "railcall_cli.py")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.install, ignore_errors=True)

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rc_home_")
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    # -- subprocess harness ---------------------------------------------------
    def run_cli(self, args, ws=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        pp = [self.install]
        if _CRYPTO_SITE:
            pp.append(_CRYPTO_SITE)
        if env.get("PYTHONPATH"):
            pp.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(pp)
        env.pop("RAILCALL_FORCE_COLOR", None)   # keep stdout plain-text (no ANSI to parse)
        if ws is not None:
            env["RAILCALL_WS"] = ws
        else:
            env.pop("RAILCALL_WS", None)
        proc = subprocess.run([sys.executable, self.cli] + list(args),
                              capture_output=True, text=True, env=env, cwd=self.home)
        return proc

    def _ws_with_key(self, keypair):
        """A trusted RAILCALL_WS holding this install's pinned signing_pubkey.json."""
        ws = os.path.join(self.home, "ws")
        os.makedirs(ws, exist_ok=True)
        with open(os.path.join(ws, "signing_pubkey.json"), "w") as fh:
            json.dump(keypair.pubkey_doc(), fh)
        return ws

    def _write(self, name, obj):
        p = os.path.join(self.home, name)
        with open(p, "w") as fh:
            json.dump(obj, fh)
        return p

    # -- F1: self-attestation loophole ---------------------------------------
    def test_forged_receipt_adjacent_key_refused(self):
        """F1: a forged receipt + its OWN adjacent signing_pubkey.json, on an empty HOME
        with no RAILCALL_WS and no --key, must NOT verify. The adjacent key must never be
        trusted (that is the self-attestation loophole the security review found)."""
        attacker = _Keypair()
        integrity = "sha256:" + "de" * 32
        forged = {
            "schema": "railcall_workflow_receipt.v1", "workflow_id": "attacker",
            "integrity_root": integrity, "artifact": "x.html",
            "signature": {"alg": "ed25519", "sig": attacker.sign_str(integrity),
                          "key_id": attacker.key_id},
        }
        adir = os.path.join(self.home, "adjacent")
        os.makedirs(adir, exist_ok=True)
        rp = os.path.join(adir, "forged_receipt.json")
        with open(rp, "w") as fh:
            json.dump(forged, fh)
        # attacker key sits RIGHT NEXT TO the receipt
        with open(os.path.join(adir, "signing_pubkey.json"), "w") as fh:
            json.dump(attacker.pubkey_doc(), fh)

        proc = self.run_cli(["verify", rp], ws=None)   # empty HOME, no RAILCALL_WS
        out = (proc.stdout + proc.stderr).upper()
        self.assertNotIn("SIGNATURE VALID", out,
                         "adjacent attacker key was trusted — self-attestation loophole is OPEN")
        self.assertNotEqual(proc.returncode, 0, "forged receipt must not verify green")

    def test_forged_receipt_with_key_flag_attributes_user_key(self):
        """F1: the SAME forged receipt WITH --key <dir> pointing at the attacker's key verifies
        (explicit third-party trust is a deliberate choice) AND the output must attribute it as a
        USER-SUPPLIED key — never present it as this install's own attestation."""
        attacker = _Keypair()
        integrity = "sha256:" + "de" * 32
        forged = {
            "schema": "railcall_workflow_receipt.v1", "workflow_id": "attacker",
            "integrity_root": integrity, "artifact": "x.html",
            "signature": {"alg": "ed25519", "sig": attacker.sign_str(integrity),
                          "key_id": attacker.key_id},
        }
        adir = os.path.join(self.home, "adjacent")
        os.makedirs(adir, exist_ok=True)
        rp = os.path.join(adir, "forged_receipt.json")
        with open(rp, "w") as fh:
            json.dump(forged, fh)
        with open(os.path.join(adir, "signing_pubkey.json"), "w") as fh:
            json.dump(attacker.pubkey_doc(), fh)

        proc = self.run_cli(["verify", rp, "--key", adir], ws=None)
        out = (proc.stdout + proc.stderr).upper()
        self.assertIn("SIGNATURE VALID", out, "explicit --key trust should verify a matching sig")
        self.assertIn("USER-SUPPLIED", out, "explicit --key trust must be attributed in the output")
        self.assertEqual(proc.returncode, 0)

    # -- F2: run receipt (integrity) -----------------------------------------
    def test_run_receipt_valid_then_tampered(self):
        """F2: a run receipt (integrity field) signed by the install key -> VALID; byte-flip the
        integrity string -> INVALID."""
        kp = _Keypair()
        ws = self._ws_with_key(kp)
        integrity = "sha256:" + "ab" * 32
        good = {
            "schema": "railcall_composed_dryrun.v0", "integrity": integrity,
            "network_audit": {"external_sockets_open": 0},
            "signature": {"alg": "ed25519", "sig": kp.sign_str(integrity), "key_id": kp.key_id},
        }
        gp = self._write("run_good.json", good)
        out = self.run_cli(["verify", gp], ws=ws).stdout.upper()
        self.assertIn("SIGNATURE VALID", out)
        self.assertNotIn("SIGNATURE INVALID", out)

        bad = json.loads(json.dumps(good))
        bad["integrity"] = "sha256:" + "ac" * 32   # flip: signature no longer covers this string
        bp = self._write("run_bad.json", bad)
        proc = self.run_cli(["verify", bp], ws=ws)
        self.assertIn("SIGNATURE INVALID", proc.stdout.upper())
        self.assertNotEqual(proc.returncode, 0)

    # -- F3: workflow receipt (integrity_root) -------------------------------
    def test_workflow_receipt_valid_then_tampered(self):
        """F3: a workflow receipt (integrity_root field) signed by the install key -> VALID;
        byte-flip integrity_root -> INVALID."""
        kp = _Keypair()
        ws = self._ws_with_key(kp)
        integrity = "sha256:" + "fa" * 32
        good = {
            "schema": "railcall_workflow_receipt.v1", "workflow_id": "scheduled_qa_workflow",
            "integrity_root": integrity, "artifact": "scheduled_qa_workflow.html",
            "signature": {"alg": "ed25519", "sig": kp.sign_str(integrity), "key_id": kp.key_id},
        }
        gp = self._write("wf_good.json", good)
        out = self.run_cli(["verify", gp], ws=ws).stdout.upper()
        self.assertIn("SIGNATURE VALID", out)
        self.assertNotIn("SIGNATURE INVALID", out)

        bad = json.loads(json.dumps(good))
        bad["integrity_root"] = "sha256:" + "fb" * 32
        bp = self._write("wf_bad.json", bad)
        proc = self.run_cli(["verify", bp], ws=ws)
        self.assertIn("SIGNATURE INVALID", proc.stdout.upper())
        self.assertNotEqual(proc.returncode, 0)

    # -- F4: flat CLI-audit receipt ------------------------------------------
    def test_flat_audit_receipt_valid_then_tampered(self):
        """F4: a flat CLI-audit receipt (top-level signature_hex/public_key_hex over the canonical
        body) -> VALID; mutate a body field after signing -> INVALID. This receipt is self-contained
        (its own pubkey verifies it) — that is the documented format-1 contract, distinct from F1."""
        kp = _Keypair()
        body = {
            "schema": "railcall_audit_receipt.v1", "ran_at": "2026-07-07T00:00:00",
            "file": {"name": "x.csv", "sha256": "sha256:" + "00" * 32, "bytes": 42},
            "audit": {"rows": 3, "columns": 2, "import_breakers": 0, "pii_columns": 0, "findings": []},
            "network_audit": {"external_sockets_open": 0}, "result": "audited",
        }
        good = dict(body)
        good["signer_alg"] = "ed25519"
        good["public_key_hex"] = kp.public_key_hex
        good["signature_hex"] = kp.sign_body(body)
        gp = self._write("flat_good.json", good)
        out = self.run_cli(["verify", gp]).stdout.upper()
        self.assertIn("SIGNATURE VALID", out)
        self.assertNotIn("SIGNATURE INVALID", out)

        bad = json.loads(json.dumps(good))
        bad["result"] = "tampered"   # body changed -> canonical bytes no longer match the signature
        bp = self._write("flat_bad.json", bad)
        proc = self.run_cli(["verify", bp])
        self.assertIn("SIGNATURE INVALID", proc.stdout.upper())
        self.assertNotEqual(proc.returncode, 0)

    # -- F5: foreign receipt (different key_id) ------------------------------
    def test_foreign_receipt_reports_different_install(self):
        """F5: a receipt validly signed by a DIFFERENT install (key_id ≠ this install's) must be
        reported as coming from a different install — NOT 'unsigned', and never a crash."""
        install_kp = _Keypair()
        foreign_kp = _Keypair()
        ws = self._ws_with_key(install_kp)     # this install pins install_kp
        integrity = "sha256:" + "77" * 32
        receipt = {
            "schema": "railcall_workflow_receipt.v1", "workflow_id": "someone_else",
            "integrity_root": integrity, "artifact": "y.html",
            "signature": {"alg": "ed25519", "sig": foreign_kp.sign_str(integrity),
                          "key_id": foreign_kp.key_id},
        }
        rp = self._write("foreign.json", receipt)
        proc = self.run_cli(["verify", rp], ws=ws)
        out = (proc.stdout + proc.stderr).upper()
        self.assertIn("DIFFERENT", out, "foreign key_id should be reported as a different install")
        self.assertNotIn("UNSIGNED", out, "a signed foreign receipt is not 'unsigned'")
        self.assertNotIn("TRACEBACK", out, "must not crash on a foreign receipt")

    # -- F6: backup on empty workspace ---------------------------------------
    def test_backup_empty_workspace_exits_zero(self):
        """F6: `railcall backup` with no receipts/policy history is a valid state — exit 0 so
        scheduled backup scripts don't flap red on a fresh install."""
        proc = self.run_cli(["backup"])   # empty HOME -> no station workspace
        self.assertEqual(proc.returncode, 0, "empty-workspace backup must exit 0\n" + proc.stdout)
        self.assertIn("nothing to back up", proc.stdout.lower())

    # -- F7: audit non-CSV input ---------------------------------------------
    def test_audit_non_csv_input_warns(self):
        """F7: auditing a .json file (parsed as CSV) must LOUDLY warn that the input isn't CSV,
        instead of silently reporting a meaningless '2 rows x 1 col spreadsheet'."""
        jf = os.path.join(self.home, "data.json")
        with open(jf, "w") as fh:
            fh.write('[\n  {"x": 1},\n  {"x": 2}\n]\n')   # >=2 lines so CSV parse yields >=2 rows
        proc = self.run_cli(["audit", jf])
        out = proc.stdout
        self.assertIn("WARNING", out.upper(), "non-CSV input must surface a warning")
        self.assertIn("does not look like CSV", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
