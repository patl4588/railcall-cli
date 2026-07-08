#!/usr/bin/env python3
"""
Fresh-install end-to-end golden path: install -> build -> receipt -> verify.

This is the whole-pipeline test that a region-string or PEP-668 packaging bug would
have tripped: it does not mock anything. It stages a CLEAN install in a throwaway
directory (the CLI + its runtime siblings, nothing else), points HOME at an empty
tempdir so `~/.railcall` resolves fresh, then runs the real user journey end to end:

    1. `railcall audit <csv>`  — a real local, zero-network run that mints a signed
                                 receipt (the offline-clean equivalent of `build`;
                                 `build` additionally meters a provisioned key over
                                 the network, which a hermetic test must not require).
    2. a signed receipt lands on disk.
    3. `railcall verify <receipt>` passes offline.
    4. the STANDALONE verifier (railcall_verify_standalone.py) — the tool a third-
       party auditor runs with zero RailCall code — also passes on the same receipt.
    5. negative control: tamper the receipt on disk and confirm BOTH verifiers reject
       it, so the green in steps 3-4 is proven to mean something.

Honest skips (never fake-green): if `cryptography` is missing, or the CLI's runtime
siblings (railcall_companion_daemon.py, receipt_signer.py, vault_io.py) can't be
located, the whole case SKIPS with the reason — it does not pass vacuously.

Dependencies: Python 3 stdlib + `cryptography`. Pure subprocess; no network.
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
STANDALONE = os.path.join(REPO, "railcall_verify_standalone.py")

# The CLI imports its runtime siblings (shipped next to it by install.sh) rather than
# vendoring them into cli/. Locate a directory that holds ALL of them and stage a
# self-contained install for the subprocess. ~/.railcall is included so a developer
# with RailCall installed gets a real end-to-end run; CI without them skips cleanly.
_RUNTIME_DEPS = ("railcall_companion_daemon.py", "receipt_signer.py", "vault_io.py")
_SRC_CANDIDATES = [
    os.environ.get("RAILCALL_SRC"),
    CLI_DIR,
    os.path.join(HERE, "..", "..", "core-fixes"),
    os.path.join(os.path.expanduser("~"), ".railcall"),
]


def _find_src():
    for cand in _SRC_CANDIDATES:
        if cand and all(os.path.isfile(os.path.join(cand, f)) for f in _RUNTIME_DEPS):
            return os.path.abspath(cand)
    return None


try:
    import cryptography

    _HAVE_CRYPTO = True
    # The subprocess runs under a throwaway HOME, which would hide a `cryptography`
    # installed in the *user* site-packages (keyed off the real HOME). Pin its exact
    # site-packages dir now — while we still see the real HOME — for the child's path.
    _CRYPTO_SITE = os.path.dirname(os.path.dirname(os.path.abspath(cryptography.__file__)))
except ImportError:
    _HAVE_CRYPTO = False
    _CRYPTO_SITE = None

_SRC = _find_src()

_SAMPLE_CSV = (
    "metric_id,component,load_value,status\n"
    "M-101,generator-alpha,87.4,active\n"
    "M-102,turbine-beta,12.1,idle\n"
    "M-103,coolant-main,55.2,active\n"
)


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed — cannot sign/verify a receipt")
@unittest.skipUnless(_SRC is not None,
                     "runtime siblings (%s) not found; set RAILCALL_SRC to their directory"
                     % ", ".join(_RUNTIME_DEPS))
class GoldenPathE2E(unittest.TestCase):
    """One hermetic install, exercised as a real user would. Fresh HOME, no network."""

    @classmethod
    def setUpClass(cls):
        # Stage a clean install: the CLI under test + its runtime siblings, nothing else.
        cls.install = tempfile.mkdtemp(prefix="rc_e2e_install_")
        shutil.copy2(CLI, os.path.join(cls.install, "railcall_cli.py"))
        for f in _RUNTIME_DEPS:
            shutil.copy2(os.path.join(_SRC, f), os.path.join(cls.install, f))
        cls.cli = os.path.join(cls.install, "railcall_cli.py")
        # audit writes its receipt into the daemon module's ROOT — i.e. the install dir.
        cls.receipt = os.path.join(cls.install, "railcall_audit_receipt.json")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.install, ignore_errors=True)

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rc_e2e_home_")
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def _env(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        pp = [self.install]
        if _CRYPTO_SITE:
            pp.append(_CRYPTO_SITE)
        if env.get("PYTHONPATH"):
            pp.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(pp)
        env.pop("RAILCALL_FORCE_COLOR", None)   # keep stdout plain-text (no ANSI to parse)
        env.pop("RAILCALL_WS", None)
        return env

    def _run_cli(self, args):
        return subprocess.run([sys.executable, self.cli] + list(args),
                              capture_output=True, text=True, env=self._env(), cwd=self.home)

    def _run_standalone(self, receipt_path, key_path):
        return subprocess.run(
            [sys.executable, STANDALONE, receipt_path, "--key", key_path],
            capture_output=True, text=True, env=self._env(), cwd=self.home)

    def test_install_build_receipt_verify(self):
        # 1. clean-install run: audit a CSV. Zero network, mints a signed receipt.
        csv_path = os.path.join(self.home, "metrics.csv")
        with open(csv_path, "w", encoding="utf-8") as fh:
            fh.write(_SAMPLE_CSV)
        audit = self._run_cli(["audit", csv_path])
        self.assertEqual(audit.returncode, 0,
                         "clean-install `railcall audit` failed\nSTDOUT:\n%s\nSTDERR:\n%s"
                         % (audit.stdout, audit.stderr))

        # 2. a signed receipt exists on disk.
        self.assertTrue(os.path.isfile(self.receipt),
                        "no receipt was written at %s" % self.receipt)
        with open(self.receipt, encoding="utf-8") as fh:
            receipt = json.load(fh)
        pub = receipt.get("public_key_hex")
        if not receipt.get("signature_hex") or not pub:
            # A genuine install with cryptography present MUST sign; an unsigned receipt
            # here means the signing chain is unavailable in this env — skip, don't fake green.
            self.skipTest("receipt minted UNSIGNED (no signing seed/vault in this env)")

        # 3. `railcall verify` passes offline (uses the receipt's own embedded key).
        v = self._run_cli(["verify", self.receipt])
        self.assertEqual(v.returncode, 0,
                         "`railcall verify` did not pass on a genuine receipt\n%s" % v.stdout)
        self.assertIn("SIGNATURE VALID", (v.stdout + v.stderr).upper())

        # 4. the STANDALONE auditor tool passes on the same receipt, against an
        #    explicitly-supplied pubkey doc built from the receipt's published key.
        key_path = os.path.join(self.home, "signing_pubkey.json")
        with open(key_path, "w", encoding="utf-8") as fh:
            json.dump({"public_key_hex": pub, "key_id": receipt.get("key_id")}, fh)
        s = self._run_standalone(self.receipt, key_path)
        self.assertEqual(s.returncode, 0,
                         "standalone verifier rejected a genuine receipt\nSTDOUT:\n%s\nSTDERR:\n%s"
                         % (s.stdout, s.stderr))
        self.assertIn("SIGNATURE VALID", (s.stdout + s.stderr).upper())

        # 5. negative control: tamper the receipt on disk; BOTH verifiers must reject it,
        #    proving the green above is real and not blind.
        tampered = dict(receipt)
        tampered["result"] = "tampered"      # a signed body field changed after signing
        tpath = os.path.join(self.home, "tampered_receipt.json")
        with open(tpath, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh)
        tv = self._run_cli(["verify", tpath])
        self.assertNotEqual(tv.returncode, 0, "`railcall verify` accepted a tampered receipt")
        self.assertIn("SIGNATURE INVALID", (tv.stdout + tv.stderr).upper())
        ts = self._run_standalone(tpath, key_path)
        self.assertNotEqual(ts.returncode, 0, "standalone verifier accepted a tampered receipt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
