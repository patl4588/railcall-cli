"""
qa/test_formula_injection.py — regression tests for formula injection detection (Bug 13).

Cells starting with =, +, -, @ can execute arbitrary code when a signed
receipt-stamped CSV is opened in Excel / Google Sheets. The audit must flag
these before they reach a downstream tool.

Mirrors the subprocess pattern used in test_regressions.py so the daemon
runtime is resolved the same way across the full CI suite.

Run standalone:  python3 -m pytest qa/test_formula_injection.py -v
     or via CI:  bash qa/run.sh
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

# Locate runtime deps (daemon + signer) — same search order as test_regressions.py.
_RUNTIME_DEPS = ("railcall_companion_daemon.py", "receipt_signer.py")
_SRC_CANDIDATES = [
    os.environ.get("RAILCALL_SRC"),
    CLI_DIR,
    os.path.join(os.path.expanduser("~"), ".railcall"),   # local install fallback
]


def _find_src():
    for cand in _SRC_CANDIDATES:
        if cand and all(os.path.isfile(os.path.join(cand, f)) for f in _RUNTIME_DEPS):
            return os.path.abspath(cand)
    return None


_SRC = _find_src()


def _run_audit(tmp_dir, csv_text):
    """Write csv_text to a temp file, run `railcall audit` against it, return (stdout, receipt)."""
    # Stage runtime deps next to the CLI so the import resolves.
    stage = os.path.join(tmp_dir, "cli")
    os.makedirs(stage, exist_ok=True)
    shutil.copy(CLI, os.path.join(stage, "railcall_cli.py"))
    if _SRC:
        for dep in _RUNTIME_DEPS:
            src = os.path.join(_SRC, dep)
            if os.path.isfile(src):
                shutil.copy(src, os.path.join(stage, dep))

    csv_path = os.path.join(tmp_dir, "test.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(csv_text)

    env = os.environ.copy()
    env["HOME"] = tmp_dir
    env["RAILCALL_WS"] = tmp_dir
    env.setdefault("RAILCALL_FORCE_COLOR", "0")

    proc = subprocess.run(
        [sys.executable, os.path.join(stage, "railcall_cli.py"), "audit", csv_path],
        capture_output=True, text=True, env=env, cwd=stage,
    )
    out = proc.stdout + proc.stderr

    receipt_path = os.path.join(stage, "railcall_audit_receipt.json")
    receipt = None
    if os.path.isfile(receipt_path):
        with open(receipt_path, encoding="utf-8") as f:
            receipt = json.load(f)

    return out, receipt


@unittest.skipIf(_SRC is None, "runtime deps not found — set RAILCALL_SRC=<dir with daemon+signer>")
class TestFormulaInjectionDetection(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rc_formula_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── detection ────────────────────────────────────────────────────────────

    def test_equals_prefix_flagged(self):
        out, receipt = _run_audit(self.tmp, "id,payload\n1,=cmd|' /C calc'!A0\n2,normal")
        self.assertIn("formula injection", out.lower())
        if receipt:
            findings = receipt["audit"].get("findings", [])
            self.assertTrue(any(f["severity"] == "formula" for f in findings),
                            "receipt must contain a 'formula' severity finding")
            self.assertGreater(receipt["audit"].get("formula_injection_cols", 0), 0)

    def test_at_prefix_flagged(self):
        out, receipt = _run_audit(self.tmp, "name,formula\nalice,@SUM(A1:A10)")
        self.assertIn("formula injection", out.lower())

    def test_plus_prefix_flagged(self):
        out, receipt = _run_audit(self.tmp, "x,y\n1,+1-2\n2,safe")
        self.assertIn("formula injection", out.lower())

    def test_minus_prefix_flagged(self):
        out, receipt = _run_audit(self.tmp, "x,y\n1,-2+cmd\n2,safe")
        self.assertIn("formula injection", out.lower())

    def test_multiple_formula_columns_counted(self):
        out, receipt = _run_audit(self.tmp, "a,b,c\n=evil(),@bad,safe\nnorm,norm,norm")
        if receipt:
            self.assertGreaterEqual(receipt["audit"].get("formula_injection_cols", 0), 2)

    def test_receipt_includes_formula_injection_cols_key(self):
        """The receipt contract must expose formula_injection_cols so verifiers can act on it."""
        _, receipt = _run_audit(self.tmp, "id,v\n1,=bad\n2,ok")
        self.assertIsNotNone(receipt, "receipt file must be written")
        self.assertIn("formula_injection_cols", receipt.get("audit", {}))

    # ── clean cases (must NOT fire) ──────────────────────────────────────────

    def test_clean_csv_no_false_positive(self):
        out, receipt = _run_audit(self.tmp, "id,name,email\n1,Alice,alice@example.com")
        self.assertIn("0 formula injection", out.lower())
        if receipt:
            self.assertEqual(receipt["audit"].get("formula_injection_cols", 0), 0)

    def test_negative_number_not_flagged(self):
        """-42 is a number, not a formula — must not fire."""
        out, receipt = _run_audit(self.tmp, "id,temp\n1,-42\n2,37")
        self.assertIn("0 formula injection", out.lower())

    def test_formula_char_mid_cell_not_flagged(self):
        """Formula chars in the middle of a cell are not injection."""
        out, receipt = _run_audit(self.tmp, "id,note\n1,price=100\n2,tax+vat")
        self.assertIn("0 formula injection", out.lower())

    def test_at_in_email_not_flagged(self):
        """An @ inside an email address (not at position 0) must not be flagged."""
        out, _ = _run_audit(self.tmp, "id,email\n1,user@example.com\n2,other@test.org")
        self.assertIn("0 formula injection", out.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
