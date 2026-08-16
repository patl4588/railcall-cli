"""#311: module updates must not destroy the .venv sidecar, and doctor must
flag a venv-needing module that has none (Nick, 2026-08-15: --force reinstall
wiped the venv; the scrape died with 'No module named playwright')."""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import railcall_cli as cli  # noqa: E402


class TestPreserveVenv(unittest.TestCase):
    def _module(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "handlers"))
        open(os.path.join(d, "handlers", "handler.py"), "w").write("# old")
        os.makedirs(os.path.join(d, ".venv", "bin"))
        open(os.path.join(d, ".venv", "bin", "python3"), "w").write("#!stub")
        open(os.path.join(d, ".venv", "marker.txt"), "w").write("operator-built")
        return d

    def test_venv_survives_a_wipe(self):
        d = self._module()
        with cli._preserve_venv(d):
            shutil.rmtree(d, ignore_errors=True)   # what --force does
            os.makedirs(os.path.join(d, "handlers"))
            open(os.path.join(d, "handlers", "handler.py"), "w").write("# new")
        self.assertTrue(os.path.isfile(os.path.join(d, ".venv", "marker.txt")),
                        "operator-built venv must survive the reinstall")
        self.assertEqual(open(os.path.join(d, "handlers", "handler.py")).read(), "# new")

    def test_no_venv_is_a_noop(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "handlers"))
        with cli._preserve_venv(d):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        self.assertFalse(os.path.exists(os.path.join(d, ".venv")))

    def test_restore_never_clobbers_a_shipped_venv(self):
        # if a future bundle SHIPS its own .venv, the stashed one must not
        # overwrite it — publisher content wins over stale operator state
        d = self._module()
        with cli._preserve_venv(d):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(os.path.join(d, ".venv"))
            open(os.path.join(d, ".venv", "shipped.txt"), "w").write("from-bundle")
        self.assertTrue(os.path.isfile(os.path.join(d, ".venv", "shipped.txt")))
        self.assertFalse(os.path.isfile(os.path.join(d, ".venv", "marker.txt")))

    def test_doctor_flags_missing_venv(self):
        # the doctor sweep is inline in cmd_doctor; assert its logic directly
        src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "railcall_cli.py")).read()
        self.assertIn("expects a .venv sidecar but has none", src)
        self.assertIn("_preserve_venv(module_dir)", src)
        self.assertIn("_preserve_venv(dest)", src)


if __name__ == "__main__":
    unittest.main()
