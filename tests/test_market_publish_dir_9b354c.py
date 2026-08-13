"""#9b354c — `railcall market publish .` must work as the walkthrough writes it.

akif: the "your first module" walkthrough says `railcall market publish .`
with no --type flag; _market_publish only routed to the module path when
--type=module was present, so "." fell to the JSON-spec branch and died on
"Spec file not found: ." — deterministically, since a directory is never a
file.

Fix under test: a directory argument containing module.json routes to the
module publish path without the flag; a directory WITHOUT module.json gets
an explanatory panel naming both forms, not "Spec file not found".

Runs the real CLI as a subprocess with a scratch HOME so no publisher key /
login / network is touched — the assertion is only about ROUTING, which
happens before any of those checks.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "railcall_cli.py")


def _run(args, cwd):
    env = dict(os.environ, HOME=tempfile.mkdtemp(), NO_COLOR="1",
               PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, CLI] + args, cwd=cwd,
                          capture_output=True, text=True, timeout=60, env=env)


class TestPublishDirRouting(unittest.TestCase):
    def setUp(self):
        self.mdir = tempfile.mkdtemp()
        with open(os.path.join(self.mdir, "module.json"), "w") as fh:
            json.dump({"slug": "greeter", "version": "0.1.0",
                       "commands": []}, fh)
        with open(os.path.join(self.mdir, "handler.py"), "w") as fh:
            fh.write("def handle(*a, **k):\n    return {}\n")

    def test_walkthrough_command_routes_to_module_path(self):
        # the docs' exact form: publish . from inside the module dir
        r = _run(["market", "publish", "."], cwd=self.mdir)
        out = r.stdout + r.stderr
        self.assertNotIn("Spec file not found", out,
                         "a dir with module.json must never hit the "
                         "JSON-spec branch:\n" + out[:800])

    def test_dir_without_module_json_gets_explanation(self):
        empty = tempfile.mkdtemp()
        r = _run(["market", "publish", "."], cwd=empty)
        out = r.stdout + r.stderr
        self.assertNotIn("Spec file not found", out)
        self.assertIn("module.json", out,
                      "refusal must explain what a module dir needs:\n" + out[:800])

    def test_explicit_flag_still_works(self):
        a = _run(["market", "publish", ".", "--type=module"], cwd=self.mdir)
        b = _run(["market", "publish", "."], cwd=self.mdir)
        # both forms must route identically (same first failure — publisher
        # key / login — never the spec-file branch)
        self.assertNotIn("Spec file not found", a.stdout + a.stderr)
        self.assertEqual(("Spec file not found" in (a.stdout + a.stderr)),
                         ("Spec file not found" in (b.stdout + b.stderr)))

    def test_missing_spec_file_message_unchanged(self):
        r = _run(["market", "publish", "no_such_spec.json"], cwd=self.mdir)
        self.assertIn("Spec file not found", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
