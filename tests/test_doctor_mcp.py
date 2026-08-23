"""railcall doctor --mcp / railcall mcp dedupe — own the Desktop↔MCP path end to end.

2026-08-23, Sami: "why is it so complex?" Four failures in a week, each at a seam
between layers that reported green on its own side. These tests make the doctor
PROVE each seam from the outside:
  · registrations: both ways Desktop can launch us (config json + extension), and
    a non-RailCall server is left alone;
  · dedupe: extension wins over json; without an extension the `railcall` entry
    wins; dry-run writes nothing; --apply writes with a backup and keeps the rest
    of the file intact;
  · probe: launches a server exactly as configured and reports what a client
    sees — lazy mode, illegal names, missing railcall_call door, a dead command.
"""
import json
import os
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import railcall_cli as cli  # noqa: E402


def _fake_home(with_json=True, with_ext=True, extra_server=True):
    home = tempfile.mkdtemp()
    appdir = os.path.join(home, "Library", "Application Support", "Claude")
    os.makedirs(os.path.join(appdir, "Claude Extensions", "local.dxt.railcall.railcall"))
    cfg = {"preferences": {"keep": "me"}, "mcpServers": {}}
    if with_json:
        cfg["mcpServers"]["railcall"] = {"command": "/usr/bin/python3", "args": ["/x/mcp_server.py"]}
    if extra_server:
        cfg["mcpServers"]["filesystem"] = {"command": "npx", "args": ["-y", "@mcp/fs"]}
    json.dump(cfg, open(os.path.join(appdir, "claude_desktop_config.json"), "w"))
    inst = {"extensions": {}}
    if with_ext:
        inst["extensions"]["local.dxt.railcall.railcall"] = {
            "id": "local.dxt.railcall.railcall", "version": "0.1.0",
            "manifest": {"name": "railcall", "display_name": "RailCall", "version": "0.1.0",
                         "server": {"mcp_config": {"command": "${HOME}/.railcall/bin/railcall",
                                                   "args": ["mcp"], "env": {"RAILCALL_WS": "${HOME}/ws"}}}}}
    json.dump(inst, open(os.path.join(appdir, "extensions-installations.json"), "w"))
    return home, os.path.join(appdir, "claude_desktop_config.json")


def _patched(home):
    cfg = os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    return mock.patch.multiple(cli, _claude_desktop_config_path=lambda: cfg), \
        mock.patch.dict(os.environ, {"HOME": home})


class Registrations(unittest.TestCase):
    def test_finds_json_and_extension_and_ignores_others(self):
        home, _ = _fake_home()
        p1, p2 = _patched(home)
        with p1, p2, mock.patch("os.path.expanduser", lambda p: p.replace("~", home)):
            regs, _, invalid = cli._mcp_desktop_registrations()
        self.assertFalse(invalid)
        kinds = sorted(r["kind"] for r in regs)
        self.assertEqual(kinds, ["ext", "json"])
        ext = next(r for r in regs if r["kind"] == "ext")
        self.assertEqual(ext["command"], os.path.join(home, ".railcall", "bin", "railcall"))   # ${HOME} expanded
        self.assertEqual(ext["env"]["RAILCALL_WS"], os.path.join(home, "ws"))
        self.assertNotIn("filesystem", [r["name"] for r in regs])

    def test_invalid_json_is_reported_not_crashed(self):
        home, cfg = _fake_home()
        open(cfg, "w").write("{not json")
        p1, p2 = _patched(home)
        with p1, p2:
            regs, _, invalid = cli._mcp_desktop_registrations()
        self.assertTrue(invalid)


class Dedupe(unittest.TestCase):
    def _run(self, home, args):
        p1, p2 = _patched(home)
        import io, contextlib
        buf = io.StringIO()
        with p1, p2, mock.patch("os.path.expanduser", lambda p: p.replace("~", home)), \
             contextlib.redirect_stdout(buf):
            rc = cli.cmd_mcp_dedupe(args)
        return rc, buf.getvalue()

    def test_dry_run_writes_nothing(self):
        home, cfg = _fake_home()
        before = open(cfg).read()
        rc, out = self._run(home, [])
        self.assertEqual(rc, 0)
        self.assertIn("dry run", out)
        self.assertEqual(open(cfg).read(), before)

    def test_apply_removes_json_keeps_extension_and_everything_else(self):
        home, cfg = _fake_home()
        rc, out = self._run(home, ["--apply"])
        self.assertEqual(rc, 0)
        after = json.load(open(cfg))
        self.assertNotIn("railcall", after["mcpServers"])
        self.assertIn("filesystem", after["mcpServers"], "other servers must survive")
        self.assertEqual(after["preferences"], {"keep": "me"}, "rest of the file intact")
        self.assertTrue(os.path.isfile(cfg + ".railcall-backup"))

    def test_without_extension_the_railcall_entry_wins(self):
        home, cfg = _fake_home(with_ext=False)
        c = json.load(open(cfg)); c["mcpServers"]["railcall-old"] = {"command": "python", "args": ["mcp_server.py"]}
        json.dump(c, open(cfg, "w"))
        rc, out = self._run(home, ["--apply"])
        after = json.load(open(cfg))
        self.assertIn("railcall", after["mcpServers"])
        self.assertNotIn("railcall-old", after["mcpServers"])

    def test_single_registration_is_a_noop(self):
        home, cfg = _fake_home(with_json=False)
        rc, out = self._run(home, ["--apply"])
        self.assertEqual(rc, 0)
        self.assertIn("nothing to do", out)


FAKE_SERVER = textwrap.dedent('''
    import json, sys
    for line in sys.stdin:
        m = json.loads(line)
        if m.get("method") == "initialize":
            print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
                "instructions": "... LAZY LISTING: core subset ...", "capabilities": {}}}), flush=True)
        elif m.get("method") == "tools/list":
            print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [
                {"name": "railcall_tool_resolve", "description": "core"},
                {"name": "bad.dotted", "description": "x · airlock-governed"},
                {"name": "good_module_tool", "description": "y · airlock-governed"}]}}), flush=True)
''')


class Probe(unittest.TestCase):
    def test_reports_lazy_illegal_and_missing_door(self):
        d = tempfile.mkdtemp(); srv = os.path.join(d, "fake.py"); open(srv, "w").write(FAKE_SERVER)
        pr = cli._mcp_probe({"command": sys.executable, "args": [srv], "env": {}})
        self.assertTrue(pr["ok"], pr)
        self.assertEqual(pr["tools"], 3)
        self.assertEqual(pr["module_tools"], 2)
        self.assertTrue(pr["lazy"])
        self.assertFalse(pr["has_call_door"])
        self.assertEqual(pr["illegal"], ["bad.dotted"])

    def test_dead_command_is_an_error_not_a_hang(self):
        pr = cli._mcp_probe({"command": "/nonexistent/python", "args": [], "env": {}})
        self.assertFalse(pr["ok"]); self.assertIn("not found", pr["error"])

    def test_server_that_never_answers_times_out(self):
        d = tempfile.mkdtemp(); srv = os.path.join(d, "mute.py")
        open(srv, "w").write("import time\nwhile True: time.sleep(1)\n")
        pr = cli._mcp_probe({"command": sys.executable, "args": [srv], "env": {}}, timeout=2)
        self.assertFalse(pr["ok"]); self.assertIn("no reply", pr["error"])


if __name__ == "__main__":
    unittest.main()
