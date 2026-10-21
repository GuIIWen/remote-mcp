"""Unit tests for tools.py: password scrubbing in tool output and the audit
log, and list_hosts following reload_config. No real SSH: pool.run /
pool.load_config are mocked. Run from the repo root:
python -m unittest tests.test_tools -v"""
import os
import tempfile
import unittest
from unittest import mock

import asyncssh

import pool
import tools

PW = "Hunter2!pw"


def _cfg(**hosts) -> dict:
    return {
        "bastion": {"host": "b", "user": "u", "port": 22},
        "hosts": {"allowed": sorted(hosts)},
        "host": hosts,
    }


def _lab4(**kw) -> dict:
    hc = {"via": "direct", "address": "10.0.0.4", "user": "u", "auth": "password", "password": PW}
    hc.update(kw)
    return hc


class ToolsTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = (pool.cfg, pool._bastion_conn, dict(pool._target_conns),
                       dict(pool._passwords), tools.AUDIT_LOG)
        pool.cfg = {}
        pool._bastion_conn = None
        pool._target_conns.clear()
        pool._passwords.clear()
        fd, self.audit = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        tools.AUDIT_LOG = self.audit

    def tearDown(self):
        pool.cfg, pool._bastion_conn, targets, passwords, tools.AUDIT_LOG = self._saved
        pool._target_conns.clear()
        pool._target_conns.update(targets)
        pool._passwords.clear()
        pool._passwords.update(passwords)
        os.remove(self.audit)

    def audit_text(self) -> str:
        with open(self.audit, encoding="utf-8") as f:
            return f.read()


class ScrubTests(ToolsTestCase):
    def test_scrub_replaces_every_known_password(self):
        pool._passwords.update({"lab4": PW, "lab5": "other-pw", "lab6": ""})
        out = tools._scrub(f"a {PW} b other-pw c {PW}")
        self.assertEqual(out, "a *** b *** c ***")

    def test_empty_password_does_not_mangle_text(self):
        pool._passwords["lab4"] = ""
        self.assertEqual(tools._scrub("unchanged"), "unchanged")

    async def test_exec_error_is_scrubbed(self):
        pool.cfg = _cfg(lab4=_lab4())
        pool._passwords["lab4"] = PW
        err = asyncssh.PermissionDenied(f"auth failed for password {PW}")
        with mock.patch.object(pool, "run", mock.AsyncMock(side_effect=err)):
            out = await tools.exec("lab4", "true")
        self.assertIn("PermissionDenied", out)
        self.assertIn("***", out)
        self.assertNotIn(PW, out)

    async def test_write_file_error_is_scrubbed(self):
        pool.cfg = _cfg(lab4=_lab4())
        pool._passwords["lab4"] = PW
        with mock.patch.object(pool, "with_sftp", mock.AsyncMock(side_effect=OSError(f"x {PW}"))):
            out = await tools.write_file("lab4", "a.txt", "hi")
        self.assertNotIn(PW, out)


class ListHostsTests(ToolsTestCase):
    async def test_password_never_listed(self):
        pool.cfg = _cfg(lab4=_lab4())
        pool._passwords["lab4"] = PW
        out = await tools.list_hosts()
        self.assertIn("lab4: direct 10.0.0.4:22, auth=password, disconnected", out)
        self.assertNotIn(PW, out)

    async def test_follows_reload_config(self):
        pool.cfg = _cfg(dev1={"user": "u"})
        before = await tools.list_hosts()
        self.assertIn("dev1: bastion", before)
        self.assertNotIn("lab4", before)

        new = _cfg(lab4=_lab4(), n1={"via": "hop", "container": "c1"})
        with mock.patch.object(pool, "load_config", return_value=(new, [])):
            reloaded = await tools.reload_config()
        self.assertIn("added: lab4, n1", reloaded)
        self.assertIn("removed: dev1", reloaded)

        after = await tools.list_hosts()
        self.assertNotIn("dev1", after)
        self.assertIn("lab4: direct 10.0.0.4:22, auth=password", after)
        self.assertIn("n1: hop via bastion → docker:c1", after)
        self.assertIn("allowed: ['lab4', 'n1']", after)
        self.assertNotIn(PW, after)

    async def test_changed_node_shows_disconnected_after_reload(self):
        pool.cfg = _cfg(lab4=_lab4())
        pool._target_conns["lab4"] = mock.Mock()
        self.assertIn("auth=password, connected", await tools.list_hosts())
        new = _cfg(lab4=_lab4(address="10.0.0.40"))
        with mock.patch.object(pool, "load_config", return_value=(new, [])):
            await tools.reload_config()
        self.assertIn("lab4: direct 10.0.0.40:22, auth=password, disconnected", await tools.list_hosts())


class ReloadConfigOutputTests(ToolsTestCase):
    async def test_success_output_and_audit_have_no_password(self):
        pool.cfg = _cfg()
        new = _cfg(lab4=_lab4())
        with mock.patch.object(pool, "load_config", return_value=(new, [f"warning: {PW}"])):
            out = await tools.reload_config()
        self.assertIn("ok: config reloaded", out)
        self.assertNotIn(PW, out)
        self.assertNotIn(PW, self.audit_text())
        self.assertIn("reload_config", self.audit_text())

    async def test_need_password_is_reported(self):
        pool.cfg = _cfg()
        with mock.patch.object(pool, "load_config", return_value=(_cfg(lab4=_lab4(password="")), [])):
            out = await tools.reload_config()
        self.assertIn("[host.lab4] 需要重启 daemon 后输入密码", out)

    async def test_failure_keeps_old_config_and_is_scrubbed(self):
        old = _cfg(lab4=_lab4())
        pool.cfg = old
        pool._passwords["lab4"] = PW
        err = pool.ConfigLoadError([f"bad value {PW}"], [])
        with mock.patch.object(pool, "load_config", side_effect=err):
            out = await tools.reload_config()
        self.assertIn("配置未改动", out)
        self.assertNotIn(PW, out)
        self.assertNotIn(PW, self.audit_text())
        self.assertIs(pool.cfg, old)


class AuditTests(ToolsTestCase):
    async def test_write_ops_audit_path_not_content(self):
        pool.cfg = _cfg(lab4=_lab4())
        with mock.patch.object(pool, "with_sftp", mock.AsyncMock(return_value=None)):
            await tools.write_file("lab4", "notes.txt", f"content {PW}")
        text = self.audit_text()
        self.assertIn("notes.txt", text)
        self.assertNotIn(PW, text)


if __name__ == "__main__":
    unittest.main()
