"""Unit tests for tools.py: password scrubbing in tool output and the audit
log, and list_hosts following reload_config. No real SSH: tool operations
and background connections are mocked. Run from the repo root:
python -m unittest tests.test_tools -v"""
import asyncio
import contextlib
import os
import tempfile
import unittest
from types import SimpleNamespace
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
        self.enterContext(mock.patch.object(pool, "connect_in_background"))
        self._saved = (pool.cfg, dict(pool._bastion_conns), dict(pool._target_conns),
                       dict(pool._passwords), tools.AUDIT_LOG)
        pool.cfg = {}
        pool._bastion_conns.clear()
        pool._target_conns.clear()
        pool._passwords.clear()
        fd, self.audit = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        tools.AUDIT_LOG = self.audit

    def tearDown(self):
        pool.cfg, bconns, targets, passwords, tools.AUDIT_LOG = self._saved
        pool._bastion_conns.clear()
        pool._bastion_conns.update(bconns)
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


class NodeAccessTests(ToolsTestCase):
    async def test_read_only_all_routes_and_reload(self):
        nodes = {route: {"via": route, "address": "node.invalid", "access": "read_only"}
                 for route in ("direct", "bastion", "hop")}
        pool.cfg = _cfg(**nodes)
        expected = SimpleNamespace(returncode=0, stdout="data", stderr="")
        with mock.patch.object(pool, "run", mock.AsyncMock(return_value=expected)) as run, \
                mock.patch.object(pool, "with_sftp", mock.AsyncMock()) as sftp:
            for route in nodes:
                self.assertEqual(await tools.read_file(route, "log"), "data")
                self.assertIn("read-only", await tools.exec(route, "true"))
                self.assertIn("read-only", await tools.write_file(route, "log", "changed"))
                self.assertIn("read-only", await tools.edit_file(route, "log", "data", "changed"))
            for call in run.await_args_list:
                self.assertIn("awk", call.args[1])
            sftp.assert_not_awaited()
            self.assertEqual(run.await_count, 3)

            nodes["hop"] = {**nodes["hop"], "access": "full"}
            pool.apply_config(_cfg(**nodes))
            self.assertIn("exit_code: 0", await tools.exec("hop", "true"))
            pool.apply_config(_cfg(**nodes) | {"hosts": {"allowed": ["direct", "bastion"]}})
            self.assertIn("allowed list", await tools.exec("hop", "true"))
            self.assertIn("not configured", await tools.exec("unknown", "true"))
            self.assertEqual(run.await_count, 4)

    async def test_activity_records_unknown_outcome_without_command_arguments(self):
        pool.cfg = _cfg(lab4=_lab4())
        with mock.patch.object(pool, "run", mock.AsyncMock(side_effect=pool.RemoteResultUnknown())):
            response = await tools.exec("lab4", "private command arguments")
        self.assertIn("remote result unknown", response)
        row = tools.recent_activity()[0]
        self.assertEqual((row["host"], row["action"], row["status"]), ("lab4", "exec", "结果未知"))
        self.assertNotIn("private command arguments", str(row))

    async def test_sftp_rechecks_before_rename_and_cleans_its_temporary_file(self):
        for operation, args, cancel in (
            (tools.write_file, ("after",), False),
            (tools.edit_file, ("before", "after"), False),
            (tools.write_file, ("after",), True),
        ):
            with self.subTest(operation=operation.__name__, cancel=cancel):
                pool.cfg = _cfg(revision=_lab4())
                at_chmod, release = asyncio.Event(), asyncio.Event()
                attrs = SimpleNamespace(permissions=0o100644)
                remote = mock.Mock()
                remote.lstat = mock.AsyncMock(return_value=attrs)
                remote.stat = mock.AsyncMock(return_value=attrs)
                remote.remove = mock.AsyncMock()
                remote.posix_rename = mock.AsyncMock()
                fh = SimpleNamespace(write=mock.AsyncMock(), read=mock.AsyncMock(return_value="before"))
                temp = []

                @contextlib.asynccontextmanager
                async def open_file(path, mode):
                    if mode == "x":
                        temp.append(path)
                    yield fh

                async def chmod(_path, _mode):
                    at_chmod.set()
                    await release.wait()

                @contextlib.asynccontextmanager
                async def start_sftp():
                    yield remote

                remote.open = open_file
                remote.chmod = chmod
                conn = mock.Mock(start_sftp_client=start_sftp)
                with mock.patch.object(pool, "get_target", return_value=conn):
                    pending = asyncio.create_task(operation("revision", "/sample", *args))
                    await asyncio.wait_for(at_chmod.wait(), 2)
                    if cancel:
                        pending.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await pending
                    else:
                        pool.apply_config(_cfg(revision=_lab4(access="read_only")))
                        release.set()
                        self.assertIn("read-only", await pending)
                self.assertEqual(len(temp), 1)
                self.assertNotEqual(temp[0], "/sample")
                remote.posix_rename.assert_not_awaited()
                remote.remove.assert_awaited_once_with(temp[0])


if __name__ == "__main__":
    unittest.main()
