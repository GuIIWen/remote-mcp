"""Unit tests for daemon.py's startup logins: bastion login retry and the
direct+password pre-connect. No real SSH: pool.get_bastion /
pool._connect_bastion / pool.get_target are mocked. Run from the repo
root:  python -m unittest tests.test_daemon -v"""
import asyncio
import contextlib
import io
import unittest
from unittest import mock

import asyncssh

import daemon
import pool


def capture():
    return contextlib.redirect_stdout(io.StringIO())


class LoginBastionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = (pool.cfg, dict(pool._bastion_conns))
        pool.cfg = {"bastion": {"host": "b", "user": "u", "port": 22}}
        pool._bastion_conns.clear()
        pool._bastion_locks.clear()

    def tearDown(self):
        pool.cfg, bconns = self._saved
        pool._bastion_conns.clear()
        pool._bastion_conns.update(bconns)

    async def test_retry_after_one_bad_code(self):
        get = mock.AsyncMock(side_effect=[asyncssh.PermissionDenied("bad code"), object()])
        with mock.patch.object(pool, "get_bastion", get), capture() as out:
            ok = await daemon._login_bastion()
        self.assertTrue(ok)
        self.assertEqual(get.await_count, 2)
        self.assertIn("bad code", out.getvalue())
        self.assertIn("还剩 2 次", out.getvalue())

    async def test_gives_up_after_three_bad_codes(self):
        get = mock.AsyncMock(side_effect=asyncssh.PermissionDenied("bad code"))
        with mock.patch.object(pool, "get_bastion", get), capture() as out:
            ok = await daemon._login_bastion()
        self.assertFalse(ok)
        self.assertEqual(get.await_count, daemon.BASTION_RETRIES)
        self.assertEqual(get.await_count, 3)
        self.assertIn("放弃启动时登录", out.getvalue())

    async def test_retry_after_one_timeout(self):
        get = mock.AsyncMock(side_effect=[asyncio.TimeoutError(), object()])
        with mock.patch.object(pool, "get_bastion", get), capture() as out:
            ok = await daemon._login_bastion()
        self.assertTrue(ok)
        self.assertEqual(get.await_count, 2)
        self.assertIn("登录超时", out.getvalue())
        self.assertIn("还剩 2 次", out.getvalue())

    async def test_gives_up_after_three_timeouts(self):
        get = mock.AsyncMock(side_effect=asyncio.TimeoutError())
        with mock.patch.object(pool, "get_bastion", get), capture() as out:
            ok = await daemon._login_bastion()
        self.assertFalse(ok)
        self.assertEqual(get.await_count, 3)
        self.assertIn("放弃启动时登录", out.getvalue())

    async def test_other_error_is_not_retried(self):
        get = mock.AsyncMock(side_effect=OSError("unreachable"))
        with mock.patch.object(pool, "get_bastion", get), capture() as out:
            ok = await daemon._login_bastion()
        self.assertFalse(ok)
        self.assertEqual(get.await_count, 1)
        self.assertIn("OSError", out.getvalue())

    async def test_failed_login_leaves_pool_clean(self):
        # Goes through the real get_bastion (lock + _ensure_bastion), failing
        # one level below it, so the lock/conn state checked is the real one.
        connect = mock.AsyncMock(side_effect=asyncssh.PermissionDenied("bad code"))
        with mock.patch.object(pool, "_connect_bastion", connect), capture():
            ok = await daemon._login_bastion()
        self.assertFalse(ok)
        self.assertEqual(connect.await_count, 3)
        self.assertIsNone(pool._bastion_conns.get("default"))
        self.assertFalse(pool._bastion_lock("default").locked())


def _pw_cfg(password: str = "") -> dict:
    return {
        "host": {
            "lab4": {"via": "direct", "address": "10.0.0.4", "user": "u",
                     "auth": "password", "password": password},
            "lab3": {"via": "direct", "address": "10.0.0.3", "user": "u", "auth": "key"},
            "dev1": {"user": "u"},
        }
    }


class PreparePasswordHostsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = dict(pool._passwords)
        pool._passwords.clear()
        pool._auth_blocked.clear()

    def tearDown(self):
        pool._auth_blocked.clear()
        pool._passwords.clear()
        pool._passwords.update(self._saved)

    async def _run(self, cfg, get_side_effect, typed=()):
        """Run _prepare_password_hosts with get_target and the getpass
        prompt mocked; `typed` is what the user types at each prompt. Records
        the password in effect at each connect attempt."""
        seen: list[str] = []

        async def fake_get(host):
            seen.append(pool._passwords.get(host))
            eff = next(effects)
            if isinstance(eff, BaseException):
                raise eff
            return eff

        effects = iter(get_side_effect)
        prompt = mock.AsyncMock(side_effect=list(typed))
        with mock.patch.object(pool, "get_target", side_effect=fake_get) as get, \
                mock.patch.object(daemon, "_prompt_password", prompt), capture() as out:
            await daemon._prepare_password_hosts(cfg, asyncio.get_running_loop())
        return get, prompt, seen, out.getvalue()

    async def test_config_password_used_without_prompt(self):
        get, prompt, seen, out = await self._run(_pw_cfg("s3cret"), [object()])
        prompt.assert_not_awaited()
        self.assertEqual(seen, ["s3cret"])
        self.assertEqual(pool._passwords["lab4"], "s3cret")
        self.assertIn("[lab4] connected", out)
        # key-auth direct and bastion-routed nodes are not pre-connected
        self.assertEqual([c.args[0] for c in get.await_args_list], ["lab4"])

    async def test_wrong_config_password_tried_once(self):
        get, prompt, seen, out = await self._run(
            _pw_cfg("wrong"), [asyncssh.PermissionDenied("denied")]
        )
        self.assertEqual(get.await_count, 1)
        prompt.assert_not_awaited()
        self.assertIn("配置里的密码错误", out)
        self.assertNotIn("wrong", out)

    async def test_empty_password_prompts_and_reprompts(self):
        denied = asyncssh.PermissionDenied("denied")
        get, prompt, seen, out = await self._run(
            _pw_cfg(""), [denied, denied, object()], typed=["a", "b", "c"]
        )
        self.assertEqual(prompt.await_count, 3)
        self.assertEqual(seen, ["a", "b", "c"])
        self.assertEqual(pool._passwords["lab4"], "c")
        self.assertIn("[lab4] connected", out)
        for typed in ("a", "b", "c"):
            self.assertNotIn(f"'{typed}'", out)

    async def test_gives_up_after_retries(self):
        get, prompt, seen, out = await self._run(
            _pw_cfg(""), [asyncssh.PermissionDenied("denied")] * daemon.PASSWORD_RETRIES,
            typed=["a", "b", "c"],
        )
        self.assertEqual(get.await_count, daemon.PASSWORD_RETRIES)
        self.assertEqual(prompt.await_count, daemon.PASSWORD_RETRIES)
        self.assertIn("次数过多", out)

    async def test_network_error_not_retried_and_not_reprompted(self):
        for exc in (OSError("unreachable"), asyncio.TimeoutError()):
            pool._passwords.clear()
            get, prompt, seen, out = await self._run(_pw_cfg(""), [exc], typed=["a"])
            self.assertEqual(get.await_count, 1, exc)
            self.assertEqual(prompt.await_count, 1, exc)
            self.assertIn("首次调用时按需重连", out)
            # password kept for the lazy reconnect later
            self.assertEqual(pool._passwords["lab4"], "a")

    async def test_other_error_skips_host(self):
        get, prompt, seen, out = await self._run(
            _pw_cfg("s3cret"), [ValueError("Host 'lab4' is not in the allowed list")]
        )
        self.assertEqual(get.await_count, 1)
        self.assertIn("跳过该节点", out)


class WrongPasswordThenSweepTests(unittest.IsolatedAsyncioTestCase):
    """Startup flow across components: _prepare_password_hosts, then the eager
    connect_nodes sweep, through the real get_target (only asyncssh.connect is
    mocked)."""

    def setUp(self):
        self._saved = (pool.cfg, dict(pool._passwords), dict(pool._target_conns))
        pool._passwords.clear()
        pool._target_conns.clear()
        pool._auth_blocked.clear()
        pool._last_error.clear()

    def tearDown(self):
        pool.cfg, passwords, targets = self._saved
        pool._passwords.clear()
        pool._passwords.update(passwords)
        pool._target_conns.clear()
        pool._target_conns.update(targets)
        pool._auth_blocked.clear()
        pool._last_error.clear()

    async def _startup(self, password, typed=()):
        cfg = _pw_cfg(password)
        pool.cfg = cfg
        connect = mock.AsyncMock(side_effect=asyncssh.PermissionDenied("denied"))
        with mock.patch.object(pool.asyncssh, "connect", connect), \
                mock.patch.object(daemon, "_prompt_password", mock.AsyncMock(side_effect=list(typed))), \
                capture():
            await daemon._prepare_password_hosts(cfg, asyncio.get_running_loop())
            await pool.connect_nodes(["lab4"])
            with self.assertRaises(asyncssh.PermissionDenied):
                await pool.run("lab4", "true")  # a later lazy call
        return connect

    async def test_wrong_config_password_costs_one_attempt(self):
        connect = await self._startup("wrong")
        self.assertEqual(connect.await_count, 1)
        self.assertIn("配置里的密码被拒绝", pool._last_error["lab4"])
        rows = {r["name"]: r for r in pool.connection_status()}
        self.assertIn("配置里的密码被拒绝", rows["lab4"]["detail"])

    async def test_password_typed_wrong_too_often_is_not_replayed_by_the_sweep(self):
        connect = await self._startup("", typed=["a", "b", "c"])
        self.assertEqual(connect.await_count, daemon.PASSWORD_RETRIES)

    async def test_lazy_call_works_again_after_block_is_lifted(self):
        await self._startup("wrong")
        pool._auth_blocked.clear()  # what reconnect_all / apply_config do
        conn = mock.Mock()
        with mock.patch.object(pool.asyncssh, "connect", mock.AsyncMock(return_value=conn)) as connect, \
                mock.patch.object(pool, "_idle_probe_ok", mock.AsyncMock(return_value=True)):
            self.assertIs(await pool.get_target("lab4"), conn)
        connect.assert_awaited_once()


class InitServiceTests(unittest.TestCase):
    def setUp(self):
        self._saved = (pool.cfg, dict(pool._passwords))

    def tearDown(self):
        pool.cfg, passwords = self._saved
        pool._passwords.clear()
        pool._passwords.update(passwords)

    def _init(self, bastion):
        cfg = {"bastion": bastion, "host": {}}
        path = mock.Mock(**{"exists.return_value": True})
        with mock.patch.object(daemon, "CONFIG_PATH", path), \
                mock.patch.object(pool, "load_config", return_value=(cfg, [])), \
                mock.patch.object(daemon, "tools"), capture():
            daemon.init_service()

    def test_restart_does_not_reuse_the_previous_runs_passwords(self):
        base = {"host": "b", "user": "u"}
        self._init({**base, "password": "old"})
        self.assertEqual(pool._passwords["[bastion]"], "old")
        pool._passwords["lab4"] = "typed-last-run"
        self._init(base)  # password removed from config
        self.assertEqual(pool._passwords, {})
        self._init({**base, "password": "new"})
        self.assertEqual(pool._passwords, {"[bastion]": "new"})


class ServeCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_during_startup_still_resets_the_pool(self):
        # The GUI stops a still-starting service by cancelling its tasks.
        started = asyncio.Event()

        async def hang(*a, **kw):
            started.set()
            await asyncio.Event().wait()

        reset = mock.AsyncMock()
        with mock.patch.object(daemon, "_prepare_password_hosts", hang), \
                mock.patch.object(pool, "reset_all", reset):
            task = asyncio.create_task(daemon.serve({"host": {}}, 0))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        reset.assert_awaited_once()

    async def test_background_connects_are_cancelled_with_the_run(self):
        async def never(*a, **kw):
            await asyncio.Event().wait()

        server = mock.Mock(serve=mock.AsyncMock())
        with mock.patch.object(pool, "connect_nodes", never), \
                mock.patch.object(pool, "reset_all", mock.AsyncMock()), \
                mock.patch.object(pool, "heartbeat_loop", never), \
                mock.patch("uvicorn.Server", return_value=server), \
                mock.patch.object(daemon, "_prepare_password_hosts", mock.AsyncMock()), \
                capture():
            await daemon.serve({"host": {"a": {}}}, 0)
        self.assertEqual(pool._bg_tasks, set())


if __name__ == "__main__":
    unittest.main()
