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
        self._saved = (pool.cfg, pool._bastion_conn)
        pool.cfg = {}
        pool._bastion_conn = None
        pool._bastion_lock = asyncio.Lock()

    def tearDown(self):
        pool.cfg, pool._bastion_conn = self._saved

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
        self.assertIsNone(pool._bastion_conn)
        self.assertFalse(pool._bastion_lock.locked())


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

    def tearDown(self):
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


if __name__ == "__main__":
    unittest.main()
