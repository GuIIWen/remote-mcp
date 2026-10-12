"""Unit tests for daemon.py's startup bastion login retry. No real SSH:
pool.get_bastion / pool._connect_bastion are mocked. Run from this
directory:  python -m unittest test_daemon -v"""
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


if __name__ == "__main__":
    unittest.main()
