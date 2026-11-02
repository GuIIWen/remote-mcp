"""Unit tests for setup_ssh_keys.py's second-factor (verification code) handling.
No real SSH: asyncssh.create_connection and the terminal are faked. Run from
the repo root:  python -m unittest tests.test_setup_ssh_keys -v"""
import asyncio
import contextlib
import io
import unittest
from unittest import mock

import setup_ssh_keys as s


def client(**kw):
    return s._NodeClient(s.Node("lab1", "10.0.0.1", 22, "root", "s3cret"), s.STAGE_LOGIN, **kw)


class PromptTests(unittest.IsolatedAsyncioTestCase):
    async def answer(self, c, prompts, typed=()):
        typed = iter(typed)
        asked: list[str] = []

        def fake_input(prompt):
            asked.append(prompt)
            return next(typed)

        with mock.patch("builtins.input", fake_input), \
                mock.patch.object(s.getpass, "getpass", fake_input), \
                contextlib.redirect_stdout(io.StringIO()):
            resp = await c.kbdint_challenge_received("", "", "", prompts)
        return resp, asked

    def test_prompt_classification(self):
        for p in ("Password: ", "请输入密码："):
            self.assertTrue(s.is_password_prompt(p), p)
        for p in ("Verification code: ", "One-time password: ", "请输入验证码：", "Passcode: "):
            self.assertFalse(s.is_password_prompt(p), p)

    async def test_password_then_code_in_one_challenge(self):
        resp, asked = await self.answer(
            client(), [("Password: ", False), ("Verification code: ", False)], ["123456"])
        self.assertEqual(resp, ["s3cret", "123456"])
        self.assertEqual(asked, ["[lab1/登录] Verification code: "])

    async def test_code_only_challenge_after_password_method(self):
        # AuthenticationMethods password,keyboard-interactive: the password
        # already went out via the password method, only the code is left.
        c = client()
        self.assertEqual(c.password_auth_requested(), "s3cret")
        resp, _ = await self.answer(c, [("Verification code: ", False)], ["654321"])
        self.assertEqual(resp, ["654321"])

    async def test_verify_stage_never_sends_password(self):
        c = client(allow_password=False)
        resp, asked = await self.answer(c, [("Password: ", False)])
        self.assertIsNone(resp)
        resp, _ = await self.answer(c, [("Verification code: ", False)], ["123456"])
        self.assertEqual(resp, ["123456"])
        self.assertTrue(c.asked_user)

    async def test_password_prompt_again_is_not_resent(self):
        c = client()
        self.assertEqual((await self.answer(c, [("Password: ", False)]))[0], ["s3cret"])
        self.assertIsNone((await self.answer(c, [("Password: ", False)]))[0])


class ConnectLoginTests(unittest.IsolatedAsyncioTestCase):
    node = s.Node("lab1", "10.0.0.1", 22, "root", "s3cret")

    async def login(self, behaviour):
        async def fake_create(factory, host, **kw):
            self.kw = kw
            return await behaviour(factory())

        with mock.patch.object(s.asyncssh, "create_connection", fake_create):
            return (await s._connect_node(self.node, s.STAGE_LOGIN, connect_timeout=0.05))[0]

    async def test_silent_hang_times_out(self):
        async def hang(c):
            await asyncio.sleep(10)

        with self.assertRaises(asyncio.TimeoutError):
            await self.login(hang)
        self.assertIsNone(self.kw["connect_timeout"])

    async def test_rejection_says_what_was_asked(self):
        async def rejected(c):
            c.password_auth_requested()
            c.trace.append("'Verification code:'→终端输入")
            raise s.asyncssh.PermissionDenied("Permission denied")

        with self.assertRaises(s.asyncssh.PermissionDenied) as cm:
            await self.login(rejected)
        self.assertIn("password 方式：已发送密码；'Verification code:'→终端输入", cm.exception.reason)
        self.assertNotIn("s3cret", cm.exception.reason)

    async def test_clock_stops_while_user_is_typing(self):
        async def slow_typist(c):
            c.prompting = True
            await asyncio.sleep(0.2)  # 4x the timeout
            c.prompting = False
            return "conn", c

        self.assertEqual(await self.login(slow_typist), "conn")


class VerifyRefusedTests(unittest.IsolatedAsyncioTestCase):
    async def test_refused_key_reports_what_the_node_says(self):
        class LoginConn:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def get_server_host_key(self): return object()

            async def run(self, cmd, input=None, **kw):
                installing = "grep -qxF" in input
                return mock.Mock(stdout="added" if installing else "drwxrwxr-x HOME")

        calls = []

        async def fake_connect(node, stage, **kw):
            calls.append(stage)
            if stage == s.STAGE_LOGIN:
                return LoginConn(), None
            raise s.asyncssh.PermissionDenied("Permission denied (trace)")

        node = s.Node("lab1", "10.0.0.1", 22, "root", "s3cret")
        with mock.patch.object(s, "_connect_node", fake_connect), \
                mock.patch.object(s.asyncssh, "get_server_auth_methods",
                                  mock.AsyncMock(return_value=["publickey", "keyboard-interactive"])), \
                mock.patch.object(s, "record_host_key", return_value="present"):
            with self.assertRaises(s.StageError) as cm:
                await s._attempt(node, object(), "ssh-ed25519 AAAA", 1)
        self.assertEqual(calls, [s.STAGE_LOGIN, s.STAGE_VERIFY])
        self.assertEqual(cm.exception.stage, s.STAGE_VERIFY)
        self.assertIsNotNone(s._no_retry_reason(cm.exception))
        self.assertIn("drwxrwxr-x HOME", str(cm.exception))


class NoPublicKeyAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_node_without_publickey_fails_before_anything_is_asked(self):
        # What the real lab1 advertises (ssh -v): no publickey.
        methods = ["gssapi-keyex", "gssapi-with-mic", "password", "keyboard-interactive"]
        connect = mock.AsyncMock()
        node = s.Node("lab1", "10.0.0.1", 22, "root", "s3cret")
        with mock.patch.object(s, "_connect_node", connect), \
                mock.patch.object(s.asyncssh, "get_server_auth_methods",
                                  mock.AsyncMock(return_value=methods)):
            with self.assertRaises(s.StageError) as cm:
                await s._attempt(node, object(), "ssh-ed25519 AAAA", 1)
        connect.assert_not_called()  # no login, no verification code, nothing installed
        self.assertEqual(cm.exception.stage, s.STAGE_PROBE)
        self.assertIn("没有 publickey", str(cm.exception))
        self.assertIn("PubkeyAuthentication", s._no_retry_reason(cm.exception))

    async def test_setup_node_does_not_retry_it(self):
        node = s.Node("lab1", "10.0.0.1", 22, "root", "s3cret")
        attempt = mock.AsyncMock(side_effect=s.StageError(s.STAGE_PROBE, s.NoPublicKeyAuth("x")))
        with mock.patch.object(s, "_attempt", attempt), contextlib.redirect_stdout(io.StringIO()):
            r = await s.setup_node(node, object(), "k", 1, 3, asyncio.Semaphore(1))
        self.assertFalse(r.ok)
        self.assertEqual(attempt.await_count, 1)


if __name__ == "__main__":
    unittest.main()
