"""Unit tests for pool.py's connection-robustness logic (drop classification,
keepalive/heartbeat config, heartbeat, idle probe). No real SSH: connections
are fakes. Run from the repo root:  python -m unittest tests.test_pool -v"""
import asyncio
import contextlib
import io
import time
import unittest
from unittest import mock

import asyncssh

import pool


class FakeConn:
    def __init__(self, run_exc=None, run_delay=0.0):
        self.run_exc = run_exc
        self.run_delay = run_delay
        self.commands: list[str] = []
        self.closed = False

    async def run(self, cmd, check=False):
        self.commands.append(cmd)
        if self.run_delay:
            await asyncio.sleep(self.run_delay)
        if self.run_exc is not None:
            raise self.run_exc

    def close(self):
        self.closed = True


def register(conn, idle=0.0, idle_real=None):
    """Give a fake conn a stats entry, as _TrackedClient.connection_made does."""
    s = pool._ConnStats()
    now = time.monotonic()
    s.last_used = now - idle
    s.last_real = now - (idle if idle_real is None else idle_real)
    pool._conn_stats[conn] = s
    return s


def capture():
    return contextlib.redirect_stdout(io.StringIO())


class PoolTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = (pool.cfg, pool._bastion_conn, dict(pool._target_conns), dict(pool._passwords))
        pool.cfg = {}
        pool._bastion_conn = None
        pool._target_conns.clear()
        pool._conn_stats.clear()
        pool._passwords.clear()
        pool._bastion_lock = asyncio.Lock()

    def tearDown(self):
        pool.cfg, pool._bastion_conn, targets, passwords = self._saved
        pool._target_conns.clear()
        pool._target_conns.update(targets)
        pool._passwords.clear()
        pool._passwords.update(passwords)
        pool._conn_stats.clear()


class ClassifyDropTests(unittest.TestCase):
    def hints(self, *a, **kw):
        return " | ".join(pool.classify_drop(*a, **kw))

    def test_local_close_is_not_a_remote_drop(self):
        h = pool.classify_drop(None, 3600, 5, local=True)
        self.assertEqual(len(h), 1)
        self.assertIn("closed by this daemon", h[0])

    def test_exc_none_is_peer_clean_disconnect(self):
        self.assertIn("exc=None", self.hints(None, 1234, 1234))

    def test_keepalive_failure(self):
        exc = asyncssh.ConnectionLost("Server not responding to keepalive")
        h = self.hints(exc, 1234, 40)
        self.assertIn("keepalive failure", h)
        self.assertNotIn("exc=None", h)

    def test_plain_connection_lost_vs_disconnect_error(self):
        self.assertIn("without a DISCONNECT", self.hints(asyncssh.ConnectionLost("Connection lost"), 777, 7))
        self.assertIn("error code", self.hints(asyncssh.DisconnectError(2, "protocol error"), 777, 7))

    def test_oserror(self):
        self.assertIn("OS-level", self.hints(ConnectionResetError("reset"), 777, 7))

    def test_fixed_lifetime_detected(self):
        h = self.hints(None, 3600 + 12, 30)
        self.assertIn("fixed session lifetime", h)
        self.assertIn("1h00m00s", h)

    def test_idle_timeout_detected_and_heartbeat_note(self):
        h = self.hints(None, 5000, 1805)
        self.assertIn("idle-timeout policy", h)
        self.assertNotIn("not counting heartbeat", h)
        # last real call ~30m ago, but heartbeat touched the channel 20s ago
        h = self.hints(None, 5000, 20, idle_real=1805)
        self.assertIn("idle-timeout policy", h)
        self.assertIn("not counting heartbeat", h)

    def test_non_round_numbers_give_no_timing_hint(self):
        h = self.hints(None, 3600 + 500, 777)
        self.assertNotIn("round number", h)

    def test_near_round(self):
        self.assertEqual(pool._near_round(300), "5m00s")
        self.assertEqual(pool._near_round(28800 - 100), "8h00m00s")
        self.assertIsNone(pool._near_round(30))
        self.assertIsNone(pool._near_round(400))

    def test_fmt(self):
        self.assertEqual(pool._fmt_dur(5), "5s")
        self.assertEqual(pool._fmt_dur(125), "2m05s")
        self.assertEqual(pool._fmt_dur(3725), "1h02m05s")
        self.assertEqual(pool._fmt_exc(None), "clean close (exc=None)")
        self.assertIn("DisconnectError(code=11): bye", pool._fmt_exc(asyncssh.DisconnectError(11, "bye")))


class ConfigTests(PoolTestCase):
    def test_defaults(self):
        self.assertEqual(
            pool._keepalive_kwargs(), dict(keepalive_interval=15, keepalive_count_max=8)
        )
        self.assertEqual(pool._heartbeat_interval(), 60)

    def test_overrides(self):
        pool.cfg = {
            "bastion": {"keepalive_interval": 5, "keepalive_count_max": 2},
            "daemon": {"heartbeat_interval": 0},
        }
        self.assertEqual(
            pool._keepalive_kwargs(), dict(keepalive_interval=5, keepalive_count_max=2)
        )
        self.assertEqual(pool._heartbeat_interval(), 0)

    def test_tcp_keepalive_not_duplicated(self):
        self.assertNotIn("tcp_keepalive", pool._keepalive_kwargs())

    def test_validate_accepts_good_and_absent(self):
        self.assertEqual(pool.validate_config({}), ([], []))
        good = {
            "bastion": {"keepalive_interval": 0, "keepalive_count_max": 3},
            "daemon": {"heartbeat_interval": 0.5},
        }
        self.assertEqual(pool.validate_config(good)[0], [])

    def test_validate_rejects_bad(self):
        for sec, key, val in (
            ("bastion", "keepalive_interval", "15"),
            ("bastion", "keepalive_interval", -1),
            ("bastion", "keepalive_count_max", 0),
            ("bastion", "keepalive_count_max", 2.5),
            ("daemon", "heartbeat_interval", True),
            ("daemon", "heartbeat_interval", -5),
        ):
            errors, _ = pool.validate_config({sec: {key: val}})
            self.assertEqual(len(errors), 1, (sec, key, val))
            self.assertIn(key, errors[0])

    def test_apply_config_keeps_restart_only_sections(self):
        pool.cfg = {"bastion": {"host": "b", "user": "u", "port": 22}, "daemon": {"heartbeat_interval": 60}}
        new = {"bastion": {"host": "b", "user": "u", "port": 22, "keepalive_interval": 1},
               "daemon": {"heartbeat_interval": 1}}
        s = pool.apply_config(new)
        self.assertEqual(sorted(s["restart"]), ["bastion", "daemon"])
        self.assertEqual(pool._heartbeat_interval(), 60)
        self.assertEqual(pool._keepalive_kwargs()["keepalive_interval"], 15)


class HeartbeatTests(PoolTestCase):
    async def test_no_bastion_skips_and_never_reconnects(self):
        with mock.patch.object(pool, "_connect_bastion", side_effect=AssertionError("reconnect!")) as c, \
                mock.patch.object(pool, "_ensure_bastion", side_effect=AssertionError("reconnect!")) as e:
            self.assertIsNone(await pool.heartbeat_once())
            c.assert_not_called()
            e.assert_not_called()

    async def test_success_opens_channel_and_touches(self):
        conn = FakeConn()
        s = register(conn, idle=50, idle_real=50)
        pool._bastion_conn = conn
        self.assertTrue(await pool.heartbeat_once())
        self.assertEqual(conn.commands, ["true"])
        self.assertLess(time.monotonic() - s.last_used, 1)  # channel activity recorded
        self.assertGreater(time.monotonic() - s.last_real, 40)  # not a real call

    async def test_failure_is_logged_not_raised_and_keeps_conn(self):
        conn = FakeConn(run_exc=asyncssh.ConnectionLost("boom"))
        pool._bastion_conn = conn
        with capture() as out:
            self.assertFalse(await pool.heartbeat_once())
        self.assertIn("heartbeat failed", out.getvalue())
        self.assertIn("ConnectionLost", out.getvalue())
        self.assertIs(pool._bastion_conn, conn)  # no invalidate -> no surprise TOTP
        self.assertFalse(conn.closed)

    async def test_timeout_is_failure(self):
        conn = FakeConn(run_delay=5)
        pool._bastion_conn = conn
        with mock.patch.object(pool, "HEARTBEAT_TIMEOUT", 0.05), capture() as out:
            self.assertFalse(await pool.heartbeat_once())
        self.assertIn("heartbeat failed", out.getvalue())

    async def test_does_not_take_bastion_lock(self):
        conn = FakeConn()
        pool._bastion_conn = conn
        async with pool._bastion_lock:  # a real call holding the lock (e.g. mid-login)
            self.assertTrue(await asyncio.wait_for(pool.heartbeat_once(), 1))

    async def test_loop_disabled_returns_immediately(self):
        await asyncio.wait_for(pool.heartbeat_loop(0), 1)

    async def test_loop_beats_and_cancels_cleanly(self):
        conn = FakeConn()
        pool._bastion_conn = conn
        with capture():
            task = asyncio.create_task(pool.heartbeat_loop(0.02))
            await asyncio.sleep(0.15)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertGreaterEqual(len(conn.commands), 2)

    async def test_loop_survives_errors_and_no_bastion(self):
        with capture() as out, mock.patch.object(
            pool, "heartbeat_once", side_effect=[RuntimeError("x"), None, True]
        ) as hb:
            task = asyncio.create_task(pool.heartbeat_loop(0.01))
            await asyncio.sleep(0.15)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self.assertIn("heartbeat error", out.getvalue())
        self.assertGreaterEqual(hb.call_count, 3)


class IdleProbeTests(PoolTestCase):
    async def test_recent_use_skips_probe(self):
        conn = FakeConn()
        register(conn, idle=5)
        self.assertTrue(await pool._idle_probe_ok(conn, "bastion"))
        self.assertEqual(conn.commands, [])

    async def test_long_idle_probes_and_touches(self):
        conn = FakeConn()
        s = register(conn, idle=pool._PROBE_IDLE_AFTER + 30)
        self.assertTrue(await pool._idle_probe_ok(conn, "bastion"))
        self.assertEqual(conn.commands, ["true"])
        self.assertLess(time.monotonic() - s.last_used, 1)

    async def test_failed_probe_reports_dead(self):
        conn = FakeConn(run_exc=asyncssh.ConnectionLost("dead"))
        register(conn, idle=1000)
        with capture() as out:
            self.assertFalse(await pool._idle_probe_ok(conn, "bastion"))
        self.assertIn("liveness probe", out.getvalue())

    async def test_hung_probe_times_out(self):
        conn = FakeConn(run_delay=5)
        register(conn, idle=1000)
        with mock.patch.object(pool, "_PROBE_TIMEOUT", 0.05), capture():
            self.assertFalse(await pool._idle_probe_ok(conn, "bastion"))

    async def test_channel_open_refused_means_alive(self):
        # e.g. MaxSessions full: the server answered, so don't force a re-login
        conn = FakeConn(run_exc=asyncssh.ChannelOpenError(2, "administratively prohibited"))
        register(conn, idle=1000)
        self.assertTrue(await pool._idle_probe_ok(conn, "bastion"))

    async def test_unknown_conn_is_left_alone(self):
        conn = FakeConn()
        self.assertTrue(await pool._idle_probe_ok(conn, "bastion"))
        self.assertEqual(conn.commands, [])

    async def test_dead_bastion_reconnects_exactly_once(self):
        dead, fresh = FakeConn(run_exc=asyncssh.ConnectionLost("dead")), FakeConn()
        register(dead, idle=1000)
        pool._bastion_conn = dead
        with capture(), mock.patch.object(pool, "_connect_bastion", return_value=fresh) as c:
            got = await pool._ensure_bastion()
        self.assertIs(got, fresh)
        self.assertIs(pool._bastion_conn, fresh)
        self.assertTrue(dead.closed)
        c.assert_called_once()

    async def test_healthy_bastion_not_reconnected(self):
        ok = FakeConn()
        register(ok, idle=1000)
        pool._bastion_conn = ok
        with mock.patch.object(pool, "_connect_bastion", side_effect=AssertionError("reconnect!")):
            self.assertIs(await pool._ensure_bastion(), ok)

    async def test_reconnect_errors_still_propagate_unchanged(self):
        # run()'s no-retry handling for PermissionDenied/TimeoutError relies on
        # these escaping _ensure_bastion as-is, not swallowed by the probe.
        for exc in (asyncssh.PermissionDenied("bad code"), TimeoutError("connect")):
            dead = FakeConn(run_exc=asyncssh.ConnectionLost("dead"))
            register(dead, idle=1000)
            pool._bastion_conn = dead
            with capture(), mock.patch.object(pool, "_connect_bastion", side_effect=exc) as c:
                with self.assertRaises(type(exc)):
                    await pool._ensure_bastion()
            c.assert_called_once()

    async def test_run_hop_no_retry_on_permission_denied(self):
        pool.cfg = {"bastion": {"host": "b", "user": "u", "port": 22},
                    "host": {"n1": {"via": "hop"}}}
        calls = []

        async def fake_hop(*a):
            calls.append(a)
            raise asyncssh.PermissionDenied("nope")

        with mock.patch.object(pool, "_run_hop", fake_hop):
            with self.assertRaises(asyncssh.PermissionDenied):
                await pool.run("n1", "echo")
        self.assertEqual(len(calls), 1)


class TrackingTests(PoolTestCase):
    async def test_in_use_touches_on_entry_and_exit(self):
        conn = FakeConn()
        s = register(conn, idle=100)
        with pool._in_use(conn, None):  # None (no bastion) is tolerated
            self.assertLess(time.monotonic() - s.last_real, 1)
            s.last_used = s.last_real = time.monotonic() - 50  # time passes mid-command
        self.assertLess(time.monotonic() - s.last_real, 1)

    async def test_in_use_host_includes_bastion_unless_direct(self):
        t, b = FakeConn(), FakeConn()
        st, sb = register(t, idle=100), register(b, idle=100)
        pool._bastion_conn = b
        pool.cfg = {"host": {"viab": {}, "d": {"via": "direct"}}}
        with pool._in_use_host("d", t):
            pass
        self.assertGreater(time.monotonic() - sb.last_used, 90)
        with pool._in_use_host("viab", t):
            pass
        self.assertLess(time.monotonic() - sb.last_used, 1)
        self.assertLess(time.monotonic() - st.last_used, 1)

    async def test_target_drop_logs_context(self):
        conn = FakeConn()
        client = pool._TargetClient("lab3")
        client.connection_made(conn)
        client._stats.connected_at -= 3600
        client._stats.last_used -= 3600
        client._stats.last_real -= 3600
        pool._target_conns["lab3"] = conn
        with capture() as out:
            client.connection_lost(None)
        text = out.getvalue()
        self.assertIn("[target lab3] connection lost: clean close", text)
        self.assertIn("alive 1h00m", text)
        self.assertIn("hint:", text)
        self.assertNotIn("lab3", pool._target_conns)
        self.assertNotIn(conn, pool._conn_stats)

    async def test_bastion_drop_announces_totp_only_when_current(self):
        conn = FakeConn()
        client = pool._BastionClient()
        client.connection_made(conn)
        pool._bastion_conn = conn
        with capture() as out:
            client.connection_lost(asyncssh.ConnectionLost("Connection lost"))
        self.assertIn("verification code", out.getvalue())
        self.assertIsNone(pool._bastion_conn)

        # a stale client's late callback must not claim anything about the pool
        stale, newer = _bc(), FakeConn()
        pool._bastion_conn = newer
        with capture() as out:
            stale.connection_lost(None)
        self.assertNotIn("verification code", out.getvalue())
        self.assertIs(pool._bastion_conn, newer)

    async def test_local_close_is_reported_as_local(self):
        conn = FakeConn()
        client = pool._BastionClient()
        client.connection_made(conn)
        pool._bastion_conn = conn
        pool._invalidate_bastion()
        self.assertTrue(conn.closed)
        with capture() as out:
            client.connection_lost(None)  # what asyncssh calls after our close()
        self.assertIn("closed by this daemon", out.getvalue())
        self.assertNotIn("exc=None: peer", out.getvalue())

    async def test_auth_completed_resets_age(self):
        client = pool._BastionClient()
        client.connection_made(FakeConn())
        client._stats.connected_at -= 600  # e.g. a slow TOTP prompt
        client.auth_completed()
        self.assertLess(time.monotonic() - client._stats.connected_at, 1)


def _bc():
    c = pool._BastionClient()
    c.connection_made(FakeConn())
    return c


class BastionPasswordTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved = dict(pool._passwords)
        pool._passwords.clear()

    def tearDown(self):
        pool._passwords.clear()
        pool._passwords.update(self._saved)

    async def answer(self, client, prompts, typed=()):
        typed = iter(typed)
        asked: list[str] = []

        def fake_input(prompt):
            asked.append(prompt)
            return next(typed)

        with mock.patch("builtins.input", fake_input), \
                mock.patch.object(pool.getpass, "getpass", fake_input), capture():
            resp = await client.kbdint_challenge_received("", "", "", prompts)
        return resp, asked

    def test_prompt_classification(self):
        for p in ("Password: ", "password for huangqd:", "请输入密码：", "Passwd:", "登录口令："):
            self.assertTrue(pool.is_password_prompt(p), p)
        for p in ("Verification code: ", "One-time password: ", "OTP password:",
                  "请输入验证码：", "动态密码：", "动态口令：", "Token: ", "Passcode: "):
            self.assertFalse(pool.is_password_prompt(p), p)

    async def test_code_then_password_in_one_challenge(self):
        pool._passwords[pool.BASTION_PASSWORD_KEY] = "s3cret"
        resp, asked = await self.answer(
            _bc(), [("Verification code: ", False), ("Password: ", False)], ["123456"]
        )
        self.assertEqual(resp, ["123456", "s3cret"])
        self.assertEqual(asked, ["Verification code: "])

    async def test_code_then_password_across_challenges(self):
        pool._passwords[pool.BASTION_PASSWORD_KEY] = "s3cret"
        c = _bc()
        resp, asked = await self.answer(c, [("Verification code: ", True)], ["123456"])
        self.assertEqual(resp, ["123456"])
        resp, asked = await self.answer(c, [("Password: ", False)])
        self.assertEqual((resp, asked), (["s3cret"], []))

    async def test_password_sent_only_once_per_connection(self):
        pool._passwords[pool.BASTION_PASSWORD_KEY] = "wrong"
        c = _bc()
        await self.answer(c, [("Password: ", False)])
        # Falling through to AsyncSSH's ordinary password method must not
        # send the same configured password a second time.
        self.assertIsNone(c.password_auth_requested())
        resp, asked = await self.answer(c, [("Password: ", False)], ["typed"])
        self.assertEqual((resp, asked), (["typed"], ["Password: "]))
        # a fresh connection (reconnect) gets to try the saved one again
        resp, asked = await self.answer(_bc(), [("Password: ", False)])
        self.assertEqual((resp, asked), (["wrong"], []))

    async def test_plain_password_auth_shares_send_once_state(self):
        pool._passwords[pool.BASTION_PASSWORD_KEY] = "s3cret"
        c = _bc()
        self.assertEqual(c.password_auth_requested(), "s3cret")
        self.assertIsNone(c.password_auth_requested())
        resp, asked = await self.answer(c, [("Password: ", False)], ["typed"])
        self.assertEqual((resp, asked), (["typed"], ["Password: "]))

    async def test_no_saved_password_prompts_as_before(self):
        resp, asked = await self.answer(_bc(), [("Password: ", False)], ["typed"])
        self.assertEqual((resp, asked), (["typed"], ["Password: "]))

    def test_validate_bastion_fields(self):
        errors, warnings = pool.validate_config({"bastion": {"password": "x"}})
        self.assertEqual((errors, warnings), ([], []))
        errors, _ = pool.validate_config({"bastion": {"password": 123}})
        self.assertTrue(any("password" in e for e in errors))
        _, warnings = pool.validate_config({"bastion": {"auth": "password"}})
        self.assertTrue(any("auth" in w for w in warnings))
        errors, _ = pool.validate_config({"bastion": {"key": "password"}})
        self.assertTrue(any("key" in e for e in errors))
        errors, _ = pool.validate_config({"bastion": {"key": __file__}})
        self.assertEqual(errors, [])
def _direct_pw(**kw) -> dict:
    hc = {"via": "direct", "address": "10.0.0.4", "port": 22, "user": "u", "auth": "password"}
    hc.update(kw)
    return hc


class PasswordTests(PoolTestCase):
    """Direct+password nodes: password reaches asyncssh, is never retried,
    and survives / is dropped across reload_config (apply_config) correctly."""

    async def test_connect_uses_password_and_offers_no_keys(self):
        pool.cfg = {"host": {"lab4": _direct_pw()}}
        pool._passwords["lab4"] = "s3cret"
        with mock.patch.object(pool.asyncssh, "connect", mock.AsyncMock(return_value=FakeConn())) as c:
            await pool.get_target("lab4")
        kwargs = c.await_args.kwargs
        self.assertEqual(c.await_args.args, ("10.0.0.4",))
        self.assertEqual(kwargs["password"], "s3cret")
        self.assertIsNone(kwargs["client_keys"])  # rejected keys would count toward lockout
        self.assertIsNone(kwargs["agent_path"])
        self.assertNotIn("tunnel", kwargs)

    async def test_reconnect_reuses_password_silently(self):
        pool.cfg = {"host": {"lab4": _direct_pw()}}
        pool._passwords["lab4"] = "s3cret"
        with mock.patch.object(pool.asyncssh, "connect", mock.AsyncMock(return_value=FakeConn())) as c:
            await pool.get_target("lab4")
            pool._invalidate_target("lab4")
            await pool.get_target("lab4")
        self.assertEqual([k.kwargs["password"] for k in c.await_args_list], ["s3cret", "s3cret"])

    async def test_run_does_not_retry_permission_denied(self):
        pool.cfg = {"host": {"lab4": _direct_pw()}}
        with mock.patch.object(pool, "get_target", mock.AsyncMock(
                side_effect=asyncssh.PermissionDenied("denied"))) as g:
            with self.assertRaises(asyncssh.PermissionDenied):
                await pool.run("lab4", "true")
        self.assertEqual(g.await_count, 1)

    def test_reload_adds_node_with_config_password(self):
        pool.cfg = {"host": {}}
        s = pool.apply_config({"host": {"lab4": _direct_pw(password="s3cret")}})
        self.assertEqual(s["added"], ["lab4"])
        self.assertEqual(s["need_password"], [])
        self.assertEqual(pool._passwords["lab4"], "s3cret")

    def test_reload_adds_node_without_password_needs_restart(self):
        pool.cfg = {"host": {}}
        s = pool.apply_config({"host": {"lab4": _direct_pw()}})
        self.assertEqual(s["need_password"], ["lab4"])
        self.assertNotIn("lab4", pool._passwords)

    def test_reload_keeps_typed_password_when_login_unchanged(self):
        pool.cfg = {"host": {"lab4": _direct_pw(default_cwd="/a")}}
        pool._passwords["lab4"] = "typed"
        s = pool.apply_config({"host": {"lab4": _direct_pw(default_cwd="/b")}})
        self.assertEqual(s["changed"], ["lab4"])
        self.assertEqual(s["need_password"], [])
        self.assertEqual(pool._passwords["lab4"], "typed")

    def test_reload_drops_typed_password_when_login_changed(self):
        for field, value in (("address", "10.0.0.99"), ("user", "other"), ("port", 2222)):
            pool.cfg = {"host": {"lab4": _direct_pw()}}
            pool._passwords["lab4"] = "typed"
            s = pool.apply_config({"host": {"lab4": _direct_pw(**{field: value})}})
            self.assertEqual(s["need_password"], ["lab4"], field)
            self.assertNotIn("lab4", pool._passwords, field)

    def test_reload_config_password_overrides_typed(self):
        pool.cfg = {"host": {"lab4": _direct_pw()}}
        pool._passwords["lab4"] = "typed"
        pool.apply_config({"host": {"lab4": _direct_pw(password="fromfile")}})
        self.assertEqual(pool._passwords["lab4"], "fromfile")

    def test_reload_drops_password_on_remove_or_switch_to_key(self):
        pool.cfg = {"host": {"lab4": _direct_pw(), "lab5": _direct_pw(address="10.0.0.5")}}
        pool._passwords.update({"lab4": "p4", "lab5": "p5"})
        conn = FakeConn()
        pool._target_conns["lab4"] = conn
        s = pool.apply_config({"host": {"lab5": _direct_pw(address="10.0.0.5", auth="key")}})
        self.assertEqual(s["removed"], ["lab4"])
        self.assertEqual(pool._passwords, {})
        self.assertTrue(conn.closed)
        self.assertNotIn("lab4", pool._target_conns)

    def test_validate_warns_password_on_non_direct(self):
        _, warnings = pool.validate_config({
            "bastion": {"host": "b"},
            "host": {"dev1": {"password": "x"}, "n1": {"via": "hop", "password": "x"}},
        })
        self.assertEqual(len(warnings), 2)
        for w in warnings:
            self.assertIn("password", w)
            self.assertNotIn("'x'", w)


if __name__ == "__main__":
    unittest.main()
