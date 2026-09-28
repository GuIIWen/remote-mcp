import asyncio
import fnmatch
import getpass
import shlex

import asyncssh

_bastion_conn: asyncssh.SSHClientConnection | None = None
_target_conns: dict[str, asyncssh.SSHClientConnection] = {}
_sems: dict[str, asyncio.Semaphore] = {}
_bastion_lock = asyncio.Lock()
_host_locks: dict[str, asyncio.Lock] = {}
cfg: dict = {}

# In-memory only — populated at startup (config value or interactive prompt)
# and reused silently on reconnect. Never written to disk, never logged.
_passwords: dict[str, str] = {}


class ConfigError(ValueError):
    """Raised for a configuration problem that should abort startup, or (for
    a route/auth mixup discovered later) surface as a clear tool error
    instead of a raw KeyError/AttributeError."""


class RemoteTimeout(RuntimeError):
    """Raised when a remote command exceeds its timeout; the process was killed."""

    def __init__(self, timeout: float):
        super().__init__(f"command timed out after {timeout}s; the remote process was terminated")


def _host_lock(host: str) -> asyncio.Lock:
    lock = _host_locks.get(host)
    if lock is None:
        lock = asyncio.Lock()
        _host_locks[host] = lock
    return lock


def _connect_timeout() -> float:
    return cfg.get("daemon", {}).get("connect_timeout", 20)


def _route(host: str) -> str:
    """"bastion" (default) tunnels through the jump host; "direct" connects
    straight to [host.<name>].address. Reserved for future values naming a
    specific bastion once multi-bastion support (see TODO.md) lands."""
    return cfg.get("host", {}).get(host, {}).get("via", "bastion")


def _default_keypairs() -> list:
    # asyncssh.load_default_keypairs isn't re-exported at the top-level
    # `asyncssh` namespace (only load_keypairs/load_public_keys/
    # load_certificates are) — it only exists in asyncssh.public_key.
    from asyncssh.public_key import load_default_keypairs

    return list(load_default_keypairs())


def _bastion_client_keys() -> list:
    path = cfg.get("bastion", {}).get("key", "")
    if path:
        return list(asyncssh.load_keypairs(path))
    return _default_keypairs()


def _host_client_keys(host: str) -> list:
    """Key resolution order for a target (bastion-routed or direct) node:
    [host.x] key/cert first, then [bastion] key, then the default keypair."""
    hc = cfg.get("host", {}).get(host, {})
    key = hc.get("key", "")
    cert = hc.get("cert", "")
    if key:
        if cert:
            return list(asyncssh.load_keypairs([(key, cert)]))
        return list(asyncssh.load_keypairs(key))
    bastion_key = cfg.get("bastion", {}).get("key", "")
    if bastion_key:
        return list(asyncssh.load_keypairs(bastion_key))
    return _default_keypairs()


class _BastionClient(asyncssh.SSHClient):
    def __init__(self):
        self._conn: asyncssh.SSHClientConnection | None = None

    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
        self._conn = conn

    def auth_banner_received(self, msg: str, lang: str) -> None:
        print(msg, end="", flush=True)

    def kbdint_auth_requested(self) -> str:
        # asyncssh only attempts keyboard-interactive auth (needed for TOTP)
        # when this returns a string instead of the default None; an empty
        # string lets the server pick the submethod.
        return ""

    async def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: list[tuple[str, bool]],
    ) -> list[str]:
        if instructions:
            print(instructions, flush=True)
        loop = asyncio.get_event_loop()
        responses = []
        for prompt, echo in prompts:
            if echo:
                answer = await loop.run_in_executor(None, input, prompt)
            else:
                answer = await loop.run_in_executor(None, getpass.getpass, prompt)
            responses.append(answer)
        return responses

    def connection_lost(self, exc: Exception | None) -> None:
        global _bastion_conn
        # A stale client's callback can arrive after a newer connection has
        # already replaced it in the pool (e.g. this client was pop()'d and
        # reconnected while the old socket's close was still in flight) —
        # only clear the pool entry if it's still this client's connection.
        if _bastion_conn is self._conn:
            _bastion_conn = None
            # Only bastion-routed targets are tunneled through this
            # connection — direct nodes have their own socket and must not
            # be dropped just because the bastion went away.
            for h in [h for h in _target_conns if _route(h) != "direct"]:
                _target_conns.pop(h, None)


class _TargetClient(asyncssh.SSHClient):
    def __init__(self, host: str):
        self._host = host
        self._conn: asyncssh.SSHClientConnection | None = None

    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
        self._conn = conn

    def connection_lost(self, exc: Exception | None) -> None:
        if _target_conns.get(self._host) is self._conn:
            _target_conns.pop(self._host, None)


def _allowed(host: str) -> bool:
    patterns: list[str] = cfg.get("hosts", {}).get("allowed", [])
    if not patterns:
        return True
    return any(fnmatch.fnmatch(host, p) for p in patterns)


async def _connect_bastion() -> asyncssh.SSHClientConnection:
    b = cfg.get("bastion")
    if not b:
        # Reachable if a bastion-routed host is used without a [bastion]
        # section configured at all — give a clear error instead of the
        # KeyError that cfg["bastion"] below would raise.
        raise ConfigError(
            "no [bastion] section is configured; this host needs one "
            "(or set via = \"direct\" and give it an address)"
        )
    print(
        f"Connecting to bastion {b['user']}@{b['host']}:{b['port']} — "
        "enter TOTP / password in this terminal when prompted.",
        flush=True,
    )
    conn, _ = await asyncssh.create_connection(
        _BastionClient,
        b["host"],
        port=b["port"],
        username=b["user"],
        client_keys=_bastion_client_keys(),
        known_hosts=None,
        keepalive_interval=30,
        keepalive_count_max=3,
        connect_timeout=_connect_timeout(),
    )
    return conn


def _is_closed(conn: asyncssh.SSHClientConnection | None) -> bool:
    # Liveness is tracked by the client's connection_lost() callback, which
    # clears the pool entry — no need to poll the connection itself.
    return conn is None


async def _ensure_bastion() -> asyncssh.SSHClientConnection:
    """Must be called with _bastion_lock already held."""
    global _bastion_conn
    if _bastion_conn is None:
        _bastion_conn = await _connect_bastion()
    return _bastion_conn


async def get_bastion() -> asyncssh.SSHClientConnection:
    async with _bastion_lock:
        return await _ensure_bastion()


async def get_target(host: str) -> asyncssh.SSHClientConnection:
    if not _allowed(host):
        raise ValueError(f"Host '{host}' is not in the allowed list")

    async with _host_lock(host):
        conn = _target_conns.get(host)
        if conn is not None:
            return conn

        host_cfg = cfg.get("host", {}).get(host, {})

        if _route(host) == "direct":
            if host not in cfg.get("host", {}):
                raise ConfigError(f"direct host '{host}' is not configured under [host.{host}]")
            address = host_cfg.get("address", "")
            if not address:
                raise ConfigError(f"[host.{host}] via=\"direct\" requires an 'address' field")
            username = host_cfg.get("user", "")
            auth = host_cfg.get("auth", "key")
            kwargs: dict = dict(
                port=host_cfg.get("port", 22),
                username=username,
                # "" in config means "don't verify"; asyncssh would treat
                # an empty string as a file path, so map it to None.
                known_hosts=host_cfg.get("known_hosts") or None,
                keepalive_interval=30,
                keepalive_count_max=3,
                connect_timeout=_connect_timeout(),
                client_factory=lambda: _TargetClient(host),
            )
            if auth == "password":
                kwargs["password"] = _passwords.get(host, "")
                # Don't offer local keys first: each rejected key counts
                # toward the server's MaxAuthTries / lockout policy.
                kwargs["client_keys"] = None
                kwargs["agent_path"] = None
            else:
                kwargs["client_keys"] = _host_client_keys(host)
            conn = await asyncssh.connect(address, **kwargs)
        else:
            async with _bastion_lock:
                bastion = await _ensure_bastion()

            username = host_cfg.get("user", cfg.get("bastion", {}).get("user", ""))

            conn = await asyncssh.connect(
                host,
                username=username,
                tunnel=bastion,
                client_keys=_host_client_keys(host),
                known_hosts=None,
                keepalive_interval=30,
                keepalive_count_max=3,
                connect_timeout=_connect_timeout(),
                client_factory=lambda: _TargetClient(host),
            )
        _target_conns[host] = conn
        if host not in _sems:
            _sems[host] = asyncio.Semaphore(8)
        return conn


async def _kill_process(process: asyncssh.SSHClientProcess) -> None:
    """Best-effort cleanup of a process abandoned after a timeout."""
    try:
        process.terminate()
        await asyncio.wait_for(process.wait(), timeout=5)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
    try:
        process.close()
    except Exception:
        pass


def _invalidate_target(host: str) -> None:
    """Drop a target connection from the pool and close it, so a subsequent
    get_target() opens a fresh one instead of reusing a socket that's already
    dead but hasn't run its connection_lost() callback yet."""
    conn = _target_conns.pop(host, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def _timeout_wrap(cmd: str, timeout: int) -> str:
    # terminate() over the SSH channel is a request many sshd builds ignore,
    # and closing the channel without a pty doesn't deliver SIGHUP either —
    # so the timeout is enforced remotely with coreutils `timeout`, which can
    # actually send signals to the process group it started. -k 5 escalates
    # to SIGKILL 5s after the initial SIGTERM if the command ignores it.
    inner = shlex.quote(cmd)
    return (
        f"if command -v timeout >/dev/null 2>&1; then "
        f"timeout -k 5 {timeout} bash -c {inner}; "
        f"else bash -c {inner}; fi"
    )


async def run(
    host: str,
    cmd: str,
    timeout: int = 60,
    stdin: str | None = None,
) -> asyncssh.SSHCompletedProcess:
    sem = _sems.setdefault(host, asyncio.Semaphore(8))
    wrapped = _timeout_wrap(cmd, timeout)

    async def _run_once() -> asyncssh.SSHCompletedProcess:
        conn = await get_target(host)
        async with sem:
            process = await conn.create_process(wrapped, input=stdin, errors="replace")
            try:
                # The remote `timeout` above is the real enforcement; this is
                # only a backstop in case the channel itself wedges, so it's
                # given extra slack (+15s) to let `timeout -k 5` finish first.
                result = await asyncio.wait_for(process.wait(), timeout=timeout + 15)
            except asyncio.TimeoutError:
                await _kill_process(process)
                raise RemoteTimeout(timeout) from None
            if result.returncode in (124, 137):
                raise RemoteTimeout(timeout)
            return result

    try:
        return await _run_once()
    except TimeoutError:
        # Raised by asyncssh when connect_timeout expires while (re)connecting
        # to the bastion or target — a builtin OSError subclass since Python
        # 3.11, but a connect timeout should surface immediately rather than
        # being treated as a disconnect and retried (which would silently
        # double the wait). RemoteTimeout (command timeout) is a distinct,
        # non-OSError type and is unaffected by this clause.
        raise
    except asyncssh.PermissionDenied:
        # PermissionDenied is a DisconnectError subclass, so it must be
        # caught (and re-raised, not retried) before the broader
        # DisconnectError clause below. Retrying a wrong password risks
        # tripping an account lockout, and on the bastion route would force
        # a second TOTP prompt for what's already a known-bad credential.
        raise
    except (asyncssh.ConnectionLost, asyncssh.DisconnectError, OSError):
        _invalidate_target(host)
        return await _run_once()


async def with_sftp(host: str, func):
    """Run func(sftp_client) under the host's semaphore, retrying once after
    reconnecting if the SFTP session drops mid-way."""
    sem = _sems.setdefault(host, asyncio.Semaphore(8))

    async def _attempt():
        conn = await get_target(host)
        async with sem:
            async with conn.start_sftp_client() as sftp:
                return await func(sftp)

    try:
        return await _attempt()
    except TimeoutError:
        raise  # see the matching comment in run()
    except asyncssh.PermissionDenied:
        raise  # see the matching comment in run()
    except (asyncssh.ConnectionLost, asyncssh.DisconnectError, OSError):
        _invalidate_target(host)
        return await _attempt()


async def reset_all() -> None:
    global _bastion_conn
    async with _bastion_lock:
        for conn in list(_target_conns.values()):
            try:
                conn.close()
            except Exception:
                pass
        _target_conns.clear()
        if _bastion_conn is not None:
            try:
                _bastion_conn.close()
            except Exception:
                pass
            _bastion_conn = None
