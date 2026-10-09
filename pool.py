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

# Hop-routed hosts (via = "hop") all ride the single bastion connection
# (`ssh <node> '<cmd>'` run *on* the bastion) instead of getting a
# connection of their own, so they share one semaphore sized against the
# bastion's own sshd MaxSessions — never a per-host one (see run()/
# _run_hop()), or concurrent calls to different hop hosts could add up
# past the bastion's limit even though each host's own count looks fine.
_hop_sem = asyncio.Semaphore(8)

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


class HopSSHError(RuntimeError):
    """Raised when the `ssh` client running on the bastion exits 255 — ssh's
    own "the connection never got as far as running the command" code
    (host key changed, permission denied, unresolvable host, ...). The
    message carries ssh's stderr verbatim so the tool output actually names
    the cause instead of just showing exit_code: 255."""


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
    straight to [host.<name>].address and owns its own connection; "hop"
    keeps no connection of its own either — every operation runs `ssh
    <node> '<cmd>'` on the resident bastion connection, which is the only
    way to reach a node whose key lives on the bastion rather than here.
    Reserved for future values naming a specific bastion once multi-bastion
    support (see TODO.md) lands."""
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
    if _route(host) == "hop":
        # A hop-routed host has no connection of its own — every access
        # goes through run()'s hop branch (ssh run on the bastion
        # connection), never through get_target()/with_sftp(). Reaching
        # here means a caller (a new tool, most likely) forgot to route on
        # _route(host) == "hop" first; fail loudly instead of silently
        # falling through to the tunnel= path below, which needs a private
        # key for the node that, for a hop host, only exists on the
        # bastion and never on this machine.
        raise ConfigError(
            f"[host.{host}] via=\"hop\" has no direct connection; "
            "use pool.run() (or a hop-aware file helper), not get_target()/with_sftp()"
        )

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


def _invalidate_bastion() -> None:
    """Drop and close the bastion connection, plus every target connection
    tunneled through it, so the next hop/bastion-routed call reconnects
    instead of reusing a socket that's already dead but hasn't run its
    connection_lost() callback yet (same reasoning as _invalidate_target).
    direct-routed targets have their own socket and are left alone."""
    global _bastion_conn
    conn = _bastion_conn
    _bastion_conn = None
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    for h in [h for h in _target_conns if _route(h) != "direct"]:
        _target_conns.pop(h, None)


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


def hop_ssh_command(host: str, cmd: str, timeout: int) -> str:
    """Build the command line a hop-routed host's operation runs *on the
    bastion*: an `ssh` client that hops one more time to `host` and runs
    `cmd` there.

    Why a plain `ssh` invocation rather than a tunnel: the private key that
    authenticates to `host` lives on the bastion, not on this machine, so
    the hop cannot be an asyncssh tunnel= (which would sign with a local
    key). It is also why port/user are optional — with neither set we emit
    no `-p`/`-l` at all and let the bastion's own ~/.ssh/config (or plain
    ssh defaults) resolve hostname, port, user and identity file, which is
    exactly how `ssh nmz01` typed by hand on the bastion behaves.

    ControlMaster/ControlPath/ControlPersist let every command reuse one
    underlying SSH connection to the node (ControlPath's %C is a hash of
    the connection parameters, so the socket name stays short regardless of
    how long the hostname/options are), which is what keeps a burst of
    tools from paying a fresh handshake each time.

    BatchMode=yes forbids any interactive prompt (password, host-key
    confirmation, passphrase) — the daemon's terminal is shared with the
    TOTP prompt and must never be blocked by a nested ssh asking a question;
    an unexpected prompt instead surfaces as exit code 255.

    Quoting is deliberately exactly one layer: this whole string is what
    the *bastion's* shell parses, so shlex.quote(wrapped) hands the node's
    login shell the wrapped command byte-for-byte, and the node's shell
    then unpacks the `timeout ... bash -c <quoted>` that _timeout_wrap
    produced. Two layers, one quote each — no more.

    The timeout wrap is applied *before* the ssh hop, so the clock covers
    the hop handshake and the remote command together: if the node is
    unreachable the client-side wait_for (timeout + 15) fires and the
    process gets terminated, exactly as for a direct/bastion host.

    Container mode ([host.x] container = "..."): `cmd` is first wrapped as
    `docker exec -i [-u <container_user>] <container> bash -c <cmd>` and
    *that* is what _timeout_wrap then wraps, so the timeout stays outermost
    and covers the whole docker exec. -i (never -t) keeps stdin flowing for
    write_file/edit_file's base64 payload and avoids a pty mangling output.
    The ssh target is the `node` field (default: the section name), so
    several sections can point at one node with different containers —
    everything else (cache, locks, semaphores) stays keyed by section name.
    """
    hc = cfg.get("host", {}).get(host, {})
    node = hc.get("node") or host
    container = hc.get("container")
    if container:
        docker = "docker exec -i "
        container_user = hc.get("container_user")
        if container_user:
            docker += "-u " + shlex.quote(str(container_user)) + " "
        cmd = docker + shlex.quote(str(container)) + " bash -c " + shlex.quote(cmd)
    opts = ["-o", "BatchMode=yes", "-o", "ControlMaster=auto",
            "-o", f"ControlPath=~/.ssh/remote-mcp-%C",
            "-o", "ControlPersist=10m"]
    port = hc.get("port")
    if port:
        opts += ["-p", str(port)]
    user = hc.get("user")
    if user:
        opts += ["-l", str(user)]
    payload = shlex.quote(_timeout_wrap(cmd, timeout))
    return "ssh " + " ".join(opts) + " " + node + " " + payload


async def _run_hop(
    host: str,
    cmd: str,
    timeout: int,
    stdin: str | None,
) -> asyncssh.SSHCompletedProcess:
    """Run one command on a hop host, by running `ssh <node> '<cmd>'` on the
    bastion connection.

    Two semantics differ from the direct/bastion path on purpose:
    - exit code 255 is ssh-on-the-bastion's own failure (auth, host key,
      hostname resolution, ControlPersist denial), not the command's — it
      is turned into HopSSHError carrying ssh's stderr, because "exit_code:
      255" alone tells the caller nothing about which of those it was;
    - a *remote* timeout (124/137) is ssh's exit status once the nested
      `timeout` fires, so it maps to RemoteTimeout just like the local path.
    """
    async with _bastion_lock:
        bastion = await _ensure_bastion()
    async with _hop_sem:
        process = await bastion.create_process(
            hop_ssh_command(host, cmd, timeout), input=stdin, errors="replace"
        )
        try:
            result = await asyncio.wait_for(process.wait(), timeout=timeout + 15)
        except asyncio.TimeoutError:
            await _kill_process(process)
            raise RemoteTimeout(timeout) from None
    if result.returncode == 255:
        detail = (result.stderr or "").strip() or "(no stderr)"
        raise HopSSHError(
            f"ssh to {host} on the bastion failed: {detail}"
        )
    if result.returncode in (124, 137):
        raise RemoteTimeout(timeout)
    return result


async def run(
    host: str,
    cmd: str,
    timeout: int = 60,
    stdin: str | None = None,
) -> asyncssh.SSHCompletedProcess:
    async def _run_once() -> asyncssh.SSHCompletedProcess:
        conn = await get_target(host)
        sem = _sems.setdefault(host, asyncio.Semaphore(8))
        async with sem:
            process = await conn.create_process(
                _timeout_wrap(cmd, timeout), input=stdin, errors="replace"
            )
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

    if _route(host) == "hop":
        # Only the bastion connection can be stale here, so a retry just
        # reconnects it (prompting for TOTP again). A HopSSHError is an ssh
        # *auth/config* failure against the node and is deliberately NOT in
        # the retry clause below — retrying a known-bad credential risks an
        # account lockout and cannot fix a host key mismatch.
        try:
            return await _run_hop(host, cmd, timeout, stdin)
        except TimeoutError:
            raise  # bastion connect_timeout expired; see the local path below
        except asyncssh.PermissionDenied:
            raise  # bastion auth rejected; never retry (lockout / TOTP again)
        except HopSSHError:
            raise
        except (asyncssh.ConnectionLost, asyncssh.DisconnectError, OSError):
            _invalidate_bastion()
            return await _run_hop(host, cmd, timeout, stdin)

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
