import asyncio
import contextlib
import fnmatch
import getpass
import re
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import asyncssh

CONFIG_PATH = Path(__file__).parent / "config.toml"

# asyncssh's connect_timeout covers auth too, and bastion auth includes a
# human typing a TOTP code — so the bastion gets a much longer budget than
# [daemon] connect_timeout (which still applies to every target).
BASTION_CONNECT_TIMEOUT = 120

# container / container_user charset (docker names, plus a numeric uid is fine);
# no leading "-" so the value can never be parsed as a docker option.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9._-]*$")

# One entry per [bastion] / [bastion.<name>]; the legacy single [bastion]
# table is the bastion called DEFAULT_BASTION.
_bastion_conns: dict[str, asyncssh.SSHClientConnection] = {}
_bastion_locks: dict[str, asyncio.Lock] = {}
_target_conns: dict[str, asyncssh.SSHClientConnection] = {}
_sems: dict[str, asyncio.Semaphore] = {}
_host_locks: dict[str, asyncio.Lock] = {}
cfg: dict = {}

DEFAULT_BASTION = "default"

# Last connect failure per node ("Type: message"), shown in the GUI status
# panel; cleared on the next success and when the node's config changes.
_last_error: dict[str, str] = {}


def bastions(c: dict | None = None) -> dict[str, dict]:
    """Configured bastions by name. Two config shapes are accepted:
      [bastion]            host=... user=...   -> {"default": {...}}  (legacy, one bastion)
      [bastion.<name>]     host=... user=...   -> {name: {...}, ...}  (one or more)"""
    b = (cfg if c is None else c).get("bastion") or {}
    if not b:
        return {}
    if all(isinstance(v, dict) for v in b.values()):
        return dict(b)
    return {DEFAULT_BASTION: b}


def _bastion_lock(name: str) -> asyncio.Lock:
    lock = _bastion_locks.get(name)
    if lock is None:
        lock = _bastion_locks[name] = asyncio.Lock()
    return lock


def _default_bastion() -> str:
    names = list(bastions())
    if not names:
        # Reachable if a bastion-routed host is used without a [bastion]
        # section configured at all — give a clear error.
        raise ConfigError(
            "no [bastion] section is configured; this host needs one "
            "(or set via = \"direct\" and give it an address)"
        )
    return names[0]


def bastion_of(host: str) -> str:
    """Which bastion a bastion/hop-routed host belongs to: its `bastion`
    field, or the only bastion when exactly one is configured."""
    names = list(bastions())
    wanted = cfg.get("host", {}).get(host, {}).get("bastion")
    if wanted:
        if wanted not in names:
            raise ConfigError(f"[host.{host}] bastion = {wanted!r} 不存在（已配置：{', '.join(names) or '无'}）")
        return wanted
    if len(names) == 1:
        return names[0]
    if not names:
        _default_bastion()  # raises the "no [bastion]" error
    raise ConfigError(
        f"[host.{host}] 配置了多个跳板机（{', '.join(names)}），必须用 bastion 字段指定走哪一台"
    )


def _bastion_or_none(host: str) -> str | None:
    try:
        return bastion_of(host)
    except ConfigError:
        return None


def _bpw_key(name: str) -> str:
    """_passwords key for a bastion's password; brackets keep it from
    colliding with a [host.x] section name."""
    return "[bastion]" if name == DEFAULT_BASTION else f"[bastion:{name}]"


def _blabel(name: str) -> str:
    return "bastion" if name == DEFAULT_BASTION else f"bastion:{name}"

# Hop-routed hosts (via = "hop") all ride the single bastion connection
# (`ssh <node> '<cmd>'` run *on* the bastion) instead of getting a
# connection of their own, so they share one semaphore sized against the
# bastion's own sshd MaxSessions — never a per-host one (see run()/
# _run_hop()), or concurrent calls to different hop hosts could add up
# past the bastion's limit even though each host's own count looks fine.
_hop_sems: dict[str, asyncio.Semaphore] = {}


def _hop_sem(name: str) -> asyncio.Semaphore:
    sem = _hop_sems.get(name)
    if sem is None:
        sem = _hop_sems[name] = asyncio.Semaphore(8)
    return sem

# In-memory only — populated at startup (config value or interactive prompt)
# and reused silently on reconnect. Never written to disk, never logged.
_passwords: dict[str, str] = {}

# _passwords key of the legacy single bastion's password (see _bpw_key).
BASTION_PASSWORD_KEY = "[bastion]"


class ConfigError(ValueError):
    """Raised for a configuration problem that should abort startup, or (for
    a route/auth mixup discovered later) surface as a clear tool error
    instead of a raw KeyError/AttributeError."""


class ConfigLoadError(ConfigError):
    """config.toml parsed but failed validation. .errors has one string per
    fatal problem, .warnings the non-fatal notes collected on the way — the
    caller decides how to report them (startup prints and exits; reload_config
    returns them and keeps the old config)."""

    def __init__(self, errors: list[str], warnings: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors
        self.warnings = warnings


def validate_config(cfg: dict) -> tuple[list[str], list[str]]:
    """Check [host.x] fields that must be right before anything connects.
    Returns (errors, warnings). A bastion-routed node carrying direct-only
    fields is just a warning, since those fields are simply ignored rather
    than causing wrong behavior."""
    errors: list[str] = []
    warnings: list[str] = []
    # A bastion always authenticates with a key first; password only answers
    # keyboard-interactive password prompts, so there is no auth switch here.
    bs = bastions(cfg)
    for bname, b in bs.items():
        tag = "[bastion]" if bname == DEFAULT_BASTION else f"[bastion.{bname}]"
        if "auth" in b:
            warnings.append(
                f"warning: {tag} 不支持 auth 字段，将被忽略（跳板机总是先发密钥，"
                "password 只用来自动回答 keyboard-interactive 里的密码提示）"
            )
        if b.get("password") is not None and not isinstance(b["password"], str):
            errors.append(f"{tag} password 必须是字符串，当前是 {type(b['password']).__name__}")
        bastion_key = b.get("key", "")
        if bastion_key and not Path(str(bastion_key)).expanduser().is_file():
            errors.append(
                f"{tag} key 应该是私钥文件路径，但 {bastion_key!r} 不存在；"
                "留空则使用默认密钥对（~/.ssh/id_*）"
            )
        # Optional numeric knobs: absent is fine (defaults apply), present must be
        # a sane number — a string here would otherwise only blow up at connect time.
        for key, lo, integer in (("keepalive_interval", 0, False), ("keepalive_count_max", 1, True)):
            v = b.get(key)
            if v is None:
                continue
            ok_type = isinstance(v, int) if integer else isinstance(v, (int, float))
            if isinstance(v, bool) or not ok_type or v < lo:
                errors.append(
                    f"{tag} {key} 必须是 >= {lo} 的{'整数' if integer else '数字'}，当前是 {v!r}"
                )
    v = cfg.get("daemon", {}).get("heartbeat_interval")
    if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0):
        errors.append(f"[daemon] heartbeat_interval 必须是 >= 0 的数字，当前是 {v!r}")
    for host, hc in cfg.get("host", {}).items():
        via = hc.get("via", "bastion")
        if via in ("bastion", "hop") and bs:
            bn = hc.get("bastion")
            if bn is not None and not isinstance(bn, str):
                errors.append(f"[host.{host}] bastion 必须是字符串（跳板机名字）")
            elif bn and bn not in bs:
                errors.append(f"[host.{host}] bastion = {bn!r} 不存在（已配置：{', '.join(bs)}）")
            elif not bn and len(bs) > 1:
                errors.append(
                    f"[host.{host}] 配置了多个跳板机（{', '.join(bs)}），"
                    f"via=\"{via}\" 的节点必须用 bastion 字段指定走哪一台"
                )
        elif via == "direct" and hc.get("bastion"):
            warnings.append(f"warning: [host.{host}] via=\"direct\" 不经过跳板机，bastion 字段将被忽略")
        if via != "hop":
            hop_only = [f for f in ("node", "container", "container_user") if hc.get(f)]
            if hop_only:
                warnings.append(
                    f"warning: [host.{host}] 只有 via=\"hop\" 才支持 {', '.join(hop_only)} 字段，将被忽略"
                )
        if via == "direct":
            if not hc.get("address"):
                errors.append(f"[host.{host}] via=\"direct\" 需要配置 address")
            auth = hc.get("auth", "key")
            if auth not in ("key", "password"):
                errors.append(f"[host.{host}] auth 必须是 \"key\" 或 \"password\"，当前是 {auth!r}")
        elif via == "hop":
            if not bs:
                errors.append(f"[host.{host}] via=\"hop\" 需要配置 [bastion] 段")
            ignored = [f for f in ("address", "password", "auth", "key", "cert") if hc.get(f)]
            if ignored:
                warnings.append(
                    f"warning: [host.{host}] via=\"hop\" 时 {', '.join(ignored)} 字段会被忽略"
                    "（命令直接由跳板机上的 ssh 发起，用的是跳板机自己的密钥和 known_hosts）"
                )
            for f in ("container", "container_user"):
                # These end up inside a shlex.quote()d docker command, but
                # restrict the charset anyway (docker names are [A-Za-z0-9_.-]).
                v = hc.get(f)
                if v and not (isinstance(v, str) and _SAFE_NAME_RE.match(v)):
                    errors.append(
                        f"[host.{host}] {f} 只能包含字母、数字、. _ -（且不能以 - 开头），当前是 {v!r}"
                    )
            if hc.get("container_user") and not hc.get("container"):
                warnings.append(
                    f"warning: [host.{host}] 配置了 container_user 但没有 container，将被忽略"
                )
        else:
            auth = hc.get("auth", "key")
            if auth not in ("key", "password"):
                errors.append(f"[host.{host}] auth 必须是 \"key\" 或 \"password\"，当前是 {auth!r}")
            elif auth == "key" and hc.get("password"):
                warnings.append(
                    f"warning: [host.{host}] 配置了 password，但认证方式是 key，密码不会被使用"
                    "（需要密码登录请设 auth = \"password\"）"
                )
    return errors, warnings


def load_config(path: Path | None = None) -> tuple[dict, list[str]]:
    """Read, parse and validate config.toml; shared by startup and
    reload_config. A missing file (OSError) or TOML syntax error
    (tomllib.TOMLDecodeError) propagates as-is; validation errors raise
    ConfigLoadError. Returns (cfg, warnings)."""
    with open(path or CONFIG_PATH, "rb") as f:
        cfg = tomllib.load(f)
    errors, warnings = validate_config(cfg)
    if errors:
        raise ConfigLoadError(errors, warnings)
    return cfg, warnings


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


# Keepalive is SSH-layer only (a global request, no channel), so it keeps NAT
# / firewall state and detects a dead peer but does NOT count as channel
# activity for a bastion that kicks idle sessions — that's what the
# application-layer heartbeat below is for. Same knobs for the bastion and
# every target connection, read from [bastion] (restart-only).
KEEPALIVE_INTERVAL_DEFAULT = 15
KEEPALIVE_COUNT_MAX_DEFAULT = 8
HEARTBEAT_INTERVAL_DEFAULT = 60
HEARTBEAT_TIMEOUT = 10  # s: one `true` over a fresh channel
_PROBE_IDLE_AFTER = 120  # s of no channel use before a reused conn is probed
_PROBE_TIMEOUT = 5  # s


def _keepalive_kwargs(name: str | None = None) -> dict:
    # tcp_keepalive is deliberately not passed: asyncssh already defaults it
    # to True (unless ~/.ssh/config says TCPKeepAlive no). A bastion uses its
    # own knobs; targets use their bastion's (direct nodes: the first one).
    bs = bastions()
    b = bs.get(name) if name else next(iter(bs.values()), {})
    b = b or {}
    return dict(
        keepalive_interval=b.get("keepalive_interval", KEEPALIVE_INTERVAL_DEFAULT),
        keepalive_count_max=b.get("keepalive_count_max", KEEPALIVE_COUNT_MAX_DEFAULT),
    )


def _heartbeat_interval() -> float:
    return cfg.get("daemon", {}).get("heartbeat_interval", HEARTBEAT_INTERVAL_DEFAULT)


def _log(msg: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def _fmt_dur(seconds: float) -> str:
    s = int(round(seconds))
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    if h:
        return f"{h}h{m:02d}m{sec:02d}s"
    if m:
        return f"{m}m{sec:02d}s"
    return f"{sec}s"


_ROUND_MINUTES = (5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 360, 480, 720, 1440)


def _near_round(seconds: float) -> str | None:
    """"1h00m00s" if seconds is within a small tolerance of a round number
    typical for session/idle policies (5m ... 24h), else None."""
    for m in _ROUND_MINUTES:
        t = m * 60
        if abs(seconds - t) <= max(45, t * 0.03):
            return _fmt_dur(t)
    return None


def _fmt_exc(exc: BaseException | None) -> str:
    if exc is None:
        return "clean close (exc=None)"
    code = getattr(exc, "code", None)
    detail = f"{type(exc).__name__}" + (f"(code={code})" if code is not None else "")
    return f"{detail}: {exc}"


def classify_drop(
    exc: BaseException | None,
    age: float,
    idle: float,
    idle_real: float | None = None,
    local: bool = False,
) -> list[str]:
    """Hint lines for a dropped connection, so a fixed-lifetime kick, an idle
    kick and a plain network drop can be told apart from the log alone.
    age = seconds since login completed; idle = since the last channel
    activity of any kind (heartbeat/probe included); idle_real = since the
    last real tool call (defaults to idle)."""
    if idle_real is None:
        idle_real = idle
    if local:
        return ["closed by this daemon (reset/invalidate), not a remote drop"]
    hints: list[str] = []
    if isinstance(exc, asyncssh.ConnectionLost) and "keepalive" in str(exc).lower():
        hints.append("keepalive failure: peer/network stopped answering (half-dead link, network drop or silent middlebox drop)")
    elif exc is None:
        # asyncssh passes None both for our own close() and for a peer
        # SSH_MSG_DISCONNECT with code 11 (by application); local closes are
        # flagged separately, so this is the peer closing on purpose.
        hints.append("exc=None: peer sent a clean DISCONNECT (by application) — deliberate server-side close, e.g. policy/idle kick, not a network failure")
    elif isinstance(exc, asyncssh.ConnectionLost):
        hints.append("connection lost without a DISCONNECT message: TCP closed/reset mid-stream (network, firewall or server dropped the socket)")
    elif isinstance(exc, asyncssh.DisconnectError):
        hints.append("server sent DISCONNECT with an error code: deliberate server-side close (see reason)")
    elif isinstance(exc, OSError):
        hints.append("OS-level socket error: network or middlebox dropped the TCP flow")
    r = _near_round(age)
    if r:
        hints.append(f"age ~{r} is a round number: looks like a fixed session lifetime limit")
    r = _near_round(idle_real)
    if r:
        hints.append(f"idle since last tool call ~{r} is a round number: looks like an idle-timeout policy")
        if idle < idle_real / 2:
            hints.append(f"but channel activity (heartbeat) was only {_fmt_dur(idle)} ago: the policy is not counting heartbeat channels")
    return hints


class _ConnStats:
    """Per-connection bookkeeping for drop diagnostics (monotonic seconds).
    last_used: any channel activity (tool calls, heartbeat, probe);
    last_real: tool calls only."""

    def __init__(self) -> None:
        self.mark_ready()
        self.closed_locally = False

    def mark_ready(self) -> None:
        now = time.monotonic()
        self.connected_at = self.last_used = self.last_real = now
        self.connected_wall = datetime.now()


_conn_stats: dict = {}  # SSHClientConnection -> _ConnStats; dropped in connection_lost


def _touch(*conns, real: bool = True) -> None:
    """Record channel activity on these connections (None / unknown ones are
    skipped, so callers don't need to guard)."""
    now = time.monotonic()
    for c in conns:
        s = _conn_stats.get(c)
        if s is not None:
            s.last_used = now
            if real:
                s.last_real = now


@contextlib.contextmanager
def _in_use(*conns):
    # Touch on entry and exit: a long-running command keeps the channel busy
    # in between, so the idle gap must be measured from its end, not start.
    _touch(*conns)
    try:
        yield
    finally:
        _touch(*conns)


def _in_use_host(host: str, conn):
    """_in_use for a target; bastion-routed targets are tunneled through the
    bastion connection, so that one counts as used too."""
    if _route(host) == "direct":
        return _in_use(conn)
    bname = _bastion_or_none(host)
    return _in_use(conn, _bastion_conns.get(bname) if bname else None)


def _close_local(conn) -> None:
    """close() a pooled connection and flag it so connection_lost() doesn't
    report our own close as a remote drop."""
    s = _conn_stats.get(conn)
    if s is not None:
        s.closed_locally = True
    try:
        conn.close()
    except Exception:
        pass


async def _ping(conn, timeout: float) -> None:
    """Open a real channel on conn, run `true`, close it. Raises on any
    failure (including timeout)."""
    await asyncio.wait_for(conn.run("true", check=False), timeout)


async def _idle_probe_ok(conn, label: str) -> bool:
    """Before reusing a conn that has sat idle for > _PROBE_IDLE_AFTER, check
    it is really alive (channel + `true`, _PROBE_TIMEOUT). False means it is
    half-dead and the caller should invalidate it. Never reconnects itself,
    and a failure here is swallowed — the caller's normal (re)connect path
    runs once, so no extra TOTP prompt beyond the one a dead bastion costs
    anyway."""
    s = _conn_stats.get(conn)
    if s is None:
        return True
    idle = time.monotonic() - s.last_used
    if idle < _PROBE_IDLE_AFTER:
        return True
    try:
        await _ping(conn, _PROBE_TIMEOUT)
    except asyncssh.ChannelOpenError:
        pass  # the server answered (e.g. MaxSessions full): alive, just busy
    except Exception as e:
        _log(f"[{label}] liveness probe after {_fmt_dur(idle)} idle failed ({_fmt_exc(e)}); reconnecting")
        return False
    _touch(conn, real=False)
    return True


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


def _bastion_client_keys(name: str | None = None) -> list:
    bs = bastions()
    path = (bs.get(name) if name else next(iter(bs.values()), {}) or {}).get("key", "")
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
    bs = bastions()
    bname = _bastion_or_none(host) or hc.get("bastion")
    bastion_key = (bs.get(bname) if bname else next(iter(bs.values()), {}) or {}).get("key", "")
    if bastion_key:
        return list(asyncssh.load_keypairs(bastion_key))
    return _default_keypairs()


class _TrackedClient(asyncssh.SSHClient):
    """Shared connect/drop bookkeeping for the bastion and target clients."""

    _label = "?"

    def __init__(self):
        self._conn: asyncssh.SSHClientConnection | None = None
        self._stats = _ConnStats()

    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
        self._conn = conn
        _conn_stats[conn] = self._stats

    def auth_completed(self) -> None:
        # Age counts from a finished login, not from the TCP connect — the
        # TOTP prompt can take minutes and would skew round-number detection.
        self._stats.mark_ready()

    def _report_lost(self, exc: Exception | None) -> None:
        s = _conn_stats.pop(self._conn, None) or self._stats
        now = time.monotonic()
        age, idle, idle_real = now - s.connected_at, now - s.last_used, now - s.last_real
        _log(
            f"[{self._label}] connection lost: {_fmt_exc(exc)}; "
            f"connected {s.connected_wall:%H:%M:%S}, alive {_fmt_dur(age)}, "
            f"idle {_fmt_dur(idle)} (last tool call {_fmt_dur(idle_real)} ago)"
        )
        for h in classify_drop(exc, age, idle, idle_real, s.closed_locally):
            _log(f"[{self._label}]   hint: {h}")


# A keyboard-interactive prompt is answered from [bastion] password only if it
# looks like a password prompt and not like a one-time code ("One-time
# password:", "OTP password:" and the like contain "password" too).
_PASSWORD_PROMPT_RE = re.compile(r"password|passwd|密码|口令", re.IGNORECASE)
_OTP_PROMPT_RE = re.compile(
    r"one[- ]?time|otp|totp|token|code|verif|passcode|2fa|mfa|验证码|动态",
    re.IGNORECASE,
)


def is_password_prompt(prompt: str) -> bool:
    return bool(_PASSWORD_PROMPT_RE.search(prompt)) and not _OTP_PROMPT_RE.search(prompt)


# Interactive input (bastion TOTP / password prompts, direct-node passwords).
# None = ask in the terminal (daemon.py CLI). The GUI (app.py) installs an
# async handler `(prompt, echo) -> str` that shows a dialog instead.
prompt_handler = None


async def ask(prompt: str, echo: bool) -> str:
    if prompt_handler is not None:
        return await prompt_handler(prompt, echo)
    loop = asyncio.get_running_loop()
    if echo:
        return await loop.run_in_executor(None, input, prompt)
    return await loop.run_in_executor(None, getpass.getpass, prompt)


class _BastionClient(_TrackedClient):
    _label = "bastion"

    def __init__(self, name: str = DEFAULT_BASTION):
        super().__init__()
        self._name = name
        self._label = _blabel(name)
        # [bastion] password is offered at most once per connection: if the
        # server asks again it was rejected, and resending it would only burn
        # attempts toward a lockout — the terminal takes over instead.
        self._password_sent = False

    def auth_banner_received(self, msg: str, lang: str) -> None:
        print(msg, end="", flush=True)

    def kbdint_auth_requested(self) -> str:
        # asyncssh only attempts keyboard-interactive auth (needed for TOTP)
        # when this returns a string instead of the default None; an empty
        # string lets the server pick the submethod.
        return ""

    def _take_config_password(self) -> str | None:
        """Return the configured bastion password at most once per connection."""
        if self._password_sent:
            return None
        saved = _passwords.get(_bpw_key(self._name))
        if not saved:
            return None
        self._password_sent = True
        return saved

    def password_auth_requested(self) -> str | None:
        """Answer plain password authentication using the shared one-shot state.

        AsyncSSH calls this for the ordinary ``password`` method when no
        password argument was supplied to ``connect``. Keeping this path in
        the same callback as keyboard-interactive prevents a rejected
        keyboard-interactive password from being sent a second time via the
        ordinary method.
        """
        return self._take_config_password()

    async def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: list[tuple[str, bool]],
    ) -> list[str]:
        # Each prompt is answered on its own, in the order the server sends
        # them, so "code then password" and "password then code" (in one
        # challenge or across several) both work: a password-looking prompt
        # gets [bastion] password, everything else is typed in the terminal.
        if instructions:
            print(instructions, flush=True)
        # With several bastions the dialog must say which one is asking.
        tag = "" if self._name == DEFAULT_BASTION else f"[{self._name}] "
        responses = []
        for prompt, echo in prompts:
            if is_password_prompt(prompt):
                saved = self._take_config_password()
            else:
                saved = None
            if saved is not None:
                print(f"{tag}{prompt.rstrip()} (using [{_blabel(self._name)}] password from config)", flush=True)
                answer = saved
            else:
                answer = await ask(tag + prompt, echo)
            responses.append(answer)
        return responses

    def connection_lost(self, exc: Exception | None) -> None:
        self._report_lost(exc)
        # A stale client's callback can arrive after a newer connection has
        # already replaced it in the pool (e.g. this client was pop()'d and
        # reconnected while the old socket's close was still in flight) —
        # only clear the pool entry if it's still this client's connection.
        if _bastion_conns.get(self._name) is self._conn:
            _bastion_conns.pop(self._name, None)
            _log(f"[{_blabel(self._name)}] next call will require a new verification code (TOTP) in this terminal")
            # Only targets tunneled through THIS bastion are dropped — direct
            # nodes have their own socket, and other bastions are unaffected.
            for h in [h for h in _target_conns
                      if _route(h) != "direct" and _bastion_or_none(h) == self._name]:
                _target_conns.pop(h, None)


class _TargetClient(_TrackedClient):
    def __init__(self, host: str):
        super().__init__()
        self._host = host
        self._label = f"target {host}"

    def connection_lost(self, exc: Exception | None) -> None:
        self._report_lost(exc)
        if _target_conns.get(self._host) is self._conn:
            _target_conns.pop(self._host, None)


def _allowed(host: str) -> bool:
    patterns: list[str] = cfg.get("hosts", {}).get("allowed", [])
    if not patterns:
        return True
    return any(fnmatch.fnmatch(host, p) for p in patterns)


async def _connect_bastion(name: str | None = None) -> asyncssh.SSHClientConnection:
    name = name or _default_bastion()
    b = bastions().get(name)
    if not b:
        raise ConfigError(f"bastion {name!r} is not configured")
    port = b.get("port", 22)
    label = _blabel(name)
    print(
        f"Connecting to {label} {b['user']}@{b['host']}:{port} — "
        "enter TOTP / password when prompted.",
        flush=True,
    )
    conn, _ = await asyncssh.create_connection(
        lambda: _BastionClient(name),
        b["host"],
        port=port,
        username=b["user"],
        client_keys=_bastion_client_keys(name),
        # Both ordinary password auth and keyboard-interactive password
        # prompts are answered by _BastionClient, which shares one
        # per-connection send-once flag between the two paths.
        known_hosts=None,
        connect_timeout=BASTION_CONNECT_TIMEOUT,
        **_keepalive_kwargs(name),
    )
    _log(f"[{label}] connected {b['user']}@{b['host']}:{port}")
    return conn


def _is_closed(conn: asyncssh.SSHClientConnection | None) -> bool:
    # Liveness is tracked by the client's connection_lost() callback, which
    # clears the pool entry — no need to poll the connection itself.
    return conn is None


async def _ensure_bastion(name: str | None = None) -> asyncssh.SSHClientConnection:
    """Must be called with that bastion's lock (_bastion_lock(name)) held."""
    name = name or _default_bastion()
    conn = _bastion_conns.get(name)
    if conn is not None and not await _idle_probe_ok(conn, _blabel(name)):
        # Half-dead after a long idle gap: drop it now and reconnect once
        # below, instead of failing a real command on it first.
        _invalidate_bastion(name)
    if _bastion_conns.get(name) is None:
        _bastion_conns[name] = await _connect_bastion(name)
    return _bastion_conns[name]


async def get_bastion(name: str | None = None) -> asyncssh.SSHClientConnection:
    name = name or _default_bastion()
    async with _bastion_lock(name):
        return await _ensure_bastion(name)


async def get_target(host: str) -> asyncssh.SSHClientConnection:
    """Pooled connection to a target. Failures are logged here (the tool
    call only returns the error to the MCP client, so without this the
    daemon window / app.log would show nothing about why a node is down)."""
    try:
        conn = await _get_target(host)
        _last_error.pop(host, None)
        return conn
    except Exception as e:
        _last_error[host] = f"{type(e).__name__}: {e}"
        _log(f"[target {host}] connect failed: {_fmt_exc(e)}")
        hc = cfg.get("host", {}).get(host, {})
        if (
            isinstance(e, asyncssh.PermissionDenied)
            and _route(host) == "bastion"
            and hc.get("password")
            and hc.get("auth", "key") != "password"
        ):
            _log(
                f"[target {host}]   hint: 配置了 password 但认证方式是 key，密码没有被使用；"
                "把“认证方式”改成 password，或确认本机密钥已加到该节点的 authorized_keys"
            )
        if (
            isinstance(e, asyncssh.ChannelOpenError)
            and _route(host) == "bastion"
            and not hc.get("address")
        ):
            _log(
                f"[target {host}]   hint: 跳板机连不上 {host!r}（常见原因：跳板机解析不了这个名字）；"
                "可在 [host." + host + "] 里填 address（IP 或域名）和 port 作为隧道目标"
            )
        raise


async def _get_target(host: str) -> asyncssh.SSHClientConnection:
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
            if await _idle_probe_ok(conn, f"target {host}"):
                return conn
            _invalidate_target(host)

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
                connect_timeout=_connect_timeout(),
                client_factory=lambda: _TargetClient(host),
                **_keepalive_kwargs(),
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
            bname = bastion_of(host)
            async with _bastion_lock(bname):
                bastion = await _ensure_bastion(bname)

            username = host_cfg.get("user", bastions()[bname].get("user", ""))

            # The tunnel destination is resolved BY the bastion: `address`
            # (if set) lets a node name that the bastion can't resolve still
            # be reached by IP; `port` is that node's SSH port.
            tkw: dict = dict(
                port=host_cfg.get("port", 22),
                username=username,
                tunnel=bastion,
                known_hosts=host_cfg.get("known_hosts") or None,
                connect_timeout=_connect_timeout(),
                client_factory=lambda: _TargetClient(host),
                **_keepalive_kwargs(bname),
            )
            if host_cfg.get("auth", "key") == "password":
                tkw["password"] = _passwords.get(host, "")
                # Same as direct: don't burn the server's MaxAuthTries on keys.
                tkw["client_keys"] = None
                tkw["agent_path"] = None
            else:
                tkw["client_keys"] = _host_client_keys(host)
            conn = await asyncssh.connect(host_cfg.get("address") or host, **tkw)
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
        _close_local(conn)


def _invalidate_bastion(name: str | None = None) -> None:
    """Drop and close a bastion connection, plus every target connection
    tunneled through it, so the next hop/bastion-routed call reconnects
    instead of reusing a socket that's already dead but hasn't run its
    connection_lost() callback yet (same reasoning as _invalidate_target).
    direct-routed targets and other bastions' targets are left alone."""
    name = name or _default_bastion()
    conn = _bastion_conns.pop(name, None)
    if conn is not None:
        _close_local(conn)
    for h in [h for h in _target_conns
              if _route(h) != "direct" and _bastion_or_none(h) == name]:
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
    bname = bastion_of(host)
    async with _bastion_lock(bname):
        bastion = await _ensure_bastion(bname)
    async with _hop_sem(bname):
        with _in_use(bastion):
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
        _log(f"[{host}] hop ssh failed on the bastion: {detail}")
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
            with _in_use_host(host, conn):
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
            _invalidate_bastion(bastion_of(host))
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
            with _in_use_host(host, conn):
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


def connection_status() -> list[dict]:
    """Snapshot for the GUI: one row per bastion, then one per configured
    node. state is "connected" | "idle" | "offline" | "via-bastion"; detail
    is a short human string. Read-only — never connects anything.
    Connections are lazy, so "idle" just means nothing has used that node
    yet (or its connection dropped); the next call connects on demand."""
    now = time.monotonic()

    def age(conn) -> str:
        s = _conn_stats.get(conn)
        return f"已连接 {_fmt_dur(now - s.connected_at)}" if s else "已连接"

    rows: list[dict] = []
    bs = bastions()
    for bname in bs:
        conn = _bastion_conns.get(bname)
        rows.append({
            "name": "跳板机" if bname == DEFAULT_BASTION else f"跳板机 {bname}",
            "host": None, "via": "bastion",
            "state": "connected" if conn is not None else "offline",
            "detail": age(conn) if conn is not None else "未登录（首次调用时需验证码）",
        })
    for host, hc in cfg.get("host", {}).items():
        via = hc.get("via", "bastion")
        bname = None if via == "direct" else _bastion_or_none(host)
        bastion_up = bname is not None and bname in _bastion_conns
        suffix = f"（{bname}）" if bname and len(bs) > 1 else ""
        if via == "hop":
            if bname is None:
                rows.append({"name": host, "host": host, "via": via, "state": "offline",
                             "detail": "未指定跳板机（bastion 字段）"})
            elif _last_error.get(host):
                rows.append({"name": host, "host": host, "via": via, "state": "offline",
                             "detail": f"连接失败：{_last_error[host]}"})
            else:
                rows.append({
                    "name": host, "host": host, "via": via,
                    "state": "via-bastion" if bastion_up else "offline",
                    "detail": f"经跳板机代跑 ssh{suffix}" if bastion_up else f"跳板机未登录{suffix}",
                })
            continue
        err = _last_error.get(host)
        conn = _target_conns.get(host)
        if conn is None and err:
            rows.append({"name": host, "host": host, "via": via, "state": "offline",
                         "detail": f"连接失败：{err}"})
            continue
        if conn is not None:
            rows.append({"name": host, "host": host, "via": via, "state": "connected", "detail": age(conn) + suffix})
        elif via == "bastion" and not bastion_up:
            rows.append({"name": host, "host": host, "via": via, "state": "offline", "detail": f"跳板机未登录{suffix}"})
        else:
            rows.append({"name": host, "host": host, "via": via, "state": "idle",
                         "detail": f"尚未连接{suffix}"})
    return rows


async def probe(host: str, timeout: int = 15) -> tuple[bool, str]:
    """Actively test a node: connect if needed (so a bastion login / TOTP
    prompt can happen) and run `true` on it. Returns (ok, detail); never
    raises. Used by the GUI's "test connection" button."""
    t0 = time.monotonic()
    try:
        await run(host, "true", timeout=timeout)
    except Exception as e:
        _last_error[host] = f"{type(e).__name__}: {e}"
        return False, f"{type(e).__name__}: {e}"
    _last_error.pop(host, None)
    return True, f"{time.monotonic() - t0:.1f}s"


def _uses_password(hc: dict) -> bool:
    """direct and bastion-routed nodes can log in with a password
    (auth = "password"); hop nodes never do (the bastion's ssh does it)."""
    return hc.get("via", "bastion") in ("direct", "bastion") and hc.get("auth", "key") == "password"


def _awaiting_password(host: str) -> bool:
    """A direct+password node whose password hasn't been supplied yet: it
    can't be connected without a prompt, which only startup may show."""
    hc = cfg.get("host", {}).get(host, {})
    return _uses_password(hc) and not _passwords.get(host)


async def connect_nodes(hosts: list[str], concurrency: int = 8) -> None:
    """Actively connect every node in `hosts` (bastion / direct: open the
    pooled connection; hop: run `true` through the bastion) instead of
    waiting for the first tool call. Failures are logged and recorded in
    _last_error, never raised. Nodes still waiting for a typed password are
    skipped."""
    sem = asyncio.Semaphore(concurrency)

    async def one(host: str) -> None:
        async with sem:
            if _awaiting_password(host):
                return
            ok, detail = await probe(host)
            _log(f"[connect] {host} " + (f"ok ({detail})" if ok else f"failed: {detail}"))

    await asyncio.gather(*(one(h) for h in hosts), return_exceptions=True)


_bg_tasks: set = set()


def connect_in_background(hosts: list[str]):
    """Start connect_nodes() as a task on the running loop (startup, config
    reload). Returns the task, or None if there is nothing to connect."""
    hosts = list(hosts)
    if not hosts:
        return None
    task = asyncio.get_running_loop().create_task(connect_nodes(hosts))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


async def reset_all() -> None:
    _last_error.clear()
    for conn in list(_target_conns.values()):
        _close_local(conn)
    _target_conns.clear()
    for name in list(_bastion_conns):
        async with _bastion_lock(name):
            conn = _bastion_conns.pop(name, None)
            if conn is not None:
                _close_local(conn)


async def heartbeat_once() -> bool | None:
    """One heartbeat: a real channel (`true`) on every *existing* bastion
    connection, to count as channel activity for a bastion that kicks
    sessions idle on channels (SSH keepalives don't). Returns True if all
    pings were ok, False if any failed, None if there was no bastion to ping.

    Never reconnects: a new bastion login means a TOTP prompt, which must
    only ever happen because a user call needed it. Uses the connection
    objects directly and not the bastion locks, so it can neither queue
    behind nor starve a real call (a login in progress isn't in
    _bastion_conns yet, so it is skipped too). A failed ping is only logged
    — not invalidated — since a slow link or a full MaxSessions must not
    cost a TOTP re-login; keepalive / the idle probe handle genuinely dead
    sockets."""
    conns = list(_bastion_conns.items())
    if not conns:
        return None
    ok = True
    for name, conn in conns:
        try:
            await _ping(conn, HEARTBEAT_TIMEOUT)
        except Exception as e:
            _log(f"[{_blabel(name)}] heartbeat failed: {_fmt_exc(e)}")
            ok = False
            continue
        _touch(conn, real=False)
    return ok


async def heartbeat_loop(interval: float | None = None) -> None:
    """Background task started by the daemon; 0 disables. Why open/close a
    channel per beat rather than hold one long-lived channel: it is
    stateless (no MaxSessions slot held for hours, nothing to re-establish
    or leak on the bastion if we die) and every beat is genuine channel
    open/data/close activity, whereas an idle held channel carries no
    traffic and may not count either. If drop logs show the bastion still
    kicks despite this, a periodically-emitting held channel is the next
    thing to try."""
    if interval is None:
        interval = _heartbeat_interval()
    if interval <= 0:
        return
    _log(f"heartbeat: bastion channel ping every {interval:g}s (timeout {HEARTBEAT_TIMEOUT}s)")
    beats = 0
    while True:
        await asyncio.sleep(interval)
        try:
            ok = await heartbeat_once()
        except Exception as e:  # never let the task die
            _log(f"[bastion] heartbeat error: {_fmt_exc(e)}")
            continue
        if ok:
            beats += 1
            if beats % 60 == 1:  # first beat, then roughly hourly at 60s
                _log(f"[bastion] heartbeat ok (#{beats})")


_RESTART_SECTIONS = ("bastion", "daemon")


def apply_config(new_cfg: dict) -> dict:
    """Swap cfg for new_cfg (reload_config) and drop the cached state of
    removed/changed nodes so the next call rebuilds them from the new config.

    [bastion] and [daemon] are only read at startup, so they keep their old
    values here and are reported in "restart" instead. The swap is a single
    assignment with no await anywhere in this function, so a concurrent tool
    call sees either the old cfg or the new one, never a half-filled one.
    The bastion connection and _hop_sem are never touched (no new TOTP).
    Raises ConfigLoadError, cfg untouched, if keeping the old [bastion]
    leaves the merged config invalid (e.g. a new hop node, no bastion)."""
    global cfg
    old = cfg
    merged = dict(new_cfg)
    restart: list[str] = []
    for sec in _RESTART_SECTIONS:
        if old.get(sec) != new_cfg.get(sec):
            restart.append(sec)
        if sec in old:
            merged[sec] = old[sec]
        else:
            merged.pop(sec, None)
    if restart:
        errors, warnings = validate_config(merged)
        if errors:
            raise ConfigLoadError(errors, warnings)

    old_hosts = old.get("host", {})
    new_hosts = merged.get("host", {})
    added = sorted(new_hosts.keys() - old_hosts.keys())
    removed = sorted(old_hosts.keys() - new_hosts.keys())
    changed = sorted(h for h in new_hosts.keys() & old_hosts.keys() if new_hosts[h] != old_hosts[h])
    allowed_changed = (
        old.get("hosts", {}).get("allowed", []) != merged.get("hosts", {}).get("allowed", [])
    )

    cfg = merged
    for h in removed + changed:
        _last_error.pop(h, None)
        _invalidate_target(h)  # no-op for hop nodes (no entry); never closes the bastion
    for h in removed:
        _passwords.pop(h, None)
    need_password: list[str] = []
    for h in added + changed:
        hc = new_hosts[h]
        if not _uses_password(hc):
            _passwords.pop(h, None)
        elif hc.get("password"):
            _passwords[h] = hc["password"]
        elif (
            h in changed
            and h in _passwords
            and all(old_hosts[h].get(k) == hc.get(k) for k in ("via", "address", "port", "user", "auth"))
        ):
            pass  # same login, keep the password typed at startup
        else:
            # No terminal inside a tool call, so never prompt here. get_target
            # will connect with an empty password and get PermissionDenied
            # (not retried, never blocks); a daemon restart is what fixes it.
            _passwords.pop(h, None)
            need_password.append(h)
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "allowed_changed": allowed_changed,
        "restart": restart,
        "need_password": need_password,
    }
