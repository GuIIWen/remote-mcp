import asyncio
import contextlib
import sys

import asyncssh

import pool
import tools

CONFIG_PATH = pool.CONFIG_PATH

PASSWORD_RETRIES = 3
BASTION_RETRIES = 3


def _report_config(warnings: list[str], errors: list[str]) -> None:
    """Startup-side reporting of pool.validate_config's result: warnings to
    stdout, fatal problems to stderr plus a non-zero exit (same output the
    old in-place validator produced)."""
    for w in warnings:
        print(w, flush=True)
    if errors:
        for e in errors:
            print(f"config error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)


def _validate_config(cfg: dict) -> None:
    errors, warnings = pool.validate_config(cfg)
    _report_config(warnings, errors)


async def _prompt_password(loop: asyncio.AbstractEventLoop, host: str) -> str:
    return (await pool.ask(f"[{host}] password: ", False)) or ""


async def _prepare_password_hosts(cfg: dict, loop: asyncio.AbstractEventLoop) -> None:
    """Collect the password of every auth="password" node at startup (prompt
    if [host.x].password is empty). Direct nodes are also pre-connected here
    to verify it; bastion-routed ones need the bastion first, so they are
    only prompted here and connect later with the rest. A bad
    interactively-typed password gets re-prompted (up to PASSWORD_RETRIES
    total attempts); a bad password taken from config.toml is never
    retried, since retrying it would be pointless and could trip a remote
    lockout policy. Either way, failure just skips the host — it doesn't
    block daemon startup, and the host can still be reached later once its
    config/password is fixed (reset_connections picks up a new attempt).
    Every other node (key-auth direct, bastion, hop) is connected by
    pool.connect_nodes() once the bastions are logged in."""
    for host, hc in cfg.get("host", {}).items():
        if not pool._uses_password(hc):
            continue

        configured_password = hc.get("password", "")
        interactive = not configured_password
        if interactive:
            pool._passwords[host] = await _prompt_password(loop, host)
        else:
            pool._passwords[host] = configured_password
        if hc.get("via", "bastion") != "direct":
            continue  # verified by connect_nodes() once the bastion is up

        attempts_left = PASSWORD_RETRIES if interactive else 1
        while True:
            try:
                await pool.get_target(host)
                print(f"[{host}] connected (direct, password)", flush=True)
                break
            except asyncssh.PermissionDenied:
                attempts_left -= 1
                if not interactive:
                    print(f"[{host}] 配置里的密码错误，跳过该节点", flush=True)
                    break
                if attempts_left <= 0:
                    print(f"[{host}] 密码连续输错次数过多，跳过该节点", flush=True)
                    break
                print(f"[{host}] 密码错误，请重新输入", flush=True)
                pool._passwords[host] = await _prompt_password(loop, host)
            except (OSError, asyncio.TimeoutError) as e:
                # Unreachable / connect_timeout expired — not an auth
                # problem, so don't burn retries on it; just defer to a
                # lazy reconnect on first actual tool call.
                print(
                    f"[{host}] 暂时连不上（{type(e).__name__}: {e}），将在首次调用时按需重连",
                    flush=True,
                )
                break
            except Exception as e:
                # Anything else (e.g. not in [hosts] allowed) is a config
                # problem for this one host — warn and move on rather than
                # taking down the whole daemon over it.
                print(f"[{host}] 预连接失败（{type(e).__name__}: {e}），跳过该节点", flush=True)
                break


async def _login_bastion(name: str | None = None) -> bool:
    """Startup login to the bastion. A rejected TOTP/password or a timeout
    (e.g. the code wasn't typed within pool.BASTION_CONNECT_TIMEOUT) gets
    retried (up to BASTION_RETRIES total attempts, each one prompting
    again); any other failure is reported once and not retried. Either way, failure
    doesn't stop the daemon — the pool reconnects lazily, so the first call
    that needs the bastion prompts for a code in this terminal."""
    label = pool._blabel(name) if name else "bastion"
    attempts_left = BASTION_RETRIES
    while True:
        try:
            await pool.get_bastion(name)
            return True
        except asyncssh.PermissionDenied as e:
            attempts_left -= 1
            reason = getattr(e, "reason", "") or str(e)
            if name and pool.prompt_cooling(pool._bpw_key(name)):
                print(f"[{label}] 已取消输入，放弃启动时登录（稍后可在菜单 服务 → 重新连接节点 重试）", flush=True)
                return False
            if attempts_left <= 0:
                print(f"[{label}] 认证失败（{reason}），次数已用完，放弃启动时登录", flush=True)
                return False
            print(f"[{label}] 认证失败（{reason}），请重新输入，还剩 {attempts_left} 次", flush=True)
        except asyncio.TimeoutError:
            attempts_left -= 1
            if attempts_left <= 0:
                print(f"[{label}] 登录超时，次数已用完，放弃启动时登录", flush=True)
                return False
            print(f"[{label}] 登录超时，请重新输入，还剩 {attempts_left} 次", flush=True)
        except Exception as e:
            print(f"[{label}] 登录失败（{type(e).__name__}: {e}），放弃启动时登录", flush=True)
            return False


def init_service() -> tuple[dict, int]:
    """Load + validate config.toml and wire it into pool/tools. Exits via
    sys.exit(1) (after printing the reason) on a missing/invalid config;
    the GUI catches SystemExit and shows the printed message."""
    if not CONFIG_PATH.exists():
        print(
            "config.toml not found. 复制 config.example.toml 为 config.toml 后填写。",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    try:
        cfg, warnings = pool.load_config(CONFIG_PATH)
    except pool.ConfigLoadError as e:
        _report_config(e.warnings, e.errors)
    _report_config(warnings, [])

    pool.cfg = cfg
    # Not prompted for when empty: the bastion's own keyboard-interactive
    # prompt already asks for it, exactly as before.
    for bname, bcfg in pool.bastions(cfg).items():
        if bcfg.get("password"):
            pool._passwords[pool._bpw_key(bname)] = bcfg["password"]

    tools.AUDIT_LOG = cfg.get("daemon", {}).get("audit_log", "")

    port = cfg.get("daemon", {}).get("port", 8765)
    tools.mcp.settings.host = "127.0.0.1"
    tools.mcp.settings.port = port
    return cfg, port


async def serve(cfg: dict, port: int, on_server=None, use_colors: bool | None = None) -> None:
    """Everything that touches the event loop — password pre-connects, the
    bastion connection, and serving — must run inside ONE event loop that
    lives as long as the service: asyncio.run() tears its loop down when it
    returns, which would leave any connection bound to a dead loop and
    unable to fire connection_lost on that loop ever again.

    on_server(server) is called with the uvicorn.Server once it exists, so
    a caller (the GUI) can stop the service by setting server.should_exit."""
    import uvicorn

    bs = pool.bastions(cfg)
    loop = asyncio.get_running_loop()
    await _prepare_password_hosts(cfg, loop)

    not_logged_in = []
    for bname in bs:
        if not await _login_bastion(bname):
            not_logged_in.append(bname)
    lines = [f"remote-mcp listening on http://127.0.0.1:{port}/mcp"]
    for bname, b in bs.items():
        lines.append(f"{pool._blabel(bname)}: {b.get('user', '')}@{b.get('host', '')}:{b.get('port', 22)}")
    if not bs:
        lines.append('no [bastion] configured; every host must use via="direct"')
    print(chr(10).join(lines), flush=True)
    for bname in not_logged_in:
        print(f"[{pool._blabel(bname)}] 尚未登录，首次需要它的调用会要求输入验证码", flush=True)
    # Started only after the initial login (so it can't race the first
    # TOTP prompt); it never reconnects, see pool.heartbeat_once().
    heartbeat = asyncio.create_task(pool.heartbeat_loop())
    # Connect every configured node now instead of on first use; runs in the
    # background so the HTTP server comes up immediately.
    sweep = pool.connect_in_background(list(cfg.get("host", {})))
    try:
        # FastMCP builds its StreamableHTTP session manager once and that
        # manager can only run() once per instance, so a second start in the
        # same process (GUI stop -> start) would die in the lifespan. Drop it
        # so streamable_http_app() makes a fresh one.
        tools.mcp._session_manager = None
        server = uvicorn.Server(
            uvicorn.Config(
                tools.mcp.streamable_http_app(),
                host="127.0.0.1",
                port=port,
                log_level=tools.mcp.settings.log_level.lower(),
                # Don't let an idle MCP client's open SSE stream block Stop forever.
                timeout_graceful_shutdown=3,
                use_colors=use_colors,
            )
        )
        if on_server:
            on_server(server)
        await server.serve()
    finally:
        if sweep is not None:
            sweep.cancel()
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        with contextlib.suppress(Exception):
            await pool.reset_all()


def main() -> None:
    cfg, port = init_service()
    asyncio.run(serve(cfg, port))


if __name__ == "__main__":
    main()
