import asyncio
import getpass
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import asyncssh

import pool
import tools

CONFIG_PATH = Path(__file__).parent / "config.toml"

PASSWORD_RETRIES = 3

# container / container_user charset (docker names, plus a numeric uid is fine);
# no leading "-" so the value can never be parsed as a docker option.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9._-]*$")


def _validate_config(cfg: dict) -> None:
    """Check [host.x] fields that must be right before anything connects.
    Fatal problems abort startup (non-zero exit); a bastion-routed node
    carrying direct-only fields is just a warning, since those fields are
    simply ignored rather than causing wrong behavior."""
    errors: list[str] = []
    for host, hc in cfg.get("host", {}).items():
        via = hc.get("via", "bastion")
        if via != "hop":
            hop_only = [f for f in ("node", "container", "container_user") if hc.get(f)]
            if hop_only:
                print(
                    f"warning: [host.{host}] 只有 via=\"hop\" 才支持 {', '.join(hop_only)} 字段，将被忽略",
                    flush=True,
                )
        if via == "direct":
            if not hc.get("address"):
                errors.append(f"[host.{host}] via=\"direct\" 需要配置 address")
            auth = hc.get("auth", "key")
            if auth not in ("key", "password"):
                errors.append(f"[host.{host}] auth 必须是 \"key\" 或 \"password\"，当前是 {auth!r}")
        elif via == "hop":
            if not cfg.get("bastion"):
                errors.append(f"[host.{host}] via=\"hop\" 需要配置 [bastion] 段")
            ignored = [f for f in ("address", "password", "auth", "key", "cert") if hc.get(f)]
            if ignored:
                print(
                    f"warning: [host.{host}] via=\"hop\" 时 {', '.join(ignored)} 字段会被忽略"
                    "（命令直接由跳板机上的 ssh 发起，用的是跳板机自己的密钥和 known_hosts）",
                    flush=True,
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
                print(
                    f"warning: [host.{host}] 配置了 container_user 但没有 container，将被忽略",
                    flush=True,
                )
        else:
            if hc.get("password") or hc.get("address"):
                print(
                    f"warning: [host.{host}] 走 bastion 路由，但配置了 password/address 字段，将被忽略",
                    flush=True,
                )
    if errors:
        for e in errors:
            print(f"config error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)


async def _prompt_password(loop: asyncio.AbstractEventLoop, host: str) -> str:
    return await loop.run_in_executor(None, getpass.getpass, f"[{host}] password: ")


async def _prepare_password_hosts(cfg: dict, loop: asyncio.AbstractEventLoop) -> None:
    """Pre-connect every direct+password node once at startup: prompt for a
    password if [host.x].password is empty, then verify it. A bad
    interactively-typed password gets re-prompted (up to PASSWORD_RETRIES
    total attempts); a bad password taken from config.toml is never
    retried, since retrying it would be pointless and could trip a remote
    lockout policy. Either way, failure just skips the host — it doesn't
    block daemon startup, and the host can still be reached later once its
    config/password is fixed (reset_connections picks up a new attempt).
    Key-auth direct nodes are untouched here: they connect lazily on first
    use, same as bastion-routed nodes always have."""
    for host, hc in cfg.get("host", {}).items():
        if hc.get("via", "bastion") != "direct":
            continue
        if hc.get("auth", "key") != "password":
            continue

        configured_password = hc.get("password", "")
        interactive = not configured_password
        if interactive:
            pool._passwords[host] = await _prompt_password(loop, host)
        else:
            pool._passwords[host] = configured_password

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


def main() -> None:
    if not CONFIG_PATH.exists():
        print(
            "config.toml not found. 复制 config.example.toml 为 config.toml 后填写。",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    with open(CONFIG_PATH, "rb") as f:
        cfg = tomllib.load(f)

    _validate_config(cfg)

    pool.cfg = cfg

    audit_log = cfg.get("daemon", {}).get("audit_log", "")
    tools.AUDIT_LOG = audit_log

    port = cfg.get("daemon", {}).get("port", 8765)
    b = cfg.get("bastion")
    tools.mcp.settings.host = "127.0.0.1"
    tools.mcp.settings.port = port

    async def _serve() -> None:
        # Everything that touches the event loop — password pre-connects,
        # the bastion connection, and serving — must run inside this one
        # asyncio.run() call: asyncio.run() tears its loop down when it
        # returns, which would leave any connection bound to a dead loop
        # and unable to fire connection_lost on that loop ever again.
        loop = asyncio.get_event_loop()
        await _prepare_password_hosts(cfg, loop)

        if b:
            await pool.get_bastion()
            print(
                f"remote-mcp listening on http://127.0.0.1:{port}/mcp\n"
                f"bastion: {b.get('user', '')}@{b.get('host', '')}:{b.get('port', 22)}",
                flush=True,
            )
        else:
            print(
                f"remote-mcp listening on http://127.0.0.1:{port}/mcp\n"
                "no [bastion] configured; every host must use via=\"direct\"",
                flush=True,
            )
        await tools.mcp.run_streamable_http_async()

    asyncio.run(_serve())


if __name__ == "__main__":
    main()
