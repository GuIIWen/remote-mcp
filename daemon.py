import asyncio
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import pool
import tools

CONFIG_PATH = Path(__file__).parent / "config.toml"


def main() -> None:
    with open(CONFIG_PATH, "rb") as f:
        cfg = tomllib.load(f)

    pool.cfg = cfg

    audit_log = cfg.get("daemon", {}).get("audit_log", "")
    tools.AUDIT_LOG = audit_log

    port = cfg.get("daemon", {}).get("port", 8765)
    b = cfg.get("bastion", {})
    tools.mcp.settings.host = "127.0.0.1"
    tools.mcp.settings.port = port

    async def _serve() -> None:
        # Connecting the bastion and serving must run on the same event
        # loop: asyncio.run() tears its loop down when it returns, which
        # would leave _bastion_conn bound to a dead loop and unable to fire
        # connection_lost on that loop ever again. So both happen inside one
        # asyncio.run() call instead of two.
        await pool.get_bastion()
        print(
            f"remote-mcp listening on http://127.0.0.1:{port}/mcp\n"
            f"bastion: {b.get('user', '')}@{b.get('host', '')}:{b.get('port', 22)}",
            flush=True,
        )
        await tools.mcp.run_streamable_http_async()

    asyncio.run(_serve())


if __name__ == "__main__":
    main()
