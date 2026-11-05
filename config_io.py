"""Read / write config.toml for the GUI config editor.

Reading uses the same TOML parser as pool.py. Writing is a small serializer
that covers what config.toml actually contains (tables of strings, numbers,
booleans and string lists). It does NOT preserve comments, so save() keeps
the previous file as <name>.bak first.
"""
import json
import re
import shutil
from pathlib import Path

import pool

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(k: str) -> str:
    return k if _BARE_KEY.match(k) else json.dumps(k, ensure_ascii=False)


def _value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_value(x) for x in v) + "]"
    raise TypeError(f"unsupported config value: {v!r}")


def _emit(table: dict, path: list[str], out: list[str]) -> None:
    scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
    subs = {k: v for k, v in table.items() if isinstance(v, dict)}
    if path and (scalars or not subs):
        if out:
            out.append("")
        out.append("[" + ".".join(_key(p) for p in path) + "]")
    for k, v in scalars.items():
        out.append(f"{_key(k)} = {_value(v)}")
    for k, v in subs.items():
        _emit(v, path + [k], out)


def dumps(cfg: dict) -> str:
    out: list[str] = [
        "# 由 Remote MCP 应用生成。注释不会保留，上一版见 config.toml.bak。",
    ]
    _emit(cfg, [], out)
    return "\n".join(out) + "\n"


def load(path: Path | None = None) -> dict:
    """Parse config.toml without validating it (the editor shows problems
    itself). Missing file -> empty config."""
    path = path or pool.CONFIG_PATH
    if not Path(path).exists():
        return {}
    with open(path, "rb") as f:
        return pool.tomllib.load(f)


def save(cfg: dict, path: Path | None = None) -> None:
    path = Path(path or pool.CONFIG_PATH)
    text = dumps(cfg)
    # Round-trip check: never write something we can't read back identically.
    if pool.tomllib.loads(text) != cfg:
        raise ValueError("内部错误：配置序列化后与原内容不一致，已放弃保存")
    if path.exists():
        shutil.copyfile(path, path.with_name(path.name + ".bak"))
    path.write_text(text, encoding="utf-8", newline="\n")
