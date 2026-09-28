import json
import posixpath
import re
import shlex
import stat
import time

import asyncssh
from mcp.server.fastmcp import FastMCP

import pool

mcp = FastMCP("remote-linux")

MAX_OUT = 30_000
MAX_GLOB_RESULTS = 200
AUDIT_LOG: str = ""

_TILDE_USER_RE = re.compile(r"^~([A-Za-z0-9_.\-]*)$")
_TILDE_PREFIX_RE = re.compile(r"^~([A-Za-z0-9_.\-]*)/")


class _RemoteFileNotFound(Exception):
    """Distinct from OSError/FileNotFoundError so pool.with_sftp's
    disconnect-retry clause (which matches OSError) doesn't swallow it."""


class _OldStrNotFound(Exception):
    pass


def _trunc(s: str) -> str:
    if len(s) <= MAX_OUT:
        return s
    half = MAX_OUT // 2
    return s[:half] + f"\n…[truncated {len(s) - MAX_OUT} chars]…\n" + s[-half:]


def _audit(host: str, action: str, detail: str) -> None:
    if not AUDIT_LOG:
        return
    record = json.dumps({"ts": time.time(), "host": host, "action": action, "detail": detail})
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(record + "\n")
    except OSError:
        pass


def _scrub(msg: str) -> str:
    """Redact any configured direct-node password that might otherwise leak
    through a library's exception message (some SSH error strings echo back
    connection parameters)."""
    for pwd in pool._passwords.values():
        if pwd:
            msg = msg.replace(pwd, "***")
    return msg


def _fmt_error(e: Exception, *, brief: bool = False) -> str:
    """Format an exception for a tool's return value. `brief=True` matches
    the existing plain `error: {e}` style used for ValueError (validation
    errors, which never come from asyncssh and don't need the type name)."""
    msg = f"error: {e}" if brief else f"error: {type(e).__name__}: {e}"
    return _scrub(msg)


def _fmt(r: asyncssh.SSHCompletedProcess) -> str:
    parts = [f"exit_code: {r.returncode}"]
    if r.stdout:
        parts.append(f"stdout:\n{_trunc(r.stdout)}")
    if r.stderr:
        parts.append(f"stderr:\n{_trunc(r.stderr)}")
    return "\n".join(parts)


def _quote_cd_path(path: str) -> str:
    """shlex.quote a path used in `cd`, but keep a leading ~ or ~user (with
    only safe username characters) unquoted so the remote shell still
    expands it."""
    if _TILDE_USER_RE.match(path):
        return path
    m = _TILDE_PREFIX_RE.match(path)
    if m:
        prefix_end = m.end()  # keep the '/' itself outside the quoted remainder
        return path[:prefix_end] + shlex.quote(path[prefix_end:])
    return shlex.quote(path)


def _host_default_cwd(host: str) -> str:
    return pool.cfg.get("host", {}).get(host, {}).get("default_cwd", "")


def _cd_prefix(path: str) -> str:
    """Build a `cd {path} && ` prefix (tilde-aware), or "" if path is empty
    or already ".". Shared by every shell-based tool so a relative path
    argument resolves the same way exec's cwd does: relative to the host's
    default_cwd, or to the login/SFTP home when unset."""
    if not path or path == ".":
        return ""
    return f"cd {_quote_cd_path(path)} && "


def _glob_body_to_regex(pattern: str) -> str:
    """Translate a glob pattern into a POSIX ERE fragment, treating `**` as
    zero-or-more path segments (real globstar semantics) and `*`/`?` as
    single-segment wildcards."""
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*" and pattern[i : i + 2] == "**":
            j = i + 2
            while j < n and pattern[j] == "*":
                j += 1
            if j < n and pattern[j] == "/":
                out.append("(.*/)?")
                j += 1
            else:
                out.append(".*")
            i = j
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c in ".^$+(){}|[]\\":
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _glob_pattern_regex(pattern: str) -> str:
    """Build the regex passed to `find . -regex`, which prints paths in
    "./foo/bar" form when starting from ".". The base itself is never
    embedded in the regex now (glob_files `cd`s into it first and always
    searches from "."), so a `base` containing regex metacharacters can't
    corrupt the match."""
    return r"^\./" + _glob_body_to_regex(pattern) + "$"


async def _sftp_home(sftp) -> str:
    home = await sftp.realpath(".")
    return home.decode() if isinstance(home, bytes) else str(home)


async def _sftp_expand(sftp, path: str) -> str:
    """Expand a leading ~ into an absolute path via the SFTP session's
    realpath("."). Only the current user's ~ is supported (SFTP has no
    portable way to resolve another account's home directory) — ~user is
    rejected. Absolute paths and plain relative paths pass through
    unchanged, the latter left for the caller to resolve against a base."""
    m_user = _TILDE_USER_RE.match(path)
    m_prefix = _TILDE_PREFIX_RE.match(path)
    user = (m_user or m_prefix).group(1) if (m_user or m_prefix) else ""
    if user:
        raise ValueError(f"'~{user}' is not supported over SFTP (only the current user's ~ is)")
    if m_user:  # bare "~"
        return await _sftp_home(sftp)
    if m_prefix:  # "~/rest"
        return posixpath.join(await _sftp_home(sftp), path[m_prefix.end() :])
    return path


async def _sftp_resolve_path(sftp, host: str, path: str) -> str:
    """Resolve `path` the same way exec resolves a shell command's cwd:
    relative to the host's configured default_cwd, or to the SFTP/login
    home when default_cwd is unset. ~ and ~/... expand to the current
    user's home, whether in `path` itself or in default_cwd."""
    expanded = await _sftp_expand(sftp, path)
    if posixpath.isabs(expanded):
        return expanded

    default_cwd = _host_default_cwd(host)
    if default_cwd:
        base = await _sftp_expand(sftp, default_cwd)
        if not posixpath.isabs(base):
            base = posixpath.join(await _sftp_home(sftp), base)
    else:
        base = await _sftp_home(sftp)
    return posixpath.normpath(posixpath.join(base, expanded))


async def _sftp_real_path(sftp, path: str) -> str:
    """Resolve path to its real target if it is a symlink, so the atomic
    write/rename below touches the real file instead of replacing the link."""
    try:
        attrs = await sftp.lstat(path)
    except asyncssh.SFTPNoSuchFile:
        return path
    if stat.S_ISLNK(attrs.permissions):
        target = await sftp.realpath(path)
        return target.decode() if isinstance(target, bytes) else str(target)
    return path


async def _atomic_write(sftp, path: str, content: str) -> None:
    tmp = path + ".mcp.tmp"
    try:
        try:
            attrs = await sftp.stat(path)
            file_mode = stat.S_IMODE(attrs.permissions)
        except asyncssh.SFTPNoSuchFile:
            file_mode = 0o644

        async with sftp.open(tmp, "w") as f:
            await f.write(content)

        await sftp.chmod(tmp, file_mode)
        await sftp.posix_rename(tmp, path)
    except Exception:
        try:
            await sftp.remove(tmp)
        except Exception:
            pass
        raise


@mcp.tool()
async def list_hosts() -> str:
    """List bastion status, allowed hosts, connected targets, and configured
    hosts (route, auth method, connection state). Never includes passwords."""
    b = pool.cfg.get("bastion")
    if b:
        bastion_addr = f"{b.get('user', '')}@{b.get('host', '')}:{b.get('port', 22)}"
        bastion_up = not pool._is_closed(pool._bastion_conn)
        bastion_line = f"bastion: {bastion_addr} ({'connected' if bastion_up else 'disconnected'})"
    else:
        bastion_line = "bastion: (not configured)"
    allowed = pool.cfg.get("hosts", {}).get("allowed", [])

    lines = [
        bastion_line,
        f"allowed: {allowed if allowed else '(unrestricted)'}",
        "configured hosts:",
    ]
    configured = sorted(pool.cfg.get("host", {}).keys())
    if not configured:
        lines.append("  (none)")
    for host in configured:
        hc = pool.cfg["host"][host]
        route = pool._route(host)
        if route == "direct":
            route_desc = f"direct {hc.get('address', '?')}:{hc.get('port', 22)}"
            auth = hc.get("auth", "key")
        else:
            route_desc = "bastion"
            auth = "key"
        conn = pool._target_conns.get(host)
        state = "connected" if not pool._is_closed(conn) else "disconnected"
        lines.append(f"  {host}: {route_desc}, auth={auth}, {state}")
    return "\n".join(lines)


@mcp.tool()
async def exec(host: str, command: str, cwd: str = "", timeout: int = 60) -> str:
    """Execute a shell command on the remote host. A relative `cwd` resolves
    against the host's default_cwd (same as glob_files' `base`), not the
    login directory; an absolute or ~-rooted `cwd` overrides it as usual."""
    _audit(host, "exec", command)
    # Chain _cd_prefix calls exactly like glob_files does for `base`: cd into
    # default_cwd first, then into cwd (each a no-op if unset/"."), so a
    # relative cwd lands relative to default_cwd rather than the login cwd —
    # exec(cwd="src") and glob_files(base="src") now agree on where "src" is.
    full_cmd = _cd_prefix(_host_default_cwd(host)) + _cd_prefix(cwd) + command
    try:
        r = await pool.run(host, full_cmd, timeout=timeout)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except Exception as e:
        return _fmt_error(e)
    return _fmt(r)


@mcp.tool()
async def read_file(host: str, path: str, offset: int = 1, limit: int = 2000) -> str:
    """Read a file with line numbers, starting at offset, up to limit lines."""
    end = offset + limit
    quoted = _quote_cd_path(path)  # path itself may start with ~
    cmd = (
        _cd_prefix(_host_default_cwd(host))
        + f"awk 'NR>={end}{{exit}} NR>={offset}{{printf \"%6d\\t%s\\n\", NR, $0}}' {quoted}"
    )
    try:
        r = await pool.run(host, cmd)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except Exception as e:
        return _fmt_error(e)
    if r.returncode != 0:
        return _fmt(r)
    return _trunc(r.stdout) if r.stdout else "(empty)"


@mcp.tool()
async def write_file(host: str, path: str, content: str) -> str:
    """Overwrite a remote file atomically via SFTP."""
    _audit(host, "write_file", path)

    async def _do(sftp):
        abs_path = await _sftp_resolve_path(sftp, host, path)
        real_path = await _sftp_real_path(sftp, abs_path)
        await _atomic_write(sftp, real_path, content)

    try:
        await pool.with_sftp(host, _do)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except Exception as e:
        return _fmt_error(e)

    return f"ok: wrote {len(content.encode('utf-8'))} bytes to {path}"


@mcp.tool()
async def edit_file(
    host: str,
    path: str,
    old_str: str,
    new_str: str,
    replace_all: bool = False,
) -> str:
    """Replace old_str with new_str in a remote file atomically."""
    if old_str == "":
        return "error: old_str must not be empty"
    _audit(host, "edit_file", path)

    result: dict = {}

    async def _do(sftp):
        if "count" in result:
            # A previous attempt already renamed the tmp file into place, but
            # the connection dropped before that success made it back to
            # pool.with_sftp's caller, triggering a retry. old_str is gone
            # from the file now, so re-running the edit would wrongly report
            # "not found" — just confirm success without touching the file.
            return
        abs_path = await _sftp_resolve_path(sftp, host, path)
        real_path = await _sftp_real_path(sftp, abs_path)
        try:
            attrs = await sftp.stat(real_path)
            file_mode = stat.S_IMODE(attrs.permissions)
        except asyncssh.SFTPNoSuchFile:
            raise _RemoteFileNotFound(path) from None

        async with sftp.open(real_path, "r") as f:
            original = await f.read()
        if isinstance(original, bytes):
            original = original.decode("utf-8")

        count = original.count(old_str)
        if count == 0:
            raise _OldStrNotFound(path)
        if count > 1 and not replace_all:
            raise ValueError(
                f"old_str appears {count} times; set replace_all=true or provide more context"
            )

        updated = original.replace(old_str, new_str)
        tmp = real_path + ".mcp.tmp"
        try:
            async with sftp.open(tmp, "w") as f:
                await f.write(updated)
            await sftp.chmod(tmp, file_mode)
            await sftp.posix_rename(tmp, real_path)
        except Exception:
            try:
                await sftp.remove(tmp)
            except Exception:
                pass
            raise
        result["count"] = count

    try:
        await pool.with_sftp(host, _do)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except _RemoteFileNotFound:
        return f"error: file not found: {path}"
    except _OldStrNotFound:
        return f"error: old_str not found in {path}"
    except Exception as e:
        return _fmt_error(e)

    replacements = result["count"] if replace_all else 1
    return f"ok: replaced {replacements} occurrence(s) in {path}"


@mcp.tool()
async def grep(
    host: str,
    pattern: str,
    path: str = ".",
    glob: str = "",
    context: int = 0,
) -> str:
    """Grep for a pattern in files on the remote host (uses rg if available)."""
    q_pattern = shlex.quote(pattern)
    q_path = _quote_cd_path(path)  # path may itself start with ~

    rg_glob = f"--glob {shlex.quote(glob)}" if glob else ""
    rg_ctx = f"-C {context}" if context else ""
    grep_include = f"--include={shlex.quote(glob)}" if glob else ""
    grep_ctx = f"-C {context}" if context else ""

    cmd = (
        _cd_prefix(_host_default_cwd(host))
        + f"if command -v rg >/dev/null 2>&1; then "
        f"rg -n {rg_ctx} {rg_glob} -e {q_pattern} {q_path}; "
        f"else "
        f"grep -rnE {grep_ctx} {grep_include} --exclude-dir=.git -e {q_pattern} {q_path}; "
        f"fi"
    )
    try:
        r = await pool.run(host, cmd)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except Exception as e:
        return _fmt_error(e)
    if not r.stdout and r.returncode in (0, 1):
        return "(no matches)"
    return _fmt(r)


@mcp.tool()
async def glob_files(host: str, pattern: str, base: str = ".") -> str:
    """Find files matching a glob pattern on the remote host, rooted at
    `base` (`**` matches zero or more directories). `base` resolves the same
    way exec's cwd does: relative to the host's default_cwd, or to the login
    home when unset; ~ and ~/... are expanded by the shell."""
    # cd into default_cwd, then into base (each a no-op if "." / unset) —
    # chaining two _cd_prefix calls is what makes a relative `base` land
    # relative to default_cwd rather than relative to the login directory,
    # and lets `find` itself always search from "." so the glob regex never
    # has to embed (and escape) a base path.
    cd = _cd_prefix(_host_default_cwd(host)) + _cd_prefix(base)
    regex = _glob_pattern_regex(pattern)
    cmd = (
        cd
        + f"find . -name .git -prune -o "
        f"-regextype posix-extended -regex {shlex.quote(regex)} -print | "
        f"head -n {MAX_GLOB_RESULTS + 1}"
    )
    try:
        r = await pool.run(host, cmd)
    except ValueError as e:
        return _fmt_error(e, brief=True)
    except Exception as e:
        return _fmt_error(e)

    # find printed "./foo/bar" (relative to base); strip the "./" so the
    # result reads like an ordinary relative path under base.
    lines = [line[2:] if line.startswith("./") else line for line in r.stdout.splitlines() if line]
    truncated = len(lines) > MAX_GLOB_RESULTS
    if truncated:
        lines = lines[:MAX_GLOB_RESULTS]
    if not lines:
        return "(no matches)"
    out = "\n".join(lines)
    if truncated:
        out += f"\n…[truncated to first {MAX_GLOB_RESULTS} results]…"
    return out


@mcp.tool()
async def reset_connections() -> str:
    """Close all SSH connections so they reconnect on next use."""
    await pool.reset_all()
    return "ok: all connections reset"
