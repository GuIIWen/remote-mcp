"""Set up passwordless SSH login from this machine to every node in a YAML
file. Per node: log in once with its password, record its host key in
~/.ssh/known_hosts (accepted automatically, so neither this script nor a
later `ssh` asks "Are you sure you want to continue connecting?"), append
the local public key to ~/.ssh/authorized_keys on the node, then verify a
key-only login. Nodes run concurrently; a failed node is retried (up to
--retries attempts in total), except a rejected password, which is never
retried — repeating it can't help and could trip a lockout policy such as
pam_faillock. Ends with a success/failure summary; exit code 1 if any node
failed, 2 if the YAML file or local key couldn't be loaded.

Usage (from this directory):
    python setup_ssh_keys.py nodes.yaml
    python setup_ssh_keys.py nodes.yaml --only lab1,lab3 --concurrency 10

See nodes.example.yaml for the file format."""
import argparse
import asyncio
import contextlib
import getpass
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

try:
    import yaml
except ImportError:  # reported in main(), so --help still works without it
    yaml = None

SSH_DIR = Path.home() / ".ssh"
KNOWN_HOSTS = SSH_DIR / "known_hosts"
DEFAULT_KEY = SSH_DIR / "id_ed25519"

RETRIES = 3
RETRY_BACKOFF = 2.0  # seconds; attempt n waits n * RETRY_BACKOFF before the next one

STAGE_LOGIN = "登录"
STAGE_HOST_KEY = "记录主机指纹"
STAGE_INSTALL = "安装公钥"
STAGE_VERIFY = "免密验证"


@dataclass
class Node:
    name: str
    ip: str
    port: int
    user: str
    password: str = field(repr=False)

    @property
    def target(self) -> str:
        return f"{self.user}@{self.ip}:{self.port}"


@dataclass
class Result:
    node: Node
    ok: bool
    attempts: int
    detail: str
    errors: list[str] = field(default_factory=list)


class StageError(Exception):
    """A failed attempt, tagged with the step it failed in."""

    def __init__(self, stage: str, exc: BaseException):
        super().__init__(f"{stage}失败（{_fmt_exc(exc)}）")
        self.stage = stage
        self.exc = exc


def _fmt_exc(e: BaseException) -> str:
    if isinstance(e, asyncio.TimeoutError):
        return "超时"
    if isinstance(e, asyncssh.ProcessError):
        err = e.stderr.strip() if isinstance(e.stderr, str) else ""
        return f"命令退出码 {e.exit_status}" + (f"：{err}" if err else "")
    reason = getattr(e, "reason", "") or str(e)
    return f"{type(e).__name__}: {reason}" if reason else type(e).__name__


def load_nodes(path: Path) -> list[Node]:
    """Expand each node name into ip/port/user/password, filling fields the
    node doesn't set from the optional `defaults` section. Every problem in
    the file is collected and raised together as one ValueError."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("顶层应为包含 defaults / nodes 的映射")
    defaults = data.get("defaults") or {}
    nodes = data.get("nodes") or {}
    if not isinstance(defaults, dict):
        raise ValueError("defaults 应为映射")
    if not isinstance(nodes, dict) or not nodes:
        raise ValueError("nodes 为空或格式不对（应为 节点名: {ip, port, user, password}）")

    errors: list[str] = []
    out: list[Node] = []
    for name, nc in nodes.items():
        if nc is not None and not isinstance(nc, dict):
            errors.append(f"{name}: 应为 {{ip, port, user, password}} 映射")
            continue
        nc = {**defaults, **(nc or {})}
        ip = str(nc.get("ip") or "").strip()
        user = str(nc.get("user") or "").strip()
        port = nc.get("port", 22)
        password = nc.get("password")
        if not ip:
            errors.append(f"{name}: 缺少 ip")
        if not user:
            errors.append(f"{name}: 缺少 user")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            errors.append(f"{name}: port 应为 1-65535 的整数，实际是 {port!r}")
            port = 22
        out.append(Node(str(name), ip, port, user, "" if password is None else str(password)))
    if errors:
        raise ValueError("\n".join(errors))
    return out


def known_hosts_name(ip: str, port: int) -> str:
    # OpenSSH's own spelling: the bare host for port 22, "[host]:port" otherwise.
    return ip if port == 22 else f"[{ip}]:{port}"


def record_host_key(node: Node, key: asyncssh.SSHKey, path: Path | None = None) -> str:
    """Accept the node's host key without asking: append it to known_hosts
    unless an identical entry is already there. Returns "present", "added",
    or "changed" (a different key was already recorded for this host — the
    old line is left alone and the new one appended, so ssh accepts either)."""
    path = path or KNOWN_HOSTS
    existing = []
    if path.exists():
        try:
            existing = asyncssh.read_known_hosts(str(path)).match(node.ip, node.ip, node.port)[0]
        except Exception:
            # An unparseable known_hosts just means "nothing matched" here;
            # appending a well-formed line is still the right move.
            existing = []
    if any(k.public_data == key.public_data for k in existing):
        return "present"

    alg_and_key = " ".join(key.export_public_key("openssh").decode("ascii").split()[:2])
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_newline = path.exists() and path.stat().st_size > 0 and not path.read_bytes().endswith(b"\n")
    with path.open("a", encoding="ascii", newline="\n") as f:
        if needs_newline:
            f.write("\n")
        f.write(f"{known_hosts_name(node.ip, node.port)} {alg_and_key}\n")
    return "changed" if existing else "added"


def install_script(pubkey: str) -> str:
    """POSIX sh script, fed to `sh -s` on the node so it doesn't depend on
    the login shell. Idempotent: appends the key only if that exact line
    isn't there yet, terminating a last line that lacks a newline first so
    the key isn't glued onto it. Prints "added" or "present"."""
    return f"""set -e
umask 077
k={shlex.quote(pubkey)}
f="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh"
touch "$f"
chmod 700 "$HOME/.ssh"
chmod 600 "$f"
if grep -qxF -e "$k" "$f"; then
  echo present
else
  if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi
  printf '%s\\n' "$k" >> "$f"
  echo added
fi
if command -v restorecon >/dev/null 2>&1; then restorecon -F "$HOME/.ssh" "$f" || true; fi
"""


@contextlib.contextmanager
def _stage(stage: str):
    """Tag any exception raised inside the block with the step it came from."""
    try:
        yield
    except StageError:
        raise
    except Exception as e:
        raise StageError(stage, e) from e


async def _attempt(node: Node, client_key: asyncssh.SSHKey, pubkey: str, timeout: float) -> str:
    # config=None: the YAML is the only source of truth — ~/.ssh/config must
    # not rewrite this node's address, user or identity behind our back.
    common = dict(
        port=node.port,
        username=node.user,
        config=None,
        agent_path=None,
        connect_timeout=timeout,
    )
    notes = []

    with _stage(STAGE_LOGIN):
        # Password only: offering local keys first would burn MaxAuthTries /
        # lockout attempts before the password is even tried. known_hosts=None
        # because recording the (still unknown) host key is the next step.
        conn = await asyncssh.connect(
            node.ip,
            password=node.password,
            client_keys=None,
            known_hosts=None,
            preferred_auth="password,keyboard-interactive",
            **common,
        )
    async with conn:
        with _stage(STAGE_HOST_KEY):
            host_key = conn.get_server_host_key()
            if host_key is None:
                raise RuntimeError("服务器未提供主机公钥")
            state = record_host_key(node, host_key)
        notes.append({
            "present": "指纹已存在",
            "added": "指纹已记录",
            "changed": "指纹与旧记录不同，已追加新指纹（请确认机器确实重装过）",
        }[state])

        with _stage(STAGE_INSTALL):
            proc = await conn.run("sh -s", input=install_script(pubkey), check=True, timeout=timeout)
            out = (proc.stdout or "").split()
            state = out[-1] if out else ""
            if state not in ("added", "present"):
                raise RuntimeError(f"安装脚本输出异常：{(proc.stdout or '').strip()!r}")
        notes.append("公钥已安装" if state == "added" else "公钥已存在")

    with _stage(STAGE_VERIFY):
        # Key only, and the host key must now verify against known_hosts —
        # exactly what a later plain ssh will rely on.
        async with asyncssh.connect(
            node.ip,
            client_keys=[client_key],
            password=None,
            known_hosts=str(KNOWN_HOSTS),
            preferred_auth="publickey",
            **common,
        ) as vconn:
            await vconn.run("true", check=True, timeout=timeout)
    notes.append("免密验证通过")
    return "；".join(notes)


def _is_auth_rejected(e: StageError) -> bool:
    return e.stage == STAGE_LOGIN and isinstance(e.exc, asyncssh.PermissionDenied)


async def setup_node(node: Node, client_key: asyncssh.SSHKey, pubkey: str,
                     timeout: float, retries: int, sem: asyncio.Semaphore) -> Result:
    errors: list[str] = []
    attempts = 0
    async with sem:
        while attempts < retries:
            attempts += 1
            try:
                detail = await _attempt(node, client_key, pubkey, timeout)
            except StageError as e:
                errors.append(f"第 {attempts} 次：{e}")
                if _is_auth_rejected(e):
                    errors.append("密码被拒绝，不再重试（避免触发账户锁定）")
                    break
                if attempts < retries:
                    wait = attempts * RETRY_BACKOFF
                    print(f"  [{node.name}] {e}，{wait:g}s 后重试", flush=True)
                    await asyncio.sleep(wait)
                continue
            print(f"  [{node.name}] 成功：{detail}", flush=True)
            return Result(node, True, attempts, detail, errors)
    print(f"  [{node.name}] 失败：{errors[-1]}", flush=True)
    return Result(node, False, attempts, errors[-1], errors)


def load_local_key(path: Path) -> tuple[asyncssh.SSHKey, str]:
    """Load the private key (prompting for its passphrase if it has one) and
    the matching one-line public key: the .pub file if present, so its
    comment survives, otherwise derived from the private key."""
    try:
        key = asyncssh.read_private_key(str(path))
    except asyncssh.KeyImportError as e:
        if "passphrase" not in str(e).lower():
            raise
        key = asyncssh.read_private_key(str(path), getpass.getpass(f"{path} 的密钥口令: "))

    pub_path = path.with_name(path.name + ".pub")
    if pub_path.exists():
        line = pub_path.read_text(encoding="ascii").strip().splitlines()[0].strip()
        if asyncssh.import_public_key(line).public_data != key.public_data:
            raise ValueError(f"{pub_path} 与私钥 {path} 不匹配")
        return key, line
    return key, key.export_public_key("openssh").decode("ascii").strip()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="为 YAML 里列出的节点批量配置 SSH 免密登录。")
    p.add_argument("nodes_file", type=Path, help="节点列表 YAML 文件（格式见 nodes.example.yaml）")
    p.add_argument("--only", default="", help="只处理这些节点，逗号分隔，例如 lab1,lab3")
    p.add_argument("--key", type=Path, default=DEFAULT_KEY,
                   help=f"本机私钥路径，公钥取同名 .pub（默认 {DEFAULT_KEY}）")
    p.add_argument("--concurrency", type=int, default=5, help="同时处理的节点数（默认 5）")
    p.add_argument("--retries", type=int, default=RETRIES, help=f"每个节点最多尝试次数（默认 {RETRIES}）")
    p.add_argument("--timeout", type=float, default=15.0, help="单次建连 / 命令超时秒数（默认 15）")
    args = p.parse_args(argv)
    if args.concurrency < 1:
        p.error("--concurrency 至少为 1")
    if args.retries < 1:
        p.error("--retries 至少为 1")
    if args.timeout <= 0:
        p.error("--timeout 必须大于 0")
    return args


async def run(nodes: list[Node], client_key: asyncssh.SSHKey, pubkey: str,
              args: argparse.Namespace) -> list[Result]:
    sem = asyncio.Semaphore(args.concurrency)
    return await asyncio.gather(*(
        setup_node(n, client_key, pubkey, args.timeout, args.retries, sem) for n in nodes
    ))


def print_summary(results: list[Result], elapsed: float) -> None:
    ok = [r for r in results if r.ok]
    bad = [r for r in results if not r.ok]
    print(f"\n==== 汇总：成功 {len(ok)}，失败 {len(bad)}，用时 {elapsed:.1f}s ====")
    for r in ok:
        retried = f"（第 {r.attempts} 次成功）" if r.attempts > 1 else ""
        print(f"  OK    {r.node.name:<12} {r.node.target}  {r.detail}{retried}")
    for r in bad:
        print(f"  FAIL  {r.node.name:<12} {r.node.target}")
        for e in r.errors:
            print(f"        {e}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if yaml is None:
        print("缺少 PyYAML：请先 pip install pyyaml", file=sys.stderr)
        return 2

    try:
        nodes = load_nodes(args.nodes_file)
    except (OSError, yaml.YAMLError, ValueError) as e:
        print(f"读取 {args.nodes_file} 失败：\n{e}", file=sys.stderr)
        return 2

    if args.only:
        wanted = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = [w for w in wanted if w not in {n.name for n in nodes}]
        if unknown:
            print(f"--only 里的节点不在 {args.nodes_file} 中：{', '.join(unknown)}", file=sys.stderr)
            return 2
        nodes = [n for n in nodes if n.name in wanted]

    try:
        client_key, pubkey = load_local_key(args.key)
    except (OSError, asyncssh.KeyImportError, ValueError) as e:
        print(f"加载本机密钥 {args.key} 失败：{_fmt_exc(e)}\n"
              f"（还没有密钥可先运行：ssh-keygen -t ed25519 -f {args.key}）", file=sys.stderr)
        return 2

    # Ask for passwords the YAML leaves out up front, before output from the
    # concurrent workers could interleave with the prompt.
    for n in nodes:
        if not n.password:
            n.password = getpass.getpass(f"{n.name} ({n.target}) 的密码: ")

    print(f"处理 {len(nodes)} 个节点（并发 {args.concurrency}，每个最多 {args.retries} 次）……", flush=True)
    start = time.monotonic()
    results = asyncio.run(run(nodes, client_key, pubkey, args))
    print_summary(results, time.monotonic() - start)
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
