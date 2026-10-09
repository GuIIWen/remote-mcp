---
name: remote-linux-mcp
description: 安装、配置并接入 remote-linux MCP server（本机 Windows daemon，经跳板机或直连访问远端 Linux）。当用户要部署这个 daemon、填写 config.toml、增加/修改节点、把它接入 Claude Code 或 Codex、排查连不上，或询问这些远端工具怎么用时使用。
---

# remote-linux MCP：安装、配置与使用

remote-linux 是一个跑在 **Windows 本机**的 MCP daemon（Python + asyncssh + FastMCP），通过 `http://127.0.0.1:8765/mcp` 给 Claude Code / Codex 提供操作远端 Linux 的工具。

- 走跳板机的节点：daemon 常驻一条跳板机连接（登录需要 TOTP），目标机以 `用户名@节点名` 经跳板机免密登录。
- hop 节点（`via = "hop"`）：目标机只有跳板机能免密登录，本机没有它的私钥（比如某些计算节点，私钥一直留在跳板机上）。daemon 不打隧道直连，而是让跳板机自己代跑 `ssh <节点名> '<命令>'`。
- 直连节点（`via = "direct"`）：直接连 `address:port`，用密钥/证书或密码登录，不经过跳板机。
- 跳板机和目标机上**不装任何东西**，也不建服务目录；远端唯一的改动是 `authorized_keys`。

下文 `<REPO>` 指包含 `daemon.py` 的仓库目录（这个 skill 放在 `<REPO>\.claude\skills\remote-linux-mcp\` 下）。不确定在哪就先问用户，不要猜。完整说明见 `<REPO>\DEPLOY.md`，设计见 `<REPO>\remote-mcp-design.html`。

## 0. 安装这个 skill

skill 就是 `remote-linux-mcp\` 这个目录（里面是 `SKILL.md`），整个目录复制过去即可，目录名保持 `remote-linux-mcp`。

| 客户端 | 范围 | 路径 |
|---|---|---|
| Claude Code | 仅本仓库（已自带，在仓库里启动 CC 即生效） | `<REPO>\.claude\skills\remote-linux-mcp\` |
| Claude Code | 用户级，所有项目可用 | `%USERPROFILE%\.claude\skills\remote-linux-mcp\` |
| Codex | 用户级，所有项目可用 | `%USERPROFILE%\.agents\skills\remote-linux-mcp\` |
| Codex | 仅本仓库 | `<REPO>\.agents\skills\remote-linux-mcp\` |

在 `<REPO>` 下执行（按需选一条或两条）：

```powershell
# Claude Code 用户级
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse -Force .claude\skills\remote-linux-mcp "$env:USERPROFILE\.claude\skills\"

# Codex 用户级
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force .claude\skills\remote-linux-mcp "$env:USERPROFILE\.agents\skills\"
```

复制后新开会话才会加载。之后仓库里的 skill 有更新，需要重新复制一次。

## 必须遵守的规则

- `config.toml` 里有真实账号和密码，已被 `.gitignore` 排除。**不要提交它，不要把密码回显到对话、日志或命令行参数里**；改动只提交 `config.example.toml`。
- 下文示例里的 `<远端用户名>`、`<远端家目录>`、`<本机用户名>` 都是占位符，必须换成当前使用者自己的值，**不要照抄别人的账号或路径**。
- 远端家目录因集群而异，不一定是 `/home/<远端用户名>`（有的集群是 `/public/home/<远端用户名>` 这类形式）。不确定时让用户在远端执行 `echo $HOME` 确认，再填进 `default_cwd`，不要猜。
- `default_cwd` 等远端字段都是 Linux 路径；只有 `key`/`cert`/`known_hosts`/`audit_log` 是本机 Windows 路径（建议用正斜杠，如 `C:/Users/<本机用户名>/.ssh/id_ed25519`，否则 TOML 里要写 `\\`）。
- **daemon 需要在前台窗口交互输入 TOTP / 密码，Claude 不能替用户启动它**（后台 shell 没有终端，会卡在提示上）。启动这一步交给用户在独立 PowerShell 窗口里执行。
- 写入用户级配置（`claude mcp add --scope user`、`~/.codex/config.toml`）前先向用户确认。

## 1. 安装依赖（一次性）

要求 Python 3.11+。推荐用 uv：

```powershell
cd <REPO>
uv --version            # 没有就先装：irm https://astral.sh/uv/install.ps1 | iex
uv venv --python 3.11
uv pip install -r requirements.txt
```

装完自检：

```powershell
uv run python -c "import asyncssh, mcp; print('deps ok', asyncssh.__version__)"
```

若报 `No module named 'pywintypes'`，补跑：`& ".venv\Scripts\python.exe" ".venv\Scripts\pywin32_postinstall.py" -install`（出现 COM 权限警告可忽略）。

## 2. 配置 config.toml

没有 `config.toml` 时从模板复制（daemon 找不到它会直接退出并提示）：

```powershell
Copy-Item config.example.toml config.toml
```

向用户收集真实值后填写。字段含义：

| 段 / 字段 | 说明 |
|---|---|
| `[bastion] host/port/user` | 跳板机地址、端口、你在跳板机上的用户名 |
| `[bastion] key` | 本机私钥路径；留空用默认密钥对（`~/.ssh/id_*`） |
| `[daemon] port` | 本地监听端口，默认 8765，只绑 127.0.0.1 |
| `[daemon] audit_log` | 审计日志 JSONL 路径，留空不记录 |
| `[daemon] connect_timeout` | 建连超时（秒），默认 20 |
| `[hosts] allowed` | 节点白名单，支持 fnmatch 通配符；`[]` 表示不限制（建议填写） |
| `[host.<名字>] user` | 目标机登录用户名 |
| `[host.<名字>] default_cwd` | 远端默认工作目录，相对路径都以它为基准 |
| `[host.<名字>] via` | 省略或 `"bastion"` 走跳板机；`"hop"` 走跳板机代跑 ssh（目标机私钥只在跳板机上）；`"direct"` 直连 |
| `node` | 仅 hop，选填：跳板机实际 ssh 的目标；省略则等于段名 |
| `container` | 仅 hop，选填：容器名或 ID 前缀，设了就用 `docker exec -i` 在容器里执行；字符集限字母、数字、`.`、`_`、`-` |
| `container_user` | 仅 hop 且已配 `container`，选填：`docker exec -u` 的值，省略不传；与 `user` 不同 |
| `address` / `port` | 仅 direct：目标地址（必填）和端口（默认 22）；hop 的 `port` 选填，是跳板机 ssh 到目标机时用的 `-p`，留空交给跳板机自己的 `~/.ssh/config` |
| `auth` | 仅 direct：`"key"`（默认）或 `"password"` |
| `key` / `cert` | 私钥 / OpenSSH 用户证书路径；key 回退顺序：`[host.x] key` → `[bastion] key` → 默认密钥对（hop 节点不适用——它用的是跳板机自己的密钥，不是本机的） |
| `password` | 仅 direct + password：明文；留空则启动时交互输入 |
| `known_hosts` | 仅 direct，可选：本机 known_hosts 文件，用来校验主机密钥；留空不校验 |

hop 节点如果同时填了 `address`/`password`/`auth`/`key`/`cert`，这些字段会被忽略并在启动时打印警告；没配 `[bastion]` 却写了 `via = "hop"` 是致命错误，daemon 直接退出。

四种节点的写法：

```toml
# 走跳板机：段名就是跳板机能解析的节点名，登录为 <远端用户名>@dev1
[host.dev1]
user        = "<远端用户名>"
default_cwd = "<远端家目录>"

# hop：目标机只有跳板机能免密登录，本机没有它的私钥（比如某些计算节点）；
# daemon 让跳板机自己执行 `ssh nmz01 '<命令>'`，不打隧道、不用本机密钥。
[host.nmz01]
via         = "hop"
user        = "<远端用户名>"   # 选填：跳板机 ssh 到 nmz01 用的 -l；留空用跳板机自己的 ~/.ssh/config
default_cwd = "<远端家目录>"
# 部署前提（在跳板机上做，不是本机）：私钥放在跳板机上，且跳板机已能免密
# ssh 到 nmz01。自检：登录跳板机后跑 `ssh -o BatchMode=yes nmz01 hostname`，
# 能直接打印 hostname、不弹密码/口令提示，才说明这里能正常工作。

# hop + 容器：命令在 nmz01 的 docker 容器里执行；段名是 MCP 里的节点名（也要加进 allowed）
[host.nmz01-ctr]
via            = "hop"
node           = "nmz01"            # 选填：跳板机实际 ssh 的目标；省略则等于段名
user           = "<远端用户名>"      # 跳板机 ssh 到 node 的 -l（不是容器内用户）
container      = "<容器名>"
container_user = "root"             # 选填：docker exec -u
default_cwd    = "/workspace/proj"  # 容器内路径

# 直连 + 密钥（或证书）
[host.lab3]
via         = "direct"
address     = "192.168.10.23"
port        = 22
user        = "<远端用户名>"
auth        = "key"
key         = "C:/Users/<本机用户名>/.ssh/id_ed25519"
cert        = ""
default_cwd = "<远端家目录>"

# 直连 + 密码
[host.lab4]
via         = "direct"
address     = "192.168.10.24"
user        = "<远端用户名>"
auth        = "password"
password    = ""          # 留空 = 启动时提示输入
default_cwd = "<远端家目录>"
```

- 所有节点都是直连时，删掉整个 `[bastion]` 段，启动时就不会连跳板机、不会要 TOTP。但只要有一个 hop 节点，`[bastion]` 就是必需的。
- hop 节点不能用 `get_target` 那条直连路径，但 `exec`/`read_file`/`write_file`/`edit_file`/`grep`/`glob_files` 这几个工具对它的用法和 bastion 节点完全一样。
- hop 容器节点（配了 `container`）：命令被包成 `docker exec -i [-u <容器用户>] <容器名> bash -c ...` 在容器里跑，`default_cwd` 和所有路径都是容器内路径。使用要点：
  - 每次 `exec` 都是新 shell，`cd` 不会保留；用 `default_cwd` 或 `cwd` 参数指定目录。
  - 起长时间服务用 `setsid nohup <命令> > <日志> 2>&1 < /dev/null &`（日志写在工作目录里）；不要用 `docker exec -d`，包装本身已经是一层 docker exec。
  - `exec` 超时只会杀跳板机上的 ssh/docker 客户端，容器里已起的前台进程不一定被杀。
  - 容器不存在/没运行时，docker 的错误（`No such container` / `is not running`，退出码 125/126/127）会作为普通命令失败返回，不会重试；容器里需要 `bash`、`stat`、`readlink`、`base64`、`timeout`。
  - 容器属于某一台节点：`node` 必须填容器所在的那台，`docker ps -a` 要在对应节点上查（先对宿主机节点 `exec` 一次 `docker ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}'` 确认）。已退出的容器不能 `docker exec`，需用户自己 `docker start`，不要替用户启动。`container` 优先填容器名，ID 在重建后会变。
- 跳板机本身不能配成 hop 节点：hop 是让跳板机再 `ssh` 一跳，而跳板机通常只接受密码/验证码，不接受密钥，BatchMode 下会失败。需要在跳板机上执行命令时目前没有对应路由，不要用 `ssh localhost` 凑。
- 新加的节点记得同时加进 `[hosts] allowed`。
- 用密钥登录的机器（跳板机、目标机、direct+key 节点）都要把本机公钥追加到对方登录账号的 `~/.ssh/authorized_keys`（即 `<远端家目录>/.ssh/authorized_keys`），并设置 `chmod 700 ~/.ssh`、`chmod 600 ~/.ssh/authorized_keys`。

填完校验语法（不会打印内容）：

```powershell
uv run python -c "import tomllib; c=tomllib.load(open('config.toml','rb')); print('hosts:', sorted(c.get('host',{})))"
```

## 3. 启动 daemon（由用户执行）

请用户在**独立的 PowerShell 窗口**运行，并保持窗口常开：

```powershell
cd <REPO>
uv run daemon.py
```

启动顺序：

1. 校验配置，有错直接退出并列出问题。
2. 对 `password` 留空的密码节点提示 `[lab4] password:`（不回显，最多试 3 次）；配置文件里写的密码只试 1 次，错了跳过该节点。网络不通只警告，不阻塞启动。
3. 有 `[bastion]` 时连跳板机，提示输入 TOTP。
4. 出现 `remote-mcp listening on http://127.0.0.1:8765/mcp` 即就绪。

之后调用 `reset_connections` 或跳板机断线，下一次工具调用会在**这个窗口**再次要求 TOTP，并一直阻塞到输入为止。

## 4. 接入客户端

Claude Code（用户级，所有项目可用）：

```powershell
claude mcp list                     # 先看是否已添加
claude mcp add --transport http --scope user remote-linux http://127.0.0.1:8765/mcp
```

Codex：在 `~/.codex/config.toml` 加入

```toml
[mcp_servers.remote-linux]
url = "http://127.0.0.1:8765/mcp"
```

若 Codex 版本不支持 `url`，改用 stdio 桥：

```toml
[mcp_servers.remote-linux]
command = "npx"
args    = ["-y", "mcp-remote", "http://127.0.0.1:8765/mcp"]
```

改了端口要同步更新这两处的 URL。已在运行的会话看不到新加的工具，需要新开会话。

## 5. 验证

在新会话里依次调用：

1. `list_hosts()`：跳板机 `connected`，每个节点显示路由（`bastion` / `direct 地址:端口` / `hop via bastion`）、认证方式和连接状态。
2. `exec(host="dev1", command="pwd")`：应返回该节点配置的 `default_cwd`（即 `<远端家目录>`）。
3. `read_file(host="dev1", path="<一个已知存在的文件>")`：能读到带行号的内容。

## 6. 工具速查

所有 `path`/`cwd`/`base` 的相对路径都以该节点的 `default_cwd` 为基准；支持 `~` 和 `~/...`（SFTP 类工具不支持 `~其他用户`）。

| 工具 | 参数 | 说明 |
|---|---|---|
| `list_hosts` | 无 | 跳板机状态、白名单、各节点路由/认证/连接状态（不含密码） |
| `exec` | `host, command, cwd="", timeout=60` | 执行 shell 命令；超时后远端进程会被杀掉 |
| `read_file` | `host, path, offset=1, limit=2000` | 带行号读文件 |
| `write_file` | `host, path, content` | 原子覆盖写入，保留原权限，跟随软链接（SFTP 节点走 SFTP，hop 节点经跳板机命令实现，对外行为一致） |
| `edit_file` | `host, path, old_str, new_str, replace_all=False` | 精确字符串替换；多处匹配需 `replace_all=True` |
| `grep` | `host, pattern, path=".", glob="", context=0` | 优先用 rg，否则 `grep -rnE` |
| `glob_files` | `host, pattern, base="."` | `**` 匹配任意层目录，最多返回 200 条 |
| `reset_connections` | 无 | 断开所有连接，下次调用重连（跳板机会重新要 TOTP） |

## 7. 排障

| 现象 | 处理 |
|---|---|
| `claude mcp list` 显示连接失败 | daemon 没启动或端口不一致；看 daemon 窗口 |
| 工具调用一直卡住 | daemon 窗口在等 TOTP / 密码输入，让用户切过去输入 |
| 启动时报 `config.toml not found` | 从 `config.example.toml` 复制一份 |
| 启动时报 `config error: ...` | 按提示补 `address` 或改正 `auth` |
| `not in the allowed list` | 把节点加进 `[hosts] allowed` |
| `ConfigError: no [bastion] section` | 该节点走跳板机但没配 `[bastion]`；补上，或改成 `via = "direct"`。hop 节点同理——没配 `[bastion]` 时写 `via = "hop"` 是启动致命错误 |
| hop 节点报 `ssh to <节点> on the bastion failed: ...` | 跳板机上 `ssh <节点名>` 本身失败（对应 ssh 退出码 255），daemon 不重试。登录跳板机手动跑 `ssh -o BatchMode=yes <节点名> hostname` 复现：常见是跳板机缺该机器的私钥、目标机 `authorized_keys` 没加跳板机公钥、host key 变了，或 `user`/`port` 与跳板机 `~/.ssh/config` 不一致 |
| 在跳板机上手动 `ssh -o BatchMode=yes <节点名> hostname` 报 `Host key verification failed` | 只是 known_hosts 里没有该主机；改用 `-o StrictHostKeyChecking=accept-new` 跑一次记住即可，之后才能看到真正的认证结果 |
| 在跳板机上手动 ssh 报 `Permission denied (gssapi...,password,keyboard-interactive)`，列表里没有 `publickey` | 该主机不接受密钥登录，hop 路由走不通（跳板机自己就是这种情况） |
| 容器节点报 `No such container: <名>` | 容器不在 `node` 指向的这台机器上，或已重建换了 ID；对宿主机节点跑 `docker ps -a` 核对，改 `container`/`node` 后重启 daemon |
| `PermissionDenied` | 密钥没加进对方 `authorized_keys`、权限不对，或密码错误；认证失败不会重试，改好后 `reset_connections` 或重启 daemon |
| 连接超时 | `Test-NetConnection <地址> -Port <端口>` 检查可达性，必要时调大 `connect_timeout` |
| 端口被占用 | 改 `[daemon] port`，同步更新客户端 URL |

更多情况见 `<REPO>\DEPLOY.md` 第 8 节。
