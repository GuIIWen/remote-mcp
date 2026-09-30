# 部署指南

方案是"架构 A"：`daemon.py` 常驻在你的 Windows 本机上，跳板机和内网目标 Linux 机器上**不需要安装任何东西**，你自己的 SSH 私钥也始终留在本机，不会上传到跳板机或目标机。

（唯一的例外是 `via = "hop"` 节点：这种节点本来就只有跳板机能免密登录，私钥在跳板机上而不是本机——daemon 不去碰这把私钥，只是让跳板机用它自己已有的 ssh 配置代跑命令，详见第 3、4 节。）

## 1. 本机环境

- Windows 上安装 [uv](https://docs.astral.sh/uv/)（免管理员权限的 Python 包管理器）：

  ```powershell
  irm https://astral.sh/uv/install.ps1 | iex
  ```

- Python 版本要求 **3.10 以上**（推荐 3.11+，因为 3.11 起 `tomllib` 是标准库，不用再装 `tomli`；本项目的超时/断线判定逻辑也依赖 3.11 之后 `TimeoutError` 与 `OSError` 的继承关系）。用 uv 拉一个：

  ```powershell
  uv python install 3.11
  ```

- 在项目目录下建虚拟环境并装依赖：

  ```powershell
  cd <REMOTE_MCP_DIR>
  uv venv --python 3.11
  uv pip install -r requirements.txt
  ```

### pywin32 的坑

`mcp[cli]` 在 Windows 上依赖 `pywin32`。如果用 `pip install --target <dir>` 这种方式装依赖（不经过标准的 venv 安装流程），pywin32 的安装后脚本 `pywin32_postinstall.py` 不会被执行，`pythoncomXX.dll` / `pywintypesXX.dll` 不会被复制到位，运行时会报：

```
ModuleNotFoundError: No module named 'pywintypes'
```

`uv pip install -r requirements.txt` 装进一个真正的 venv 通常不会踩这个坑；如果确实遇到，手动补跑一次安装后脚本即可：

```powershell
& ".venv\Scripts\python.exe" ".venv\Scripts\pywin32_postinstall.py" -install
```

（跑完可能会看到一条"You do not have the permissions to install COM objects"的警告——这是正常的，不影响 daemon 需要的 DLL 注册，可以忽略。）

## 2. 目录

项目文件放在本机任意目录即可，下文用 `<REMOTE_MCP_DIR>` 代表这个路径（例如 `D:\tools\remote-mcp`、`C:\Users\<you>\remote-mcp`，自己选一个稳定不会被误删的位置）。目录下应该有：

```
<REMOTE_MCP_DIR>\
├── config.toml
├── requirements.txt
├── pool.py
├── tools.py
├── daemon.py
└── audit.jsonl        # 首次运行后自动生成（如果配置了 audit_log）
```

## 3. config.toml 填法

把 `config.example.toml` 复制一份改名成 `config.toml`，再按自己的环境填值（`config.example.toml` 里每个字段都有中文注释，`.gitignore` 已经排除了 `config.toml` 本身，放心填真实凭据）：

```powershell
cd <REMOTE_MCP_DIR>
copy config.example.toml config.toml
notepad config.toml
```

`config.toml` 里的节点分三类，用每个 `[host.x]` 段的 `via` 字段区分（省略 `via` 时默认是 `"bastion"`）：

```toml
[bastion]
host = "bastion.example.com"   # 跳板机地址，换成你实际的跳板机域名/IP
port = 22
user = "<跳板机用户名>"            # 你在跳板机上的登录用户名
key  = ""                      # 私钥路径；留空则用默认密钥对 (~/.ssh/id_*)

[daemon]
port            = 8765         # daemon 监听的本地端口，仅 127.0.0.1
audit_log       = ""           # 留空不记录；填绝对路径（如 "D:/tools/remote-mcp/audit.jsonl"）则写 JSONL 审计日志
connect_timeout = 20           # 跳板机 / 目标机建连超时（秒），超时不重试，直接报错

[hosts]
allowed = ["dev1", "lab3", "lab4"]   # 允许访问的目标机白名单，支持 fnmatch 通配符（如 "10.0.*"）；留空表示不限制

# 走跳板机的节点：省略 via，或写 via = "bastion"
[host.dev1]
user        = "<远端用户名>"
default_cwd = "<远端家目录>"   # exec/read_file/grep/glob_files/write_file/edit_file 的默认工作目录
# hop 节点：目标机只有跳板机能免密登录，本机没有它的私钥（比如某些计算节点，私钥一直
# 留在跳板机上）。daemon 不会给这种节点开一条直连的隧道，而是让跳板机自己代跑
# `ssh <节点名> '<命令>'`，即执行的是跳板机上的 ssh，不是本机的。
[host.nmz01]
via         = "hop"
user        = "<远端用户名>"          # 选填：跳板机 ssh 到 nmz01 时用的 -l；留空则用跳板机自己的 ~/.ssh/config
port        = 22                    # 选填：跳板机 ssh 到 nmz01 时用的 -p；留空同上
default_cwd = "<远端家目录>"
# 直连节点（密钥认证）：不经过跳板机，daemon 直接和这台机器的 sshd 建立连接
[host.lab3]
via         = "direct"
address     = "192.168.10.23"                # 必填：这台机器的地址（域名或 IP）
port        = 2222                           # 选填，默认 22
user        = "<远端用户名>"
auth        = "key"                          # "key" 或 "password"
key         = "C:/Users/<本机用户名>/.ssh/lab3_ed25519"  # 留空则回退到 [bastion] key，再回退到默认密钥对
cert        = ""                             # 如果用 OpenSSH 用户证书，填证书路径，和 key 配对使用
default_cwd = "<远端家目录>"

# 直连节点（密码认证）：password 留空则 daemon 启动时用 getpass 提示输入，不会明文写在这里
[host.lab4]
via         = "direct"
address     = "192.168.10.24"
port        = 22
user        = "<远端用户名>"
auth        = "password"
password    = ""                             # 留空 = 启动时交互输入；填了就直接用（仅一次机会，错了不重试）
default_cwd = "<远端家目录>"
```

字段说明：

| 字段 | 含义 |
|---|---|
| `bastion.host`/`port`/`user` | 跳板机地址和你的登录账号 |
| `bastion.key` | 留空则用 `~/.ssh/id_*` 默认密钥对；如果专门为这个 daemon 生成了一对独立的密钥，填这个私钥的绝对路径 |
| `daemon.port` | daemon 的 HTTP 端口，只监听 `127.0.0.1`，不会暴露到局域网 |
| `daemon.connect_timeout` | 建立 SSH 连接（跳板机或目标机）的超时时间；命令执行超时是单独在每次工具调用里指定的，与这个字段无关 |
| `hosts.allowed` | 目标机白名单，防止误操作连到没打算连的机器 |
| `host.<name>.user` | 该目标机上的登录用户名 |
| `host.<name>.default_cwd` | 该目标机的默认工作目录；`exec` 的 `cwd` 参数、`read_file`/`grep`/`glob_files`/`write_file`/`edit_file` 的相对路径参数，都会以这个目录为基准解析 |
| `host.<name>.via` | 省略或 `"bastion"`：通过跳板机连接（原有行为不变）。`"direct"`：daemon 直接连这台机器，不经过跳板机、不占用跳板机连接。`"hop"`：这台机器只有跳板机能免密登录，daemon 没有它的私钥；每次操作都是让跳板机自己执行 `ssh <节点名> '<命令>'`，命令实际跑在跳板机的 ssh 进程里 |
| `host.<name>.address` | **仅 direct 节点需要**：这台机器的地址（域名或 IP）。bastion / hop 路由的节点不需要这个字段（直接用节点名当主机名，交给跳板机或跳板机上的 ssh 解析），如果误填了会在启动时打印警告并忽略 |
| `host.<name>.port` | direct 节点：SSH 端口，默认 22。hop 节点：选填，跳板机 ssh 到目标机时用的 `-p`；留空则由跳板机自己的 `~/.ssh/config` 或 ssh 默认值决定 |
| `host.<name>.auth` | 仅 direct 节点：`"key"`（默认）或 `"password"`。bastion / hop 路由的节点固定用密钥登录（且密钥都不在本机——bastion 路由是跳板机隧道到目标机时用本机私钥，hop 路由是跳板机自己的私钥），不支持这个字段 |
| `host.<name>.key` / `cert` | 仅 direct + `auth="key"`：私钥路径（和可选的 OpenSSH 用户证书路径）。留空时的回退顺序是 `[host.x] key` → `[bastion] key` → 本机默认密钥对（`~/.ssh/id_*`） |
| `host.<name>.password` | 仅 direct + `auth="password"`：留空则 daemon 启动时用 `getpass` 交互提示输入（提示里会带上节点名），不会明文出现在配置文件里；如果填了，daemon 只会用这一份密码尝试一次，认证失败不重试（避免触发远端账号锁定策略），也绝不会出现在日志、错误信息或 `list_hosts` 输出里 |
| `host.<name>.known_hosts` | 选填，direct 节点：一个 `known_hosts` 文件路径，用来校验目标机的 host key。direct 节点不在跳板机后面，建议至少对密码认证的 direct 节点配置这个字段；留空则不校验（等同现在 bastion 路由节点的行为） |

**注意**：`<远端家目录>` 因集群而异，不一定是 `/home/<远端用户名>`（有的集群是 `/public/home/<远端用户名>` 这类形式）。请在远端执行 `echo $HOME` 确认后原样填入 `default_cwd`，写错会导致所有相对路径解析到不存在的目录。

`via = "hop"` 节点如果同时填了 `address`/`password`/`auth`/`key`/`cert`，daemon 启动时会打印警告并忽略这些字段——它们属于"daemon 直接连这台机器"的场景，hop 节点从头到尾都是跳板机在连，本机根本用不上这些字段。没有配置 `[bastion]` 却给某个节点写了 `via = "hop"` 是致命配置错误，daemon 会在启动时直接报错退出。

## 4. 密钥部署

daemon 用同一对本机私钥分别认证跳板机和目标机（目标机认证是通过 `tunnel=` 直接在跳板机连接上打隧道完成的，跳板机本身不会经手你的私钥，也不需要开 agent forwarding）。你需要：

1. 确认本机有一对可用的密钥（没有就 `ssh-keygen -t ed25519` 生成一对）。
2. 把**公钥**内容分别追加到跳板机和目标机的 `authorized_keys`：
   - 跳板机：`<远端家目录>/.ssh/authorized_keys`
   - 目标机（每台要访问的目标机都要做一遍，不管是走跳板机还是直连）：`<远端家目录>/.ssh/authorized_keys`
3. 权限要求（sshd 对权限过松的文件会直接拒绝，即使公钥内容正确）：
   ```bash
   chmod 700 <远端家目录>/.ssh
   chmod 600 <远端家目录>/.ssh/authorized_keys
   ```
4. 私钥**只放在本机**，不上传、不复制到跳板机或目标机。

跳板机额外要求开启 TOTP（keyboard-interactive）登录——这个通常是跳板机侧已有的策略，本文档不涉及配置它，只是 daemon 在连接时会走这个交互流程。

**direct 节点（`via = "direct"`，`auth = "key"`）同样要把公钥放到这台机器自己的 `authorized_keys`，路径同上——`<远端家目录>/.ssh/authorized_keys`（这台机器登录账号自己的家目录）。因为 direct 节点不经过跳板机，这一步是这台机器独立要做的，和跳板机、其它节点的 `authorized_keys` 互不影响。密码认证的 direct 节点（`auth = "password"`）不需要这一步。**

**hop 节点（`via = "hop"`）完全不涉及本机密钥**——本机既没有、也不需要它的私钥。需要的是跳板机自己能免密 `ssh` 到这台机器：私钥放在跳板机上（不是本机），且跳板机上已经把它的公钥加进了这台机器的 `authorized_keys`。这套配置通常是集群内网已经有的（跳板机到计算节点互信），本项目不负责生成或分发这把私钥。部署前建议登录跳板机手动自检一次：

```bash
ssh -o BatchMode=yes nmz01 hostname
```

能直接打印出 `nmz01` 的 hostname、不弹密码或密钥口令提示，才说明 daemon 这边能正常工作；如果这一步本身就卡住或报错，要先在跳板机上把它解决，而不是去改 daemon 的配置。

## 5. 启动 daemon

```powershell
cd <REMOTE_MCP_DIR>
uv run daemon.py
```

daemon 启动时会立即连接跳板机，并在**这个窗口**里提示输入 TOTP 验证码（或密码，取决于跳板机的 keyboard-interactive 挑战内容）。输入一次后，这次进程运行期间不需要再输入，除非：

- 手动调用了 `reset_connections` 工具，或
- 跳板机连接因为网络问题 / 空闲超时被断开，下一次工具调用触发重连时。

以上两种情况都会**再次在 daemon 窗口弹出 TOTP 提示**，而且是阻塞式的——重连协程会一直等在那里，直到有人在这个窗口里输入验证码为止。这意味着：

> **daemon 必须运行在一个你能随时切回去、保持前台可交互的窗口里**（一个独立的 PowerShell 窗口、或者 Windows Terminal 的一个常驻标签页）。不要把它扔进看不到输出、也没法输入的后台任务里，否则一旦触发重连，所有工具调用会一直卡住直到有人发现并去那个窗口输入 TOTP。

**如果配置了 direct + `auth = "password"` 的节点，且对应的 `password` 字段留空，daemon 启动过程中还会额外弹出一次或多次密码提示**（提示文字里带节点名，比如 `[lab4] password:`），同样在这个窗口里输入，输入不回显。这一步和跳板机的 TOTP 提示是独立的、顺序发生的（先处理密码节点，再连跳板机），都发生在同一次 `uv run daemon.py` 启动过程中。如果交互输入的密码连续错误达到 3 次，或者配置文件里写的密码本身就是错的，daemon 会打印一条提示、跳过这台机器，不会阻塞其它节点或跳板机的启动；也不会因为个别 direct 节点一时连不上（网络不通/超时）而卡住启动——这种情况只打印警告，等第一次调用这个节点时再按需重连。

## 6. 接入 Claude Code / Codex

**Claude Code：**

```powershell
claude mcp add --transport http --scope user remote-linux http://127.0.0.1:8765/mcp
```

`--scope user` 让本机所有项目都能直接用这个 MCP server。

**Codex：**

编辑 `~/.codex/config.toml`，加入：

```toml
[mcp_servers.remote-linux]
url = "http://127.0.0.1:8765/mcp"
```

（如果用的是不支持 `url` 字段的旧版 Codex，需要用 `mcp-remote` 做 stdio→HTTP 桥接，具体写法参考设计文档第 8 节。）

## 7. 验证接入

daemon 启动、TOTP 输入完成后，依次验证：

1. **`list_hosts`**：确认跳板机状态是 `connected`，`configured hosts` 里能看到 `dev1`；hop 节点会显示成 `hop via bastion`，连接状态跟着跳板机走（跳板机 `connected` 时它也是 `connected`，不是单独一条连接）。
2. **`exec(host="dev1", command="pwd")`**：预期返回该节点配置的 `default_cwd`（即 `<远端家目录>`，因为没传 `cwd` 参数时 `exec` 会先 `cd` 进 `default_cwd` 再执行命令）。
3. **`read_file(host="dev1", path="一个已知存在的文件")`**：确认能读到内容，行号格式正确。
4. 如果要验证路径解析的一致性，可以试 `exec(host="dev1", command="ls some_dir")` 之后再 `read_file(host="dev1", path="some_dir/some_file")`——两者应该指向同一个文件。
5. 配置了 hop 节点的话，额外用它跑一遍 `exec`/`read_file`/`write_file`/`edit_file`——这几个工具对 hop 节点的外部行为应该和 bastion 节点完全一致，区别只在内部是跳板机代跑 ssh 还是 daemon 自己直连/打隧道。

## 8. 排障

| 现象 | 可能原因 / 处理 |
|---|---|
| 启动后 daemon 窗口没有 TOTP 提示，卡住不动 | 检查 `config.toml` 里 `bastion.host`/`port`/`user` 是否正确；也可能是网络不通，等到 `connect_timeout` 秒后会报错退出，而不是一直卡着——如果一直卡着超过这个时间还没反应，说明连接本身没有建立（比如端口被防火墙拦截），检查网络连通性 |
| 连接超时（`connect_timeout` 报错） | 检查跳板机地址/端口是否可达（`Test-NetConnection <host> -Port 22`）；如果跳板机本身响应慢，适当调大 `config.toml` 里的 `connect_timeout` |
| 报错提示 `MaxSessions` 相关，或者并发调用工具时偶尔失败 | sshd 默认限制单条连接最多 10 个并发 channel，daemon 对每台目标机限制了 8 个并发（留 2 个余量给 SFTP），如果还是触发，检查是不是有其它进程也在用同一条连接，或联系跳板机管理员确认 `MaxSessions` 配置 |
| 报错 `Host '...' is not in the allowed list` | `config.toml` 的 `[hosts] allowed` 白名单里没有这台机器，按需加上（支持 `fnmatch` 通配符），或者确认没有手滑写错主机名 |
| daemon 启动报端口被占用 | `config.toml` 里的 `daemon.port` 和本机其它程序冲突，改成一个空闲端口，同时同步更新 `claude mcp add` / Codex 里配置的 URL |
| TOTP 输错 / 认证失败 | 直接在 daemon 窗口按 Ctrl+C 退出重新 `uv run daemon.py`；不需要额外清理状态 |
| 直连密码错误或被锁 | 交互输入的密码连续错 3 次，或配置文件里 `password` 字段本身就是错的，daemon 会打印提示并跳过这台机器，不阻塞启动；确认密码正确后重新 `uv run daemon.py`，或者手动调用 `reset_connections` 后重试该节点。如果远端账号已经因为多次失败被锁，需要先在目标机上解锁（这不是本工具能处理的） |
| direct 节点连不上 | 先确认 `config.toml` 里这个节点的 `address`/`port` 正确、网络可达（`Test-NetConnection <address> -Port <port>`）；direct 节点不经过跳板机，所以跳板机状态正常不代表 direct 节点能连上。密钥认证失败会报 `PermissionDenied`，检查公钥是否已经放到这台机器的 `authorized_keys`（见第 4 节）；网络不可达或超时只在启动时打印警告，不影响其它节点，下一次调用这个节点时会按需重连并把真正的错误返回 |
| hop 节点报 `ssh to <节点> on the bastion failed: ...`（对应 ssh 退出码 255） | 说明跳板机上的 `ssh <节点名>` 本身失败了，跟 daemon/本机配置无关，daemon 也不会重试这类失败。先登录跳板机手动跑 `ssh -o BatchMode=yes <节点名> hostname` 复现：常见原因是跳板机上没有这台机器的私钥、这台机器的 `authorized_keys` 没加跳板机的公钥、host key 变了，或者 `user`/`port` 填得跟跳板机 `~/.ssh/config` 里的不一致 |
| `ConfigError: [host.x] via="hop" 有 ... 需要 [bastion] 段` | hop 节点必须有 `[bastion]` 配置（所有命令都要经跳板机代跑）；补上 `[bastion]`，或者如果这台机器本机能直连，改成 `via = "direct"` |
| hop 节点并发调用偶尔失败、或报跟 session 数量有关的错误 | 所有 hop 节点共用同一条跳板机连接，daemon 对全部 hop 流量合计限制了 8 个并发 session（留给跳板机自己 sshd `MaxSessions` 一点余量）；如果同时有大量 hop 调用在跑，属于预期的排队等待，不是错误 |

## 9. 远端机器的要求

**跳板机和目标机不需要安装任何组件，也不需要在 `<远端家目录>` 下建立任何服务目录。** 唯一需要的远端改动是第 4 节里的 `authorized_keys` 配置——除此之外，所有逻辑（连接池、超时控制、命令拼接、审计日志）都跑在本机的 daemon 进程里，远端只是被 SSH/SFTP 到的普通目标。

## 10. 多跳板机

暂不支持；如果以后需要接入多台并列跳板机，改动方案见 `TODO.md`。
