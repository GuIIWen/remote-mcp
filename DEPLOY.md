# 部署指南

方案是"架构 A"：`daemon.py` 常驻在你的 Windows 本机上，跳板机和内网目标 Linux 机器上**不需要安装任何东西**，你的 SSH 私钥也始终留在本机，不会上传到跳板机或目标机。

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

```toml
[bastion]
host = "bastion.example.com"   # 跳板机地址，换成你实际的跳板机域名/IP
port = 22
user = "songjiajun"            # 你在跳板机上的登录用户名
key  = ""                      # 私钥路径；留空则用默认密钥对 (~/.ssh/id_*)

[daemon]
port            = 8765         # daemon 监听的本地端口，仅 127.0.0.1
audit_log       = ""           # 留空不记录；填绝对路径（如 "D:/tools/remote-mcp/audit.jsonl"）则写 JSONL 审计日志
connect_timeout = 20           # 跳板机 / 目标机建连超时（秒），超时不重试，直接报错

[hosts]
allowed = ["dev1"]             # 允许访问的目标机白名单，支持 fnmatch 通配符（如 "10.0.*"）；留空表示不限制

[host.dev1]
user        = "songjiajun"
default_cwd = "/public/home/songjiajun"   # exec/read_file/grep/glob_files/write_file/edit_file 的默认工作目录
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

**注意**：这套环境里远端家目录是 `/public/home/songjiajun`，**不是** `/home/songjiajun`——两者路径不同，必须逐字照抄成 `/public/home/songjiajun`，写错会导致所有相对路径解析到不存在的目录。

## 4. 密钥部署

daemon 用同一对本机私钥分别认证跳板机和目标机（目标机认证是通过 `tunnel=` 直接在跳板机连接上打隧道完成的，跳板机本身不会经手你的私钥，也不需要开 agent forwarding）。你需要：

1. 确认本机有一对可用的密钥（没有就 `ssh-keygen -t ed25519` 生成一对）。
2. 把**公钥**内容分别追加到跳板机和目标机的 `authorized_keys`：
   - 跳板机：`/public/home/songjiajun/.ssh/authorized_keys`
   - 目标机（每台要访问的目标机都要做一遍）：`/public/home/songjiajun/.ssh/authorized_keys`（目标机的家目录同样是 `/public/home/songjiajun`）
3. 权限要求（sshd 对权限过松的文件会直接拒绝，即使公钥内容正确）：
   ```bash
   chmod 700 /public/home/songjiajun/.ssh
   chmod 600 /public/home/songjiajun/.ssh/authorized_keys
   ```
4. 私钥**只放在本机**，不上传、不复制到跳板机或目标机。

跳板机额外要求开启 TOTP（keyboard-interactive）登录——这个通常是跳板机侧已有的策略，本文档不涉及配置它，只是 daemon 在连接时会走这个交互流程。

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

1. **`list_hosts`**：确认跳板机状态是 `connected`，`configured hosts` 里能看到 `dev1`。
2. **`exec(host="dev1", command="pwd")`**：预期返回 `/public/home/songjiajun`（即 `default_cwd`，因为没传 `cwd` 参数时 `exec` 会先 `cd` 进 `default_cwd` 再执行命令）。
3. **`read_file(host="dev1", path="一个已知存在的文件")`**：确认能读到内容，行号格式正确。
4. 如果要验证路径解析的一致性，可以试 `exec(host="dev1", command="ls some_dir")` 之后再 `read_file(host="dev1", path="some_dir/some_file")`——两者应该指向同一个文件。

## 8. 排障

| 现象 | 可能原因 / 处理 |
|---|---|
| 启动后 daemon 窗口没有 TOTP 提示，卡住不动 | 检查 `config.toml` 里 `bastion.host`/`port`/`user` 是否正确；也可能是网络不通，等到 `connect_timeout` 秒后会报错退出，而不是一直卡着——如果一直卡着超过这个时间还没反应，说明连接本身没有建立（比如端口被防火墙拦截），检查网络连通性 |
| 连接超时（`connect_timeout` 报错） | 检查跳板机地址/端口是否可达（`Test-NetConnection <host> -Port 22`）；如果跳板机本身响应慢，适当调大 `config.toml` 里的 `connect_timeout` |
| 报错提示 `MaxSessions` 相关，或者并发调用工具时偶尔失败 | sshd 默认限制单条连接最多 10 个并发 channel，daemon 对每台目标机限制了 8 个并发（留 2 个余量给 SFTP），如果还是触发，检查是不是有其它进程也在用同一条连接，或联系跳板机管理员确认 `MaxSessions` 配置 |
| 报错 `Host '...' is not in the allowed list` | `config.toml` 的 `[hosts] allowed` 白名单里没有这台机器，按需加上（支持 `fnmatch` 通配符），或者确认没有手滑写错主机名 |
| daemon 启动报端口被占用 | `config.toml` 里的 `daemon.port` 和本机其它程序冲突，改成一个空闲端口，同时同步更新 `claude mcp add` / Codex 里配置的 URL |
| TOTP 输错 / 认证失败 | 直接在 daemon 窗口按 Ctrl+C 退出重新 `uv run daemon.py`；不需要额外清理状态 |

## 9. 远端机器的要求

**跳板机和目标机不需要安装任何组件，也不需要在 `/public/home/songjiajun` 下建立任何服务目录。** 唯一需要的远端改动是第 4 节里的 `authorized_keys` 配置——除此之外，所有逻辑（连接池、超时控制、命令拼接、审计日志）都跑在本机的 daemon 进程里，远端只是被 SSH/SFTP 到的普通目标。

## 10. 多跳板机

暂不支持；如果以后需要接入多台并列跳板机，改动方案见 `TODO.md`。
