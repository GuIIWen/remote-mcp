# DCU 节点连接池 MCP 工具（remote-linux MCP）


## 背景
为 Claude Code、Codex 等 Agent 提供一个连接池，把 tool call 转发到多个计算节点或客户节点执行，并把远端输出返回给 Agent，用来提高定位、部署的效率，省去每次在远端安装工具、配置环境的时间。


## 工具介绍

本机常驻一个 Daemon（Python + asyncssh + FastMCP），Agent 通过 MCP 协议（`http://127.0.0.1:8765/mcp`）连接到它。Agent 不接触登录信息；命令由 Daemon 转发到节点执行，不需要在远端安装任何插件或做额外配置，只用 Linux 自带命令，宿主机和容器内都可以操作。

可以在多个节点上同时做环境信息对比、巡检、日志和代码对比、多机部署等。

```
Agent (CC / Codex)
      │  MCP / HTTP  127.0.0.1:8765
      ▼
  Daemon (连接池) ──┬── 跳板机 ──┬── bastion：隧道到节点（本机私钥）
                    │            └── hop：跳板机代跑 ssh（宿主机或 docker 容器）
                    └── direct：本机直连节点
```

### 三种连接方式（`via`）

| via | 适用 | 说明 |
|---|---|---|
| `bastion`（默认） | 本机有私钥，经跳板机访问的节点 | 经跳板机开隧道，用本机私钥以 `用户名@节点名` 登录；节点名由跳板机解析 |
| `hop` | 只有跳板机能登录的节点（私钥在跳板机上） | 由跳板机执行 `ssh <node>`；可用 `node` 指定 IP 或主机名，用 `port`、`user` 指定端口和用户；加 `container` 可进入已有容器（`docker exec`） |
| `direct` | 本机能直接访问的节点 | 直连 `address:port`，密钥、证书或密码登录，不经过跳板机 |

当前只支持一台跳板机，不支持多台并列。

### 工具

| 工具 | 作用 |
|---|---|
| `list_hosts` | 查看跳板机状态、白名单，以及各节点的路由、认证方式和连接状态 |
| `exec` | 执行 shell 命令，默认 60 秒超时（`timeout` 参数可调） |
| `read_file` / `write_file` / `edit_file` | 带行号读取、原子写入、精确替换 |
| `grep` / `glob_files` | 搜索内容、匹配文件 |
| `reload_config` | 热加载 `config.toml` 中的节点和白名单，不用重启 |
| `reset_connections` | 关闭所有连接，下次调用时重建 |

相对路径都以节点的 `default_cwd` 为基准。每次 `exec` 是新 shell，`cd` 不保留。

## 使用说明

### 工具安装

获取代码：

```shell
git clone https://github.com/GuIIWen/remote-mcp.git
```

需要 Python 3.11 及以上，推荐用 [uv](https://docs.astral.sh/uv/)：

```shell
cd <REMOTE_MCP_DIR>        # 本机存放项目文件的目录
uv venv --python 3.11      # 创建虚拟环境（.venv）
uv pip install -r requirements.txt
```

### 修改配置

复制 `config.example.toml` 为 `config.toml`（已加入 `.gitignore`，不会被提交），再修改跳板机和节点信息：

```toml
# 跳板机：host / port / user 必须有，key 可留空（自动读取 ~/.ssh/id_*）
# 全部节点都是 direct 时可以整段省略
[bastion]
host = "bastion.example.com"
port = 22
user = "yourname"
key  = ""
# password = ""            # 可选：自动回答跳板机的密码提示，验证码仍在终端输入

# 监听端口及审计日志，audit_log 留空则不记录
[daemon]
port      = 8765
audit_log = "D:/tools/remote-mcp/audit.jsonl"

# 允许 Agent 访问的节点白名单。匹配的是下面 [host.xxx] 的节点名（不是 IP），支持通配符
[hosts]
allowed = ["dev1", "nmz01", "hop01", "hop01-ctr", "lab1"]

[host.dev1]               # bastion：经跳板机隧道，用本机私钥以 用户名@dev1 登录
via         = "bastion"   # 省略时默认就是 bastion
user        = "<远端用户名>"
default_cwd = "<远端家目录>"

[host.nmz01]              # hop：私钥只在跳板机上，由跳板机代跑 ssh
via         = "hop"
user        = "<远端用户名>"
default_cwd = "<远端家目录>"

[host.hop01]              # hop，用内网 IP 和端口指定目标
via         = "hop"
node        = "10.0.1.63" # 跳板机实际 ssh 的目标，可以是内网 IP 或主机名
port        = 22          # 选填：跳板机 ssh 到该机器用的 -p
user        = "user"      # 选填：-l
default_cwd = "/workspace"

[host.hop01-ctr]          # hop + 容器：用 docker exec 在已有容器里执行
via            = "hop"
node           = "hop01"  # 容器所在的节点（跳板机 ssh 的目标）
user           = "user"   # 跳板机 ssh 到 node 用的用户（不是容器内用户）
container      = "container-name"
container_user = "root"   # 选填：docker exec -u
default_cwd    = "/workspace"  # 容器内路径

[host.lab1]               # direct：本机直连
via         = "direct"
address     = "192.168.10.23"
port        = 2222
user        = "<远端用户名>"
auth        = "key"       # key | password
default_cwd = "<远端家目录>"
```

`default_cwd` 因集群而异，不一定是 `/home/<用户名>`（有的是 `/public/home/<用户名>`），先在远端执行 `echo $HOME` 确认。完整字段说明见 `config.example.toml` 里的注释。

### 启动服务

`daemon.py` 默认读取同级目录下的 `config.toml`。在工具目录中启动，并在**这个窗口**里输入跳板机的验证码；如果没有配置免密登录，还需要在这里输入跳板机密码：

```shell
cd <REMOTE_MCP_DIR>
uv run daemon.py
```

> **这个窗口要一直保持在前台、可以输入。** 跳板机断线重连（或调用 `reset_connections`）时会在这里再次要求输入，在此之前所有工具调用都会等待。

### mcp 安装

Claude Code：

```shell
claude mcp add --transport http --scope user remote-linux http://127.0.0.1:8765/mcp
```

Codex：

```shell
codex mcp add remote-linux --url http://127.0.0.1:8765/mcp
```

装好后新开会话，让 Agent 调用一次 `list_hosts`，跳板机显示 `connected` 就说明接通了。其他支持 MCP 的 Agent 同理，填同一个地址即可。

### skill 安装

将 skill 复制到对应工具的 skill 目录下，重启 Agent 即可。在项目目录下执行：

```powershell
# Claude Code 用户级
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse -Force .claude\skills\remote-linux-mcp "$env:USERPROFILE\.claude\skills\"

# Codex 用户级
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force .claude\skills\remote-linux-mcp "$env:USERPROFILE\.agents\skills\"
```

### 免密登录

多个节点需要配置免密登录时，用仓库里的 `setup_ssh_keys.py` 和 `nodes.example.yaml`：复制为 `nodes.yaml`、填写后运行：

```shell
uv run setup_ssh_keys.py nodes.yaml
```

```yaml
# nodes 中没有写的项会使用 defaults 里的值，同一个集群只需要填 ip
defaults:
  port: 22
  user: yourname
  # password: "shared-password"

nodes:
  lab1:
    ip: 192.168.10.21
  lab2:
    ip: 192.168.10.22
    password: "lab2-password"
  lab3:
    ip: 192.168.10.23
    port: 2222
    user: root
```

该脚本不经过跳板机，只适用于本机能直连、且目前可以用密码登录的机器（`via = "direct"`）。`nodes.yaml` 里是明文密码，已加入 `.gitignore`，配完后建议删掉。

## 配置热更

运行中改了 `config.toml`，让 Agent 调用 `reload_config` 即可生效，不需要重启：

- `[host.*]` 和 `[hosts]` 的新增、删除、修改（包括改 `via`）都会热更，变化的节点会重建连接，跳板机连接不受影响，也不会再要验证码。
- 修改 `[bastion]`、`[daemon]`，或新增需要交互输入密码的直连节点（`auth = "password"` 且 `password` 留空），需要重启 Daemon。

## 注意事项

- 单次命令默认 60 秒超时。耗时较长的任务（编译、训练）请用 `nohup` 或 `setsid` 放到后台，再用 `tail` 查日志。
- 空闲一段时间后又要求输入验证码，是跳板机断开了连接。Daemon 窗口会打印原因提示（`hint:`）。
- 容器模式下，超时只会结束跳板机上的 ssh / docker 客户端，容器里已启动的进程不一定被结束。
- 目前没有命令黑名单，Daemon 也只监听 `127.0.0.1`，没有鉴权。请只把需要的节点放进 `[hosts] allowed`，重要机器谨慎授权。
- 密码只保存在进程内存中，不会出现在审计日志、错误信息和 `list_hosts` 的输出里。`config.toml` 里的明文密码请不要提交到仓库。

## 文档与测试

| 文件 | 内容 |
|---|---|
| `config.example.toml` | 配置模板，每个字段都有注释 |
| `remote-mcp-design.html` | 设计文档 |
| `.claude/skills/remote-linux-mcp/` | 安装与使用 Skill |
| `tests/` | 单元测试（`test_pool.py`、`test_daemon.py`、`test_tools.py`），不连真实 SSH |

在项目根目录运行单元测试：

```shell
python -m unittest discover            # 全部
python -m unittest tests.test_pool -v  # 单个文件
```
