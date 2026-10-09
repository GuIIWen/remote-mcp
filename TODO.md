# remote-mcp TODO

## 支持多个并列跳板机

现在只有一台跳板机。以后可能会加几台并列的，每台目标机固定走其中一台。串联和冗余不做，已确认只有并列这一种场景。

改动点：

- **config**：允许配置多个 `[bastion.<name>]`，目标机用 `[host.<name>] via = "<bastion>"` 指定走哪台。
- **pool**：`_bastion_conn` 改成 `dict[name, conn]`，每台跳板机一把锁。某台跳板机断开时，只清理经它连出去的目标机连接。
- **daemon**：启动时逐台连接跳板机，TOTP 提示里带上跳板机名字，比如 `[bastion-b] Verification code:`。
- **list_hosts**：显示每台跳板机的连接状态，以及每台目标机走的是哪台跳板机。

## 局域网访问：可配置监听地址 + 访问密钥

现在监听地址在 `daemon.py` 里写死为 `127.0.0.1`，且没有任何认证：谁能连上端口，谁就能通过 daemon 在白名单节点上执行命令、读写文件。要让局域网里的其它机器访问，必须先有鉴权，再开放监听。

- **监听地址**：新增 `[daemon] host`，默认 `"127.0.0.1"`，可显式写 `"0.0.0.0"`（或某块网卡的 IP）。不配等于现状，不改变默认安全性。
- **访问密钥**：新增 `[daemon] api_key`（留空表示不校验）。配了之后，所有 `/mcp` 请求必须带 `Authorization: Bearer <key>`，否则返回 401；比较用 `hmac.compare_digest`，密钥不写入日志和审计。
- **强制关联**：`host` 不是回环地址（`127.0.0.1` / `::1` / `localhost`）而 `api_key` 为空时，启动直接报错退出，避免无意中把无认证的服务暴露到局域网。
- **启动输出**：打印实际监听地址；绑非回环地址时额外提示一行“已开放局域网访问，key 已启用”，但不回显 key。
- **热更**：`host`、`port`、`api_key` 都在 `[daemon]` 段，`reload_config` 不应用，仍需重启（和现有 `[daemon]` 规则一致）。
- **客户端接入**：Claude Code 用 `claude mcp add --transport http --header "Authorization: Bearer <key>" ...`；Codex 用 `bearer_token_env_var` 或 headers 配置，key 放环境变量，不写进命令行历史。文档和 skill 里补充这两种写法，示例用 `<密钥>` 占位。
- **明文传输**：HTTP 在局域网上是明文，key 和命令内容都能被抓包。先接受这一限制并写进文档风险节；需要时再加 TLS，或建议走 SSH 隧道。
- **测试**：无 key / 错 key / 对 key 三种请求的状态码；非回环绑定且无 key 时启动失败；默认配置下行为与现状完全一致。
