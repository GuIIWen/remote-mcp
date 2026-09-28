# remote-mcp TODO

## 支持多个并列跳板机

现在只有一台跳板机。以后可能会加几台并列的，每台目标机固定走其中一台。串联和冗余不做，已确认只有并列这一种场景。

改动点：

- **config**：允许配置多个 `[bastion.<name>]`，目标机用 `[host.<name>] via = "<bastion>"` 指定走哪台。
- **pool**：`_bastion_conn` 改成 `dict[name, conn]`，每台跳板机一把锁。某台跳板机断开时，只清理经它连出去的目标机连接。
- **daemon**：启动时逐台连接跳板机，TOTP 提示里带上跳板机名字，比如 `[bastion-b] Verification code:`。
- **list_hosts**：显示每台跳板机的连接状态，以及每台目标机走的是哪台跳板机。
