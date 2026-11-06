# PR #2 审查记录：认证重试与 GUI 生命周期

本文记录 PR #2（`feat/gui-app-multi-bastion`）在本地审查中发现的三个行为级问题及修复结果。审查基线为 `main@1e83473`，被审查的 PR 提交为 `9ec7b95`，修复提交为 `873fcff`。

## 结论

初始 PR 的 118 项单元测试、Python 编译检查和 `git diff --check` 均通过，但测试没有覆盖“启动登录失败后批量连接”和“GUI 停止后再次启动”这两条跨组件流程，因此发现了本文记录的问题。修复提交新增跨组件回归测试，当前全量测试为 138 项。

## 问题一：跳板机认证失败会被每个节点重复触发

**风险：高。**

### 现象

`daemon.serve()` 先逐台调用 `_login_bastion()`。即使某台跳板机登录失败，后续仍会无条件调用 `pool.connect_in_background()`，对所有配置节点执行 eager connect。节点连接进入 `_get_target()` 后，又会调用 `_ensure_bastion()`，再次尝试登录同一台跳板机。

因此，一次启动失败会被放大成“每个节点一次”的认证尝试。对于密码、TOTP、MFA 或有 `MaxAuthTries` 的 SSH 服务，这可能导致重复弹窗、账号锁定或验证码失效。

相关路径：

- `daemon.py:195`：启动全量 eager connect
- `pool.py:792`：`_ensure_bastion()` 负责重新登录
- `pool.py:1270`：`connect_nodes()` 对每个节点执行探测

### 复现证据

在模拟 `_connect_bastion()` 始终返回 `PermissionDenied`、配置 3 个经同一跳板机路由的节点时，eager connect 会触发 3 次额外的跳板机连接尝试。

### 建议方案

1. 让启动登录结果成为本次 eager connect 的输入。对登录失败的 bastion 标记 `unavailable`，只记录一次失败原因。
2. `connect_nodes()` 在处理节点前检查所属 bastion；如果该 bastion 不可用，直接记录“依赖的跳板机未登录”，不要调用 `_ensure_bastion()`。
3. 只有显式的“重新连接节点”、`reset_connections` 后的用户调用，或后续明确需要该节点的工具调用，才允许重新触发跳板机认证。
4. 对同一 bastion 增加一次性并发闸门：同一时间最多存在一个登录任务，其他节点等待该任务结果，不各自创建新的登录尝试。

### 验收标准

- 一个 bastion 登录失败、配置 N 个节点时，启动阶段只产生 1 次登录尝试。
- 节点状态显示“依赖的 bastion 未登录”，而不是 N 条相同的认证失败。
- 用户显式重试时，最多按重试策略产生新的登录尝试。

## 问题二：配置密码失败后，直连节点仍会被再次尝试

**风险：高。**

### 现象

`daemon._prepare_password_hosts()` 对配置文件中的 `auth = "password"` 密码只尝试一次；认证失败后打印“跳过该节点”。但失败密码仍保留在 `pool._passwords` 中，随后 `daemon.serve()` 继续启动全量 eager connect，`connect_nodes()` 又会对该节点调用 `probe()`，从而再次使用同一个错误密码。

相关路径：

- `daemon.py:59`：把配置密码放进 `_passwords`
- `daemon.py:69`：配置密码被拒绝后跳过预连接
- `daemon.py:195`：仍然启动全量 eager connect
- `pool.py:1263`：只要 `_passwords` 非空，节点就不会被跳过

### 复现证据

用错误配置密码模拟 `PermissionDenied`，`_prepare_password_hosts()` 后再执行 `connect_nodes([host])`，同一节点的连接调用次数为 2。

### 建议方案

1. 为节点保存启动阶段的认证结果，例如 `_auth_blocked[host] = "configured password rejected"`，或者在失败时移除 `_passwords[host]` 并保留不可重试状态。
2. `connect_nodes()`、`probe()` 和普通懒连接在发现该状态时直接返回失败，直到用户修改配置、重启服务或显式执行“重新连接节点”。
3. 配置密码失败时不要把错误密码继续作为后续连接凭据；显式重试前也不要自动重试。
4. 若用户在 GUI 中改了密码，`apply_config()` 应清除该节点的阻断状态，并允许新的密码进行一次新的连接尝试。

### 验收标准

- 配置密码被拒绝后，启动阶段对该节点只有 1 次认证尝试。
- 节点状态清楚显示“配置密码被拒绝”，而不是泛化为“尚未连接”。
- 修改密码或显式重连后，阻断状态被清除，新密码只按正常策略尝试。

## 问题三：GUI 停止/重启可能复用旧密码，且关闭时可能卡住

**风险：中。**

### 现象 A：旧密码残留

GUI 启动服务时会把非空的 bastion 密码写入 `pool._passwords`。停止服务时，`app.py` 只清理连接、锁和 semaphore，没有清理 `_passwords`。再次启动时，如果新配置把密码改空或改成别的值，`daemon.init_service()` 不会覆盖旧的内存值，后续认证可能继续使用上一次运行的密码。

相关路径：

- `app.py:286-292`：重置连接对象，但未清理 `_passwords`
- `daemon.py:153`：只写入非空配置密码
- `pool.py:639`：认证回调从 `_passwords` 读取密码

### 现象 B：关闭窗口可能阻塞 Tk 主线程

`stop()` 为 5 秒后设置 `server.force_exit = True`，但 `on_close()` 随后在 Tk 主线程中调用 `thread.join(timeout=5)`。如果主线程阻塞，Tk 的 `after()` 回调无法及时运行，强制退出回调可能被延迟，导致窗口关闭卡住。

相关路径：

- `app.py:318-331`：停止服务和定时强制退出
- `app.py:441-447`：关闭窗口时同步 `join`

### 建议方案

1. 每次服务启动前清空本次运行的认证缓存，至少清理 `_passwords`、认证阻断状态和 prompt cooldown；然后只从当前配置重新填充密码。
2. 更稳妥的做法是给每次服务运行建立独立的 `RuntimeState`，停止时整体丢弃，不让下一次运行复用上一轮的认证状态。
3. `on_close()` 不要同步等待线程。设置停止状态后，用 `root.after(100, poll_thread)` 轮询线程是否结束；超时后提示用户或继续执行最终清理，让 Tk 主循环保持可运行。
4. `stop()` 应保存并取消启动阶段的任务（密码预连接、bastion 登录、eager connect），并统一调用 `pool.reset_all()`，避免连接回调在下一次运行中落回旧状态。

### 验收标准

- 修改配置密码后停止并重新启动，第一次认证只使用新配置或重新弹窗输入，不使用旧密码。
- 连续执行“启动 → 停止 → 启动”不会出现旧连接、旧 prompt 或旧密码影响新运行。
- 关闭 GUI 时 Tk 窗口保持响应，服务线程在正常情况下退出；强制退出由 Tk 定时回调实际执行。

## 推荐修复顺序

1. 先增加认证状态模型：区分“未连接”“依赖 bastion 不可用”“凭据被拒绝”“等待用户输入”。
2. 用该状态阻止启动阶段的重复认证，修复问题一和问题二。
3. 把认证缓存和后台任务纳入一次服务运行的生命周期，修复问题三。
4. 增加跨组件回归测试：启动失败 + 多节点、错误配置密码 + eager connect、GUI stop/start 和关闭超时。

## 修复状态

三个问题均已修复，新增 20 个测试（`tests/test_pool.py::AuthFailureOnceTests`、`tests/test_daemon.py`、`tests/test_app.py`），全量 138 项通过。

| 问题 | 做法 |
|---|---|
| 一 | `pool._bastion_failed`：`_ensure_bastion()` 登录失败时记录、成功时清除；`connect_nodes()` 跳过所属跳板机登录失败的节点（只记一行日志），直连节点不受影响。工具调用仍可重试登录。 |
| 二 | `pool._auth_blocked`：配置密码被拒（或手输密码用尽次数）后记录原因；`_get_target()` 直接抛 `PermissionDenied`，eager connect、`probe()` 和懒连接都不再重放该密码，状态面板显示原因。 |
| 三 A | `init_service()` 在写入配置密码前清空 `_passwords`。 |
| 三 B | `on_close()` 改为 `root.after(100)` 轮询（上限 8 秒），不再在 Tk 主线程 `join`；`closing` 标志防止重复点击。 |
| 三 4 | `serve()` 的 `try/finally` 从启动登录阶段就开始，启动中被取消也会 `reset_all()`；`finally` 取消 `_bg_tasks` 与心跳。 |

阻断状态在 `reconnect_all()`、`reset_all()`（含 `reset_connections` 工具与服务停止）和 `apply_config()`（节点被改动或删除）时清除。`reconnect_all()` 对被拒绝的手输密码会重新弹窗询问（取消则该节点等待密码，不重放旧值）；被拒绝的 `config.toml` 密码保留，显式重连时再试一次。`reset_all()` 不询问，保留密码。

未做：问题一的“单 bastion 登录结果共享”闸门（`_bastion_lock` 已保证同一时刻只有一个登录，启动阶段的重复已由 `_bastion_failed` 消除；并发的工具调用各自重试仍是显式需求）；问题三的 `RuntimeState` 整体重构（用“启动时清缓存 + 停止时 `reset_all`”达到同样效果）。
