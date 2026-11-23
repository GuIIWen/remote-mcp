"""remote-mcp 桌面应用：点按钮启动 / 停止 MCP 连接服务。

和 `python daemon.py` 跑的是同一套服务，区别只是：
  - 用窗口里的“启动 / 停止”按钮控制，不用敲命令；
  - 跳板机的验证码 / 密码提示改成弹窗输入，不再占用终端；
  - 日志显示在窗口里。
只用标准库 tkinter，无需额外依赖。运行：python app.py（或双击 start-app.bat）。
"""
import asyncio
import contextlib
import logging
import queue
import re
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from tkinter import messagebox, scrolledtext, ttk

import httpx
from mcp import ClientSession
from mcp.client import streamable_http

import daemon
import pool
import tools
from config_editor import ACCESS_LABELS, ConfigEditor

# ANSI colour / cursor escapes (uvicorn, rich) show up as garbage in a Tk Text.
_ANSI_RE = re.compile(chr(27) + r"\[[0-9;?]*[ -/]*[@-~]")


class _LogWriter:
    """File-like object that forwards writes to a queue for the Tk thread."""

    def __init__(self, q: queue.Queue):
        self._q = q
        try:
            self._file = open(daemon.CONFIG_PATH.with_name("app.log"), "a", encoding="utf-8")
        except OSError:
            self._file = None

    def write(self, s: str) -> int:
        if s:
            s = _ANSI_RE.sub("", s).replace(chr(13), "")
            if s:
                self._q.put(s)
                if self._file:
                    try:
                        self._file.write(s)
                        self._file.flush()
                    except OSError:
                        pass
        return len(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


class _PromptDialog(tk.Toplevel):
    """Non-blocking input dialog (no nested event loop). on_done(value) gets
    the text, or None if the user cancelled / closed it; dismiss() closes it
    programmatically (e.g. the connection that asked has already given up)."""

    def __init__(self, master, prompt: str, echo: bool, on_done):
        super().__init__(master)
        self._on_done = on_done
        self._finished = False
        self.title("需要输入")
        self.transient(master)
        self.resizable(False, False)
        tk.Label(self, text=prompt.strip() or "请输入", justify="left", wraplength=380,
                 padx=14, pady=10).pack(anchor="w")
        self.var = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.var, show="" if echo else "*", width=40)
        self.entry.pack(padx=14)
        tk.Label(self, fg="gray", padx=14, anchor="w", justify="left",
                 text="取消后 10 分钟内不再为它弹窗；菜单 服务 → 重新连接节点 可立即重试。").pack(fill="x")
        row = tk.Frame(self)
        row.pack(pady=10)
        tk.Button(row, text="确定", width=8, command=self._ok).pack(side="left", padx=6)
        tk.Button(row, text="取消", width=8, command=self._cancel).pack(side="left", padx=6)
        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        # A dialog opened from a background-triggered callback can end up
        # behind other windows; make sure the user can see it.
        self.attributes("-topmost", True)
        self.after(300, lambda: self.winfo_exists() and self.attributes("-topmost", False))
        self.lift()
        self.grab_set()
        self.entry.focus_force()

    def _finish(self, value) -> None:
        if self._finished:
            return
        self._finished = True
        self._on_done(value)
        self.destroy()

    def _ok(self) -> None:
        self._finish(self.var.get())

    def _cancel(self) -> None:
        self._finish(None)

    def dismiss(self) -> None:
        if not self._finished:
            self._finished = True
            self.destroy()


@dataclass(eq=False)
class _AuthRequest:
    bastion: str | None
    prompt: str
    echo: bool
    future: asyncio.Future[str | None]
    done: Callable[[str | None], None]
    dialog: _PromptDialog | None = None

    @property
    def action(self) -> str:
        return "输入密码" if pool.is_password_prompt(self.prompt) else "输入验证码"


def _port_in_use(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


async def _check_mcp_endpoint(url: str) -> tuple[bool, str]:
    """Check the same HTTP transport a client uses, without calling an SSH tool."""
    async with asyncio.timeout(5), contextlib.AsyncExitStack() as stack:
        client = getattr(streamable_http, "streamable_http_client", None)
        if client:
            http = await stack.enter_async_context(httpx.AsyncClient(trust_env=False))
            transport = client(url, http_client=http)
        else:
            transport = streamable_http.streamablehttp_client(url)
        read, write, _ = await stack.enter_async_context(transport)
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        tools = await session.list_tools()
    if not any(tool.name == "list_hosts" for tool in tools.tools):
        return False, "MCP 已响应，但未提供 Remote MCP 的 list_hosts 工具"
    return True, f"握手通过，{len(tools.tools)} 个工具"


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Remote MCP")
        root.geometry("760x520")
        root.protocol("WM_DELETE_WINDOW", self.on_window_close)

        self.log_q: queue.Queue = queue.Queue()
        self.ui_q: queue.Queue = queue.Queue()
        sys.stdout = sys.stderr = _LogWriter(self.log_q)
        # FastMCP installs a rich handler (box drawing, column padding, colours);
        # swap it for a plain one-line-per-record handler writing to the window.
        for h in list(logging.root.handlers):
            logging.root.removeHandler(h)
        plain = logging.StreamHandler(sys.stderr)
        plain.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.root.addHandler(plain)
        logging.getLogger("asyncssh").setLevel(logging.WARNING)

        self.thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server = None
        self.closing = False
        self.port = 8765
        self.service_state = "stopped"
        self.stop_requested = threading.Event()
        self.mcp_check_busy = False
        self.node_operation = None
        self.node_result = None
        self.node_rows = {}
        self.pending_auth = None
        self.recovering_bastion = None
        self.recovery_result = None
        self._recovery_connection = None
        self.tray = None
        self.in_tray = False
        self.activity_items = {}

        # ── 导航栏（菜单） ──
        menubar = tk.Menu(root)
        self.svc_menu = tk.Menu(menubar, tearoff=False)
        self.svc_menu.add_command(label="启动服务", command=self.start)
        self.svc_menu.add_command(label="停止服务", command=self.stop, state="disabled")
        self.svc_menu.add_command(label="重新连接节点", command=self.reconnect_nodes)
        self.svc_menu.add_separator()
        self.svc_menu.add_command(label="退出", command=self.on_close)
        menubar.add_cascade(label="服务", menu=self.svc_menu)

        cfg_menu = tk.Menu(menubar, tearoff=False)
        cfg_menu.add_command(label="配置编辑…", command=self.open_editor)
        menubar.add_cascade(label="配置", menu=cfg_menu)

        self.tool_menu = tk.Menu(menubar, tearoff=False)
        self.tool_menu.add_command(label="检查 MCP 接入", command=self.check_mcp, state="disabled")
        self.tool_menu.add_command(label="复制 MCP 地址", command=self.copy_url, state="disabled")
        self.tool_menu.add_command(label="复制 Claude Code 注册命令", command=self.copy_claude_cmd, state="disabled")
        self.tool_menu.add_command(label="复制 Codex 注册命令", command=self.copy_codex_cmd, state="disabled")
        self.tool_menu.add_separator()
        self.tool_menu.add_command(label="清空日志", command=self.clear_log)
        menubar.add_cascade(label="工具", menu=self.tool_menu)
        root.configure(menu=menubar)

        # ── 状态 + 地址 ──
        top = tk.Frame(root, padx=10, pady=8)
        top.pack(fill="x")
        self.status = tk.Label(top, text="● 未启动", fg="gray", font=("", 11, "bold"))
        self.status.pack(side="left")
        self.url_var = tk.StringVar(value="（服务启动后显示）")
        tk.Entry(top, textvariable=self.url_var, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(12, 0))
        self.mcp_feedback = tk.StringVar()
        tk.Label(root, textvariable=self.mcp_feedback, anchor="w", padx=10,
                 wraplength=680, justify="left").pack(fill="x")

        self.recovery_panel = ttk.Frame(root, padding=(10, 6))
        self.recovery_message = tk.StringVar()
        ttk.Label(self.recovery_panel, textvariable=self.recovery_message, anchor="w",
                  justify="left", wraplength=510).pack(side="left", fill="x", expand=True)
        self.recovery_button = ttk.Button(self.recovery_panel)
        self.recovery_button.pack(side="right", padx=(8, 0))

        self.body = tk.Frame(root)
        self.body.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        # 日志(左)和节点状态(右)放在可左右拖动的分隔窗格里，默认 3:2
        self.paned = ttk.PanedWindow(self.body, orient="horizontal")
        self.paned.pack(side="left", fill="both", expand=True)

        history = ttk.Frame(self.paned)
        self.paned.add(history, weight=3)
        ttk.Label(history, text="最近的 AI 操作").pack(anchor="w")
        self.activity = ttk.Treeview(history, columns=("time", "host", "action", "status"),
                                     show="headings", height=4, selectmode="browse")
        for column, label, width in (("time", "时间", 65), ("host", "节点", 88),
                                     ("action", "操作", 82), ("status", "结果", 100)):
            self.activity.heading(column, text=label)
            self.activity.column(column, width=width, minwidth=35, stretch=column == "host")
        self.activity.pack(fill="x")
        self.inspect_button = ttk.Button(history, text="查看节点状态", command=self.inspect_activity_node,
                                         state="disabled")
        self.inspect_button.pack(anchor="w", pady=(4, 6))
        self.activity.bind("<<TreeviewSelect>>", self.update_activity_controls)
        self.log = scrolledtext.ScrolledText(history, state="disabled", wrap="word", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

        self.panel = tk.Frame(self.paned)
        self.paned.add(self.panel, weight=2)
        self.panel_open = True
        tk.Button(self.panel, text="节点状态  ▸ 收起", anchor="w", relief="flat",
                  command=self.toggle_panel).pack(fill="x")
        self.tree = ttk.Treeview(self.panel, columns=("via", "state"), height=8, selectmode="browse")
        self.tree.heading("#0", text="节点")
        self.tree.heading("via", text="路由")
        self.tree.heading("state", text="状态")
        self.tree.column("#0", width=80, minwidth=50, stretch=False)
        self.tree.column("via", width=55, minwidth=40, stretch=False)
        self.tree.column("state", width=150, minwidth=80)
        self.tree.tag_configure("connected", foreground="#1a7f37")
        self.tree.tag_configure("via-bastion", foreground="#6e7781")
        self.tree.tag_configure("idle", foreground="#6e7781")
        self.tree.tag_configure("offline", foreground="#cf222e")
        self.tree.pack(fill="both", expand=True)
        actions = ttk.Frame(self.panel)
        actions.pack(fill="x", pady=(6, 0))
        self.test_node_button = ttk.Button(actions, text="测试连接", command=self.test_node, state="disabled")
        self.test_node_button.pack(side="left")
        self.reconnect_node_button = ttk.Button(actions, text="重连节点", command=self.reconnect_node, state="disabled")
        self.reconnect_node_button.pack(side="left", padx=6)
        self.node_feedback = tk.StringVar()
        ttk.Label(self.panel, textvariable=self.node_feedback, wraplength=270, justify="left").pack(fill="x", pady=6)
        self.tree.bind("<<TreeviewSelect>>", self.update_node_controls)
        # 收起后留在右边缘的小按钮，点它重新展开
        self.expand_btn = tk.Button(self.body, text="◂" + chr(10) + "节" + chr(10) + "点" + chr(10) + "状" + chr(10) + "态",
                                    width=2, relief="flat", command=self.toggle_panel)
        self.root.after(80, self.reset_sash)

        self.root.after(100, self.drain_log)
        self.refresh_nodes()
        if not daemon.CONFIG_PATH.exists():
            self.append("未找到 config.toml：请在菜单 配置 → 配置编辑… 中填写并保存。" + chr(10))

    # ── 日志 ──────────────────────────────────────────────
    def append(self, s: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", s)
        self.log.see("end")
        self.log.configure(state="disabled")

    def drain_log(self) -> None:
        chunks = []
        try:
            while True:
                chunks.append(self.log_q.get_nowait())
        except queue.Empty:
            pass
        if chunks:
            self.append("".join(chunks))
        try:
            while True:
                fn, args = self.ui_q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self.drain_log)

    def call_ui(self, fn, *args) -> None:
        """Run fn(*args) on the Tk thread; safe to call from any thread
        (Tk's own after() from a worker thread isn't)."""
        self.ui_q.put((fn, args))

    # ── 状态 ──────────────────────────────────────────────
    def set_state(self, state: str) -> None:
        self.service_state = state
        text, color = {
            "stopped": ("● 未启动", "gray"),
            "starting": ("● 启动中…（可能需要输入验证码）", "orange"),
            "running": ("● 运行中", "green"),
            "stopping": ("● 停止中…", "orange"),
        }[state]
        self.status.configure(text=text, fg=color)
        self.svc_menu.entryconfigure("启动服务", state="normal" if state == "stopped" else "disabled")
        self.svc_menu.entryconfigure("停止服务", state="normal" if state in ("starting", "running") else "disabled")
        for item in ("检查 MCP 接入", "复制 MCP 地址", "复制 Claude Code 注册命令", "复制 Codex 注册命令"):
            self.tool_menu.entryconfigure(item, state="normal" if state == "running" else "disabled")
        if state == "stopped":
            self.url_var.set("（服务启动后显示）")
        if state != "running":
            self.mcp_feedback.set("")
        self.update_node_controls()
        self.refresh_recovery()

    # ── 启动 / 停止 ──────────────────────────────────────
    def start(self) -> None:
        try:
            cfg, port = daemon.init_service()
        except SystemExit:
            messagebox.showerror("配置错误", "配置有误，详情见下方日志。")
            return
        except Exception as e:
            print(f"启动失败：{type(e).__name__}: {e}")
            messagebox.showerror("启动失败", str(e))
            return

        busy = _port_in_use(port)
        if busy:
            msg = (f"端口 {port} 已被占用，可能已经有一个 Remote MCP（本窗口的另一个实例，"
                   f"或 python daemon.py）在运行。请先关闭它，或在配置里换一个 [daemon] port。")
            print(msg)
            messagebox.showerror("端口被占用", msg)
            return

        self.port = port
        self.server = None
        self.stop_requested.clear()
        self.set_state("starting")
        self.thread = threading.Thread(target=self._run_service, args=(cfg, port), daemon=True)
        self.thread.start()

    def _run_service(self, cfg: dict, port: int) -> None:
        # asyncio primitives created at import time belong to the previous
        # run's loop; start each run with fresh ones.
        pool._bastion_locks.clear()
        pool._hop_sems.clear()
        pool._host_locks.clear()
        pool._sems.clear()
        pool._bastion_conns.clear()
        pool._target_conns.clear()
        self._prompt_lock = asyncio.Lock()
        pool.prompt_handler = self._prompt_from_service

        async def wait_for_listener(server) -> None:
            while not server.started:
                await asyncio.sleep(0.05)
            self.call_ui(self._on_listening, port)

        def on_server(server) -> None:
            self.server = server
            pool.start_background(wait_for_listener(server))

        async def serve() -> None:
            if not self.stop_requested.is_set():
                await daemon.serve(cfg, port, on_server, use_colors=False)

        try:
            with asyncio.Runner() as runner:
                self.loop = runner.get_loop()
                runner.run(serve())
        except asyncio.CancelledError:
            if not self.stop_requested.is_set():
                print("服务启动任务已取消")
        except BaseException as e:  # noqa: BLE001 - report everything to the log
            print(f"服务异常退出：{type(e).__name__}: {e}")
        finally:
            pool.prompt_handler = None
            self.loop = None
            self.call_ui(self._on_stopped)

    def _on_listening(self, port: int) -> None:
        if self.service_state == "starting" and self.thread and self.thread.is_alive():
            self.url_var.set(f"http://127.0.0.1:{port}/mcp")
            self.set_state("running")
            self.check_mcp()

    def _on_stopped(self) -> None:
        self.server = None
        self.mcp_check_busy = False
        self.node_operation = None
        self.node_result = None
        self.recovering_bastion = None
        self.recovery_result = None
        self._recovery_connection = None
        self.set_state("stopped")
        print("服务已停止")

    def stop(self) -> None:
        self.stop_requested.set()
        self.set_state("stopping")
        if self.server is not None:
            server = self.server
            server.should_exit = True
            # Safety net: if graceful shutdown is still stuck (e.g. a client
            # holding a connection open), force it after a few seconds.
            self.root.after(5000, lambda: setattr(server, "force_exit", True))
        elif self.loop is not None:
            # Still in startup (e.g. waiting on a verification code): cancel.
            loop = self.loop
            loop.call_soon_threadsafe(
                lambda: [t.cancel() for t in asyncio.all_tasks(loop)]
            )

    # ── 弹窗输入（在 Tk 主线程里执行） ────────────────────
    async def _prompt_from_service(self, prompt: str, echo: bool) -> "str | None":
        """One dialog at a time. Returns the text, or None if dismissed."""
        loop = asyncio.get_running_loop()
        async with self._prompt_lock:
            fut: "asyncio.Future[str | None]" = loop.create_future()

            def done(value) -> None:
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(value))

            request = _AuthRequest(pool.auth_bastion.get(), prompt, echo, fut, done)
            self.call_ui(self.set_pending_auth, request)
            try:
                return await fut
            finally:
                self.call_ui(self.clear_pending_auth, request)

    def set_pending_auth(self, request: _AuthRequest) -> None:
        if request.future.done():
            return
        self.pending_auth = request
        self.refresh_recovery()
        if self.in_tray:
            self.tray.notify(self.recovery_message.get())
            return
        if self.root.state() == "iconic":
            self.root.deiconify()
            self.root.lift()
        if request.bastion is None:
            self.open_auth_dialog()

    def clear_pending_auth(self, request: _AuthRequest) -> None:
        if request.dialog:
            request.dialog.dismiss()
        if self.pending_auth is request:
            self.pending_auth = None
            self.refresh_recovery()

    def open_auth_dialog(self) -> None:
        request = self.pending_auth
        if not self.in_tray and request and not request.future.done() and request.dialog is None:
            request.dialog = _PromptDialog(self.root, request.prompt, request.echo, request.done)

    def refresh_recovery(self) -> None:
        request = self.pending_auth
        if self.recovery_result and self.recovery_result[1]:
            name = self.recovery_result[0]
            connection = pool._bastion_conns.get(name)
            if connection is None or connection is not self._recovery_connection:
                self.recovery_result = None
                self._recovery_connection = None
        if request and not request.future.done() and self.service_state in ("starting", "running"):
            if request.bastion is None:
                detail = f"节点等待验证 · {request.prompt.strip()}"
            else:
                detail = self.bastion_message(request.bastion, f"需要{request.action}")
            self.recovery_message.set(detail)
            self.recovery_button.configure(text=request.action, command=self.open_auth_dialog, state="normal")
        elif self.service_state == "running" and (name := self.unavailable_bastion()) is not None:
            detail = self.bastion_message(name, "正在验证…" if self.recovering_bastion == name else "未连接")
            if self.recovery_result and self.recovery_result[:2] == (name, False):
                detail += f"\n{self.recovery_result[2]}"
            self.recovery_message.set(detail)
            self.recovery_button.configure(text="重新验证", command=partial(self.recover_bastion, name),
                                           state="disabled" if self.recovering_bastion else "normal")
        elif self.service_state == "running" and self.recovery_result and self.recovery_result[1]:
            name, _ok, detail = self.recovery_result
            self.recovery_message.set(f"跳板机 {name} {detail}")
            self.recovery_button.configure(text="关闭提示", command=self.dismiss_recovery_result, state="normal")
        else:
            self.recovery_panel.pack_forget()
            return
        self.recovery_panel.pack(fill="x", before=self.body)

    def unavailable_bastion(self) -> str | None:
        offline = [name for name in pool.bastions() if not pool._bastion_conns.get(name) and pool.affected_nodes(name)]
        selected = self.tree.selection()
        if selected:
            for name in offline:
                label = "跳板机" if name == pool.DEFAULT_BASTION else f"跳板机 {name}"
                if selected[0] == f"bastion:{label}":
                    return name
        return next(iter(offline), None)

    def bastion_message(self, name: str, detail: str) -> str:
        label = "默认跳板机" if name == pool.DEFAULT_BASTION else f"跳板机 {name}"
        hosts = pool.affected_nodes(name)
        affected = "、".join(hosts[:4])
        if len(hosts) > 4:
            affected += f" 等 {len(hosts)} 台"
        return f"{label} {detail}" + (f" · 受影响节点 {affected}" if hosts else "")

    def recover_bastion(self, name: str) -> None:
        if self._submit(partial(pool.reconnect_bastion, name), partial(self.show_recovery_result, name)):
            self.recovering_bastion = name
            self.recovery_result = None
            self._recovery_connection = None
            self.refresh_recovery()

    def show_recovery_result(self, name: str, ok: bool, detail: str) -> None:
        self.recovering_bastion = None
        self.recovery_result = (name, ok, detail)
        self._recovery_connection = pool._bastion_conns.get(name) if ok else None
        print(f"[{name}] {detail}")
        self.refresh_recovery()

    def dismiss_recovery_result(self) -> None:
        self.recovery_result = None
        self._recovery_connection = None
        self.refresh_recovery()

    def reconnect_nodes(self) -> None:
        if not self._submit(pool.reconnect_all):
            messagebox.showinfo("重新连接节点", "服务还没有运行。")
            return
        print("重新连接所有节点…")

    def _submit(self, operation, on_result=None) -> bool:
        """Queue a UI action on the service loop and deliver its result on Tk."""
        loop, server = self.loop, self.server
        if self.service_state != "running" or not (loop and server):
            return False

        async def run() -> None:
            try:
                result = await operation()
            except Exception as exc:
                while isinstance(exc, ExceptionGroup):
                    exc = exc.exceptions[0]
                result = False, f"{type(exc).__name__}: {exc}"
            if on_result:
                self.call_ui(self._action_result, loop, on_result, result)
            elif result:
                print(result[1])

        def schedule() -> None:
            if not server.should_exit:
                pool.start_background(run())

        try:
            loop.call_soon_threadsafe(schedule)
        except RuntimeError:
            return False
        return True

    def _action_result(self, loop, callback, result) -> None:
        if self.loop is loop and self.service_state == "running":
            callback(*result)

    def check_mcp(self) -> None:
        if self.mcp_check_busy or not self._submit(
            partial(_check_mcp_endpoint, self.url_var.get()), self._show_mcp_result
        ):
            return
        self.mcp_check_busy = True
        self.mcp_feedback.set("正在检查 MCP 握手…")

    def _show_mcp_result(self, ok: bool, detail: str) -> None:
        self.mcp_check_busy = False
        if not ok and detail.startswith("TimeoutError:"):
            detail = "等待 MCP 响应超时（5 秒）"
        message = f"MCP 接入{'成功' if ok else '失败'}：{detail}"
        self.mcp_feedback.set(message)
        print(message)

    # ── 配置编辑 ──────────────────────────────────────────
    def open_editor(self) -> None:
        if getattr(self, "editor", None) and self.editor.winfo_exists():
            self.editor.lift()
            return
        self.editor = ConfigEditor(self.root, on_saved=self.on_config_saved)

    def on_config_saved(self, cfg: dict) -> None:
        """Hot-apply [host.*]/[hosts] to a running service (same as the
        reload_config MCP tool); [bastion]/[daemon] need a restart."""
        loop = self.loop
        if not (self.thread and self.thread.is_alive() and loop and self.server):
            return

        def apply() -> None:
            try:
                s = pool.apply_config(cfg)
            except Exception as e:  # noqa: BLE001
                print(f"配置未热更新：{type(e).__name__}: {e}")
                return
            print(f"已热更新节点配置：新增 {s['added']} 删除 {s['removed']} 修改 {s['changed']}")
            pool.connect_in_background([h for h in s["added"] + s["changed"] if h not in s["need_password"]])
            for sec in s["restart"]:
                print(f"[{sec}] 有变化，需要停止后重新启动服务才生效")
            for h in s["need_password"]:
                print(f"[host.{h}] 等待密码，请在节点面板选中它并点「重连节点」")

        loop.call_soon_threadsafe(apply)

    # ── 节点状态面板 ──────────────────────────────────────
    def reset_sash(self) -> None:
        """Log : status = 3 : 2."""
        self.root.update_idletasks()
        w = self.paned.winfo_width()
        if w > 1 and self.panel_open:
            self.paned.sashpos(0, int(w * 0.6))

    def toggle_panel(self) -> None:
        self.panel_open = not self.panel_open
        if self.panel_open:
            self.expand_btn.pack_forget()
            self.paned.add(self.panel, weight=2)
            self.root.after(50, self.reset_sash)
        else:
            self.paned.forget(self.panel)
            self.expand_btn.pack(side="right", fill="y", padx=(6, 0))

    def refresh_nodes(self, *, schedule: bool = True) -> None:
        if self.panel_open:
            rows = pool.connection_status() if self.service_state == "running" else []
            ids = []
            self.node_rows = {}
            for r in rows:
                mark = {"connected": "● ", "via-bastion": "● ", "idle": "○ ", "offline": "✕ "}[r["state"]]
                host = r["host"]
                item_id = f"node:{host}" if host is not None else f"bastion:{r['name']}"
                ids.append(item_id)
                if host is not None:
                    self.node_rows[item_id] = r
                options = {"text": r["name"], "values": (r["via"], mark + r["detail"]), "tags": (r["state"],)}
                if self.tree.exists(item_id):
                    self.tree.item(item_id, **options)
                else:
                    self.tree.insert("", "end", iid=item_id, **options)
            if not rows:
                ids.append("empty")
                text = self.status.cget("text").removeprefix("● ") if self.service_state != "running" else "暂无配置节点"
                if self.tree.exists("empty"):
                    self.tree.item("empty", text=text)
                else:
                    self.tree.insert("", "end", iid="empty", text=text, tags=("idle",))
            self.tree.delete(*(set(self.tree.get_children()) - set(ids)))
            self.tree.set_children("", *ids)
            self.update_node_controls()
        self.refresh_recovery()
        self.refresh_activity()
        if schedule:
            self.root.after(2000, self.refresh_nodes)

    def selected_node(self):
        selection = self.tree.selection()
        return self.node_rows.get(selection[0]) if selection else None

    def update_node_controls(self, _event=None) -> None:
        if _event is not None:
            self.refresh_recovery()
        node = self.selected_node() if self.service_state == "running" else None
        enabled = node is not None and self.node_operation is None
        self.test_node_button.configure(state="normal" if enabled else "disabled")
        self.reconnect_node_button.configure(state="normal" if enabled else "disabled")
        if not node:
            self.node_feedback.set("")
            return
        route = node["via"]
        if node["bastion"]:
            route += f" / 跳板机 {node['bastion']}"
        detail = f"{route} · {ACCESS_LABELS[node['access']]}\n{node['detail']}"
        if self.node_operation and self.node_operation[0] == node["host"]:
            detail += f"\n{self.node_operation[1]}中…"
        elif self.node_result and self.node_result[0] == node["host"]:
            detail += f"\n{self.node_result[1]}"
        self.node_feedback.set(detail)

    def test_node(self) -> None:
        self._node_action("测试连接", pool.probe)

    def reconnect_node(self) -> None:
        self._node_action("重连节点", pool.reconnect_node)

    def _node_action(self, label, operation) -> None:
        node = self.selected_node()
        if self.node_operation or not node:
            return
        host = node["host"]
        if self._submit(partial(operation, host), partial(self._show_node_result, host, label)):
            self.node_operation = (host, label)
            self.node_result = None
            self.update_node_controls()

    def _show_node_result(self, host: str, label: str, ok: bool, detail: str) -> None:
        self.node_operation = None
        message = f"{label}{'成功' if ok else '失败'}：{detail}"
        self.node_result = (host, message)
        print(f"[{host}] {message}")
        self.update_node_controls()

    def refresh_activity(self) -> None:
        rows = tools.recent_activity()[:5]
        self.activity_items = {str(row["id"]): row for row in rows}
        for item, row in self.activity_items.items():
            timestamp = time.strftime("%H:%M:%S", time.localtime(row["time"]))
            values = (timestamp, row["host"], row["action"], row["status"])
            if self.activity.exists(item):
                self.activity.item(item, values=values)
            else:
                self.activity.insert("", "end", iid=item, values=values)
        self.activity.delete(*(set(self.activity.get_children()) - self.activity_items.keys()))
        self.activity.set_children("", *self.activity_items)
        self.update_activity_controls()

    def selected_activity(self):
        selected = self.activity.selection()
        return self.activity_items.get(selected[0]) if selected else None

    def update_activity_controls(self, _event=None) -> None:
        row = self.selected_activity()
        enabled = self.service_state == "running" and row and row["status"] == "结果未知"
        self.inspect_button.configure(state="normal" if enabled else "disabled")

    def inspect_activity_node(self) -> None:
        row = self.selected_activity()
        if row is None:
            return
        host = row["host"]
        item = f"node:{host}"
        if not self.panel_open:
            self.toggle_panel()
        self.refresh_nodes(schedule=False)
        if not self.tree.exists(item):
            messagebox.showinfo("查看节点状态", f"{host} 当前不在节点列表中。请先确认上一条操作的状态。")
            return
        self.tree.selection_set(item)
        self.tree.see(item)
        self.node_result = (host, "上一条操作结果未知。连接测试只确认能否连接，请先核查原操作。")
        self.update_node_controls()

    def clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def copy_url(self) -> None:
        self._copy(self.url_var.get())

    def copy_claude_cmd(self) -> None:
        self._copy(f"claude mcp add --transport http --scope user remote-linux {self.url_var.get()}")

    def copy_codex_cmd(self) -> None:
        self._copy(f"codex mcp add remote-linux --url {self.url_var.get()}")

    def on_window_close(self) -> None:
        if sys.platform == "win32" and self.thread and self.thread.is_alive() and not self.closing:
            try:
                if self.tray is None:
                    from windows_tray import WindowsTray

                    self.tray = WindowsTray(self.call_ui, open_window=self.show_window,
                                            stop_service=self.stop_from_tray, exit_app=self.quit_from_tray)
                self.in_tray = True
                self.root.withdraw()
                if self.pending_auth:
                    self.tray.notify(self.recovery_message.get())
                return
            except Exception as exc:
                print(f"无法使用 Windows 托盘：{exc}")
        self.on_close()

    def show_window(self) -> None:
        self.in_tray = False
        self.root.deiconify()
        self.root.lift()

    def stop_from_tray(self) -> None:
        if self.service_state in ("starting", "running"):
            self.stop()

    def quit_from_tray(self) -> None:
        self.show_window()
        self.on_close()

    def on_close(self) -> None:
        if self.closing:
            return
        if self.thread and self.thread.is_alive():
            if not messagebox.askyesno("退出", "服务仍在运行，退出将断开所有连接。确定退出？"):
                return
            self.closing = True
            self.stop()
            # Never join() on the Tk thread: it would freeze the window and
            # stop the after() callbacks (force_exit) that make the service exit.
            self._wait_exit(time.monotonic() + 8)
            return
        self.destroy_window()

    def _wait_exit(self, deadline: float) -> None:
        if self.thread and self.thread.is_alive() and time.monotonic() < deadline:
            self.root.after(100, self._wait_exit, deadline)
        else:
            self.destroy_window()  # the service thread is a daemon: it can't outlive us

    def destroy_window(self) -> None:
        try:
            if self.tray:
                self.tray.close()
        finally:
            self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
