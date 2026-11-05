"""remote-mcp 桌面应用：点按钮启动 / 停止 MCP 连接服务。

和 `python daemon.py` 跑的是同一套服务，区别只是：
  - 用窗口里的“启动 / 停止”按钮控制，不用敲命令；
  - 跳板机的验证码 / 密码提示改成弹窗输入，不再占用终端；
  - 日志显示在窗口里。
只用标准库 tkinter，无需额外依赖。运行：python app.py（或双击 start-app.bat）。
"""
import asyncio
import logging
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk

import daemon
import pool
from config_editor import ConfigEditor

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


def _port_in_use(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Remote MCP")
        root.geometry("760x520")
        root.protocol("WM_DELETE_WINDOW", self.on_close)

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
        self.port = 8765

        # ── 导航栏（菜单） ──
        menubar = tk.Menu(root)
        self.svc_menu = tk.Menu(menubar, tearoff=False)
        self.svc_menu.add_command(label="启动服务", command=self.start)
        self.svc_menu.add_command(label="停止服务", command=self.stop, state="disabled")
        self.svc_menu.add_separator()
        self.svc_menu.add_command(label="退出", command=self.on_close)
        menubar.add_cascade(label="服务", menu=self.svc_menu)

        cfg_menu = tk.Menu(menubar, tearoff=False)
        cfg_menu.add_command(label="配置编辑…", command=self.open_editor)
        menubar.add_cascade(label="配置", menu=cfg_menu)

        tool_menu = tk.Menu(menubar, tearoff=False)
        tool_menu.add_command(label="复制 MCP 地址", command=self.copy_url)
        tool_menu.add_command(label="复制 claude 注册命令", command=self.copy_claude_cmd)
        tool_menu.add_separator()
        tool_menu.add_command(label="清空日志", command=self.clear_log)
        menubar.add_cascade(label="工具", menu=tool_menu)
        root.configure(menu=menubar)

        # ── 状态 + 地址 ──
        top = tk.Frame(root, padx=10, pady=8)
        top.pack(fill="x")
        self.status = tk.Label(top, text="● 未启动", fg="gray", font=("", 11, "bold"))
        self.status.pack(side="left")
        self.url_var = tk.StringVar(value="（服务启动后显示）")
        tk.Entry(top, textvariable=self.url_var, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(12, 0))

        self.body = tk.Frame(root)
        self.body.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        # 日志(左)和节点状态(右)放在可左右拖动的分隔窗格里，默认 3:2
        self.paned = ttk.PanedWindow(self.body, orient="horizontal")
        self.paned.pack(side="left", fill="both", expand=True)

        self.log = scrolledtext.ScrolledText(self.paned, state="disabled", wrap="word", font=("Consolas", 9))
        self.paned.add(self.log, weight=3)

        self.panel = tk.Frame(self.paned)
        self.paned.add(self.panel, weight=2)
        self.panel_open = True
        tk.Button(self.panel, text="节点状态  ▸ 收起", anchor="w", relief="flat",
                  command=self.toggle_panel).pack(fill="x")
        self.tree = ttk.Treeview(self.panel, columns=("via", "state", "test"), height=8)
        self.tree.heading("#0", text="节点")
        self.tree.heading("via", text="路由")
        self.tree.heading("state", text="状态")
        self.tree.heading("test", text="测试")
        self.tree.column("#0", width=80, minwidth=50, stretch=False)
        self.tree.column("via", width=55, minwidth=40, stretch=False)
        self.tree.column("state", width=150, minwidth=80)
        self.tree.column("test", width=110, minwidth=60)
        self.tree.tag_configure("connected", foreground="#1a7f37")
        self.tree.tag_configure("via-bastion", foreground="#1a7f37")
        self.tree.tag_configure("idle", foreground="#6e7781")
        self.tree.tag_configure("offline", foreground="#cf222e")
        self.tree.tag_configure("ok", foreground="#1a7f37")
        self.tree.tag_configure("fail", foreground="#cf222e")
        self.tree.pack(fill="both", expand=True)
        btns = tk.Frame(self.panel)
        btns.pack(fill="x", pady=(4, 0))
        self.btn_test_sel = tk.Button(btns, text="测试选中", command=self.test_selected)
        self.btn_test_sel.pack(side="left")
        self.btn_test_all = tk.Button(btns, text="测试全部", command=self.test_all)
        self.btn_test_all.pack(side="left", padx=6)
        self.probe_results: dict[str, str] = {}  # node -> text shown in the 测试 column
        self.probing = False
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
        text, color = {
            "stopped": ("● 未启动", "gray"),
            "starting": ("● 启动中…（可能需要输入验证码）", "orange"),
            "running": ("● 运行中", "green"),
            "stopping": ("● 停止中…", "orange"),
        }[state]
        self.status.configure(text=text, fg=color)
        self.svc_menu.entryconfigure("启动服务", state="normal" if state == "stopped" else "disabled")
        self.svc_menu.entryconfigure("停止服务", state="disabled" if state == "stopped" else "normal")
        if state == "stopped":
            self.url_var.set("（服务启动后显示）")

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
        self.set_state("starting")
        self.thread = threading.Thread(target=self._run_service, args=(cfg, port), daemon=True)
        self.thread.start()

    def _run_service(self, cfg: dict, port: int) -> None:
        loop = asyncio.new_event_loop()
        self.loop = loop
        asyncio.set_event_loop(loop)
        # asyncio primitives created at import time belong to the previous
        # run's loop; start each run with fresh ones.
        pool._bastion_locks.clear()
        pool._hop_sems.clear()
        pool._host_locks.clear()
        pool._sems.clear()
        pool._bastion_conns.clear()
        pool._target_conns.clear()
        pool.prompt_handler = self._prompt_from_service

        def on_server(server) -> None:
            self.server = server
            self.call_ui(self._on_listening, port)

        try:
            loop.run_until_complete(daemon.serve(cfg, port, on_server, use_colors=False))
        except BaseException as e:  # noqa: BLE001 - report everything to the log
            print(f"服务异常退出：{type(e).__name__}: {e}")
        finally:
            pool.prompt_handler = None
            loop.close()
            self.loop = None
            self.call_ui(self._on_stopped)

    def _on_listening(self, port: int) -> None:
        if self.thread and self.thread.is_alive():
            self.url_var.set(f"http://127.0.0.1:{port}/mcp")
            self.set_state("running")

    def _on_stopped(self) -> None:
        self.set_state("stopped")
        print("服务已停止")

    def stop(self) -> None:
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
    async def _prompt_from_service(self, prompt: str, echo: bool) -> str:
        loop = asyncio.get_running_loop()
        fut: "asyncio.Future[str]" = loop.create_future()

        def ask() -> None:
            # A dialog opened from a background-triggered callback can end up
            # behind other windows; make sure the user can see it.
            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after(300, lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
            ans = simpledialog.askstring(
                "需要输入", prompt.strip() or "请输入", show="" if echo else "*", parent=self.root
            )
            # Cancelled dialog -> empty answer (server will reject it; the
            # daemon's normal retry/give-up logic takes over).
            loop.call_soon_threadsafe(fut.set_result, ans or "")

        self.call_ui(ask)
        return await fut

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
            for sec in s["restart"]:
                print(f"[{sec}] 有变化，需要停止后重新启动服务才生效")
            for h in s["need_password"]:
                print(f"[host.{h}] 需要重启服务后输入密码")

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

    def refresh_nodes(self) -> None:
        running = bool(self.thread and self.thread.is_alive() and self.server)
        if self.panel_open:
            selected = set(self.tree.selection())
            rows = pool.connection_status() if running else []
            self.tree.delete(*self.tree.get_children())
            if not running:
                self.tree.insert("", "end", text="服务未启动", tags=("idle",))
            for i, r in enumerate(rows):
                mark = {"connected": "● ", "via-bastion": "● ", "idle": "○ ", "offline": "✕ "}[r["state"]]
                host = r.get("host")
                result = self.probe_results.get(host, "") if host else ""
                tags = [r["state"]]
                if result.startswith("✓"):
                    tags = ["ok"]
                elif result.startswith("✗"):
                    tags = ["fail"]
                iid = f"n:{host}" if host else f"b:{i}"
                self.tree.insert("", "end", iid=iid, text=r["name"],
                                 values=(r["via"], mark + r["detail"], result), tags=tags)
                if iid in selected:
                    self.tree.selection_add(iid)
        self.btn_test_sel.configure(state="normal" if running and not self.probing else "disabled")
        self.btn_test_all.configure(state="normal" if running and not self.probing else "disabled")
        self.root.after(2000, self.refresh_nodes)

    # ── 测试连接 ──────────────────────────────────────────
    def test_selected(self) -> None:
        hosts = [i[2:] for i in self.tree.selection() if i.startswith("n:")]
        if not hosts:
            messagebox.showinfo("测试连接", "请先在节点状态里选中一个或多个节点（跳板机行不能测试）。")
            return
        self._run_probes(hosts)

    def test_all(self) -> None:
        self._run_probes([h for h in pool.cfg.get("host", {})])

    def _run_probes(self, hosts: list[str]) -> None:
        loop = self.loop
        if not (loop and self.server) or self.probing or not hosts:
            return
        self.probing = True
        for h in hosts:
            self.probe_results[h] = "测试中…"

        async def work() -> None:
            # One node at a time: a bastion login may need a verification
            # code, and several dialogs at once would be confusing.
            try:
                for h in hosts:
                    ok, detail = await pool.probe(h)
                    text = ("✓ " if ok else "✗ ") + detail
                    print(f"[测试] {h} {text}")
                    self.call_ui(self.probe_results.__setitem__, h, text)
            finally:
                self.call_ui(setattr, self, "probing", False)

        asyncio.run_coroutine_threadsafe(work(), loop)
        self.refresh_nodes_now()

    def refresh_nodes_now(self) -> None:
        # refresh_nodes() reschedules itself; just redraw the rows once.
        if self.panel_open:
            for iid in self.tree.get_children():
                if iid.startswith("n:"):
                    vals = list(self.tree.item(iid, "values"))
                    vals[2] = self.probe_results.get(iid[2:], "")
                    self.tree.item(iid, values=vals)

    def clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def copy_url(self) -> None:
        self._copy(f"http://127.0.0.1:{self.port}/mcp")

    def copy_claude_cmd(self) -> None:
        self._copy(f"claude mcp add --transport http remote-linux http://127.0.0.1:{self.port}/mcp")

    def on_close(self) -> None:
        if self.thread and self.thread.is_alive():
            if not messagebox.askyesno("退出", "服务仍在运行，退出将断开所有连接。确定退出？"):
                return
            self.stop()
            self.thread.join(timeout=5)
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
