"""图形化配置编辑器：镜像 config.toml，可直接改每个节点的字段、新增 / 删除节点。

保存时先用 pool.validate_config 校验，再写回 config.toml（旧文件备份为 config.toml.bak，
注释不保留）。
"""
import copy
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import config_io
import pool

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

# (key, label, kind, hint). kind: str | int | num | secret | file | choice:a,b,c
BASTION_FIELDS = [
    ("host", "地址", "str", "跳板机域名或 IP"),
    ("port", "端口", "int", "默认 22"),
    ("user", "用户名", "str", "跳板机登录用户名"),
    ("key", "私钥路径", "file", "留空则用默认密钥对 (~/.ssh/id_*)"),
    ("password", "密码", "secret", "可选：自动回答 keyboard-interactive 的密码提示；验证码仍需输入"),
    ("keepalive_interval", "保活间隔(秒)", "num", "默认 15，0 关闭；该跳板机及经它的连接使用"),
    ("keepalive_count_max", "保活失败次数", "int", "连续多少次无响应判定断线，默认 8"),
]
DAEMON_FIELDS = [
    ("port", "监听端口", "int", "仅绑定 127.0.0.1，默认 8765；改后需重启服务"),
    ("audit_log", "审计日志", "file", "留空不记录；填路径则写 JSONL（不含密码）"),
    ("connect_timeout", "目标机建连超时(秒)", "num", "默认 20"),
    ("heartbeat_interval", "心跳间隔(秒)", "num", "默认 60，0 关闭"),
]
NODE_FIELDS = [
    ("via", "路由方式", "choice:bastion,hop,direct",
     "bastion=经跳板机；hop=跳板机代 ssh 到该节点；direct=本机直连"),
    ("bastion", "所属跳板机", "bastion",
     "bastion / hop 节点走哪台跳板机；有多台时必填，只有一台可留空"),
    ("user", "用户名", "str", "目标机登录用户名"),
    ("address", "地址", "str", "direct 必填；bastion 节点可选：跳板机解析不了节点名时填 IP / 域名"),
    ("port", "端口", "int", "目标机 SSH 端口（direct / bastion），hop：跳板机 ssh 的 -p"),
    ("auth", "认证方式", "choice:key,password", "direct 节点：密钥或密码"),
    ("key", "私钥路径", "file", "留空则回退到所属跳板机的 key / 默认密钥对"),
    ("cert", "用户证书", "file", "可选：CA 签发的 *-cert.pub"),
    ("password", "密码", "secret", "留空则启动服务时弹窗输入"),
    ("known_hosts", "known_hosts", "file", "可选：校验 host key，密码认证节点建议配置"),
    ("node", "跳板机 ssh 目标", "str", "hop：省略则等于节点名"),
    ("container", "容器名", "str", "hop：设了就在 docker 容器里执行"),
    ("container_user", "容器内用户", "str", "hop：docker exec -u"),
    ("default_cwd", "默认工作目录", "str", "远端 Linux 路径（容器节点为容器内路径）"),
]
VIA_HINTS = {
    "bastion": "提示：经跳板机的节点只用密钥认证，password 字段暂不生效。"
               "节点名需要能被跳板机解析；解析不了就在“地址”里填 IP（端口用“端口”）。",
    "hop": "提示：所有字段都可以填写并保存。hop 节点由跳板机上的 ssh 代为连接，"
           "本机的地址 / 密钥 / 密码字段暂不生效。",
    "direct": "直连节点：认证方式选 password 时使用密码（留空则启动服务时弹窗输入）。",
}

SEC_DAEMON, SEC_HOSTS = "daemon", "hosts"


def _parse(kind: str, text: str, label: str):
    if kind == "int":
        try:
            return int(text)
        except ValueError:
            raise ValueError(f"“{label}”必须是整数") from None
    if kind == "num":
        try:
            return int(text)
        except ValueError:
            pass
        try:
            return float(text)
        except ValueError:
            raise ValueError(f"“{label}”必须是数字") from None
    return text


class ConfigEditor(tk.Toplevel):
    def __init__(self, master, on_saved=None):
        super().__init__(master)
        self.title("配置编辑")
        self.geometry("900x580")
        self.transient(master)
        self.on_saved = on_saved
        self.cfg = copy.deepcopy(config_io.load())
        # bastions are edited as name -> table; on save a lone "default" goes
        # back to the legacy flat [bastion], anything else to [bastion.<name>].
        self.bastions: dict[str, dict] = copy.deepcopy(pool.bastions(self.cfg))
        self.cfg.pop("bastion", None)
        self.cfg.setdefault("host", {})
        # ("sec", daemon|hosts) | ("node", name) | ("bastion", name)
        self.current: tuple[str, str] | None = None
        self.vars: dict[str, tk.StringVar] = {}
        self.rows: dict[str, tk.Frame] = {}
        self.ctrls: dict[str, tuple] = {}
        self.dirty = False

        left = tk.Frame(self, padx=8, pady=8)
        left.pack(side="left", fill="y")
        self.listbox = tk.Listbox(left, width=24, exportselection=False, activestyle="none")
        self.listbox.pack(fill="y", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)
        tk.Button(left, text="＋ 新增跳板机", command=self.add_bastion).pack(fill="x", pady=(6, 0))
        tk.Button(left, text="－ 删除跳板机", command=self.delete_bastion).pack(fill="x", pady=(4, 0))
        tk.Button(left, text="＋ 新增节点", command=self.add_node).pack(fill="x", pady=(10, 0))
        tk.Button(left, text="－ 删除节点", command=self.delete_node).pack(fill="x", pady=(4, 0))

        right = tk.Frame(self, padx=8, pady=8)
        right.pack(side="left", fill="both", expand=True)
        self.title_lbl = tk.Label(right, text="", font=("", 11, "bold"), anchor="w")
        self.title_lbl.pack(fill="x")
        self.form = tk.Frame(right)
        self.form.pack(fill="both", expand=True, pady=6)
        bottom = tk.Frame(right)
        bottom.pack(fill="x")
        tk.Label(bottom, fg="gray", anchor="w", justify="left",
                 text="保存会重写 config.toml（注释不保留，旧版备份为 config.toml.bak）").pack(side="left")
        tk.Button(bottom, text="关闭", width=8, command=self.close).pack(side="right")
        tk.Button(bottom, text="保存", width=8, command=self.save).pack(side="right", padx=6)
        tk.Button(bottom, text="用记事本打开", command=self.open_in_notepad).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh_list()
        self.select(self.first_target())

    def first_target(self) -> tuple[str, str]:
        return ("bastion", next(iter(self.bastions))) if self.bastions else ("sec", SEC_DAEMON)

    # ── 左侧列表 ─────────────────────────────────────────
    def entries(self) -> list[tuple[str, str, str]]:
        e = [("bastion", n, f"跳板机  {n}") for n in self.bastions]
        e += [("sec", SEC_DAEMON, "服务 [daemon]"),
              ("sec", SEC_HOSTS, "白名单 [hosts]")]
        for name, hc in self.cfg["host"].items():
            e.append(("node", name, f"节点  {name}  ({hc.get('via', 'bastion')})"))
        return e

    def refresh_list(self) -> None:
        self.listbox.delete(0, "end")
        for _, _, label in self.entries():
            self.listbox.insert("end", label)

    def highlight(self, target: tuple[str, str]) -> None:
        for i, (kind, name, _) in enumerate(self.entries()):
            if (kind, name) == target:
                self.listbox.selection_clear(0, "end")
                self.listbox.selection_set(i)
                self.listbox.see(i)
                break

    def select(self, target: tuple[str, str]) -> None:
        self.highlight(target)
        self.show(target)

    def on_select(self, _event=None) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        kind, name, _ = self.entries()[sel[0]]
        if (kind, name) == self.current:
            return
        if not self.commit():
            if self.current:
                self.highlight(self.current)  # keep the form (and the bad input) as is
            return
        self.refresh_list()  # a rename in the form changes the label
        self.select((kind, name))

    # ── 表单 ─────────────────────────────────────────────
    def clear_form(self) -> None:
        for w in self.form.winfo_children():
            w.destroy()
        self.vars, self.rows, self.ctrls = {}, {}, {}

    def add_row(self, key, label, kind, hint, value) -> None:
        row = tk.Frame(self.form)
        lbl = tk.Label(row, text=label, width=18, anchor="e")
        lbl.pack(side="left")
        ctrls = []
        var = tk.StringVar(value="" if value is None else str(value))
        var.trace_add("write", lambda *_: setattr(self, "dirty", True))
        if kind == "bastion":
            w = ttk.Combobox(row, textvariable=var, state="readonly", width=28,
                             values=[""] + list(self.bastions))
            w.bind("<<ComboboxSelected>>", lambda _e: self.layout_node_rows())
        elif kind.startswith("choice:"):
            w = ttk.Combobox(row, textvariable=var, state="readonly", width=28,
                             values=kind.split(":", 1)[1].split(","))
            if key in ("via", "auth"):
                w.bind("<<ComboboxSelected>>", lambda _e: self.layout_node_rows())
        else:
            w = tk.Entry(row, textvariable=var, width=32, show="*" if kind == "secret" else "")
        w.pack(side="left", padx=6)
        ctrls.append(w)
        if kind == "secret":
            def toggle(e=w):
                e.configure(show="" if e.cget("show") else "*")
            b = tk.Button(row, text="显示", width=4, command=toggle)
            b.pack(side="left")
            ctrls.append(b)
        if kind == "file":
            def browse(v=var):
                p = filedialog.askopenfilename(parent=self)
                if p:
                    v.set(p)
            b = tk.Button(row, text="浏览…", command=browse)
            b.pack(side="left")
            ctrls.append(b)
        tk.Label(row, text=hint, fg="gray", anchor="w").pack(side="left", padx=6)
        self.vars[key] = var
        self.rows[key] = row
        self.ctrls[key] = (lbl, ctrls, kind)

    def show(self, target: tuple[str, str]) -> None:
        self.clear_form()
        self.current = target
        kind, name = target
        if kind == "node":
            hc = self.cfg["host"][name]
            self.title_lbl.configure(text=f"节点：{name}")
            self.add_row("__name", "节点名", "str", "MCP 里使用的名字，也是白名单匹配的名字", name)
            for key, label, k, hint in NODE_FIELDS:
                self.add_row(key, label, k, hint, hc.get(key, "bastion" if key == "via"
                                                         else "key" if key == "auth" else ""))
            self.via_hint = tk.Label(self.form, fg="#9a6700", anchor="w", justify="left", wraplength=560)
            self.layout_node_rows()
        elif name == SEC_HOSTS:
            self.title_lbl.configure(text="白名单 [hosts]")
            tk.Label(self.form, anchor="w", justify="left",
                     text="允许访问的目标机，每行一个，支持 fnmatch 通配符（如 lab*）。\n"
                          "留空表示不限制（生产环境建议显式配置）。").pack(fill="x")
            self.allowed_text = tk.Text(self.form, height=14, width=40)
            self.allowed_text.pack(anchor="w", pady=6)
            self.allowed_text.insert("1.0", "\n".join(self.cfg.get("hosts", {}).get("allowed", [])))
            self.allowed_text.edit_modified(False)
            self.allowed_text.bind("<<Modified>>", lambda _e: setattr(self, "dirty", True))
        elif kind == "bastion":
            bc = self.bastions[name]
            self.title_lbl.configure(text=f"跳板机：{name}（改动需重启服务）")
            self.add_row("__name", "跳板机名字", "str",
                         "节点的“所属跳板机”引用这个名字；只有一台时可叫 default", name)
            for key, label, k, hint in BASTION_FIELDS:
                self.add_row(key, label, k, hint, bc.get(key, ""))
            for r in self.rows.values():
                r.pack(fill="x", pady=2)
            tk.Label(self.form, fg="gray", anchor="w", justify="left", wraplength=560,
                     text="有多台跳板机时，每个 bastion / hop 节点都要在“所属跳板机”里指定走哪一台；"
                          "启动时会逐台登录，验证码弹窗里会带上跳板机名字。").pack(fill="x", pady=6)
        else:
            self.title_lbl.configure(text="服务 [daemon]（端口等改动需重启服务）")
            sec = self.cfg.get(name, {})
            for key, label, k, hint in DAEMON_FIELDS:
                self.add_row(key, label, k, hint, sec.get(key, ""))
            for r in self.rows.values():
                r.pack(fill="x", pady=2)
        if kind == "sec" and name == SEC_DAEMON and not self.bastions:
            tk.Label(self.form, fg="gray", anchor="w",
                     text="当前没有跳板机：所有节点都必须是 direct。点左下“＋ 新增跳板机”添加。").pack(fill="x", pady=6)
        self.dirty = False

    def layout_node_rows(self) -> None:
        via = self.vars["via"].get() or "bastion"
        for r in self.rows.values():
            r.pack_forget()
        self.rows["__name"].pack(fill="x", pady=2)
        for key, *_ in NODE_FIELDS:  # every field is always editable...
            if key == "bastion" and via == "direct":
                continue  # ...except the bastion binding: direct nodes bypass bastions
            self.rows[key].pack(fill="x", pady=2)
        text = VIA_HINTS.get(via, "")
        if via in ("bastion", "hop") and len(self.bastions) > 1 and not self.vars["bastion"].get():
            text += "\n⚠ 现有多台跳板机，必须在“所属跳板机”里选择走哪一台，否则保存会报错。"
        self.via_hint.configure(text=text)
        self.via_hint.pack(fill="x", pady=(8, 0))

    # ── 把表单写回 self.cfg ──────────────────────────────
    def commit(self) -> bool:
        if not self.current:
            return True
        kind, name = self.current
        try:
            if kind == "node":
                self._commit_node(name)
            elif name == SEC_HOSTS:
                lines = [x.strip() for x in self.allowed_text.get("1.0", "end").splitlines()]
                allowed = [x for x in lines if x]
                if allowed:
                    self.cfg["hosts"] = {**self.cfg.get("hosts", {}), "allowed": allowed}
                else:
                    self.cfg.pop("hosts", None)
            elif kind == "bastion":
                self._commit_bastion(name)
            else:
                self._commit_section(name, DAEMON_FIELDS)
        except ValueError as e:
            messagebox.showerror("输入有误", str(e), parent=self)
            return False
        return True

    def _commit_section(self, name: str, fields) -> None:
        sec = dict(self.cfg.get(name, {}))
        for key, label, kind, _ in fields:
            text = self.vars[key].get().strip()
            if text == "":
                sec.pop(key, None)
            else:
                sec[key] = _parse(kind, text, label)
        if sec:
            self.cfg[name] = sec
        else:
            self.cfg.pop(name, None)

    def _commit_bastion(self, old: str) -> None:
        new = self.vars["__name"].get().strip()
        if not NAME_RE.match(new):
            raise ValueError("跳板机名字只能包含字母、数字、. _ -，且不能为空")
        if new != old and new in self.bastions:
            raise ValueError(f"跳板机名字 {new!r} 已存在")
        bc = dict(self.bastions[old])
        for key, label, kind, _ in BASTION_FIELDS:
            text = self.vars[key].get().strip()
            if text == "":
                bc.pop(key, None)
            else:
                bc[key] = _parse(kind, text, label)
        self.bastions = {(new if k == old else k): (bc if k == old else v)
                         for k, v in self.bastions.items()}
        if new != old:
            for hc in self.cfg["host"].values():
                if hc.get("bastion") == old:
                    hc["bastion"] = new
            self.current = ("bastion", new)

    def _commit_node(self, old: str) -> None:
        new = self.vars["__name"].get().strip()
        if not NAME_RE.match(new):
            raise ValueError("节点名只能包含字母、数字、. _ -，且不能为空")
        if new != old and new in self.cfg["host"]:
            raise ValueError(f"节点名 {new!r} 已存在")
        via = self.vars["via"].get() or "bastion"
        hc = dict(self.cfg["host"][old])
        for key, label, kind, _ in NODE_FIELDS:
            text = self.vars[key].get().strip()
            if text == "":
                hc.pop(key, None)
            else:
                hc[key] = _parse(kind, text, label)
        if via == "direct":
            hc.pop("bastion", None)  # direct nodes never go through a bastion
        if via == "bastion":
            hc.pop("via", None)  # default; keep the file minimal
        if hc.get("auth") == "key":
            hc.pop("auth", None)  # default
        # rename keeping order
        self.cfg["host"] = {(new if k == old else k): (hc if k == old else v)
                            for k, v in self.cfg["host"].items()}
        if new != old:
            allowed = self.cfg.get("hosts", {}).get("allowed")
            if allowed and old in allowed:
                allowed[allowed.index(old)] = new
            self.current = ("node", new)

    # ── 新增 / 删除 ──────────────────────────────────────
    def add_bastion(self) -> None:
        if not self.commit():
            return
        i = 1
        while f"bastion{i}" in self.bastions:
            i += 1
        name = "default" if not self.bastions else f"bastion{i}"
        self.bastions[name] = {}
        self.refresh_list()
        self.select(("bastion", name))
        self.dirty = True

    def delete_bastion(self) -> None:
        if not self.current or self.current[0] != "bastion":
            messagebox.showinfo("删除跳板机", "请先在左侧选中一台跳板机", parent=self)
            return
        name = self.current[1]
        users = [h for h, hc in self.cfg["host"].items() if hc.get("bastion") == name]
        extra = f"\n以下节点引用了它，会被清空“所属跳板机”：{', '.join(users)}" if users else ""
        if not messagebox.askyesno("删除跳板机", f"确定删除跳板机 {name}？{extra}\n（点“保存”后才会写入文件）",
                                   parent=self):
            return
        del self.bastions[name]
        for h in users:
            self.cfg["host"][h].pop("bastion", None)
        self.current = None
        self.refresh_list()
        self.select(self.first_target())
        self.dirty = True

    def add_node(self) -> None:
        if not self.commit():
            return
        i = 1
        while f"node{i}" in self.cfg["host"]:
            i += 1
        name = f"node{i}"
        self.cfg["host"][name] = {}
        allowed = self.cfg.get("hosts", {}).get("allowed")
        if allowed is not None:
            allowed.append(name)  # keep the new node reachable under an explicit whitelist
        self.refresh_list()
        self.select(("node", name))
        self.dirty = True

    def delete_node(self) -> None:
        if not self.current or self.current[0] != "node":
            messagebox.showinfo("删除节点", "请先在左侧选中一个节点", parent=self)
            return
        name = self.current[1]
        if not messagebox.askyesno("删除节点", f"确定删除节点 {name}？（点“保存”后才会写入文件）", parent=self):
            return
        del self.cfg["host"][name]
        allowed = self.cfg.get("hosts", {}).get("allowed")
        if allowed and name in allowed:
            allowed.remove(name)
        self.current = None
        self.refresh_list()
        self.select(self.first_target())
        self.dirty = True

    # ── 保存 / 关闭 ──────────────────────────────────────
    def save(self) -> bool:
        if not self.commit():
            return False
        cfg = {k: v for k, v in self.cfg.items() if k != "host" or v}
        if self.bastions:
            if list(self.bastions) == ["default"]:
                cfg["bastion"] = self.bastions["default"]
            else:
                cfg["bastion"] = self.bastions
        # keep section order stable: bastion first
        cfg = {k: cfg[k] for k in ("bastion", "daemon", "hosts", "host") if k in cfg} | {
            k: v for k, v in cfg.items() if k not in ("bastion", "daemon", "hosts", "host")}
        errors, warnings = pool.validate_config(cfg)
        if errors:
            messagebox.showerror("配置有误，未保存", "\n".join(errors), parent=self)
            return False
        try:
            config_io.save(cfg)
        except Exception as e:
            messagebox.showerror("保存失败", str(e), parent=self)
            return False
        self.refresh_list()
        self.select(self.current)  # redraw from the saved data; clears dirty
        print("config.toml 已保存" + ("".join("\n" + w for w in warnings)))
        if self.on_saved:
            self.on_saved(cfg)
        messagebox.showinfo("已保存", "配置已保存。" + ("\n\n" + "\n".join(warnings) if warnings else ""),
                            parent=self)
        return True

    def open_in_notepad(self) -> None:
        path = pool.CONFIG_PATH
        if not path.exists():
            messagebox.showinfo("用记事本打开", "config.toml 还不存在，请先保存一次。", parent=self)
            return
        if self.dirty:
            messagebox.showinfo("用记事本打开", "表单里有未保存的修改，记事本里看到的是上次保存的内容。", parent=self)
        try:
            os.startfile(path)  # type: ignore[attr-defined]  # Windows only
        except Exception as e:
            messagebox.showerror("无法打开", f"{path}\n{e}", parent=self)

    def close(self) -> None:
        if self.current and not self.commit():
            return
        if self.dirty and messagebox.askyesno("未保存", "有未保存的修改，是否保存？", parent=self):
            if not self.save():
                return
        self.destroy()
