"""A Windows notification-area icon driven by the Tk thread's message loop."""

import contextlib

import win32api
import win32con
import win32gui
from pywintypes import error as Win32Error


class WindowsTray:
    _notify_message = win32con.WM_APP + 1
    _balloon_click = win32con.WM_USER + 5

    def __init__(self, dispatch, *, open_window, stop_service, exit_app):
        self._dispatch = dispatch
        self._actions = (
            ("打开 Remote MCP", open_window),
            ("停止服务", stop_service),
            ("退出", exit_app),
        )
        self._module = win32api.GetModuleHandle(None)
        self._taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")
        wc = win32gui.WNDCLASS()
        wc.hInstance = self._module
        wc.lpszClassName = f"RemoteMcpTray{id(self)}"
        wc.lpfnWndProc = {
            self._taskbar_created: self._restore_icon,
            self._notify_message: self._on_notify,
            win32con.WM_COMMAND: self._on_command,
        }
        self._window_class = win32gui.RegisterClass(wc)
        self._hwnd = None
        try:
            self._hwnd = win32gui.CreateWindow(
                self._window_class, "Remote MCP", 0, 0, 0, 0, 0, 0, 0, self._module, None,
            )
            self._add_icon()
        except Exception:
            self.close()
            raise

    def _add_icon(self):
        icon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        flags = win32gui.NIF_ICON | win32gui.NIF_TIP | win32gui.NIF_MESSAGE
        win32gui.Shell_NotifyIcon(
            win32gui.NIM_ADD, (self._hwnd, 0, flags, self._notify_message, icon, "Remote MCP"),
        )

    def _restore_icon(self, *_):
        with contextlib.suppress(Win32Error):
            self._add_icon()
        return 0

    def _on_notify(self, hwnd, _msg, _wparam, event):
        if event in (win32con.WM_LBUTTONUP, self._balloon_click):
            self._dispatch(self._actions[0][1])
        elif event == win32con.WM_RBUTTONUP:
            menu = win32gui.CreatePopupMenu()
            try:
                for index, (label, _action) in enumerate(self._actions, 1):
                    win32gui.AppendMenu(menu, win32con.MF_STRING, index, label)
                x, y = win32gui.GetCursorPos()
                with contextlib.suppress(Win32Error):
                    win32gui.SetForegroundWindow(hwnd)
                win32gui.TrackPopupMenu(menu, win32con.TPM_RIGHTBUTTON, x, y, 0, hwnd, None)
                win32gui.PostMessage(hwnd, win32con.WM_NULL, 0, 0)
            finally:
                win32gui.DestroyMenu(menu)
        return 0

    def _on_command(self, _hwnd, _msg, wparam, _lparam):
        index = win32gui.LOWORD(wparam)
        if 1 <= index <= len(self._actions):
            self._dispatch(self._actions[index - 1][1])
        return 0

    def notify(self, text: str):
        with contextlib.suppress(Win32Error):
            win32gui.Shell_NotifyIcon(
                win32gui.NIM_MODIFY,
                (self._hwnd, 0, win32gui.NIF_INFO, 0, None, "", text[:240], 0, "Remote MCP"),
            )

    def close(self):
        if self._hwnd is not None:
            with contextlib.suppress(Win32Error):
                win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (self._hwnd, 0))
            win32gui.DestroyWindow(self._hwnd)
            self._hwnd = None
        win32gui.UnregisterClass(self._window_class, self._module)
