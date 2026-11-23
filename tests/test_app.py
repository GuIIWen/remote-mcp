"""Unit tests for app.py's window-close handling (no Tk window is created).
Run from the repo root:  python -m unittest tests.test_app -v"""
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import app
import config_editor
from config_editor import ConfigEditor


def fake_app(alive=True):
    thread = mock.Mock(**{"is_alive.side_effect": lambda: alive})
    thread.join.side_effect = AssertionError("on_close must not block the Tk thread")
    self = SimpleNamespace(closing=False, thread=thread, root=mock.Mock(), stop=mock.Mock(), tray=None)
    self._wait_exit = lambda deadline: app.App._wait_exit(self, deadline)
    self.destroy_window = lambda: app.App.destroy_window(self)
    return self


class OnCloseTests(unittest.TestCase):
    def test_closing_a_running_service_polls_instead_of_joining(self):
        self = fake_app()
        with mock.patch.object(app.messagebox, "askyesno", return_value=True):
            app.App.on_close(self)
        self.stop.assert_called_once()
        self.root.after.assert_called_once()  # Tk stays responsive between polls
        self.root.destroy.assert_not_called()

    def test_window_is_destroyed_once_the_service_thread_is_gone(self):
        self = fake_app(alive=False)
        app.App._wait_exit(self, time.monotonic() + 100)
        self.root.destroy.assert_called_once()

    def test_window_is_destroyed_at_the_deadline_even_if_the_thread_hangs(self):
        self = fake_app(alive=True)
        app.App._wait_exit(self, time.monotonic() - 1)
        self.root.destroy.assert_called_once()

    def test_declining_keeps_the_window_and_a_second_click_is_ignored(self):
        self = fake_app()
        with mock.patch.object(app.messagebox, "askyesno", return_value=False):
            app.App.on_close(self)
        self.stop.assert_not_called()
        self.closing = True
        app.App.on_close(self)
        self.root.destroy.assert_not_called()

    def test_idle_window_closes_immediately(self):
        self = fake_app(alive=False)
        app.App.on_close(self)
        self.root.destroy.assert_called_once()


class CopyNodeTests(unittest.TestCase):
    def test_copies_current_draft_with_unique_name(self):
        source = {"via": "direct", "address": "example.invalid", "extra": {"value": [1]}}
        name_entry = mock.Mock()
        editor = SimpleNamespace(
            current=("node", "lab"),
            cfg={"host": {"lab": source, "lab-copy": {}}, "hosts": {"allowed": ["lab"]}},
            commit=mock.Mock(return_value=True),
            refresh_list=mock.Mock(),
            select=mock.Mock(),
            ctrls={"__name": (None, [name_entry], "str")},
            dirty=False,
        )
        ConfigEditor.copy_node(editor)
        editor.commit.assert_called_once()
        editor.select.assert_called_once_with(("node", "lab-copy-2"))
        self.assertEqual(editor.cfg["hosts"]["allowed"], ["lab"])
        copied = editor.cfg["host"]["lab-copy-2"]
        self.assertEqual(copied, source)
        copied["extra"]["value"].append(2)
        self.assertEqual(source["extra"]["value"], [1])
        self.assertTrue(editor.dirty)


class AuthRecoveryTests(unittest.TestCase):
    def test_pending_auth_recovers_normal_minimization_but_respects_tray(self):
        for in_tray, bastion in ((False, None), (False, "jump-a"), (True, None)):
            with self.subTest(in_tray=in_tray, bastion=bastion):
                ui = SimpleNamespace(root=mock.Mock(), in_tray=in_tray, tray=mock.Mock(),
                                     refresh_recovery=mock.Mock(), recovery_message=mock.Mock())
                ui.root.state.return_value = "iconic"
                ui.open_auth_dialog = lambda: app.App.open_auth_dialog(ui)
                request = app._AuthRequest(
                    bastion, "password:", False, mock.Mock(**{"done.return_value": False}), mock.Mock(),
                )

                def create_dialog(*_args):
                    ui.root.deiconify.assert_called_once()
                    return mock.Mock()

                with mock.patch.object(app, "_PromptDialog", side_effect=create_dialog) as dialog:
                    app.App.set_pending_auth(ui, request)
                if in_tray:
                    ui.root.deiconify.assert_not_called()
                    ui.tray.notify.assert_called_once()
                else:
                    ui.root.deiconify.assert_called_once()
                    ui.tray.notify.assert_not_called()
                self.assertEqual(dialog.call_count, int(not in_tray))

    def test_live_outage_replaces_past_recovery_message(self):
        conn = object()
        ui = SimpleNamespace(pending_auth=None, service_state="running", recovering_bastion=None,
                             recovery_result=("a", True, "已连接"), _recovery_connection=conn,
                             recovery_panel=mock.Mock(), recovery_message=mock.Mock(),
                             recovery_button=mock.Mock(), body=mock.Mock(), recover_bastion=mock.Mock(),
                             dismiss_recovery_result=mock.Mock())
        ui.unavailable_bastion = mock.Mock(return_value="b")
        ui.bastion_message = lambda name, detail: f"{name} {detail}"
        with mock.patch.object(app.pool, "_bastion_conns", {"a": conn}):
            app.App.refresh_recovery(ui)
            ui.recovery_message.set.assert_called_with("b 未连接")
            self.assertEqual(ui.recovery_button.configure.call_args.kwargs["text"], "重新验证")
        ui.unavailable_bastion.return_value = "a"
        with mock.patch.object(app.pool, "_bastion_conns", {}):
            app.App.refresh_recovery(ui)
        self.assertIsNone(ui.recovery_result)
        ui.recovery_message.set.assert_called_with("a 未连接")


class InvalidNodeAccessTests(unittest.TestCase):
    def test_invalid_permission_values_are_editable(self):
        for invalid in ([], {}, "unrecognized"):
            with self.subTest(invalid=invalid):
                editor = SimpleNamespace(clear_form=mock.Mock(), title_lbl=mock.Mock(), add_row=mock.Mock(),
                                         layout_node_rows=mock.Mock(), form=mock.Mock(),
                                         cfg={"host": {"test": {"via": "direct", "access": invalid}}})
                with mock.patch.object(config_editor.tk, "Label"):
                    ConfigEditor.show(editor, ("node", "test"))
                access_row = next(c.args for c in editor.add_row.call_args_list if c.args[0] == "access")
                self.assertEqual(access_row[-1], "")
                self.assertIn("权限值无效", access_row[-2])
                fields = {"__name": "test", "via": "direct", "access": "仅查看"}
                editor.vars = {
                    key: mock.Mock(**{"get.return_value": fields.get(key, "")})
                    for key in ["__name", *(field[0] for field in config_editor.NODE_FIELDS)]
                }
                ConfigEditor._commit_node(editor, "test")
                self.assertEqual(editor.cfg["host"]["test"]["access"], "read_only")


if __name__ == "__main__":
    unittest.main()
