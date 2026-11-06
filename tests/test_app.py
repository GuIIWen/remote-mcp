"""Unit tests for app.py's window-close handling (no Tk window is created).
Run from the repo root:  python -m unittest tests.test_app -v"""
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import app


def fake_app(alive=True):
    thread = mock.Mock(**{"is_alive.side_effect": lambda: alive})
    thread.join.side_effect = AssertionError("on_close must not block the Tk thread")
    self = SimpleNamespace(closing=False, thread=thread, root=mock.Mock(), stop=mock.Mock())
    self._wait_exit = lambda deadline: app.App._wait_exit(self, deadline)
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


if __name__ == "__main__":
    unittest.main()
