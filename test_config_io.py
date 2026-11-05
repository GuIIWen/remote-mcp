"""Unit tests for config_io.py:  python -m unittest test_config_io -v"""
import tempfile
import unittest
from pathlib import Path

import config_io
import pool


class RoundTripTests(unittest.TestCase):
    def test_round_trip(self):
        cfg = {
            "bastion": {"host": "b.example.com", "port": 22, "user": "me", "password": 'p"w\\d'},
            "daemon": {"port": 8765, "heartbeat_interval": 1.5, "audit_log": "C:\\x\\a.jsonl"},
            "hosts": {"allowed": ["dev1", "lab*"]},
            "host": {
                "dev1": {"user": "me", "default_cwd": "/home/me"},
                "lab.3": {"via": "direct", "address": "1.2.3.4", "port": 2222, "auth": "key"},
                "中文": {"user": "u"},
            },
        }
        self.assertEqual(pool.tomllib.loads(config_io.dumps(cfg)), cfg)

    def test_round_trip_multi_bastion(self):
        cfg = {"bastion": {"a": {"host": "ha", "user": "u"}, "b": {"host": "hb", "user": "v"}},
               "host": {"n": {"via": "hop", "bastion": "b"}}}
        self.assertEqual(pool.tomllib.loads(config_io.dumps(cfg)), cfg)

    def test_save_makes_backup(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.toml"
            p.write_text("# old\n[daemon]\nport = 1\n", encoding="utf-8")
            config_io.save({"daemon": {"port": 2}}, p)
            self.assertIn("port = 2", p.read_text(encoding="utf-8"))
            self.assertIn("# old", (Path(d) / "config.toml.bak").read_text(encoding="utf-8"))
            self.assertEqual(config_io.load(p), {"daemon": {"port": 2}})

    def test_load_missing_is_empty(self):
        self.assertEqual(config_io.load(Path("nope-does-not-exist.toml")), {})


if __name__ == "__main__":
    unittest.main()
