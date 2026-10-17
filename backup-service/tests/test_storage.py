"""Check the independent Neon SQL contract without cloud credentials."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from storage import NeonStore


class FakeCursor:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, query, parameters):
        self.calls.append((query, parameters))

    def fetchone(self):
        return ("TEST-REQUEST-1",)


class FakeConnection:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def cursor(self):
        return FakeCursor(self.calls)


class StorageTests(unittest.TestCase):
    def test_insert_and_conditional_accept_use_neon_connection(self):
        calls = []

        def connect(url, **options):
            self.assertEqual(url, "postgresql://demo:secret@neon.example/demo")
            self.assertEqual(options["sslmode"], "require")
            return FakeConnection(calls)

        record = {"request_id": "TEST-REQUEST-1", "token_id": "ptok_" + "a" * 32,
                  "request_digest": "d" * 64, "version": 1, "nonce": "nonce",
                  "ciphertext": "ciphertext", "wallet_status": "pending", "route": "neon_standby"}
        with patch.dict(os.environ, {"BACKUP_DATABASE_URL": "postgresql://demo:secret@neon.example/demo"}):
            store = NeonStore(connect=connect)
            store.create(record)
            self.assertTrue(store.accept("TEST-REQUEST-1", "wallet-demo", "2026-01-01T00:00:00Z"))
        self.assertIn("ON CONFLICT (request_id) DO NOTHING", calls[0][0])
        self.assertEqual(calls[0][1][0], "TEST-REQUEST-1")
        self.assertIn("wallet_status = 'pending'", calls[1][0])
        self.assertEqual(calls[1][1][2], "TEST-REQUEST-1")


if __name__ == "__main__":
    unittest.main()
