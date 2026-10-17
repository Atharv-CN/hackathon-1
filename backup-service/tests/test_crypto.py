"""The Wallet must reject altered stored ciphertext and mismatched request IDs."""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto import StandbyCipher


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.cipher = StandbyCipher(base64.b64encode(bytes(range(32))).decode())

    def test_round_trip_and_tamper_rejection(self):
        envelope = self.cipher.encrypt("TEST-REQUEST-1", b"fake payment handoff")
        self.assertEqual(self.cipher.decrypt(envelope), b"fake payment handoff")
        changed = dict(envelope, request_id="TEST-REQUEST-2")
        with self.assertRaises(ValueError):
            self.cipher.decrypt(changed)
        raw = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw[0] ^= 1
        changed = dict(envelope, ciphertext=base64.b64encode(raw).decode())
        with self.assertRaises(ValueError):
            self.cipher.decrypt(changed)

    def test_rejects_invalid_key(self):
        with self.assertRaises(ValueError):
            StandbyCipher(base64.b64encode(b"too short").decode())

    def test_ignores_copied_whitespace_around_key(self):
        key = base64.b64encode(bytes(range(32))).decode()
        cipher = StandbyCipher(" \n" + key + "\n ")
        envelope = cipher.encrypt("TEST-REQUEST-1", b"synthetic")
        self.assertEqual(cipher.decrypt(envelope), b"synthetic")


if __name__ == "__main__":
    unittest.main()
