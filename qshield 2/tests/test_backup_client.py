"""The QShield backup request contains no card details."""
import unittest
import hashlib
import hmac
import io
import json
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch

from core.backup_client import BackupError, build_payload, create_backup_handoff


@dataclass
class Result:
    status: str = "succeeded"
    provider_ref: str = "mockpay_abcdefghijklmnop"
    amount_paise: int = 49900
    currency: str = "INR"
    simulated: bool = True
    brand: str = "Visa"
    last4: str = "1111"
    card_number: str = "4111111111111111"


class BackupClientTests(unittest.TestCase):
    def test_payload_contains_only_synthetic_fields(self):
        payload = build_payload(Result(), "ptok_" + "a" * 32)
        self.assertEqual(set(payload), {"request_id", "token_id", "provider_reference",
                                        "amount_minor", "currency", "payment_status"})
        self.assertNotIn("4111111111111111", repr(payload))
        self.assertEqual(payload["amount_minor"], 49900)
        self.assertEqual(payload["request_id"], "TEST-mockpay_abcdefghijklmnop")

    def test_refuses_unconfirmed_result(self):
        with self.assertRaises(BackupError):
            build_payload(Result(status="declined"), "ptok_" + "a" * 32)

    def test_sends_signed_card_free_request(self):
        def setting(name):
            return {"BACKUP_CREATOR_URL": "https://creator.example",
                    "PRIMARY_TO_BACKUP_SECRET": "creator-secret"}.get(name)

        def urlopen(request, timeout):
            self.assertEqual(request.full_url, "https://creator.example/v1/handoffs")
            self.assertEqual(timeout, 90)
            self.assertNotIn(b"4111111111111111", request.data)
            headers = {key.lower(): value for key, value in request.header_items()}
            signed = (headers["x-timestamp"].encode() + b"./v1/handoffs." + request.data)
            signature = hmac.new(b"creator-secret", signed, hashlib.sha256).hexdigest()
            self.assertEqual(headers["x-signature"], signature)
            return io.BytesIO(json.dumps({"request_id": "TEST-mockpay_abcdefghijklmnop",
                                          "route": "neon_standby", "wallet_status": "pending"}).encode())

        with patch.dict(sys.modules, {"relay": SimpleNamespace(_setting=setting)}), \
                patch("urllib.request.urlopen", side_effect=urlopen):
            response = create_backup_handoff(Result(), "ptok_" + "a" * 32)
        self.assertEqual(response["wallet_status"], "pending")


if __name__ == "__main__":
    unittest.main()
