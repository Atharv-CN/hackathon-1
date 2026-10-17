import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logic import authenticate, canonical, request_digest, validate_handoff


class LogicTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "request_id": "TEST-REQUEST-42",
            "token_id": "ptok_" + "a" * 32,
            "provider_reference": "mockpay_" + "a" * 16,
            "amount_minor": 49900,
            "currency": "INR",
            "payment_status": "succeeded",
        }

    def test_accepts_only_synthetic_confirmed_payment(self):
        self.assertEqual(validate_handoff(self.payload), self.payload)
        for change in (
            {"provider_reference": "4242424242424242"},
            {"provider_reference": "TEST-PROVIDER-42"},
            {"currency": "EUR"},
            {"currency": "USD"},
            {"payment_status": "pending"},
            {"amount_minor": True},
            {"card_number": "4242424242424242"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_handoff({**self.payload, **change})

        usd = {**self.payload, "provider_reference": "TEST-PROVIDER-42", "currency": "USD"}
        self.assertEqual(validate_handoff(usd), usd)

    def test_canonical_digest_is_order_independent(self):
        reversed_payload = dict(reversed(list(self.payload.items())))
        self.assertEqual(request_digest(self.payload), request_digest(reversed_payload))

    def test_signed_request_rejects_changes_and_expiry(self):
        body = canonical(self.payload)
        timestamp = "1000"
        path = "/v1/handoffs"
        signature = hmac.new(b"demo-secret", timestamp.encode() + b"." + path.encode() + b"." + body,
                             hashlib.sha256).hexdigest()
        self.assertTrue(authenticate("demo-secret", timestamp, signature, path, body, now=1000))
        self.assertFalse(authenticate("demo-secret", timestamp, signature, path, body + b" ", now=1000))
        self.assertFalse(authenticate("demo-secret", timestamp, signature, "/v1/handoffs/other", body, now=1000))
        self.assertFalse(authenticate("demo-secret", timestamp, signature, path, body, now=1301))
        self.assertFalse(authenticate("other-secret", timestamp, signature, path, body, now=1000))


if __name__ == "__main__":
    unittest.main()
