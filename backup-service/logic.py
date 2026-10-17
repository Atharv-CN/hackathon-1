"""Pure validation, authentication, and envelope formatting for the standby path."""

import base64
import hashlib
import hmac
import json
import re
import time

TEST_ID = re.compile(r"^TEST-[A-Za-z0-9_-]{3,75}$")
MOCK_PAYMENT_REF = re.compile(r"^mockpay_[A-Za-z0-9_-]{16}$")
TOKEN_ID = re.compile(r"^ptok_[A-Za-z0-9_-]{32}$")
MAX_BODY_BYTES = 4096


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def validate_handoff(value):
    if not isinstance(value, dict) or set(value) != {
        "request_id", "token_id", "provider_reference", "amount_minor", "currency", "payment_status"
    }:
        raise ValueError("Expected the six synthetic handoff fields only.")
    if not isinstance(value["request_id"], str) or not TEST_ID.fullmatch(value["request_id"]):
        raise ValueError("Request ID must start with TEST-.")
    reference = value["provider_reference"]
    if not isinstance(reference, str):
        raise ValueError("Invalid synthetic provider reference.")
    if value["currency"] == "INR":
        if not MOCK_PAYMENT_REF.fullmatch(reference):
            raise ValueError("INR test payments need a mockpay_ reference.")
    elif value["currency"] == "USD":
        if not TEST_ID.fullmatch(reference):
            raise ValueError("USD test payments need a TEST- reference.")
    else:
        raise ValueError("Unsupported test currency.")
    if not isinstance(value["token_id"], str) or not TOKEN_ID.fullmatch(value["token_id"]):
        raise ValueError("Invalid test token ID.")
    if type(value["amount_minor"]) is not int or not 1 <= value["amount_minor"] <= 10_000_000_000:
        raise ValueError("Invalid amount in minor currency units.")
    if value["payment_status"] != "succeeded":
        raise ValueError("Only a confirmed test payment is supported.")
    return value


def request_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def authenticate(secret, timestamp, signature, path, body, now=None):
    if not secret or not timestamp or not signature or len(body) > MAX_BODY_BYTES:
        return False
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if now is None else now) - sent_at) > 300:
        return False
    try:
        message = timestamp.encode("ascii") + b"." + path.encode("ascii") + b"." + body
    except UnicodeEncodeError:
        return False
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


