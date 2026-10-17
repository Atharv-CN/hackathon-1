"""Server-side caller for the independent Render + Neon synthetic backup."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

TOKEN_RE = re.compile(r"^ptok_[A-Za-z0-9_-]{32}$")
REF_RE = re.compile(r"^mockpay_[A-Za-z0-9_-]{16}$")


class BackupError(Exception):
    """A safe message to show when the test backup cannot be reached."""


def build_payload(result, token_id: str) -> dict:
    """Exclude every card field. The mock provider result is the only input."""
    reference = getattr(result, "provider_ref", None)
    amount = getattr(result, "amount_paise", None)
    if (getattr(result, "status", None) != "succeeded"
            or getattr(result, "simulated", None) is not True
            or not isinstance(reference, str) or not REF_RE.fullmatch(reference)
            or not isinstance(token_id, str) or not TOKEN_RE.fullmatch(token_id)
            or type(amount) is not int or not 1 <= amount <= 10_000_000_000
            or getattr(result, "currency", None) != "INR"):
        raise BackupError("Only confirmed mock INR payments can use Neon backup.")
    return {
        "request_id": "TEST-" + reference,
        "token_id": token_id,
        "provider_reference": reference,
        "amount_minor": amount,
        "currency": "INR",
        "payment_status": "succeeded",
    }


def create_backup_handoff(result, token_id: str) -> dict:
    import relay

    base_url = (relay._setting("BACKUP_CREATOR_URL") or "").strip().rstrip("/")
    secret = (relay._setting("PRIMARY_TO_BACKUP_SECRET") or "").strip()
    parts = urlsplit(base_url)
    if parts.scheme != "https" or not parts.netloc or parts.path or parts.query:
        raise BackupError("Set BACKUP_CREATOR_URL to the HTTPS Render creator URL.")
    if not secret:
        raise BackupError("Set PRIMARY_TO_BACKUP_SECRET on the QShield server.")
    body = json.dumps(build_payload(result, token_id), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    timestamp = str(int(time.time()))
    path = "/v1/handoffs"
    signature = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + path.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    request = urllib.request.Request(
        base_url + path, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Timestamp": timestamp,
                 "X-Signature": signature},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        raise BackupError("Render creator returned HTTP " + str(exc.code) + ".") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BackupError("Could not reach the Render creator.") from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise BackupError("Render creator returned an invalid response.") from exc
    if (not isinstance(data, dict) or data.get("route") != "neon_standby"
            or data.get("request_id") != "TEST-" + result.provider_ref
            or data.get("wallet_status") not in ("pending", "accepted")):
        raise BackupError("Render creator returned an unexpected handoff.")
    return data
