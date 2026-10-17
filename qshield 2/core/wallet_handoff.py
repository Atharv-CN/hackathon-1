"""Payments -> Wallet handoff, protected by QShield.

Payments puts the payment details in one message, SIGNS it with the Payments
identity (hybrid Ed25519 + ML-DSA-65) and LOCKS it for the Wallet team's public
key (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM). This file adds no cryptography:
it calls core/transfer_flow.py -> core/signed_transfer.py ("package version 2").

What is inside the locked message (JSON):
    token, payment_ref, amount, currency, and the TEST card number, expiry and name.
What is NOT inside, on purpose:
    the CVV. A CVV must not be kept after a payment is authorised, so it is never
    put in the handoff, never stored, and never logged.

Who holds which key:
    Payments service : the Wallet PUBLIC key + its own signing identity
                       (settings below; secret ones go in host env vars, never in git)
    Wallet person    : the Wallet PRIVATE key file + password. It is NOT on the server.
                       The Wallet tab asks for it each time a handoff is opened.

The Wallet side refuses a handoff unless ALL of these hold:
    - it can be unlocked with the Wallet private key,
    - it is signed by the Payments identity whose fingerprint the Wallet person
      typed in (confirmed over a phone call, not taken from the server),
    - it is not older than the age limit,
    - the token inside exists, matches the stored payment, and is in status 'sent'.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

from core import transfer_flow
from core.mock_provider import luhn_valid
from core.token_store import TOKEN_RE, TokenError

HANDOFF_VERSION = 1
HANDOFF_FILENAME = "handoff.json"
HANDOFF_MAX_AGE_SECONDS = 24 * 3600

SETTING_WALLET_PUBLIC_KEY = "WALLET_PUBLIC_KEY"
SETTING_SIGNING_IDENTITY = "PAYMENTS_SIGNING_IDENTITY_B64"
SETTING_SIGNING_PASSWORD = "PAYMENTS_SIGNING_PASSWORD"
SETTING_PAYMENTS_PUBLIC = "PAYMENTS_PUBLIC_IDENTITY"  # public; lets the Wallet tab prefill


class HandoffError(Exception):
    """A plain-English reason the handoff could not be made or was refused."""


@dataclass(frozen=True)
class HandoffConfig:
    wallet_public_key: str
    signing_identity: bytes
    signing_password: str
    payments_public_identity: str = ""


def _default_getter(name: str):
    import relay  # same place the app reads SUPABASE_* from (env vars or Streamlit secrets)

    return relay._setting(name)


def load_config(getter=None) -> tuple[HandoffConfig | None, list[str]]:
    """Return (config, []) if everything needed is set, else (None, missing names)."""
    getter = getter or _default_getter
    values = {n: (getter(n) or "").strip() for n in
              (SETTING_WALLET_PUBLIC_KEY, SETTING_SIGNING_IDENTITY, SETTING_SIGNING_PASSWORD)}
    missing = [n for n, v in values.items() if not v]
    if missing:
        return None, missing
    try:
        identity = base64.b64decode(values[SETTING_SIGNING_IDENTITY], validate=True)
    except Exception:
        return None, [SETTING_SIGNING_IDENTITY + " (not valid base64)"]
    return HandoffConfig(
        wallet_public_key=values[SETTING_WALLET_PUBLIC_KEY],
        signing_identity=identity,
        signing_password=values[SETTING_SIGNING_PASSWORD],
        payments_public_identity=(getter(SETTING_PAYMENTS_PUBLIC) or "").strip(),
    ), []


def build_handoff(config: HandoffConfig, *, token, payment, card_number: str, expiry: str,
                  cardholder: str) -> bytes:
    """Make the signed + locked package. Card details are used here and not kept."""
    number = re.sub(r"[ -]", "", card_number or "")
    if not number.isdigit() or not luhn_valid(number):
        raise HandoffError("The card number is not usable for a handoff.")
    if token.payment_ref != payment.provider_ref or payment.status != "succeeded":
        raise HandoffError("The token does not belong to this successful payment.")
    body = {
        "v": HANDOFF_VERSION,
        "token": token.token,
        "payment_ref": payment.provider_ref,
        "amount_paise": payment.amount_paise,
        "currency": payment.currency,
        "card": {"number": number, "expiry": expiry.strip(), "name": cardholder.strip()},
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    try:
        return transfer_flow.sign_and_encrypt_uploaded_file(
            raw, HANDOFF_FILENAME, config.wallet_public_key,
            config.signing_identity, config.signing_password,
        )
    except Exception as exc:
        raise HandoffError(f"Could not sign and lock the handoff ({type(exc).__name__}): {exc}") from exc


@dataclass(frozen=True)
class OpenedHandoff:
    token: str
    payment_ref: str
    amount_paise: int
    currency: str
    card_number: str = field(repr=False)  # never shown in logs/tracebacks
    expiry: str = ""
    cardholder: str = ""
    sender_fingerprint: str = ""
    created_at: int = 0
    package_id: str = ""
    verified: bool = True

    @property
    def card_masked(self) -> str:
        return f"{self.card_number[:4]} •••• •••• {self.card_number[-4:]}"


def open_handoff(package: bytes, *, wallet_private_pem: bytes, wallet_password: str,
                 payments_public_text: str, expected_fingerprint: str, store,
                 max_age_seconds: int = HANDOFF_MAX_AGE_SECONDS) -> OpenedHandoff:
    """Unlock and verify a handoff. Returns it only if EVERY check passes."""
    if not (expected_fingerprint or "").strip():
        raise HandoffError(
            "NOT verified: enter the Payments fingerprint (confirm it by phone). "
            "Nothing was opened."
        )
    if not (payments_public_text or "").strip():
        raise HandoffError("NOT verified: the Payments public identity is missing.")
    try:
        trusted = transfer_flow.trusted_sender_from_text(
            payments_public_text.strip(), expected_fingerprint.strip()
        )
    except Exception as exc:
        raise HandoffError(
            "NOT verified: that fingerprint does not match the Payments identity "
            f"({type(exc).__name__}). Do not trust this handoff."
        ) from exc
    try:
        verified = transfer_flow.verify_uploaded_package(
            package, wallet_private_pem, wallet_password, trusted,
            max_age_seconds=max_age_seconds,
        )
    except Exception as exc:
        raise HandoffError(
            f"Refused ({type(exc).__name__}): {exc}. Nothing was released."
        ) from exc

    data = _parse(verified.data)
    _check_against_store(data, store)
    return OpenedHandoff(
        token=data["token"], payment_ref=data["payment_ref"],
        amount_paise=data["amount_paise"], currency=data["currency"],
        card_number=data["card"]["number"], expiry=data["card"]["expiry"],
        cardholder=data["card"]["name"], sender_fingerprint=verified.sender_fingerprint,
        created_at=verified.created_at, package_id=verified.package_id,
    )


def _parse(raw: bytes) -> dict:
    try:
        data = json.loads(raw)
        card = data["card"]
        ok = (
            data.get("v") == HANDOFF_VERSION
            and set(data) == {"v", "token", "payment_ref", "amount_paise", "currency", "card"}
            and set(card) == {"number", "expiry", "name"}
            and isinstance(data["token"], str) and TOKEN_RE.match(data["token"])
            and isinstance(data["payment_ref"], str)
            and isinstance(data["amount_paise"], int) and not isinstance(data["amount_paise"], bool)
            and isinstance(data["currency"], str)
            and all(isinstance(card[k], str) for k in card)
            and card["number"].isdigit() and luhn_valid(card["number"])
        )
    except Exception:
        ok = False
    if not ok:
        raise HandoffError("The handoff is signed but its contents are not in the expected format.")
    return data


def _check_against_store(data: dict, store) -> None:
    try:
        rec = store.get(data["token"])
    except TokenError as exc:
        raise HandoffError(str(exc)) from exc
    if rec is None:
        raise HandoffError("Unknown token: Payments has no record of it.")
    if rec.payment_ref != data["payment_ref"] or rec.amount_paise != data["amount_paise"]:
        raise HandoffError("The handoff does not match the stored payment. Do not approve it.")
    if rec.status != "sent":
        raise HandoffError(f"This token is '{rec.status}', not 'sent'. It cannot be approved now.")


def payments_fingerprint(config: HandoffConfig) -> str | None:
    """The Payments identity fingerprint, for reading out over a phone call."""
    from core import signatures

    if not config.payments_public_identity:
        return None
    try:
        return signatures.PublicIdentity.from_text(config.payments_public_identity).fingerprint(pretty=True)
    except Exception:
        return None
