"""MOCK payment provider for the QShield demo.

This is a SIMULATION. No bank, card network or real payment processor is
contacted and no money moves. Every result it returns carries `simulated=True`
and the UI must say so.

Safety rules built in:
  - Only the documented TEST cards below are accepted. Any other number (even a
    valid-looking real card) is refused, so nobody can type a real card here.
  - The full card number, expiry and CVV are used for the check and then thrown
    away. Only the brand and last 4 digits are returned or kept.
  - Idempotency: charging twice with the same idempotency key returns the first
    result instead of creating a second payment.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

# Documented test cards: number -> (outcome, message)
TEST_CARDS = {
    "4111111111111111": ("succeeded", "Payment approved (simulated)."),
    "5555555555554444": ("succeeded", "Payment approved (simulated)."),
    "4000000000000002": ("declined", "Card declined (simulated)."),
    "4000000000009995": ("declined", "Insufficient funds (simulated)."),
}

MIN_AMOUNT_PAISE = 100  # Rs 1.00
MAX_AMOUNT_PAISE = 10_000_000  # Rs 1,00,000 - this is only a demo


class PaymentInputError(ValueError):
    """Raised with a plain-English message when the form input is not usable."""


@dataclass(frozen=True)
class PaymentResult:
    status: str  # "succeeded" or "declined"
    provider_ref: str  # e.g. "mockpay_AbC..."; NOT a card number
    brand: str
    last4: str
    amount_paise: int
    currency: str
    message: str
    created_at: str
    simulated: bool = True  # always True: this module is a mock


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _brand(number: str) -> str:
    if number.startswith("4"):
        return "Visa"
    if number[:2] in {"51", "52", "53", "54", "55"}:
        return "Mastercard"
    return "Card"


def _clean_number(raw: str) -> str:
    number = re.sub(r"[ -]", "", raw or "")
    if not number.isdigit() or not 12 <= len(number) <= 19:
        raise PaymentInputError("Enter the card number using digits only.")
    if not luhn_valid(number):
        raise PaymentInputError("That card number is not valid.")
    return number


def _check_expiry(raw: str, now: datetime) -> None:
    match = re.fullmatch(r"\s*(\d{2})\s*/\s*(\d{2})\s*", raw or "")
    if not match:
        raise PaymentInputError("Enter the expiry as MM/YY.")
    month, year = int(match.group(1)), 2000 + int(match.group(2))
    if not 1 <= month <= 12:
        raise PaymentInputError("Expiry month must be 01-12.")
    if (year, month) < (now.year, now.month):
        raise PaymentInputError("This card has expired.")


def charge(
    *,
    card_number: str,
    expiry: str,
    cvv: str,
    amount_paise: int,
    idempotency_key: str,
    ledger: dict,
    currency: str = "INR",
    now: datetime | None = None,
) -> PaymentResult:
    """Run one simulated payment. `ledger` is a dict the caller keeps between
    calls; it only ever holds PaymentResult objects (no card data)."""
    now = now or datetime.now(timezone.utc)
    if not idempotency_key:
        raise PaymentInputError("Missing idempotency key.")
    if idempotency_key in ledger:
        return ledger[idempotency_key]  # retry: same payment, no second charge

    if not isinstance(amount_paise, int) or isinstance(amount_paise, bool):
        raise PaymentInputError("Amount must be a whole number of paise.")
    if not MIN_AMOUNT_PAISE <= amount_paise <= MAX_AMOUNT_PAISE:
        raise PaymentInputError("Amount must be between Rs 1 and Rs 1,00,000.")

    number = _clean_number(card_number)
    _check_expiry(expiry, now)
    if not re.fullmatch(r"\d{3}", cvv or ""):
        raise PaymentInputError("CVV must be 3 digits.")
    if number not in TEST_CARDS:
        raise PaymentInputError(
            "This is a demo. Only the listed test cards are accepted; "
            "never enter a real card."
        )

    outcome, message = TEST_CARDS[number]
    result = PaymentResult(
        status=outcome,
        provider_ref="mockpay_" + secrets.token_urlsafe(12),
        brand=_brand(number),
        last4=number[-4:],
        amount_paise=amount_paise,
        currency=currency,
        message=message,
        created_at=now.isoformat(timespec="seconds"),
    )
    ledger[idempotency_key] = result
    return result
