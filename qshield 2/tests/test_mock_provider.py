"""Mock payment provider: test cards only, no card data kept, retries are safe."""
import dataclasses
from datetime import datetime, timezone

import pytest

from core.mock_provider import PaymentInputError, charge, luhn_valid

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


def pay(ledger, card="4111 1111 1111 1111", key="k1", expiry="12/30", cvv="123", amount=49900):
    return charge(card_number=card, expiry=expiry, cvv=cvv, amount_paise=amount,
                  idempotency_key=key, ledger=ledger, now=NOW)


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_success_card_succeeds_and_is_marked_simulated():
    r = pay({})
    assert r.status == "succeeded" and r.simulated is True
    assert r.last4 == "1111" and r.brand == "Visa"
    assert r.provider_ref.startswith("mockpay_")


def test_declined_cards():
    assert pay({}, card="4000000000000002").status == "declined"
    assert pay({}, card="4000000000009995").status == "declined"


def test_result_and_ledger_never_contain_card_number_or_cvv():
    ledger = {}
    r = pay(ledger, card="4111111111111111", cvv="987")
    blob = repr(dataclasses.asdict(r)) + repr(ledger)
    assert "4111111111111111" not in blob
    assert "987" not in blob


def test_real_looking_card_is_refused():
    # Passes Luhn but is not one of our documented test cards.
    with pytest.raises(PaymentInputError, match="test cards"):
        pay({}, card="4242424242424242")


def test_retry_with_same_key_returns_same_payment():
    ledger = {}
    first = pay(ledger, key="attempt-1")
    second = pay(ledger, key="attempt-1")
    assert second is first and len(ledger) == 1


def test_new_key_is_a_new_payment():
    ledger = {}
    a, b = pay(ledger, key="a"), pay(ledger, key="b")
    assert a.provider_ref != b.provider_ref and len(ledger) == 2


@pytest.mark.parametrize("kwargs, msg", [
    ({"card": "abcd"}, "digits"),
    ({"card": "4111111111111112"}, "not valid"),
    ({"expiry": "13/30"}, "01-12"),
    ({"expiry": "09/26"}, "expired"),
    ({"expiry": "1230"}, "MM/YY"),
    ({"cvv": "12"}, "CVV"),
    ({"amount": 0}, "between"),
    ({"amount": 10**9}, "between"),
    ({"key": ""}, "idempotency"),
])
def test_bad_input_rejected_and_nothing_recorded(kwargs, msg):
    ledger = {}
    with pytest.raises(PaymentInputError, match=msg):
        pay(ledger, **kwargs)
    assert ledger == {}
