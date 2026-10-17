"""Payments -> Wallet handoff, with the REAL QShield crypto (no mocks of the crypto)."""
import base64
import json
import time
from datetime import datetime, timezone

import pytest

from core import transfer_flow
from core.mock_provider import charge
from core.token_store import MemoryTokenStore
from core.wallet_handoff import (
    HandoffConfig, HandoffError, build_handoff, load_config, open_handoff, payments_fingerprint,
)

WALLET_PW, PAY_PW = "wallet-password-1", "payments-password-1"
CARD = "4111111111111111"
NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def keys():
    wallet = transfer_flow.create_recipient_key_bundle(WALLET_PW, suite=1)
    payments = transfer_flow.create_sender_identity_bundle(PAY_PW)
    other_wallet = transfer_flow.create_recipient_key_bundle("other-wallet-pw-1", suite=1)
    attacker = transfer_flow.create_sender_identity_bundle("attacker-password-1")
    return wallet, payments, other_wallet, attacker


def config_for(keys):
    wallet, payments, *_ = keys
    return HandoffConfig(wallet.public_text, payments.protected_file, PAY_PW, payments.public_text)


def make(keys, store=None, advance=True, card=CARD):
    store = store or MemoryTokenStore()
    payment = charge(card_number=card, expiry="12/30", cvv="123", amount_paise=49900,
                     idempotency_key=str(time.time_ns()), ledger={}, now=NOW)
    token = store.issue(payment)
    package = build_handoff(config_for(keys), token=token, payment=payment,
                            card_number=card, expiry="12/30", cardholder="Test User")
    if advance:
        store.advance(token.token, "sent")
    return package, token, payment, store


def open_ok(keys, package, store, **over):
    wallet, payments, *_ = keys
    args = dict(wallet_private_pem=wallet.protected_pem, wallet_password=WALLET_PW,
                payments_public_text=payments.public_text,
                expected_fingerprint=payments.fingerprint, store=store)
    args.update(over)
    return open_handoff(package, **args)


def test_round_trip_opens_verified_with_right_contents(keys):
    package, token, payment, store = make(keys)
    opened = open_ok(keys, package, store)
    assert opened.verified and opened.token == token.token
    assert opened.payment_ref == payment.provider_ref and opened.amount_paise == 49900
    assert opened.card_number == CARD and opened.expiry == "12/30" and opened.cardholder == "Test User"
    assert opened.card_masked == "4111 •••• •••• 1111"
    assert opened.sender_fingerprint == keys[1].fingerprint
    assert CARD not in repr(opened)  # card number is hidden from repr/tracebacks


def test_nothing_readable_on_the_wire_and_no_cvv(keys):
    package, token, *_ = make(keys)
    for secret in (CARD.encode(), token.token.encode(), b"Test User", b"123"):
        assert secret not in package
    wallet, payments, *_ = keys
    # open it and make sure the CVV field does not exist at all
    pkg, tok, pay, store = make(keys)
    from core import transfer_flow as tf
    from core.pq_transfer import load_private_key_from_bytes
    from core import signed_transfer
    trusted = tf.trusted_sender_from_text(payments.public_text, payments.fingerprint)
    raw = signed_transfer.decrypt_and_verify(
        pkg, load_private_key_from_bytes(wallet.protected_pem, WALLET_PW), trusted).data
    assert "cvv" not in json.loads(raw)["card"] and b"cvv" not in raw.lower()


def test_wrong_wallet_key_cannot_open(keys):
    package, _, _, store = make(keys)
    other = keys[2]
    with pytest.raises(HandoffError, match="Refused"):
        open_ok(keys, package, store, wallet_private_pem=other.protected_pem,
                wallet_password="other-wallet-pw-1")


def test_wrong_password_cannot_open(keys):
    package, _, _, store = make(keys)
    with pytest.raises(HandoffError, match="Refused"):
        open_ok(keys, package, store, wallet_password="not-the-password")


def test_tampered_package_is_rejected(keys):
    package, _, _, store = make(keys)
    for index in (10, len(package) // 2, len(package) - 1):
        bad = bytearray(package)
        bad[index] ^= 0x01
        with pytest.raises(HandoffError, match="Refused"):
            open_ok(keys, bytes(bad), store)


def test_missing_fingerprint_means_not_verified_and_nothing_opens(keys):
    package, _, _, store = make(keys)
    for blank in ("", "   "):
        with pytest.raises(HandoffError, match="NOT verified"):
            open_ok(keys, package, store, expected_fingerprint=blank)


def test_wrong_fingerprint_is_rejected(keys):
    package, _, _, store = make(keys)
    attacker = keys[3]
    with pytest.raises(HandoffError, match="NOT verified"):
        open_ok(keys, package, store, expected_fingerprint=attacker.fingerprint)


def test_package_signed_by_someone_else_is_rejected(keys):
    wallet, payments, _, attacker = keys
    store = MemoryTokenStore()
    payment = charge(card_number=CARD, expiry="12/30", cvv="123", amount_paise=49900,
                     idempotency_key="x", ledger={}, now=NOW)
    token = store.issue(payment)
    fake = build_handoff(HandoffConfig(wallet.public_text, attacker.protected_file,
                                       "attacker-password-1", attacker.public_text),
                         token=token, payment=payment, card_number=CARD, expiry="12/30",
                         cardholder="Test User")
    store.advance(token.token, "sent")
    with pytest.raises(HandoffError, match="Refused"):  # Wallet trusts Payments, not the attacker
        open_ok(keys, fake, store)


def test_unsigned_v1_package_is_refused(keys):
    wallet, *_ = keys
    store = MemoryTokenStore()
    unsigned = transfer_flow.encrypt_uploaded_file(b"{}", "x.json", wallet.public_text)
    with pytest.raises(HandoffError, match="Refused"):
        open_ok(keys, unsigned, store)


def test_old_handoff_is_refused(keys):
    package, _, _, store = make(keys)
    with pytest.raises(HandoffError, match="Refused"):
        open_ok(keys, package, store, max_age_seconds=-1)


def test_token_must_exist_match_and_be_sent(keys):
    # unknown token (Payments has no record)
    package, *_ = make(keys)
    with pytest.raises(HandoffError, match="Unknown token"):
        open_ok(keys, package, MemoryTokenStore())
    # token still 'created' (never actually sent)
    package, _, _, store = make(keys, advance=False)
    with pytest.raises(HandoffError, match="not 'sent'"):
        open_ok(keys, package, store)
    # already approved: cannot be approved again through a replayed handoff
    package, token, _, store = make(keys)
    store.advance(token.token, "approved")
    with pytest.raises(HandoffError, match="not 'sent'"):
        open_ok(keys, package, store)


def test_build_refuses_bad_card_or_mismatched_token(keys):
    store = MemoryTokenStore()
    p1 = charge(card_number=CARD, expiry="12/30", cvv="123", amount_paise=49900, idempotency_key="a", ledger={}, now=NOW)
    p2 = charge(card_number=CARD, expiry="12/30", cvv="123", amount_paise=49900, idempotency_key="b", ledger={}, now=NOW)
    t1 = store.issue(p1)
    with pytest.raises(HandoffError, match="card number"):
        build_handoff(config_for(keys), token=t1, payment=p1, card_number="1234", expiry="12/30", cardholder="x")
    with pytest.raises(HandoffError, match="does not belong"):
        build_handoff(config_for(keys), token=t1, payment=p2, card_number=CARD, expiry="12/30", cardholder="x")


def test_load_config_reports_missing_and_bad_values(keys):
    wallet, payments, *_ = keys
    good = {"WALLET_PUBLIC_KEY": wallet.public_text,
            "PAYMENTS_SIGNING_IDENTITY_B64": base64.b64encode(payments.protected_file).decode(),
            "PAYMENTS_SIGNING_PASSWORD": PAY_PW, "PAYMENTS_PUBLIC_IDENTITY": payments.public_text}
    cfg, missing = load_config(good.get)
    assert cfg is not None and missing == []
    assert payments_fingerprint(cfg) == payments.fingerprint_pretty
    cfg, missing = load_config({}.get)
    assert cfg is None and set(missing) == {"WALLET_PUBLIC_KEY", "PAYMENTS_SIGNING_IDENTITY_B64", "PAYMENTS_SIGNING_PASSWORD"}
    cfg, missing = load_config(dict(good, PAYMENTS_SIGNING_IDENTITY_B64="!!!notbase64").get)
    assert cfg is None and "base64" in missing[0]
