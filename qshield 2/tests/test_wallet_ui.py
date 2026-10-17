"""Full path through the real app: Pay -> encrypted handoff -> Wallet opens, verifies, approves."""
import base64
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from core import transfer_flow
from core.token_store import get_store

APP = str(Path(__file__).resolve().parents[1] / "app.py")
WALLET_PW, PAY_PW = "wallet-password-1", "payments-password-1"
CARD = "4111111111111111"


@pytest.fixture(scope="module")
def keys():
    return (transfer_flow.create_recipient_key_bundle(WALLET_PW, suite=1),
            transfer_flow.create_sender_identity_bundle(PAY_PW))


@pytest.fixture
def configured(monkeypatch, keys):
    wallet, payments = keys
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)
    monkeypatch.setenv("WALLET_PUBLIC_KEY", wallet.public_text)
    monkeypatch.setenv("PAYMENTS_SIGNING_IDENTITY_B64", base64.b64encode(payments.protected_file).decode())
    monkeypatch.setenv("PAYMENTS_SIGNING_PASSWORD", PAY_PW)
    monkeypatch.setenv("PAYMENTS_PUBLIC_IDENTITY", payments.public_text)


def pay(app, card=CARD):
    app.text_input(key="pay_name").set_value("Test User")
    app.text_input(key="pay_card").set_value(card)
    app.text_input(key="pay_expiry").set_value("12/30")
    app.text_input(key="pay_cvv").set_value("123")
    next(b for b in app.button if b.label == "Pay (test mode)").click().run()


def open_in_wallet(app, keys, *, fingerprint, password=WALLET_PW):
    wallet, payments = keys
    app.checkbox(key="wallet_use_session").set_value(True)
    app.file_uploader(key="wallet_key_file").upload("wallet.pem", wallet.protected_pem)
    app.text_input(key="wallet_key_pw").set_value(password)
    app.text_input(key="wallet_fp").set_value(fingerprint)
    app.button(key="wallet_open_btn").click().run()


def test_payment_is_encrypted_for_wallet_and_token_becomes_sent(configured):
    app = AppTest.from_file(APP).run()
    pay(app)
    assert not app.exception
    ss = app.session_state
    assert ss["handoff_error"] is None
    package = ss["handoff_package"]
    assert package and CARD.encode() not in package
    assert ss["payment_token"].status == "sent"
    assert any("encrypted with QShield" in s.value for s in app.success)
    # the card number, expiry and CVV are not left anywhere in the Pay-tab state
    state = repr({k: ss[k] for k in ss.keys() if k != "handoff_package"})
    assert CARD not in state


def test_not_configured_sends_nothing_and_says_so(monkeypatch):
    for name in ("WALLET_PUBLIC_KEY", "PAYMENTS_SIGNING_IDENTITY_B64", "PAYMENTS_SIGNING_PASSWORD",
                 "SUPABASE_URL", "SUPABASE_SERVICE_KEY"):
        monkeypatch.delenv(name, raising=False)
    app = AppTest.from_file(APP).run()
    pay(app)
    assert app.session_state["handoff_package"] is None
    assert app.session_state["payment_token"].status == "created"
    assert any("NOTHING was sent" in w.value for w in app.warning)


def test_wallet_opens_verifies_and_approves(configured, keys):
    app = AppTest.from_file(APP).run()
    pay(app)
    token = app.session_state["payment_token"].token
    open_in_wallet(app, keys, fingerprint=keys[1].fingerprint)
    assert not app.exception
    opened = app.session_state["wallet_opened"]
    assert opened is not None and opened.token == token and opened.card_number == CARD
    assert any("VERIFIED" in s.value for s in app.success)
    app.button(key="wallet_approve").click().run()
    assert get_store().get(token).status == "approved"
    assert any("approved" in s.value for s in app.success)


def test_wallet_refuses_without_fingerprint_and_with_wrong_password(configured, keys):
    app = AppTest.from_file(APP).run()
    pay(app)
    token = app.session_state["payment_token"].token
    open_in_wallet(app, keys, fingerprint="")
    assert app.session_state["wallet_opened"] is None
    assert any("NOT verified" in e.value for e in app.error)
    open_in_wallet(app, keys, fingerprint=keys[1].fingerprint, password="wrong-password-x")
    assert app.session_state["wallet_opened"] is None
    assert any("Refused" in e.value for e in app.error)
    assert get_store().get(token).status == "sent"  # nothing changed


def test_wallet_can_reject(configured, keys):
    app = AppTest.from_file(APP).run()
    pay(app)
    token = app.session_state["payment_token"].token
    open_in_wallet(app, keys, fingerprint=keys[1].fingerprint)
    app.button(key="wallet_reject").click().run()
    assert get_store().get(token).status == "rejected"
