"""Pay tab: end-to-end through the real Streamlit app, no card data left behind."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def fill(app, card, expiry="12/30", cvv="123", name="Test User"):
    app.text_input(key="pay_name").set_value(name)
    app.text_input(key="pay_card").set_value(card)
    app.text_input(key="pay_expiry").set_value(expiry)
    app.text_input(key="pay_cvv").set_value(cvv)
    next(b for b in app.button if b.label == "Pay (test mode)").click().run()


def test_pay_tab_loads_and_says_simulation():
    app = AppTest.from_file(APP).run()
    assert not app.exception
    assert any("Simulation only" in w.value for w in app.warning)


def test_successful_test_payment():
    app = AppTest.from_file(APP).run()
    fill(app, "4111 1111 1111 1111")
    assert not app.exception
    result = app.session_state["payment_result"]
    assert result.status == "succeeded" and result.simulated
    assert any("approved" in s.value for s in app.success)


def test_declined_test_payment():
    app = AppTest.from_file(APP).run()
    fill(app, "4000000000000002")
    assert app.session_state["payment_result"].status == "declined"
    assert any("declined" in e.value for e in app.error)


def test_real_card_refused_and_not_stored():
    app = AppTest.from_file(APP).run()
    fill(app, "4242424242424242")
    assert app.session_state["payment_result"] is None
    assert any("test cards" in e.value for e in app.error)


def test_two_payments_get_different_references_and_no_card_in_state():
    app = AppTest.from_file(APP).run()
    fill(app, "4111111111111111")
    first = app.session_state["payment_result"].provider_ref
    fill(app, "4111111111111111")
    second = app.session_state["payment_result"].provider_ref
    assert first != second
    state = {k: app.session_state[k] for k in app.session_state.keys()}
    assert "4111111111111111" not in repr(state)
    assert "4111 1111 1111 1111" not in repr(state)


def test_successful_payment_shows_token_with_status_created(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)
    app = AppTest.from_file(APP).run()
    fill(app, "4111111111111111")
    tok = app.session_state["payment_token"]
    assert tok.token.startswith("ptok_") and tok.status == "created"
    assert tok.token in [c.value for c in app.code]
    assert "4111111111111111" not in tok.token
    assert any("NOT persistent" in c.value for c in app.caption)  # memory store is labelled honestly


def test_declined_payment_creates_no_token():
    app = AppTest.from_file(APP).run()
    fill(app, "4000000000000002")
    assert app.session_state["payment_token"] is None


def test_new_payment_gets_new_token_and_failed_attempt_clears_old_success():
    app = AppTest.from_file(APP).run()
    fill(app, "4111111111111111")
    t1 = app.session_state["payment_token"].token
    fill(app, "5555555555554444")
    t2 = app.session_state["payment_token"].token
    assert t1 != t2
    fill(app, "4242424242424242")  # refused -> nothing from the old payment left on screen
    assert app.session_state["payment_result"] is None
    assert app.session_state["payment_token"] is None


def test_app_is_payments_only_no_file_transfer_screens():
    app = AppTest.from_file(APP).run()
    assert not app.exception
    assert [t.label for t in app.tabs] == ["Pay", "Wallet"]
    text = " ".join(m.value for m in app.markdown)
    assert "Receive" not in text and "Encrypt a file" not in text
    # the only file input left is the Wallet person's private key
    assert [u.key for u in app.file_uploader] == ["wallet_key_file"]
