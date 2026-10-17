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
