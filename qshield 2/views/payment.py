"""Payment page: a fake test-card checkout backed by the MOCK provider."""

import secrets

import streamlit as st

from core.mock_provider import MAX_AMOUNT_PAISE, MIN_AMOUNT_PAISE, TEST_CARDS, PaymentInputError, charge
from core.token_store import TokenError, get_store


def _rupees(paise: int) -> str:
    return f"₹{paise / 100:,.2f}"


def _submit() -> None:
    """Runs when the form is submitted. Uses the card details once, then wipes
    them from session state so the full number never lingers in server memory."""
    ss = st.session_state
    name, number, expiry, cvv = ss["pay_name"], ss["pay_card"], ss["pay_expiry"], ss["pay_cvv"]
    amount_paise = int(round(ss["pay_amount"] * 100))
    ss["pay_card"] = ss["pay_expiry"] = ss["pay_cvv"] = ""  # wipe first, use local copies below
    ss["payment_error"] = None
    ss["payment_token"] = None
    ss["payment_result"] = None  # a failed attempt must not leave an old success on screen
    if not name.strip():
        ss["payment_error"] = "Enter the name on the card."
        return
    try:
        result = charge(
            card_number=number, expiry=expiry, cvv=cvv, amount_paise=amount_paise,
            idempotency_key=ss["payment_attempt_id"], ledger=ss["payment_ledger"],
        )
    except PaymentInputError as exc:
        ss["payment_error"] = str(exc)
        return
    ss["payment_result"] = result
    ss["payment_attempt_id"] = secrets.token_urlsafe(16)  # next submit = a NEW payment
    if result.status == "succeeded":
        _issue_token()


def _issue_token() -> None:
    """Make (or re-fetch) the token for the last successful payment. Safe to repeat:
    the same payment always gives the same token."""
    ss = st.session_state
    try:
        ss["payment_token"] = get_store().issue(ss["payment_result"])
        ss["payment_error"] = None
    except TokenError as exc:
        ss["payment_error"] = f"Payment succeeded, but the token was not saved: {exc}"


def show_payment() -> None:
    st.subheader("Pay (test mode)")
    st.warning(
        "**Simulation only.** This uses a mock payment provider: no bank is contacted "
        "and no money moves. Use the test cards below. Never enter a real card."
    )
    with st.expander("Test cards"):
        st.table(
            [{"Card number": n, "Result": msg} for n, (_, msg) in TEST_CARDS.items()]
            + [{"Card number": "Expiry / CVV", "Result": "Any future date (e.g. 12/30) / any 3 digits"}]
        )

    if st.session_state["payment_attempt_id"] is None:
        st.session_state["payment_attempt_id"] = secrets.token_urlsafe(16)

    with st.form("payment_form"):
        st.text_input("Name on card", key="pay_name")
        st.number_input(
            "Amount (₹)", min_value=MIN_AMOUNT_PAISE / 100, max_value=MAX_AMOUNT_PAISE / 100,
            value=499.0, step=1.0, key="pay_amount",
        )
        st.text_input("Test card number", key="pay_card", autocomplete="off")
        col1, col2 = st.columns(2)
        with col1:
            st.text_input("Expiry (MM/YY)", key="pay_expiry", autocomplete="off")
        with col2:
            st.text_input("CVV", type="password", max_chars=3, key="pay_cvv", autocomplete="off")
        st.form_submit_button("Pay (test mode)", type="primary", on_click=_submit)

    if st.session_state.get("payment_error"):
        st.error(st.session_state["payment_error"])

    result = st.session_state["payment_result"]
    if result is not None:
        if result.status == "succeeded":
            st.success(f"{result.message} {_rupees(result.amount_paise)} on {result.brand} •••• {result.last4}")
        else:
            st.error(f"{result.message} {result.brand} •••• {result.last4}")
        st.caption(f"Provider reference: `{result.provider_ref}` · {result.created_at} · SIMULATED")
        st.caption("Only the brand and last 4 digits are kept. The full card number is discarded.")

        if result.status == "succeeded":
            token = st.session_state["payment_token"]
            if token is None:
                st.button("Create token", on_click=_issue_token, key="pay_create_token")
            else:
                st.markdown("**Payment token**")
                st.code(token.token, language=None)
                st.caption(
                    f"Status: **{token.status}** · a random reference, not the card number · "
                    f"Stored in: {get_store().name}"
                )
