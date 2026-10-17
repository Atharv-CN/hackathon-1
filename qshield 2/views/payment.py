"""Payment page: a fake test-card checkout backed by the MOCK provider."""

import secrets

import streamlit as st

from core.mock_provider import MAX_AMOUNT_PAISE, MIN_AMOUNT_PAISE, TEST_CARDS, PaymentInputError, charge
from core.backup_client import BackupError, create_backup_handoff
from core.token_store import TokenError, get_store, new_token
from core.wallet_handoff import HandoffError, build_handoff, load_config, payments_fingerprint
import relay


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
    ss["backup_handoff"] = ss["backup_error"] = ss["backup_token_id"] = None
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
        if ss.get("simulate_primary_outage"):
            _send_to_backup(result)
        else:
            _issue_token()
            if ss["payment_token"] is None:
                _send_to_backup(result)
            else:
                _send_to_wallet(number, expiry, name)


def _send_to_backup(result) -> None:
    """Send only the simulated payment result and random token to Neon standby."""
    ss = st.session_state
    ss["backup_handoff"] = ss["backup_error"] = None
    if ss.get("backup_token_id") is None:
        ss["backup_token_id"] = (ss["payment_token"].token if ss["payment_token"] else new_token())
    try:
        ss["backup_handoff"] = create_backup_handoff(result, ss["backup_token_id"])
        ss["payment_error"] = None
    except BackupError as exc:
        ss["backup_error"] = str(exc)


def _send_to_wallet(number: str, expiry: str, name: str) -> None:
    """Lock + sign the payment details for the Wallet team. This is the only moment the
    card details exist on the server; after this function returns they are gone.
    The CVV is never passed in and never sent."""
    ss = st.session_state
    ss["handoff_package"] = ss["handoff_code"] = ss["handoff_error"] = None
    token = ss["payment_token"]
    if token is None:
        return
    config, missing = load_config()
    if config is None:
        ss["handoff_error"] = (
            "Wallet handoff is not set up (missing: " + ", ".join(missing) + "). "
            "The card details were discarded and NOTHING was sent to Wallet."
        )
        return
    try:
        package = build_handoff(config, token=token, payment=ss["payment_result"],
                                card_number=number, expiry=expiry, cardholder=name)
        code = relay.put("package", package, "handoff.qshield") if relay.is_configured() else None
        ss["handoff_package"], ss["handoff_code"] = package, code
        ss["payment_token"] = get_store().advance(token.token, "sent")
    except (HandoffError, relay.RelayError, TokenError) as exc:
        ss["handoff_error"] = f"The handoff to Wallet failed: {exc}"


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
        st.checkbox("Simulate QShield + Supabase outage (use Neon backup)",
                    key="simulate_primary_outage")
        st.form_submit_button("Pay (test mode)", type="primary", on_click=_submit)

    if st.session_state.get("payment_error"):
        st.error(st.session_state["payment_error"])
    if st.session_state.get("backup_error"):
        st.error("Neon backup failed: " + st.session_state["backup_error"])

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
            backup = st.session_state.get("backup_handoff")
            if backup:
                st.info("Neon backup recorded this simulated payment; Wallet verification is pending.")
                st.code(backup["request_id"], language=None)
                st.caption("Backup token: " + st.session_state["backup_token_id"] +
                           " · Status: " + backup["wallet_status"] +
                           " · No card number or CVV was sent to Render.")
            elif token is None:
                st.button("Create token", on_click=_issue_token, key="pay_create_token")
                if st.session_state.get("backup_error"):
                    st.button("Retry Neon backup", on_click=_send_to_backup,
                              args=(result,), key="pay_retry_backup")
            else:
                st.markdown("**Payment token**")
                st.code(token.token, language=None)
                st.caption(
                    f"Status: **{token.status}** · a random reference, not the card number · "
                    f"Stored in: {get_store().name}"
                )
                _show_handoff()


def _show_handoff() -> None:
    ss = st.session_state
    if ss.get("handoff_error"):
        st.warning(ss["handoff_error"])
    package = ss.get("handoff_package")
    if package:
        st.success("🔐 Card details signed by Payments and encrypted with QShield for the Wallet team.")
        if ss.get("handoff_code"):
            st.markdown("**Handoff code for Wallet**")
            st.code(ss["handoff_code"], language=None)
        else:
            st.caption("Ready for Wallet in this browser session (open the Wallet tab). "
                       "To reach Wallet on another device, connect Supabase.")
        st.caption("The CVV is never sent or stored. The Wallet team opens this in the Wallet tab "
                   "with their private key.")
    config, _ = load_config()
    fp = payments_fingerprint(config) if config else None
    if fp:
        with st.expander("Payments fingerprint (read this to Wallet over a phone call)"):
            st.code(fp, language=None)
