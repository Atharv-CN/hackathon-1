"""Wallet team screen: open the encrypted handoff, check who signed it, approve or reject."""

import streamlit as st

import relay
from core.token_store import TokenError, get_store
from core.wallet_handoff import HandoffError, load_config, open_handoff


def _package_bytes():
    ss = st.session_state
    uploaded = ss.get("wallet_pkg_file")
    if uploaded is not None:
        return uploaded.getvalue()
    code = (ss.get("wallet_code") or "").strip()
    if code:
        if not relay.is_configured():
            raise HandoffError("No relay is configured, so a code cannot be looked up. Upload the package file instead.")
        try:
            data, _name = relay.get(code, "package")
        except relay.RelayError as exc:
            raise HandoffError(str(exc)) from exc
        if data is None:
            raise HandoffError("No handoff found for that code.")
        return data
    if ss.get("wallet_use_session") and ss.get("handoff_package"):
        return ss["handoff_package"]
    raise HandoffError("Enter a handoff code, upload a package, or use the one from this session.")


def _open() -> None:
    ss = st.session_state
    ss["wallet_opened"] = ss["wallet_error"] = None
    key_file = ss.get("wallet_key_file")
    password = ss.get("wallet_key_pw") or ""
    ss["wallet_key_pw"] = ""  # don't leave the password sitting in the page state
    try:
        if key_file is None or not password:
            raise HandoffError("Upload your Wallet private key file and enter its password.")
        ss["wallet_opened"] = open_handoff(
            _package_bytes(),
            wallet_private_pem=key_file.getvalue(), wallet_password=password,
            payments_public_text=ss.get("wallet_payments_identity") or "",
            expected_fingerprint=ss.get("wallet_fp") or "",
            store=get_store(),
        )
    except HandoffError as exc:
        ss["wallet_error"] = str(exc)


def _decide(new_status: str) -> None:
    ss = st.session_state
    opened = ss["wallet_opened"]
    try:
        get_store().advance(opened.token, new_status)
    except TokenError as exc:
        ss["wallet_error"] = str(exc)


def show_wallet() -> None:
    ss = st.session_state
    st.subheader("Wallet team (receiver)")
    st.info(
        "Open a handoff from Payments. It is opened with **your** private key, which "
        "is never stored on this server, and only if it is signed by the Payments "
        "fingerprint you confirmed by phone."
    )
    config, _missing = load_config()

    st.text_input("Handoff code", key="wallet_code")
    st.file_uploader("…or upload a handoff package (.qshield)", key="wallet_pkg_file")
    st.checkbox("Use the handoff made in this browser session", key="wallet_use_session",
                disabled=ss.get("handoff_package") is None)
    st.file_uploader("Your Wallet private key file (.pem)", key="wallet_key_file")
    st.text_input("Private key password", type="password", key="wallet_key_pw")
    st.text_area("Payments public identity", key="wallet_payments_identity",
                 value=(config.payments_public_identity if config else ""), height=80)
    st.text_input("Payments fingerprint (read out to you over a phone call)", key="wallet_fp")
    st.button("Open and verify", type="primary", on_click=_open, key="wallet_open_btn")

    if ss.get("wallet_error"):
        st.error(ss["wallet_error"])

    opened = ss.get("wallet_opened")
    if opened is None:
        return
    st.success("✅ VERIFIED: signed by the Payments identity you confirmed, and opened with your key.")
    reveal = st.checkbox("Show full test card number", key="wallet_reveal")
    st.table([
        {"Field": "Token", "Value": opened.token},
        {"Field": "Amount", "Value": f"₹{opened.amount_paise / 100:,.2f} {opened.currency}"},
        {"Field": "Card (test)", "Value": opened.card_number if reveal else opened.card_masked},
        {"Field": "Expiry", "Value": opened.expiry},
        {"Field": "Cardholder", "Value": opened.cardholder},
        {"Field": "Payment reference", "Value": opened.payment_ref},
        {"Field": "Signed by (fingerprint)", "Value": opened.sender_fingerprint[:32] + "…"},
    ])
    st.caption("The CVV is never part of a handoff. These are TEST card details from a mock provider.")

    try:
        rec = get_store().get(opened.token)
    except TokenError as exc:
        st.error(str(exc))
        return
    status = rec.status if rec else "unknown"
    st.markdown(f"**Token status:** `{status}`")
    if status == "sent":
        col1, col2 = st.columns(2)
        with col1:
            st.button("Approve token", type="primary", on_click=_decide, args=("approved",), key="wallet_approve")
        with col2:
            st.button("Reject", on_click=_decide, args=("rejected",), key="wallet_reject")
    elif status == "approved":
        st.success("Token approved: it can now be used by Wallet.")
    elif status == "rejected":
        st.warning("Token rejected.")
