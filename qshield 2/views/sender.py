"""Sender screen: encrypt a test file for the receiver's public key."""

import streamlit as st

import relay
from core.pq_transfer import (
    encrypt_for_recipient,
    public_key_fingerprint,
    public_key_from_text,
    suite_name,
    suite_of,
)
from core.transfer_flow import (
    package_download_name,
)


def _clear_package():
    st.session_state["encrypted_package"] = None


def _clear_recipient():
    _clear_package()
    st.session_state["sender_manual_confirmed"] = False
    st.session_state["sender_allow_legacy"] = False


def show_sender() -> None:
    st.subheader("2 · Encrypt a file")
    st.caption("First, ask the receiver to create keys and share their public key.")
    uploaded = st.file_uploader("1. Choose your file", key="sender_upload", on_change=_clear_package)
    public_key_text = st.text_area(
        "2. Paste the receiver’s public key", height=100,
        key="sender_public_key", on_change=_clear_recipient,
    )
    public_key = None
    manual_confirmed = False
    legacy_confirmed = False
    if public_key_text.strip():
        try:
            public_key = public_key_from_text(public_key_text.strip())
        except (ValueError, TypeError):
            st.error("This public key is not valid. Ask the receiver to copy the complete key.")
        else:
            st.caption("Compare this fingerprint with the receiver by phone or in person:")
            st.code(public_key_fingerprint(public_key, pretty=True), language=None)
            manual_confirmed = st.checkbox(
                "I checked this fingerprint with the receiver",
                key="sender_manual_confirmed", on_change=_clear_package,
            )
            if suite_of(public_key) != 4:
                st.warning("This is an older key type. Ask the receiver to create a recommended key if possible.")
                with st.expander("Advanced · use older key"):
                    legacy_confirmed = st.checkbox(
                        "I need to use this older key", key="sender_allow_legacy",
                        on_change=_clear_package,
                    )

    st.caption("The package hides the original file name and exact size. Padding obscures its approximate size.")

    if st.button("Encrypt file", type="primary"):
        _clear_package()
        if uploaded is None:
            st.error("Choose a file first.")
        elif uploaded.size > 25 * 1024 * 1024:
            st.error("Choose a file smaller than 25 MB.")
        elif public_key is None or not manual_confirmed:
            st.error("Paste a valid public key and confirm its fingerprint first.")
        elif suite_of(public_key) != 4 and not legacy_confirmed:
            st.error("Ask the receiver for a recommended key, or choose the older-key option under Advanced.")
        else:
            try:
                package = encrypt_for_recipient(
                    uploaded.getvalue(), public_key, filename=uploaded.name, padding="padme",
                )
                st.session_state["encrypted_package"] = {
                    "package_name": package_download_name(uploaded.name, hide_name=True),
                    "package_bytes": package,
                    "original_name": uploaded.name,
                    "original_size": uploaded.size,
                    "recipient_fingerprint": public_key_fingerprint(public_key, pretty=True),
                    "suite": suite_of(public_key),
                    "suite_name": suite_name(suite_of(public_key)),
                    "relay_code": None,
                }
            except (ValueError, TypeError, relay.RelayError) as exc:
                st.error(str(exc))

    encrypted = st.session_state.get("encrypted_package")
    if encrypted is None:
        return
    st.success("File encrypted. Share only the .qshield package.")
    st.download_button(
        "Download encrypted file", data=encrypted["package_bytes"],
        file_name=encrypted["package_name"], mime="application/octet-stream",
        key="download_qshield", type="primary",
    )
    with st.expander("Package details & relay delivery"):
        st.caption(f"Encryption: {encrypted['suite_name']} + AES-256-GCM. Metadata encrypted; size padded.")
        st.caption("Encrypted for this public-key fingerprint:")
        st.code(encrypted["recipient_fingerprint"], language=None)
        if relay.is_configured():
            st.caption("Relay accepts encrypted packages up to 5 MB.")
            if st.button("Send via relay", key="relay_send_package"):
                try:
                    encrypted["relay_code"] = relay.put("package", encrypted["package_bytes"], encrypted["package_name"])
                except (relay.RelayError, ValueError) as exc:
                    st.error(str(exc))
            if encrypted.get("relay_code"):
                st.write("Share this package code with the receiver:")
                st.code(encrypted["relay_code"], language=None)
