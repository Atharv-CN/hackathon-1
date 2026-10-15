"""Sender screen: encrypt a test file for the receiver's public key."""

from datetime import datetime

import os

import streamlit as st

import relay
from core.file_utils import human_size, sha256_of_bytes
from core.identity import KeyAuthError
from core.key_directory import fetch_authenticated_receiver_key
from core.pq_transfer import public_key_fingerprint, public_key_from_bytes, public_key_from_text
from core.transfer_flow import (
    encrypt_for_verified_key,
    encrypt_uploaded_file,
    package_download_name,
)
from core.trust_store import TrustStore, TrustStoreError


def _trust_store() -> TrustStore:
    """File-backed if QSHIELD_TRUST_STORE is set (single-user installs); otherwise
    per-session, with download/restore below. Never shared between visitors."""
    store = st.session_state.get("trust_store")
    if store is None:
        path = os.environ.get("QSHIELD_TRUST_STORE")
        try:
            store = TrustStore(path) if path else TrustStore()
        except TrustStoreError as exc:
            st.error(f"{exc} QShield will not continue with an unreadable trust store.")
            st.stop()
        st.session_state["trust_store"] = store
    return store


def _show_trust_store_tools(store: TrustStore) -> None:
    with st.expander("Trusted receivers (remembered keys)"):
        if not store.records:
            st.caption("No receivers remembered yet.")
        for ident, rec in store.records.items():
            st.code(ident, language=None)
            st.caption(f"Latest bundle number {rec['seq']}; {len(rec['revoked'])} revoked key(s).")
        st.download_button("Download trust store", data=store.to_json(), file_name="qshield-trust.json", key="dl_trust")
        up = st.file_uploader("Restore a trust store", type=["json"], key="trust_restore")
        if up is not None and st.button("Restore trust store", key="restore_trust_btn"):
            try:
                st.session_state["trust_store"] = TrustStore.from_json(up.getvalue())
            except TrustStoreError as exc:
                st.error(str(exc))
            else:
                st.rerun()


def show_sender() -> None:
    st.header("📤 Sender")
    st.write(
        "Upload a **test file** (not real secrets) and paste the receiver's "
        "public key. QShield encrypts the file with ML-KEM-768 + AES-256-GCM."
    )
    st.caption(
        "Encryption hides the file contents from anyone who does not have the "
        "receiver's private key. It does **not** prove who you are."
    )

    uploaded = st.file_uploader("Choose a file to encrypt", key="sender_upload")
    store = _trust_store()
    receiver_code = ""
    receiver_id = ""
    if relay.is_configured():
        st.markdown("**Option A (recommended): relay with a verified key**")
        receiver_id = st.text_input(
            "Receiver's QShield ID (from the receiver, NOT from the relay)",
            placeholder="QSID1-...",
            key="sender_receiver_id",
        )
        receiver_code = st.text_input("Receiver's code", key="sender_receiver_code")
        st.markdown("**Option B: paste a public key you received yourself**")
    public_key_text = st.text_area(
        "Receiver's public key",
        height=120,
        placeholder="Paste the public key from the Receiver tab",
        key="sender_public_key",
    )
    manual_confirmed = False
    if public_key_text.strip():
        manual_confirmed = st.checkbox(
            "I confirmed this key's fingerprint with the receiver over a separate channel",
            key="sender_manual_confirmed",
        )

    if uploaded is not None:
        data = uploaded.getvalue()
        st.subheader("File details")
        st.write(f"**Name:** {uploaded.name}")
        st.write(f"**Size:** {human_size(len(data))}")
        st.write("**SHA-256 of the original file** (optional; share after the receiver decrypts):")
        st.code(sha256_of_bytes(data), language=None)

    encrypt_clicked = st.button("Encrypt File", type="primary")
    if encrypt_clicked:
        use_relay = bool(receiver_code.strip() or receiver_id.strip()) and not public_key_text.strip()
        if uploaded is None:
            st.error("Please upload a file first.")
        elif not public_key_text.strip() and not use_relay:
            st.error("Enter the receiver's QShield ID and code, or paste a public key.")
        elif public_key_text.strip() and not manual_confirmed:
            st.error("Confirm the key's fingerprint with the receiver first, or use the QShield ID option.")
        elif use_relay and not (receiver_code.strip() and receiver_id.strip()):
            st.error("The relay option needs BOTH the receiver's QShield ID and their code.")
        else:
            trust = None
            try:
                if use_relay:
                    verified = fetch_authenticated_receiver_key(receiver_code, receiver_id, store)
                    public_key = public_key_from_bytes(verified.kem_public_key)
                    package = encrypt_for_verified_key(uploaded.getvalue(), uploaded.name, verified)
                    trust = verified
                else:
                    public_key = public_key_from_text(public_key_text)
                    package = encrypt_uploaded_file(uploaded.getvalue(), uploaded.name, public_key_text)
            except KeyAuthError as exc:
                st.error(f"🚫 Key NOT trusted: {exc}")
            except (ValueError, TypeError, relay.RelayError) as exc:
                st.error(str(exc))
            else:
                st.session_state["encrypted_package"] = {
                    "package_name": package_download_name(uploaded.name),
                    "package_bytes": package,
                    "original_name": uploaded.name,
                    "original_size": len(uploaded.getvalue()),
                    "recipient_fingerprint": public_key_fingerprint(public_key, pretty=True),
                    "prepared_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "relay_code": None,
                }
                if trust is not None:
                    st.success("✅ Key verified: signed by the QShield ID you entered. File encrypted.")
                    if trust.rotated:
                        st.warning(
                            "The receiver has rotated their key since you last used it. "
                            "The change is signed by the same identity, so it is accepted."
                        )
                else:
                    st.warning("File encrypted for a key you verified by hand. QShield could not check who owns it.")

    _show_trust_store_tools(store)

    encrypted = st.session_state.get("encrypted_package")
    if encrypted is None:
        return

    st.subheader("Encrypted package")
    st.write(f"**Download name:** {encrypted['package_name']}")
    st.write(f"**Original file:** {encrypted['original_name']} ({human_size(encrypted['original_size'])})")
    st.write(f"**Encrypted at:** {encrypted['prepared_at']}")
    st.write(f"**Package size:** {human_size(len(encrypted['package_bytes']))}")
    if encrypted.get("recipient_fingerprint"):
        st.caption(f"Encrypted for public-key fingerprint: {encrypted['recipient_fingerprint']}")

    st.download_button(
        "Download .qshield package",
        data=encrypted["package_bytes"],
        file_name=encrypted["package_name"],
        mime="application/octet-stream",
        key="download_qshield",
    )
    if relay.is_configured():
        if st.button("Send to receiver via relay", key="relay_send_package"):
            try:
                encrypted["relay_code"] = relay.put(
                    "package", encrypted["package_bytes"], encrypted["package_name"]
                )
            except (relay.RelayError, ValueError) as exc:
                st.error(str(exc))
        if encrypted.get("relay_code"):
            st.write("**Package code** (give this to the receiver; the stored file is encrypted):")
            st.code(encrypted["relay_code"], language=None)
    st.info(
        "Give this `.qshield` file to the receiver. The original unencrypted "
        "file is not included."
    )
