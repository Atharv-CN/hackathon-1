"""Sender screen: encrypt a test file for the receiver's public key."""

import os

import streamlit as st

import relay
from core.identity import KeyAuthError
from core.key_directory import fetch_authenticated_receiver_key
from core.pq_transfer import (
    encrypt_for_recipient,
    public_key_fingerprint,
    public_key_from_bytes,
    public_key_from_text,
    suite_name,
    suite_of,
)
from core.transfer_flow import package_download_name
from core.trust_store import TrustStore, TrustStoreError


def _trust_store() -> TrustStore:
    """Use a configured file store or a private per-session trust store."""
    store = st.session_state.get("trust_store")
    if store is None:
        path = os.environ.get("QSHIELD_TRUST_STORE")
        try:
            store = TrustStore(path) if path else TrustStore()
        except TrustStoreError as exc:
            st.error(
                f"{exc} QShield will not continue with an unreadable trust store."
            )
            st.stop()
        st.session_state["trust_store"] = store
    return store


def _show_trust_store_tools(store: TrustStore) -> None:
    with st.expander("Trusted receivers (remembered keys)"):
        if not store.records:
            st.caption("No receivers remembered yet.")

        for ident, rec in store.records.items():
            st.code(ident, language=None)
            st.caption(
                f"Latest bundle number {rec['seq']}; "
                f"{len(rec['revoked'])} revoked key(s)."
            )

        st.download_button(
            "Download trust store",
            data=store.to_json(),
            file_name="qshield-trust.json",
            key="dl_trust",
        )
        up = st.file_uploader(
            "Restore a trust store",
            type=["json"],
            key="trust_restore",
        )
        if up is not None and st.button(
            "Restore trust store", key="restore_trust_btn"
        ):
            try:
                st.session_state["trust_store"] = TrustStore.from_json(
                    up.getvalue()
                )
            except TrustStoreError as exc:
                st.error(str(exc))
            else:
                st.rerun()


def _clear_package() -> None:
    st.session_state["encrypted_package"] = None


def _clear_recipient() -> None:
    _clear_package()
    st.session_state["sender_manual_confirmed"] = False


def show_sender() -> None:
    st.subheader("Send a file")
    st.caption("First, ask the receiver to create keys and share their public key.")

    uploaded = st.file_uploader(
        "1. Choose your file",
        key="sender_upload",
        on_change=_clear_package,
    )
    public_key_text = st.text_area(
        "2. Paste the receiver’s public key",
        height=100,
        key="sender_public_key",
        on_change=_clear_recipient,
    )

    public_key = None
    manual_confirmed = False
    if public_key_text.strip():
        try:
            public_key = public_key_from_text(public_key_text.strip())
        except (ValueError, TypeError):
            st.error(
                "This public key is not valid. Ask the receiver to copy the complete key."
            )
        else:
            st.caption(
                "Compare this fingerprint with the receiver by phone or in person:"
            )
            st.code(
                public_key_fingerprint(public_key, pretty=True),
                language=None,
            )
            manual_confirmed = st.checkbox(
                "I checked this fingerprint with the receiver",
                key="sender_manual_confirmed",
                on_change=_clear_package,
            )

    receiver_code = ""
    receiver_id = ""
    with st.expander("Advanced · relay and trusted receivers"):
        st.caption(
            "New packages always hide their metadata and use size padding. "
            "The encrypted package’s approximate size remains visible."
        )
        if relay.is_configured():
            st.write(
                "Or use a signed receiver key. Leave the public-key box above empty."
            )
            receiver_id = st.text_input(
                "Receiver’s QShield ID (confirm directly with them)",
                key="sender_receiver_id",
                on_change=_clear_package,
            )
            receiver_code = st.text_input(
                "Receiver code",
                key="sender_receiver_code",
                on_change=_clear_package,
            )
        else:
            st.caption(
                "Relay is not configured. Download and share the encrypted "
                "package instead."
            )

        store = _trust_store()
        _show_trust_store_tools(store)

    if st.button("3. Encrypt file", type="primary"):
        _clear_package()
        use_relay = bool(receiver_code.strip() or receiver_id.strip())

        if uploaded is None:
            st.error("Choose a file first.")
        elif uploaded.size > 25 * 1024 * 1024:
            st.error("Choose a file smaller than 25 MB.")
        elif use_relay and public_key_text.strip():
            st.error(
                "Use one recipient method: clear the pasted key or the relay fields."
            )
        elif use_relay and not (receiver_code.strip() and receiver_id.strip()):
            st.error("Enter both the receiver’s QShield ID and receiver code.")
        elif not use_relay and (public_key is None or not manual_confirmed):
            st.error(
                "Paste a valid public key and confirm its fingerprint first."
            )
        else:
            try:
                trust = None
                if use_relay:
                    trust = fetch_authenticated_receiver_key(
                        receiver_code,
                        receiver_id,
                        store,
                    )
                    public_key = public_key_from_bytes(trust.kem_public_key)

                package = encrypt_for_recipient(
                    uploaded.getvalue(),
                    public_key,
                    filename=uploaded.name,
                    padding="padme",
                )
                st.session_state["encrypted_package"] = {
                    "package_name": package_download_name(
                        uploaded.name,
                        hide_name=True,
                    ),
                    "package_bytes": package,
                    "original_name": uploaded.name,
                    "original_size": uploaded.size,
                    "recipient_fingerprint": public_key_fingerprint(
                        public_key,
                        pretty=True,
                    ),
                    "suite": suite_of(public_key),
                    "suite_name": suite_name(suite_of(public_key)),
                    "relay_code": None,
                }

                if trust is not None and trust.rotated:
                    st.info(
                        "The receiver’s new key was verified with their "
                        "existing identity."
                    )
            except KeyAuthError as exc:
                st.error(f"Key NOT trusted. Nothing encrypted. {exc}")
            except (ValueError, TypeError, relay.RelayError) as exc:
                st.error(str(exc))

    encrypted = st.session_state.get("encrypted_package")
    if encrypted is None:
        return

    st.success("File encrypted. Share only the .qshield package.")
    st.download_button(
        "Download encrypted file",
        data=encrypted["package_bytes"],
        file_name=encrypted["package_name"],
        mime="application/octet-stream",
        key="download_qshield",
        type="primary",
    )

    with st.expander("Package details & relay delivery"):
        st.caption(
            f"Encryption: {encrypted['suite_name']} + AES-256-GCM. "
            "Metadata encrypted; size padded."
        )
        st.caption("Encrypted for this public-key fingerprint:")
        st.code(encrypted["recipient_fingerprint"], language=None)

        if relay.is_configured():
            st.caption("Relay accepts encrypted packages up to 5 MB.")
            if st.button("Send via relay", key="relay_send_package"):
                try:
                    encrypted["relay_code"] = relay.put(
                        "package",
                        encrypted["package_bytes"],
                        encrypted["package_name"],
                    )
                except (relay.RelayError, ValueError) as exc:
                    st.error(str(exc))

            if encrypted.get("relay_code"):
                st.write("Share this package code with the receiver:")
                st.code(encrypted["relay_code"], language=None)