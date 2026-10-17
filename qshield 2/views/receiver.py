"""Receiver screen: create keys and open encrypted packages."""

from datetime import datetime

import streamlit as st

import relay
from core.file_crypto import DecryptionError
from core.file_utils import human_size
from core.pq_transfer import TransferError, WrongRecipientError
from core.identity import KeyAuthError
from core.transfer_flow import (
    create_identity_bundle,
    create_recipient_key_bundle,
    decrypt_uploaded_package,
    open_identity_bundle,
    sign_key_bundle,
)


DECRYPT_FAIL_MESSAGE = (
    "Security warning: this package could not be opened. The private key may "
    "be wrong, or the file may have been changed or damaged. QShield will not "
    "release any file contents."
)


def _show_generate_keys() -> None:
    st.subheader("Create your keys")
    st.write(
        "Make a key pair. Share only the **public** key with the sender. Keep "
        "the private key on this side, protected by a password."
    )

    with st.expander("Advanced · key compatibility"):
        st.caption(
            "Hybrid encryption is the default. The signed-key relay currently "
            "requires ML-KEM-768 keys."
        )
        suite = st.selectbox(
            "Key type",
            options=[2, 1, 3],
            format_func=lambda n: {
                2: "Hybrid (recommended)",
                1: "ML-KEM-768 (signed-key relay)",
                3: "ML-KEM-1024 (compatibility)",
            }[n],
            key="receiver_suite",
        )

    password = st.text_input(
        "Password to protect your private key",
        type="password",
        key="receiver_key_password",
        help="Required. The private key is saved only in password-protected form.",
    )

    if st.button("Create keys", type="primary"):
        if not password:
            st.error("Please enter a password to protect the private key.")
        else:
            try:
                bundle = create_recipient_key_bundle(password, suite)
            except Exception as exc:
                st.error(str(exc))
            else:
                _clear_recovered()
                st.session_state["recipient_keys"] = {
                    "public_text": bundle.public_text,
                    "fingerprint": bundle.fingerprint,
                    "fingerprint_pretty": bundle.fingerprint_pretty,
                    "protected_pem": bundle.protected_pem,
                    "suite": bundle.suite,
                    "suite_name": bundle.suite_name,
                }
                st.success(
                    "Key pair created. Copy the public key for the sender, and "
                    "download your password-protected private key."
                )

    keys = st.session_state.get("recipient_keys")
    if keys is None:
        st.info("Generate a key pair to get a public key you can share.")
        return

    st.write("**Your public key** (safe to copy and send):")
    st.code(keys["public_text"], language=None)
    st.write("**Public-key fingerprint:**")
    st.code(keys["fingerprint_pretty"], language=None)
    st.caption(
        "Sending the public key by hand? The sender should confirm this fingerprint "
        "over a separate channel."
    )

    with st.expander("Advanced · signed-key relay"):
        if keys.get("suite", 1) != 1:
            st.caption(
                "These keys use hybrid encryption or ML-KEM-1024. Share the public "
                "key directly. Signed-key publishing requires a separate ML-KEM-768 "
                "key pair from Advanced key compatibility."
            )
        else:
            _show_relay_publish(keys)

    st.download_button(
        "Save private key",
        data=keys["protected_pem"],
        file_name="qshield-private-key.pem",
        mime="application/x-pem-file",
        key="download_private_key",
    )
    st.warning(
        "Keep this key file and its password safe. You need both to open future "
        "files. Lost keys cannot be recovered."
    )


def _show_relay_publish(keys: dict) -> None:
    """Share a signed key bundle through the optional relay."""
    if not relay.is_configured():
        return

    st.markdown("**Share through the relay (signed)**")
    ident = st.session_state.get("receiver_identity")
    password = st.session_state.get("receiver_key_password") or ""

    if ident is None:
        st.caption(
            "Create a QShield identity once. Give your QShield ID to the sender "
            "by chat, email or in person (not through the relay). It lets them "
            "verify your key."
        )
        if st.button("Create QShield identity", key="create_identity"):
            if not password:
                st.error("Enter the password above first; it protects your identity key.")
            else:
                try:
                    st.session_state["receiver_identity"] = vars(
                        create_identity_bundle(password)
                    )
                except Exception as exc:
                    st.error(str(exc))
                else:
                    st.rerun()

        restore = st.file_uploader(
            "Or restore a saved identity (.pem)",
            type=["pem"],
            key="identity_restore",
        )
        if restore is not None and st.button(
            "Restore identity", key="restore_identity"
        ):
            try:
                st.session_state["receiver_identity"] = vars(
                    open_identity_bundle(restore.getvalue(), password)
                )
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.rerun()
        return

    st.write("**Your QShield ID** (safe to share outside the relay):")
    st.code(ident["qshield_id"], language=None)
    st.download_button(
        "Download password-protected identity key",
        data=ident["protected_pem"],
        file_name="qshield-identity.pem",
        mime="application/x-pem-file",
        key="download_identity_key",
    )

    if st.button("Publish signed key bundle to relay", key="relay_publish_bundle"):
        if not password:
            st.error("Enter your key password above to sign the bundle.")
            return
        try:
            envelope, seq = sign_key_bundle(
                ident["protected_pem"],
                password,
                keys["public_text"],
                previous_seq=keys.get("bundle_seq", 0),
            )
            keys["relay_code"] = relay.put("keybundle", envelope)
            keys["bundle_seq"] = seq
        except (relay.RelayError, ValueError, KeyAuthError) as exc:
            st.error(str(exc))

    if keys.get("relay_code"):
        st.write("**Receiver code** (give this to the sender):")
        st.code(keys["relay_code"], language=None)


def _show_relay_fetch() -> None:
    """Fetch an encrypted package from the optional relay."""
    if not relay.is_configured():
        return

    code = st.text_input(
        "Package code from the sender (optional)",
        key="receiver_package_code",
    )
    if st.button("Fetch package from relay", key="relay_fetch_package"):
        _clear_recovered()
        st.session_state["fetched_package"] = None
        try:
            data, name = relay.get(code, "package")
        except relay.RelayError as exc:
            st.error(str(exc))
            return

        if data is None:
            st.error("No package found for that code. Check it and try again.")
        else:
            st.session_state["fetched_package"] = {
                "name": name or "package.qshield",
                "data": data,
            }
            st.success(f"Fetched {name or 'package'} ({human_size(len(data))}).")

    fetched = st.session_state.get("fetched_package")
    if fetched is not None:
        st.caption(
            f"Using fetched package: **{fetched['name']}** "
            "(an uploaded file takes priority)."
        )


def _protected_pem_for_decrypt(source: str):
    keys = st.session_state.get("recipient_keys")
    if source == "This session's generated key":
        if keys is None:
            st.error("Generate a key pair first, or upload a private key file.")
            return None
        return keys["protected_pem"]

    uploaded_key = st.session_state.get("receiver_key_file_upload")
    if uploaded_key is None:
        st.error("Please upload your password-protected private key file.")
        return None
    return uploaded_key.getvalue()


def _show_decrypt_section() -> None:
    st.subheader("Open an encrypted file")
    st.write(
        "Upload the encrypted package. Unlock it with your private key. "
        "If the key is wrong or the package was modified, nothing is released."
    )

    with st.expander("Advanced · fetch from relay"):
        _show_relay_fetch()

    package_file = st.file_uploader(
        "Upload a .qshield package",
        type=["qshield"],
        key="receiver_package_upload",
        on_change=_clear_recovered,
    )

    sources = (
        ["This session's generated key", "Upload a password-protected key file"]
        if st.session_state.get("recipient_keys")
        else ["Upload a password-protected key file"]
    )
    source = st.radio(
        "Private key to use",
        sources,
        key="receiver_key_source",
        on_change=_clear_recovered,
    )
    if source == "Upload a password-protected key file":
        st.file_uploader(
            "Password-protected private key (.pem)",
            type=["pem", "key"],
            key="receiver_key_file_upload",
            on_change=_clear_recovered,
        )

    key_password = st.text_input(
        "Private key password",
        type="password",
        key="receiver_decrypt_password",
        on_change=_clear_recovered,
    )

    if st.button("Decrypt file", type="primary"):
        _clear_recovered()
        fetched = st.session_state.get("fetched_package")
        if package_file is not None:
            package_bytes = package_file.getvalue()
        elif fetched is not None:
            package_bytes = fetched["data"]
        else:
            st.error("Please upload a .qshield package or fetch one with a package code.")
            return

        if not key_password:
            st.error("Please enter the password for your private key.")
            return

        pem = _protected_pem_for_decrypt(source)
        if pem is None:
            return

        st.session_state["last_decrypt_ok"] = False
        try:
            result = decrypt_uploaded_package(package_bytes, pem, key_password)
        except (
            WrongRecipientError,
            TransferError,
            DecryptionError,
            ValueError,
            TypeError,
        ) as exc:
            st.error(DECRYPT_FAIL_MESSAGE)
            st.caption(str(exc))
            return

        st.session_state["last_decrypt_ok"] = True
        st.session_state["recovered_file"] = {
            "name": result.filename,
            "data": result.data,
            "opened_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        st.success("Package verified and decrypted. You can download the original file.")

    recovered = st.session_state.get("recovered_file")
    if recovered is None:
        return

    st.download_button(
        "Download recovered file",
        data=recovered["data"],
        file_name=recovered["name"],
        key="download_recovered",
    )
    st.caption(
        f"Recovered **{recovered['name']}** ({human_size(len(recovered['data']))}) "
        f"at {recovered['opened_at']}. This download is shown only after verification succeeded."
    )


def _clear_recovered() -> None:
    st.session_state["recovered_file"] = None
    st.session_state["last_decrypt_ok"] = None


def show_receiver() -> None:
    action = st.radio(
        "What would you like to do?",
        ["Create keys", "Open a file"],
        horizontal=True,
        label_visibility="collapsed",
    )
    if action == "Create keys":
        _show_generate_keys()
    else:
        _show_decrypt_section()