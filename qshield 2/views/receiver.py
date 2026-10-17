"""Receiver screen: generate keys, decrypt .qshield packages, optional hash check."""

from datetime import datetime

import streamlit as st

import relay
from core.file_crypto import DecryptionError
from core.file_utils import human_size
from core.pq_transfer import TransferError, WrongRecipientError
from core.transfer_flow import (
    create_recipient_key_bundle,
    decrypt_uploaded_package,
)


DECRYPT_FAIL_MESSAGE = (
    "Security warning: this package could not be opened. The private key may "
    "be wrong, or the file may have been changed or damaged. QShield will not "
    "release any file contents."
)


def _show_generate_keys() -> None:
    st.subheader("1 · Create your keys")
    st.write(
        "Make a key pair. Share only the **public** key with the sender. Keep "
        "the private key on this side, protected by a password."
    )

    password = st.text_input(
        "Password to protect your private key",
        type="password",
        key="receiver_key_password",
        help="Use a unique password of at least 12 characters. You will need it to open files.",
    )
    confirmation = st.text_input(
        "Repeat password", type="password", key="receiver_key_password_confirm",
    )
    suite = 4
    with st.expander("Advanced · key compatibility"):
        st.caption("New keys use ML-KEM-1024 + X25519. Choose an older type only to support an existing integration.")
        suite = st.selectbox(
            "Key type", options=[4, 3, 2, 1],
            format_func=lambda n: {4: "ML-KEM-1024 + X25519 (recommended)", 3: "ML-KEM-1024", 2: "ML-KEM-768 + X25519 (older)", 1: "ML-KEM-768 (older)"}[n],
            key="receiver_suite",
        )

    if st.button("Create keys", type="primary"):
        if len(password) < 12:
            st.error("Use a password with at least 12 characters.")
        elif password != confirmation:
            st.error("Passwords do not match. Please enter them again.")
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
        "The sender must confirm this fingerprint with you through another channel "
        "before encrypting. A pasted key alone does not establish your identity."
    )
    st.download_button(
        "Save private key",
        data=keys["protected_pem"],
        file_name="qshield-private-key.pem",
        mime="application/x-pem-file",
        key="download_private_key",
    )
    st.warning(
        "Keep this key file and its password safe. You need both to open future files. Lost keys cannot be recovered."
    )


def _show_relay_fetch() -> None:
    """Optional: fetch an encrypted package the sender left on the relay."""
    if not relay.is_configured():
        return
    code = st.text_input("Package code from the sender (optional)", key="receiver_package_code")
    if st.button("Fetch package from relay", key="relay_fetch_package"):
        _clear_recovered()
        st.session_state["fetched_package"] = None
        try:
            data, name = relay.get(code, "package")
        except relay.RelayError as exc:
            st.error(str(exc))
            return
        if data is None:
            st.session_state["fetched_package"] = None
            st.error("No package found for that code. Check it and try again.")
        else:
            st.session_state["fetched_package"] = {"name": name or "package.qshield", "data": data}
            st.success(f"Fetched {name or 'package'} ({human_size(len(data))}).")
    fetched = st.session_state.get("fetched_package")
    if fetched is not None:
        st.caption(f"Using fetched package: **{fetched['name']}** (an uploaded file takes priority).")


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
    st.subheader("3 · Open an encrypted file")
    st.write(
        "Upload the encrypted package. Unlock it with your private key. "
        "If the key is wrong or the package was modified, nothing is released."
    )

    with st.expander("Advanced · fetch from relay"):
        _show_relay_fetch()

    package_file = st.file_uploader(
        "Upload a .qshield package",
        type=["qshield"],
        key="receiver_package_upload", on_change=_clear_recovered,
    )

    source = st.radio(
        "Private key to use",
        (["This session's generated key", "Upload a password-protected key file"]
         if st.session_state.get("recipient_keys") else ["Upload a password-protected key file"]),
        key="receiver_key_source", on_change=_clear_recovered,
    )
    if source == "Upload a password-protected key file":
        st.file_uploader(
            "Password-protected private key (.pem)",
            type=["pem", "key"],
            key="receiver_key_file_upload", on_change=_clear_recovered,
        )

    key_password = st.text_input(
        "Private key password",
        type="password",
        key="receiver_decrypt_password", on_change=_clear_recovered,
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

        st.session_state["recovered_file"] = None
        st.session_state["last_decrypt_ok"] = False

        try:
            result = decrypt_uploaded_package(package_bytes, pem, key_password)
        except (WrongRecipientError, TransferError, DecryptionError, ValueError, TypeError):
            st.error(DECRYPT_FAIL_MESSAGE)
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


def _clear_recovered():
    st.session_state["recovered_file"] = None
    st.session_state["last_decrypt_ok"] = None


def show_receiver() -> None:
    action = st.radio("What would you like to do?", ["Create keys", "Open a file"], horizontal=True, label_visibility="collapsed")
    if action == "Create keys":
        _show_generate_keys()
    else:
        _show_decrypt_section()
