"""Sender screen: encrypt a test file for the receiver's public key."""

from datetime import datetime

import streamlit as st

import relay
from core.file_utils import human_size, sha256_of_bytes
from core.pq_transfer import public_key_fingerprint, public_key_from_text
from core.transfer_flow import encrypt_uploaded_file, package_download_name


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
    public_key_text = st.text_area(
        "Receiver's public key",
        height=120,
        placeholder="Paste the public key from the Receiver tab",
        key="sender_public_key",
    )

    receiver_code = ""
    if relay.is_configured():
        receiver_code = st.text_input(
            "Or enter the receiver's code (instead of pasting the key)",
            key="sender_receiver_code",
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
        if uploaded is None:
            st.error("Please upload a file first.")
        elif not public_key_text.strip() and not receiver_code.strip():
            st.error("Please paste the receiver's public key or enter their code.")
        else:
            try:
                key_text = public_key_text
                if not key_text.strip():
                    key_bytes, _ = relay.get(receiver_code, "pubkey")
                    if key_bytes is None:
                        raise ValueError("No public key found for that code. Check it and try again.")
                    key_text = key_bytes.decode("utf-8")
                public_key = public_key_from_text(key_text)
                package = encrypt_uploaded_file(
                    uploaded.getvalue(), uploaded.name, key_text
                )
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
                st.success("File encrypted. Download the `.qshield` package below.")

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
