"""Receiver screen: generate keys, decrypt .qshield packages, optional hash check."""

from datetime import datetime

import streamlit as st

import relay
from core.file_crypto import DecryptionError
from core.file_utils import clean_hash_text, human_size, sha256_of_bytes
from core.pq_transfer import SUITES, TransferError, WrongRecipientError
from core.transfer_flow import create_recipient_key_bundle, decrypt_uploaded_package


DECRYPT_FAIL_MESSAGE = (
    "Security warning: this package could not be opened. The private key may "
    "be wrong, or the file may have been changed or damaged. QShield will not "
    "release any file contents."
)


def _show_generate_keys() -> None:
    st.subheader("1. Generate your keys")
    st.write(
        "Make a key pair. Share only the **public** key with the sender. Keep "
        "the private key on this side, protected by a password."
    )

    suite = st.selectbox(
        "Algorithm suite",
        options=list(SUITES),
        format_func=lambda n: {
            1: "Suite 1: ML-KEM-768 only",
            2: "Suite 2: X25519 + ML-KEM-768 (hybrid: an attacker must break both)",
            3: "Suite 3: ML-KEM-1024 (higher security level, larger keys)",
        }[n],
        key="receiver_suite",
        help=(
            "Suite 2 still protects against ordinary computers if a flaw is found "
            "in ML-KEM. Suite 3 adds safety margin but is the same algorithm family "
            "as suite 1. The sender needs no setting: the public key says which suite to use."
        ),
    )

    password = st.text_input(
        "Password to protect your private key",
        type="password",
        key="receiver_key_password",
        help="Required. The private key is saved only in password-protected form.",
    )

    if st.button(f"Generate {SUITES[suite].name} key pair", type="primary"):
        if not password:
            st.error("Please enter a password to protect the private key.")
        else:
            try:
                bundle = create_recipient_key_bundle(password, suite)
            except Exception as exc:
                st.error(str(exc))
            else:
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

    st.caption(f"Suite {keys.get('suite', 1)}: {keys.get('suite_name', 'ML-KEM-768')}")
    st.write("**Your public key** (safe to copy and send):")
    st.code(keys["public_text"], language=None)
    st.write("**Public-key fingerprint** (read this aloud to the sender to confirm it):")
    st.code(keys["fingerprint_pretty"], language=None)
    _show_relay_publish(keys)
    st.download_button(
        "Download password-protected private key",
        data=keys["protected_pem"],
        file_name="qshield-private-key.pem",
        mime="application/x-pem-file",
        key="download_private_key",
    )
    st.warning(
        "Never share the private key or this download with the sender. "
        "QShield does not show the unencrypted private key."
    )


def _show_relay_publish(keys: dict) -> None:
    """Optional: share the PUBLIC key with another device through the relay."""
    if not relay.is_configured():
        return
    if st.button("Share public key with another device", key="relay_publish_pubkey"):
        try:
            keys["relay_code"] = relay.put("pubkey", keys["public_text"].encode("utf-8"))
        except (relay.RelayError, ValueError) as exc:
            st.error(str(exc))
    if keys.get("relay_code"):
        st.write("**Receiver code** (give this to the sender; it points to your public key only):")
        st.code(keys["relay_code"], language=None)


def _show_relay_fetch() -> None:
    """Optional: fetch an encrypted package the sender left on the relay."""
    if not relay.is_configured():
        return
    code = st.text_input("Package code from the sender (optional)", key="receiver_package_code")
    if st.button("Fetch package from relay", key="relay_fetch_package"):
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
    st.subheader("2. Decrypt a .qshield package")
    st.write(
        "Upload the encrypted package. Unlock it with your private key. "
        "If the key is wrong or the package was modified, nothing is released."
    )

    session_package = st.session_state.get("encrypted_package")
    if session_package is not None:
        st.caption(
            "The sender in this same browser session encrypted "
            f"**{session_package['original_name']}**. You can download that "
            ".qshield file, or upload one you received another way."
        )
        st.download_button(
            "Download the encrypted package from this session",
            data=session_package["package_bytes"],
            file_name=session_package["package_name"],
            mime="application/octet-stream",
            key="download_session_qshield",
        )

    _show_relay_fetch()

    package_file = st.file_uploader(
        "Upload a .qshield package",
        type=["qshield"],
        key="receiver_package_upload",
    )

    source = st.radio(
        "Private key to use",
        ["This session's generated key", "Upload a password-protected key file"],
        key="receiver_key_source",
    )
    if source == "Upload a password-protected key file":
        st.file_uploader(
            "Password-protected private key (.pem)",
            type=["pem", "key"],
            key="receiver_key_file_upload",
        )

    key_password = st.text_input(
        "Private key password",
        type="password",
        key="receiver_decrypt_password",
    )

    if st.button("Decrypt package"):
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
        except (WrongRecipientError, TransferError, DecryptionError, ValueError, TypeError) as exc:
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


def _show_verify_section() -> None:
    st.subheader("3. Optional: check a recovered file's fingerprint")
    st.write(
        "After decryption, you can compare SHA-256 with a fingerprint the sender "
        "gave you. Encryption already checked that the package was not changed."
    )

    received = st.file_uploader("Choose the recovered file", key="receiver_hash_upload")
    expected_text = st.text_input("Expected SHA-256 fingerprint (64 characters)")

    if st.button("Check file"):
        if received is None:
            st.error("Please upload a file first.")
            return
        expected = clean_hash_text(expected_text)
        if len(expected) != 64:
            st.error("A SHA-256 fingerprint has exactly 64 characters. Please check what you pasted.")
            return

        actual = sha256_of_bytes(received.getvalue())
        matched = actual == expected
        st.session_state["last_check"] = {
            "file_name": received.name,
            "matched": matched,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        if matched:
            st.success("✅ Match. The file is exactly what the fingerprint describes.")
        else:
            st.error("❌ No match. The file is different from what the sender fingerprinted.")
            st.write("Fingerprint of the file you uploaded:")
            st.code(actual, language=None)


def show_receiver() -> None:
    st.header("📥 Receiver")
    st.caption("Use test files only. Do not upload real private keys from other systems.")
    _show_generate_keys()
    st.divider()
    _show_decrypt_section()
    st.divider()
    _show_verify_section()
