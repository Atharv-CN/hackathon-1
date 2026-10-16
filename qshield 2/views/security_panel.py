"""Security-status section: shows what is really working and what is not."""

import streamlit as st

from core.security_status import get_feature_list


def show_security_status() -> None:
    st.header("🛡️ Security Status")

    st.info(
        "AES-256-GCM, ML-KEM key establishment (ML-KEM-768, hybrid X25519 + "
        "ML-KEM-768, or ML-KEM-1024), and encrypted-file integrity "
        "checks are implemented and connected to the Sender and Receiver tabs."
    )
    st.warning(
        "This is a hackathon prototype. Use **test files only**. Encryption does "
        "**not** prove who the sender is. Files are not sent over a network yet. "
        "There has been no independent security audit."
    )

    st.subheader("Features")
    st.table(get_feature_list())

    st.subheader("Live activity in this session")
    encrypted = st.session_state["encrypted_package"]
    last_decrypt_ok = st.session_state["last_decrypt_ok"]
    last_check = st.session_state["last_check"]

    col1, col2, col3 = st.columns(3)
    with col1:
        if encrypted is None:
            st.metric("Encrypted package", "No")
        else:
            st.metric("Encrypted package", "Yes")
            st.caption(f"{encrypted['package_name']} at {encrypted['prepared_at']}")
    with col2:
        if last_decrypt_ok is None:
            st.metric("Last decrypt", "None yet")
        elif last_decrypt_ok:
            st.metric("Last decrypt", "Verified")
        else:
            st.metric("Last decrypt", "Failed (nothing released)")
    with col3:
        if last_check is None:
            st.metric("Last fingerprint check", "None yet")
        else:
            st.metric("Last fingerprint check", "Match" if last_check["matched"] else "No match")
            st.caption(f"{last_check['file_name']} at {last_check['checked_at']}")
