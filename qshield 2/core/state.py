"""Initialize Streamlit session state for the encrypted file demo."""
import streamlit as st


def init_state() -> None:
    for name in ('recipient_private_key', 'encrypted_download', 'recovered_download'):
        if name not in st.session_state:
            st.session_state[name] = None
