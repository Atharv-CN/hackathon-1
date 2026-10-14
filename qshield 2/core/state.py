"""Shared memory for the app.

Streamlit re-runs the whole script on every click. `st.session_state` is a
dictionary that survives those re-runs, so the Sender, Receiver and Security
Status screens can share information through it.

Keys we use:
- "encrypted_package": the .qshield bytes the Sender made (never the original file)
- "recipient_keys": password-protected private key + public text (Receiver only)
- "recovered_file": original file after a successful decrypt (or None)
- "last_decrypt_ok": True/False/None for the Security Status tab
- "last_check": the result of the Receiver's most recent hash check (or None)
"""

import streamlit as st


def init_state() -> None:
    """Create the shared keys the first time the app starts."""
    defaults = {
        "encrypted_package": None,
        "recipient_keys": None,
        "recovered_file": None,
        "last_decrypt_ok": None,
        "last_check": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
