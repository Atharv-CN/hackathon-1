"""QShield simple server-based demo. Run: streamlit run app.py."""
import streamlit as st
from core.state import init_state
from views.payment import show_payment
from views.receiver import show_receiver
from views.sender import show_sender
from views.wallet import show_wallet

st.set_page_config(page_title="QShield · Private file transfer", page_icon="🛡️")
init_state()
st.markdown("""<style>
.block-container {max-width: 780px; padding-top: 2.5rem;}
h1 {letter-spacing: -0.04em;}
[data-testid="stCaptionContainer"] {line-height: 1.6;}
.stButton button, .stDownloadButton button {border-radius: 10px;}
</style>""", unsafe_allow_html=True)
st.title("🛡️ QShield")
st.write("**1. Create keys** → **2. Encrypt a file** → **3. Open it**")
st.caption("Demo with test files only. This server handles files, keys and passwords; for private device-local use, install the Python SDK or use qshield-local. The protocol is unaudited.")
receive, send, pay, wallet = st.tabs(["Receive", "Send", "Pay (test)", "Wallet"])
with receive:
    show_receiver()
with send:
    show_sender()
with pay:
    show_payment()
with wallet:
    show_wallet()
