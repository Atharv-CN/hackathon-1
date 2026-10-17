"""QShield secure payments demo. Run: streamlit run app.py

Flow: Pay (test card) -> QShield signs + encrypts the details (AES-256-GCM) and a random
token is made -> the Wallet team opens, verifies and approves. The old file-transfer
screens live in files_app.py.
"""
import streamlit as st
from core.state import init_state
from views.payment import show_payment
from views.wallet import show_wallet

st.set_page_config(page_title="QShield · Secure payments", page_icon="🛡️")
init_state()
st.markdown("""<style>
.block-container {max-width: 780px; padding-top: 2.5rem;}
h1 {letter-spacing: -0.04em;}
[data-testid="stCaptionContainer"] {line-height: 1.6;}
.stButton button {border-radius: 10px;}
</style>""", unsafe_allow_html=True)
st.title("🛡️ QShield Payments")
st.write("**1. Pay** → **2. QShield encrypts and signs** → **3. Wallet verifies and approves**")
st.caption(
    "Demo with TEST cards only: the payment provider is a simulation and no money moves. "
    "The server sees the card number once, while it encrypts it. The protocol is unaudited."
)
pay, wallet = st.tabs(["Pay", "Wallet"])
with pay:
    show_payment()
with wallet:
    show_wallet()
