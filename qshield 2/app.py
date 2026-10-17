"""QShield simple server-based demo. Run: streamlit run app.py."""
import streamlit as st
from core.state import init_state
from views.receiver import show_receiver
from views.sender import show_sender

st.set_page_config(page_title="QShield · Private file transfer", page_icon="🛡️")
init_state()
st.markdown("""<style>
.block-container {max-width: 780px; padding-top: 2.5rem;}
h1 {letter-spacing: -0.04em;}
[data-testid="stCaptionContainer"] {line-height: 1.6;}
.stButton button, .stDownloadButton button {border-radius: 10px;}
</style>""", unsafe_allow_html=True)
st.title("🛡️ QShield")
st.write("A private file. The right receiver. Three simple steps.")
st.caption("Server-based prototype: this server processes files, keys and passwords. Use test files only.")
receive, send = st.tabs(["Receive", "Send"])
with receive:
    show_receiver()
with send:
    show_sender()
