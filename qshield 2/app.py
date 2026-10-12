"""QShield - main file. Start the app with:  streamlit run app.py"""

import streamlit as st

from core.state import init_state
from views.receiver import show_receiver
from views.security_panel import show_security_status
from views.sender import show_sender

st.set_page_config(page_title="QShield", page_icon="🛡️")

init_state()

st.title("🛡️ QShield")
st.caption("24-hour hackathon prototype · secure file sharing (work in progress)")

sender_tab, receiver_tab, status_tab = st.tabs(["Sender", "Receiver", "Security Status"])

with sender_tab:
    show_sender()

with receiver_tab:
    show_receiver()

with status_tab:
    show_security_status()
