"""Sender: encrypt files for a recipient's ML-KEM public key."""
import streamlit as st
from core import pq_transfer as pq
from core.file_utils import human_size, sha256_of_bytes


def show_sender() -> None:
    st.header('📤 Sender — Encrypt a file')
    st.write('Ask the receiver to share their **public** key. Do not request their private key.')
    public_text = st.text_area('Receiver public key', height=120, key='recipient_public_text')
    uploaded = st.file_uploader('Choose a test file', key='sender_upload')
    if uploaded is not None:
        st.write(f'**File:** {uploaded.name} ({human_size(len(uploaded.getvalue()))})')
        st.caption('Original file SHA-256 fingerprint')
        st.code(sha256_of_bytes(uploaded.getvalue()), language=None)
    if st.button('🔒 Encrypt file', disabled=uploaded is None or not public_text.strip()):
        st.session_state.pop('encrypted_download', None)
        try:
            public_key = pq.public_key_from_text(public_text)
            package = pq.encrypt_for_recipient(uploaded.getvalue(), public_key, filename=uploaded.name)
        except (ValueError, TypeError, pq.TransferError) as exc:
            st.error(f'Encryption failed: {exc}')
        else:
            st.session_state['encrypted_download'] = (uploaded.name + '.qshield', package)
            st.success('Encrypted package created! Only the receiver with the matching private key can open it.')
    encrypted = st.session_state.get('encrypted_download')
    if encrypted is not None:
        st.download_button('⬇️ Download encrypted package', data=encrypted[1], file_name=encrypted[0], mime='application/octet-stream')
    st.caption('Encryption and integrity checks do not verify the sender’s identity. Network transfer is not included.')
