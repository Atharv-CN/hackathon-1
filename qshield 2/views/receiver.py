"""Receiver: generate an ML-KEM key pair and decrypt a QShield package."""
import streamlit as st
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from core import pq_transfer as pq


def show_receiver() -> None:
    st.header('📥 Receiver — Keys and Decryption')
    st.subheader('1. Generate a recipient key pair')
    if st.button('🔑 Generate key pair'):
        try:
            st.session_state['recipient_private_key'] = pq.generate_recipient_keypair()
            st.session_state.pop('recovered_download', None)
        except pq.PostQuantumUnavailableError as exc:
            st.error(str(exc))
    private = st.session_state.get('recipient_private_key')
    if private is not None:
        public = private.public_key()
        st.text_area('Public key — copy and share with sender', pq.public_key_to_text(public), height=120)
        st.caption('Public key fingerprint: ' + pq.public_key_fingerprint(public))
        save_password = st.text_input('Password for a backup of your private key', type='password', key='backup_password')
        if save_password:
            try:
                pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(save_password.encode('utf-8')))
                st.download_button('⬇️ Download password-protected private key', data=pem,
                    file_name='qshield-private.pem', mime='application/x-pem-file')
            except ValueError as exc:
                st.error(f'Could not protect private key: {exc}')
        st.warning('Keep your private key and its password secret. A new key pair cannot decrypt packages encrypted for an old key.')
    st.divider()
    st.subheader('2. Decrypt an encrypted package')
    key_file = st.file_uploader('Optional: upload your password-protected private key (.pem)', type=['pem'], key='private_key_upload')
    key_password = st.text_input('Password for uploaded key', type='password', key='uploaded_key_password') if key_file else ''
    package_file = st.file_uploader('Upload an encrypted .qshield package', key='receiver_package_upload')
    if st.button('🔓 Decrypt and verify', disabled=package_file is None):
        st.session_state.pop('recovered_download', None)
        try:
            selected_private = private
            if key_file is not None:
                selected_private = serialization.load_pem_private_key(key_file.getvalue(), password=key_password.encode('utf-8'))
                if not isinstance(selected_private, MLKEM768PrivateKey):
                    raise ValueError('Uploaded key is not an ML-KEM-768 private key.')
            if selected_private is None:
                st.error('First generate a key pair or upload your saved private key.')
                return
            result = pq.decrypt_package(package_file.getvalue(), selected_private)
        except (ValueError, TypeError, pq.TransferError) as exc:
            st.error(f'Package rejected or key could not be opened: {exc}')
        else:
            st.session_state['recovered_download'] = (result.filename, result.data)
            st.success('Package integrity verified. File successfully decrypted.')
    recovered = st.session_state.get('recovered_download')
    if recovered is not None:
        st.download_button('⬇️ Download recovered file', data=recovered[1], file_name=recovered[0])
    st.caption('Package integrity verification is not sender identity verification; digital signatures are not implemented.')
