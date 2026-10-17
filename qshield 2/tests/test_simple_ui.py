"""Regression coverage for the simplified UI's security-sensitive behavior."""
from io import BytesIO
from pathlib import Path
import streamlit as st
from streamlit.testing.v1 import AppTest
from core.transfer_flow import create_recipient_key_bundle, decrypt_uploaded_package

APP = str(Path(__file__).resolve().parents[1] / 'app.py')

class Upload(BytesIO):
    def __init__(self, data, name):
        super().__init__(data)
        self.name = name
        self.size = len(data)


def button(app, label):
    return next(x for x in app.button if x.label == label)


def test_new_keys_default_to_hybrid():
    app = AppTest.from_file(APP).run()
    app.text_input(key='receiver_key_password').set_value('demo-password')
    button(app, 'Create keys').click().run()
    assert not app.exception
    assert app.session_state['recipient_keys']['suite'] == 2


def test_confirmation_resets_when_recipient_changes():
    a = create_recipient_key_bundle('password', 2)
    b = create_recipient_key_bundle('password', 2)
    app = AppTest.from_file(APP).run()
    app.text_area(key='sender_public_key').set_value(a.public_text).run()
    app.checkbox(key='sender_manual_confirmed').check().run()
    app.text_area(key='sender_public_key').set_value(b.public_text).run()
    assert not app.checkbox(key='sender_manual_confirmed').value
    assert b.fingerprint_pretty in [x.value for x in app.code]
    assert not app.exception


def test_ui_encrypt_decrypt_and_reject_tampering(monkeypatch):
    uploads = {'sender_upload': Upload(b'private demo contents', 'secret-name.txt')}
    original = st.file_uploader
    def uploader(*args, **kwargs):
        original(*args, **kwargs)
        return uploads.get(kwargs.get('key'))
    monkeypatch.setattr(st, 'file_uploader', uploader)
    app = AppTest.from_file(APP).run()
    app.text_input(key='receiver_key_password').set_value('demo-password')
    button(app, 'Create keys').click().run()
    bundle = app.session_state['recipient_keys']
    app.text_area(key='sender_public_key').set_value(bundle['public_text']).run()
    button(app, '3. Encrypt file').click().run()
    assert app.session_state['encrypted_package'] is None
    app.checkbox(key='sender_manual_confirmed').check().run()
    button(app, '3. Encrypt file').click().run()
    package = app.session_state['encrypted_package']
    assert package['package_bytes'][4] == 1
    assert b'secret-name.txt' not in package['package_bytes']
    assert package['package_name'].startswith('qshield-')
    assert decrypt_uploaded_package(package['package_bytes'], bundle['protected_pem'], 'demo-password').data == b'private demo contents'
    uploads['receiver_package_upload'] = Upload(package['package_bytes'], 'received.qshield')
    app.radio[0].set_value('Open a file').run()
    app.text_input(key='receiver_decrypt_password').set_value('demo-password')
    button(app, 'Decrypt file').click().run()
    assert app.session_state['recovered_file']['data'] == b'private demo contents'
    tampered = bytearray(package['package_bytes'])
    tampered[-1] ^= 1
    uploads['receiver_package_upload'] = Upload(bytes(tampered), 'tampered.qshield')
    button(app, 'Decrypt file').click().run()
    assert app.session_state['recovered_file'] is None
    assert any('Security warning' in x.value for x in app.error)
    assert not app.exception
