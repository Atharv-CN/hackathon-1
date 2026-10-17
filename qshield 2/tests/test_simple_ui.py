"""Regression coverage for the simplified UI's security-sensitive behavior."""
from io import BytesIO
from pathlib import Path
import streamlit as st
from streamlit.testing.v1 import AppTest
import relay
from core.transfer_flow import create_recipient_key_bundle, decrypt_uploaded_package

APP = str(Path(__file__).resolve().parents[1] / 'app.py')

class Upload(BytesIO):
    def __init__(self, data, name):
        super().__init__(data)
        self.name = name
        self.size = len(data)


def button(app, label):
    return next(x for x in app.button if x.label == label)


def test_new_keys_default_to_mlkem1024_hybrid():
    app = AppTest.from_file(APP).run()
    app.text_input(key='receiver_key_password').set_value('demo-password')
    app.text_input(key='receiver_key_password_confirm').set_value('demo-password')
    button(app, 'Create keys').click().run()
    assert not app.exception
    assert app.session_state['recipient_keys']['suite'] == 4


def test_receiver_catches_short_or_mistyped_password():
    app = AppTest.from_file(APP).run()
    app.text_input(key='receiver_key_password').set_value('short')
    app.text_input(key='receiver_key_password_confirm').set_value('short')
    button(app, 'Create keys').click().run()
    assert app.session_state['recipient_keys'] is None
    app.text_input(key='receiver_key_password').set_value('longer-password')
    button(app, 'Create keys').click().run()
    assert app.session_state['recipient_keys'] is None
    assert any('Passwords do not match' in x.value for x in app.error)


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
    app.text_input(key='receiver_key_password_confirm').set_value('demo-password')
    button(app, 'Create keys').click().run()
    bundle = app.session_state['recipient_keys']
    app.text_area(key='sender_public_key').set_value(bundle['public_text']).run()
    button(app, 'Encrypt file').click().run()
    assert app.session_state['encrypted_package'] is None
    app.checkbox(key='sender_manual_confirmed').check().run()
    button(app, 'Encrypt file').click().run()
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


def test_two_independent_browser_sessions_and_wrong_key(monkeypatch):
    uploads = {}
    original = st.file_uploader
    def uploader(*args, **kwargs):
        original(*args, **kwargs)
        return uploads.get(kwargs.get('key'))
    monkeypatch.setattr(st, 'file_uploader', uploader)

    receiver = AppTest.from_file(APP).run()
    receiver.text_input(key='receiver_key_password').set_value('receiver-password')
    receiver.text_input(key='receiver_key_password_confirm').set_value('receiver-password')
    button(receiver, 'Create keys').click().run()
    public = receiver.session_state['recipient_keys']['public_text']
    assert not receiver.exception

    uploads['sender_upload'] = Upload(b'two separate sessions', 'example.txt')
    sender = AppTest.from_file(APP).run()
    assert sender.session_state['recipient_keys'] is None
    sender.text_area(key='sender_public_key').set_value(public).run()
    sender.checkbox(key='sender_manual_confirmed').check().run()
    button(sender, 'Encrypt file').click().run()
    package = sender.session_state['encrypted_package']['package_bytes']
    assert not sender.exception

    uploads['receiver_package_upload'] = Upload(package, 'delivery.qshield')
    receiver.radio[0].set_value('Open a file').run()
    receiver.text_input(key='receiver_decrypt_password').set_value('receiver-password')
    button(receiver, 'Decrypt file').click().run()
    assert receiver.session_state['recovered_file']['data'] == b'two separate sessions'

    wrong = AppTest.from_file(APP).run()
    wrong.text_input(key='receiver_key_password').set_value('receiver-password')
    wrong.text_input(key='receiver_key_password_confirm').set_value('receiver-password')
    button(wrong, 'Create keys').click().run()
    wrong.radio[0].set_value('Open a file').run()
    wrong.text_input(key='receiver_decrypt_password').set_value('receiver-password')
    button(wrong, 'Decrypt file').click().run()
    assert wrong.session_state['recovered_file'] is None
    assert any('Security warning' in x.value for x in wrong.error)


def test_older_key_needs_advanced_opt_in(monkeypatch):
    uploads = {'sender_upload': Upload(b'test', 'test.txt')}
    original = st.file_uploader
    def uploader(*args, **kwargs):
        original(*args, **kwargs)
        return uploads.get(kwargs.get('key'))
    monkeypatch.setattr(st, 'file_uploader', uploader)
    old = create_recipient_key_bundle('password', 1)
    app = AppTest.from_file(APP).run()
    app.text_area(key='sender_public_key').set_value(old.public_text).run()
    app.checkbox(key='sender_manual_confirmed').check().run()
    button(app, 'Encrypt file').click().run()
    assert app.session_state['encrypted_package'] is None
    app.checkbox(key='sender_allow_legacy').check().run()
    button(app, 'Encrypt file').click().run()
    assert app.session_state['encrypted_package']['suite'] == 1
    assert not app.exception


def test_optional_relay_moves_only_encrypted_package_between_sessions(monkeypatch):
    storage = {}
    monkeypatch.setattr(relay, 'is_configured', lambda: True)
    def put(kind, data, filename):
        assert kind == 'package'
        storage['package'] = (data, filename)
        return 'demo-code'
    monkeypatch.setattr(relay, 'put', put)
    monkeypatch.setattr(relay, 'get', lambda code, kind:
                        storage['package'] if code == 'demo-code' and kind == 'package'
                        else (None, None))
    uploads = {'sender_upload': Upload(b'relay test contents', 'hidden-name.txt')}
    original = st.file_uploader
    def uploader(*args, **kwargs):
        original(*args, **kwargs)
        return uploads.get(kwargs.get('key'))
    monkeypatch.setattr(st, 'file_uploader', uploader)

    receiver = AppTest.from_file(APP).run()
    receiver.text_input(key='receiver_key_password').set_value('receiver-password')
    receiver.text_input(key='receiver_key_password_confirm').set_value('receiver-password')
    button(receiver, 'Create keys').click().run()

    sender = AppTest.from_file(APP).run()
    sender.text_area(key='sender_public_key').set_value(
        receiver.session_state['recipient_keys']['public_text']).run()
    sender.checkbox(key='sender_manual_confirmed').check().run()
    button(sender, 'Encrypt file').click().run()
    button(sender, 'Send via relay').click().run()
    package, name = storage['package']
    assert name.startswith('qshield-') and name.endswith('.qshield')
    assert b'relay test contents' not in package
    assert b'hidden-name.txt' not in package
    assert sender.session_state['encrypted_package']['relay_code'] == 'demo-code'

    receiver.radio[0].set_value('Open a file').run()
    receiver.text_input(key='receiver_package_code').set_value('demo-code')
    button(receiver, 'Fetch package from relay').click().run()
    receiver.text_input(key='receiver_decrypt_password').set_value('receiver-password')
    button(receiver, 'Decrypt file').click().run()
    assert receiver.session_state['recovered_file']['data'] == b'relay test contents'
    assert not receiver.exception and not sender.exception
