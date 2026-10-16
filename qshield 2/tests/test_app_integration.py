"""Integration tests for the Streamlit app's encryption flow.

These tests call the same helpers the Sender and Receiver tabs use.
They do not start a browser. Run from the qshield folder with: pytest
"""

import pytest

from core.file_crypto import DecryptionError
from core.pq_transfer import (
    MAGIC,
    WrongRecipientError,
    load_private_key_from_bytes,
    public_key_from_text,
)
from core.security_status import WORKING, get_feature_list
from core.transfer_flow import (
    create_recipient_key_bundle,
    decrypt_uploaded_package,
    encrypt_uploaded_file,
    package_download_name,
)

SECRET = b"qshield-demo-test-file-not-real-secrets\n"


def test_website_flow_generate_encrypt_decrypt_download():
    """Receiver makes keys, sender encrypts with the public text, receiver opens the package."""
    bundle = create_recipient_key_bundle("correct horse battery")

    assert b"ENCRYPTED PRIVATE KEY" in bundle.protected_pem
    sender_public = public_key_from_text(bundle.public_text)

    package = encrypt_uploaded_file(SECRET, "notes.txt", bundle.public_text)
    assert package.startswith(MAGIC)
    assert SECRET not in package
    assert package_download_name("notes.txt") == "notes.txt.qshield"

    result = decrypt_uploaded_package(package, bundle.protected_pem, "correct horse battery")
    assert result.data == SECRET
    assert result.filename == "notes.txt"
    assert result.data == decrypt_uploaded_package(
        package,
        bundle.protected_pem,
        "correct horse battery",
    ).data

    # The sender only ever received public text; the loaded key still matches it.
    loaded = load_private_key_from_bytes(bundle.protected_pem, "correct horse battery")
    assert loaded.public_key().public_bytes_raw() == sender_public.public_bytes_raw()


def test_wrong_password_does_not_release_the_file():
    bundle = create_recipient_key_bundle("right-password")
    package = encrypt_uploaded_file(SECRET, "notes.txt", bundle.public_text)
    with pytest.raises(ValueError):
        decrypt_uploaded_package(package, bundle.protected_pem, "wrong-password")


def test_wrong_recipient_key_does_not_release_the_file():
    intended = create_recipient_key_bundle("pw-a")
    other = create_recipient_key_bundle("pw-b")
    package = encrypt_uploaded_file(SECRET, "notes.txt", intended.public_text)
    with pytest.raises(WrongRecipientError):
        decrypt_uploaded_package(package, other.protected_pem, "pw-b")


def test_modified_package_does_not_release_the_file():
    bundle = create_recipient_key_bundle("pw")
    package = bytearray(encrypt_uploaded_file(SECRET, "notes.txt", bundle.public_text))
    package[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_uploaded_package(bytes(package), bundle.protected_pem, "pw")


def test_protected_pem_does_not_contain_raw_private_key():
    bundle = create_recipient_key_bundle("pw")
    private = load_private_key_from_bytes(bundle.protected_pem, "pw")
    assert private.private_bytes_raw() not in bundle.protected_pem


def test_empty_password_is_refused():
    with pytest.raises(ValueError):
        create_recipient_key_bundle("")


@pytest.mark.parametrize(
    "name, expected",
    [
        ("photo.jpg", "photo.jpg.qshield"),
        ("photo.jpg.qshield", "photo.jpg.qshield"),
        ("../evil.txt", "evil.txt.qshield"),
        ("", "file.qshield"),
    ],
)
def test_package_download_name(name, expected):
    assert package_download_name(name) == expected


def test_security_status_marks_connected_crypto_as_working():
    rows = {row["Feature"]: row for row in get_feature_list()}
    assert rows["File encryption (AES-256-GCM)"]["Status"] == WORKING
    assert rows["Key establishment, suite 1 (ML-KEM-768 + HKDF-SHA256)"]["Status"] == WORKING
    assert rows["Hybrid key establishment, suite 2 (X25519 + ML-KEM-768 + HKDF-SHA256)"]["Status"] == WORKING
    assert rows["Higher security level, suite 3 (ML-KEM-1024 + HKDF-SHA256)"]["Status"] == WORKING
    assert rows["Encrypted file integrity verification"]["Status"] == WORKING
    assert "not connected" not in rows["File encryption (AES-256-GCM)"]["Details"].lower()
    assert rows["Sender identity verification"]["Status"] != WORKING
    assert rows["Network file transfer"]["Status"] != WORKING
