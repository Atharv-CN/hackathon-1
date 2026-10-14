"""Glue used by the Streamlit tabs. No new cryptographic algorithms.

Every function here calls core/pq_transfer.py (ML-KEM-768 + HKDF-SHA256 +
AES-256-GCM). The encrypted package format is unchanged.
"""

from dataclasses import dataclass

from core.file_crypto import DecryptedFile
from core.pq_transfer import (
    decrypt_package,
    encrypt_for_recipient,
    generate_recipient_keypair,
    load_private_key_from_bytes,
    private_key_to_protected_pem,
    public_key_fingerprint,
    public_key_from_text,
    public_key_to_text,
)


@dataclass
class RecipientKeyBundle:
    """What the Receiver tab needs after generating a key pair.

    protected_pem is encrypted PKCS#8. The raw private key is not stored.
    """

    public_text: str
    fingerprint: str
    fingerprint_pretty: str
    protected_pem: bytes


def create_recipient_key_bundle(password: str) -> RecipientKeyBundle:
    """Make an ML-KEM-768 pair and immediately wrap the private key in a password."""
    if not password:
        raise ValueError("A password is required to protect the private key file.")
    private_key = generate_recipient_keypair()
    public_key = private_key.public_key()
    protected_pem = private_key_to_protected_pem(private_key, password)
    return RecipientKeyBundle(
        public_text=public_key_to_text(public_key),
        fingerprint=public_key_fingerprint(public_key),
        fingerprint_pretty=public_key_fingerprint(public_key, pretty=True),
        protected_pem=protected_pem,
    )


def package_download_name(original_filename: str) -> str:
    name = (original_filename or "file").replace("\\", "/").split("/")[-1].strip()
    if not name or name in (".", ".."):
        name = "file"
    if name.lower().endswith(".qshield"):
        return name
    return f"{name}.qshield"


def encrypt_uploaded_file(file_bytes: bytes, filename: str, public_key_text: str) -> bytes:
    """Encrypt a sender upload for the pasted recipient public key."""
    public_key = public_key_from_text(public_key_text)
    return encrypt_for_recipient(file_bytes, public_key, filename=filename)


def decrypt_uploaded_package(package_bytes: bytes, protected_pem: bytes, password: str) -> DecryptedFile:
    """Open a .qshield package with a password-protected private key.

    Raises TransferError / WrongRecipientError / ValueError on failure.
    Nothing is returned unless every check passes.
    """
    private_key = load_private_key_from_bytes(protected_pem, password)
    return decrypt_package(package_bytes, private_key)
