"""Glue used by the Streamlit tabs. No new cryptographic algorithms.

Every function here calls core/pq_transfer.py (ML-KEM-768 + HKDF-SHA256 +
AES-256-GCM). The encrypted package format is unchanged.
"""

import time
from dataclasses import dataclass

from core import identity
from core.file_crypto import DecryptedFile
from core.pq_transfer import (
    decrypt_package,
    encrypt_for_recipient,
    generate_recipient_keypair,
    load_private_key_from_bytes,
    private_key_to_protected_pem,
    public_key_fingerprint,
    public_key_from_bytes,
    public_key_from_text,
    public_key_to_bytes,
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


# ---- Authenticated receiver keys (see core/identity.py) ----------------------------
@dataclass
class IdentityBundle:
    """A receiver's signing identity. protected_pem is encrypted PKCS#8; the raw key is not stored."""

    qshield_id: str
    protected_pem: bytes


def create_identity_bundle(password: str) -> IdentityBundle:
    if not password:
        raise ValueError("A password is required to protect the identity key.")
    key = identity.generate_identity()
    return IdentityBundle(identity.identity_id(key), identity.identity_to_protected_pem(key, password))


def open_identity_bundle(protected_pem: bytes, password: str) -> IdentityBundle:
    key = identity.load_identity_from_pem(protected_pem, password)
    return IdentityBundle(identity.identity_id(key), bytes(protected_pem))


def sign_key_bundle(protected_identity_pem: bytes, password: str, kem_public_text: str,
                    previous_seq: int = 0, revoked_key_ids=()) -> tuple[bytes, int]:
    """Sign the receiver's ML-KEM public key with their identity. Returns (envelope, seq).

    seq is time-based and always greater than previous_seq, so it needs no stored counter."""
    signer = identity.load_identity_from_pem(protected_identity_pem, password)
    kem_bytes = public_key_to_bytes(public_key_from_text(kem_public_text))
    seq = max(int(time.time()), previous_seq + 1)
    envelope = identity.create_key_bundle(signer, kem_bytes, seq=seq, revoked_key_ids=revoked_key_ids)
    return envelope, seq


def encrypt_for_verified_key(file_bytes: bytes, filename: str, verified: identity.VerifiedKey) -> bytes:
    """Encrypt for a key that already passed verify_key_bundle(). Nothing else is accepted."""
    if not isinstance(verified, identity.VerifiedKey):
        raise TypeError("Only an authenticated key (VerifiedKey) can be used here.")
    return encrypt_for_recipient(file_bytes, public_key_from_bytes(verified.kem_public_key), filename=filename)
