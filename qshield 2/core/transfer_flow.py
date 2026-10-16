"""Glue used by the Streamlit tabs. No new cryptographic algorithms.

Every function here calls core/pq_transfer.py (ML-KEM + HKDF-SHA256 +
AES-256-GCM). The receiver picks one of three suites when making keys:
1 = ML-KEM-768, 2 = X25519 + ML-KEM-768 (hybrid), 3 = ML-KEM-1024.
"""

import io
import secrets
import time
from dataclasses import dataclass

from core import identity
from core.file_crypto import DecryptedFile
from core.pq_transfer import (
    decrypt_package,
    encrypt_for_recipient,
    encrypt_stream_for_recipient,
    generate_recipient_keypair,
    load_private_key_from_bytes,
    private_key_to_protected_pem,
    public_key_fingerprint,
    public_key_from_bytes,
    suite_name,
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
    suite: int = 1
    suite_name: str = "ML-KEM-768"


def create_recipient_key_bundle(password: str, suite: int = 1) -> RecipientKeyBundle:
    """Make a key pair for the chosen suite and immediately wrap the private key in a password."""
    if not password:
        raise ValueError("A password is required to protect the private key file.")
    private_key = generate_recipient_keypair(suite)
    public_key = private_key.public_key()
    protected_pem = private_key_to_protected_pem(private_key, password)
    return RecipientKeyBundle(
        public_text=public_key_to_text(public_key),
        fingerprint=public_key_fingerprint(public_key),
        fingerprint_pretty=public_key_fingerprint(public_key, pretty=True),
        protected_pem=protected_pem,
        suite=suite,
        suite_name=suite_name(suite),
    )


def package_download_name(original_filename: str, hide_name: bool = False) -> str:
    """The name for the downloaded package.

    hide_name=True gives a neutral random name, so the original file name is not
    visible outside the encryption (in the file system, an email, or the relay).
    The real name is stored inside the package and comes back when it is opened.
    """
    if hide_name:
        return f"qshield-{secrets.token_hex(4)}.qshield"
    name = (original_filename or "file").replace("\\", "/").split("/")[-1].strip()
    if not name or name in (".", ".."):
        name = "file"
    if name.lower().endswith(".qshield"):
        return name
    return f"{name}.qshield"


def encrypt_uploaded_file(file_bytes: bytes, filename: str, public_key_text: str,
                          padding=None) -> bytes:
    """Encrypt a sender upload for the pasted recipient public key.

    padding: None (exact size visible), "padme", or a block size in bytes.
    """
    public_key = public_key_from_text(public_key_text)
    return encrypt_for_recipient(file_bytes, public_key, filename=filename, padding=padding)


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


# ---- Streaming from an upload handle (version 2 packages) -----------------------------
# Streamlit's UploadedFile is an in-memory file object, so this reads it in segments
# instead of calling .getvalue(), but the framework has already buffered the whole upload
# and the result is returned as bytes for the download button. See README.
def encrypt_stream_to_package(file_obj, filename: str, size: int, public_key, *, legacy: bool = False) -> bytes:
    """Encrypt an open binary file object for a recipient and return the package bytes.

    legacy=True makes a version 1 package (the only kind the browser app can open)."""
    file_obj.seek(0)
    if legacy:
        return encrypt_for_recipient(file_obj.read(), public_key, filename=filename)
    out = io.BytesIO()
    encrypt_stream_for_recipient(file_obj, out, public_key, filename, size=size)
    return out.getvalue()


def encrypt_stream_for_verified_key(file_obj, filename: str, size: int,
                                    verified: identity.VerifiedKey, *, legacy: bool = False) -> bytes:
    """Like encrypt_for_verified_key(), but reads from a file object."""
    if not isinstance(verified, identity.VerifiedKey):
        raise TypeError("Only an authenticated key (VerifiedKey) can be used here.")
    return encrypt_stream_to_package(
        file_obj, filename, size, public_key_from_bytes(verified.kem_public_key), legacy=legacy
    )
