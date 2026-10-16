"""Glue used by the Streamlit tabs. No new cryptographic algorithms.

Every function here calls core/pq_transfer.py (ML-KEM-768 + HKDF-SHA256 +
AES-256-GCM). The encrypted package format is unchanged.
"""

from dataclasses import dataclass

from core.file_crypto import DecryptedFile
from core import signatures, signed_transfer
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


# ---- Signed (version 2) packages: prove WHO sent it ------------------------------------
# These helpers are NOT used by the Streamlit tabs yet. They are the same
# functions the tabs (or any other software) would call.
@dataclass
class SenderIdentityBundle:
    """What the sender needs after creating a signing identity.

    protected_file is the encrypted private identity (password protected).
    public_text and the fingerprint are safe to share.
    """

    public_text: str
    fingerprint: str
    fingerprint_pretty: str
    protected_file: bytes


def create_sender_identity_bundle(password: str) -> SenderIdentityBundle:
    """Make a hybrid signing identity (Ed25519 + ML-DSA-65) and wrap it in a password."""
    identity = signatures.generate_signing_identity()
    protected = signatures.signing_identity_to_protected_bytes(identity, password)
    return SenderIdentityBundle(
        public_text=identity.public.to_text(),
        fingerprint=identity.public.fingerprint(),
        fingerprint_pretty=identity.public.fingerprint(pretty=True),
        protected_file=protected,
    )


def trusted_sender_from_text(public_identity_text: str, expected_fingerprint: str | None = None):
    """Turn pasted sender text into a PublicIdentity.

    Pass the fingerprint the sender read out to you over a second channel.
    A mismatch raises ValueError.
    """
    return signatures.PublicIdentity.from_text(public_identity_text, expected_fingerprint)


def sign_and_encrypt_uploaded_file(file_bytes: bytes, filename: str, public_key_text: str,
                                   identity_file: bytes, password: str) -> bytes:
    """Sign a sender upload with a protected identity, then encrypt it for the pasted key."""
    identity = signatures.load_signing_identity_from_bytes(identity_file, password)
    public_key = public_key_from_text(public_key_text)
    return signed_transfer.sign_and_encrypt(file_bytes, public_key, identity, filename=filename)


def verify_uploaded_package(package_bytes: bytes, protected_pem: bytes, password: str,
                            trusted_senders, max_age_seconds: int | None = None
                            ) -> "signed_transfer.VerifiedFile":
    """Open a signed .qshield package and check it was signed by a trusted sender.

    `trusted_senders` is a PublicIdentity (or a list of them). Raises
    UnsignedPackageError, UnknownSenderError, InvalidSignatureError,
    WrongRecipientError or TransferError. Nothing is returned unless every
    check passes.
    """
    private_key = load_private_key_from_bytes(protected_pem, password)
    return signed_transfer.decrypt_and_verify(
        package_bytes, private_key, trusted_senders, max_age_seconds=max_age_seconds
    )
