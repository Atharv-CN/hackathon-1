"""Send a file to a recipient using ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.

THE IDEA (think of a padlock)
  1. The receiver makes a key pair. The PUBLIC key is like an open padlock:
     it can be handed to anyone. The PRIVATE key is the only key that opens
     it, and it never leaves the receiver's side.
  2. The sender uses the public key to make a brand-new shared secret plus a
     "locked box" (the KEM ciphertext) that only the receiver's private key
     can open. This step is ML-KEM-768 (NIST FIPS 203), a key-establishment
     algorithm designed to resist quantum computers. It is done by the
     `cryptography` library (OpenSSL), not by code in this file.
  3. Now both sides know the same secret. HKDF-SHA256 (RFC 5869) turns it into
     a 256-bit AES key. The whole package header is mixed into this step.
  4. The file is encrypted with AES-256-GCM (core/file_crypto.py).

WHY THE PRIVATE KEY STAYS WITH THE RECEIVER
  The sender functions only accept a PUBLIC key (a private key is refused).
  Nothing in the package is secret key material: it holds only the locked box.

PACKAGE LAYOUT (version 1). Every field has a fixed size.
  +-------+---------+-------+---------------------+------------------+-----------------+
  | magic | version | suite | recipient key       | KEM ciphertext   | encrypted file  |
  | QSHK  | 1 byte  | 1 byte| fingerprint         | (the locked box) | (a file_crypto  |
  | 4 B   |         |       | SHA-256, 32 bytes   | 1088 bytes       |  container)     |
  +-------+---------+-------+---------------------+------------------+-----------------+
  suite 1 = ML-KEM-768 + HKDF-SHA256 + AES-256-GCM. A new "suite" number is how
  future versions can change algorithms without confusing old packages.
  The recipient fingerprint tells the receiver which key the package is for.
  It is only a label: the real protection is that the AES key cannot be
  derived without the right private key.

IMPORTANT LIMITS - please read
  - NO SENDER IDENTITY. Anyone who has the recipient's public key can make a
    valid package. The receiver cannot tell who sent it. (Digital signatures
    would be needed for that. They are not built.)
  - CHECK THE PUBLIC KEY. If an attacker swaps the receiver's public key for
    their own, the sender would encrypt for the attacker. Compare key
    fingerprints over a second channel (phone call, in person) before trusting
    a public key. Use public_key_fingerprint().
  - NO FORWARD SECRECY for the long-term key. Whoever steals the receiver's
    private key later can open packages saved earlier.
  - The file name and file size are visible (the name is protected from being
    changed, but it is not secret).
  - This code has not had an independent security audit.
  - The Streamlit Sender and Receiver tabs call this module. Encryption still
    does not prove who the sender is.
  - If the installed `cryptography` build cannot do ML-KEM, this module STOPS
    with PostQuantumUnavailableError. It never quietly switches to ordinary
    encryption.
"""

import base64
import binascii
import functools
import hashlib
import hmac
import os
import struct
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto
from core.file_crypto import DecryptedFile, DecryptionError

# ---- Format constants (version 1) -------------------------------------------
MAGIC = b"QSHK"                  # marks "this is a QShield key-transfer package"
VERSION = 1
SUITE_MLKEM768_HKDF_SHA256_AES256GCM = 1

PUBLIC_KEY_SIZE = 1184           # ML-KEM-768 public key (FIPS 203)
KEM_CIPHERTEXT_SIZE = 1088       # ML-KEM-768 ciphertext  (FIPS 203)
SHARED_SECRET_SIZE = 32          # ML-KEM-768 shared secret (FIPS 203)
FINGERPRINT_SIZE = 32            # SHA-256 of the recipient's public key
AES_KEY_SIZE = 32                # AES-256

# magic (4 bytes), version (1), suite (1), recipient fingerprint (32)
_PREFIX = struct.Struct(">4sBB32s")
HEADER_SIZE = _PREFIX.size + KEM_CIPHERTEXT_SIZE   # 38 + 1088 = 1126

# Written into the key derivation so keys made for QShield can never be
# confused with keys made for something else.
KDF_LABEL = b"QShield v1: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"


# ---- Errors -----------------------------------------------------------------
class TransferError(DecryptionError):
    """The package could not be opened (changed, damaged, or not for this key).

    It is a kind of DecryptionError, so `except DecryptionError` catches it too.
    """


class WrongRecipientError(TransferError):
    """The package was made for a different recipient key."""


class PostQuantumUnavailableError(RuntimeError):
    """ML-KEM-768 is not available. QShield will NOT fall back to ordinary encryption."""


def _no_fallback(func):
    """Turn "this build has no ML-KEM" into a clear error. (A decorator wraps a
    function with extra behaviour; here it only watches for that one problem.)"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except UnsupportedAlgorithm:
            raise PostQuantumUnavailableError(
                "This installation of the 'cryptography' library does not support "
                "ML-KEM-768. QShield will NOT fall back to ordinary encryption. "
                "Install a newer 'cryptography' (see requirements.txt)."
            ) from None

    return wrapper


# ---- Recipient keys ----------------------------------------------------------
@_no_fallback
def generate_recipient_keypair() -> MLKEM768PrivateKey:
    """Make a new ML-KEM-768 key pair. Keep the returned PRIVATE key on the
    receiving side. Get the public half with `.public_key()`."""
    return MLKEM768PrivateKey.generate()


def _fingerprint_bytes(public_key: MLKEM768PublicKey) -> bytes:
    return hashlib.sha256(public_key.public_bytes_raw()).digest()


def public_key_fingerprint(public_key: MLKEM768PublicKey, pretty: bool = False) -> str:
    """A short ID of a public key (SHA-256, in hex). Compare it with the
    receiver over a second channel to be sure you have the right key.
    pretty=True groups it in blocks of 4 so it is easier to read aloud."""
    digest = _fingerprint_bytes(public_key).hex()
    if pretty:
        return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
    return digest


def public_key_to_bytes(public_key: MLKEM768PublicKey) -> bytes:
    """The public key as 1184 raw bytes. Safe to share."""
    return public_key.public_bytes_raw()


@_no_fallback
def public_key_from_bytes(data: bytes) -> MLKEM768PublicKey:
    """Rebuild a public key from 1184 raw bytes."""
    return MLKEM768PublicKey.from_public_bytes(data)


def public_key_to_text(public_key: MLKEM768PublicKey) -> str:
    """The public key as copy-and-paste text (URL-safe base64). Safe to share."""
    return base64.urlsafe_b64encode(public_key_to_bytes(public_key)).decode("ascii")


def public_key_from_text(text: str) -> MLKEM768PublicKey:
    """Rebuild a public key from the text made by public_key_to_text()."""
    cleaned = "".join(text.split()).replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        data = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("That is not a valid public key. Copy the whole key again.") from None
    return public_key_from_bytes(data)


# ---- Keeping the private key safe on the receiving side ------------------------
def _password_bytes(password) -> bytes:
    data = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not data:
        raise ValueError("A password is required to protect the private key file.")
    return data


def private_key_to_protected_pem(private_key: MLKEM768PrivateKey, password) -> bytes:
    """Return the private key as password-protected PKCS#8 PEM bytes.

    The PEM is encrypted. It is safe to download or keep in memory. Never print
    it in logs or show it on the sender's screen.
    """
    if not isinstance(private_key, MLKEM768PrivateKey):
        raise TypeError("private_key must be an ML-KEM-768 private key.")
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_password_bytes(password)),
    )


@_no_fallback
def load_private_key_from_bytes(data: bytes, password) -> MLKEM768PrivateKey:
    """Load a private key from PEM bytes made by private_key_to_protected_pem()."""
    try:
        key = serialization.load_pem_private_key(bytes(data), _password_bytes(password))
    except (ValueError, TypeError):
        raise ValueError("Could not open the key file: wrong password, or the file is damaged.") from None
    if not isinstance(key, MLKEM768PrivateKey):
        raise ValueError("This key file is not an ML-KEM-768 private key.")
    return key


def save_private_key(private_key: MLKEM768PrivateKey, path, password, overwrite: bool = False) -> Path:
    """Save the private key to a password-protected file (encrypted PKCS#8 PEM).

    Only the receiver should ever do this, on the receiver's own computer.
    The file is created readable by its owner only (on Linux and macOS) and an
    existing file is never replaced unless overwrite=True.
    """
    pem = private_key_to_protected_pem(private_key, password)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    flags |= getattr(os, "O_BINARY", 0)  # Windows only; harmless elsewhere
    with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
        f.write(pem)
    return path


def load_private_key(path, password) -> MLKEM768PrivateKey:
    """Load a private key saved by save_private_key()."""
    return load_private_key_from_bytes(Path(path).read_bytes(), password)


# ---- Key derivation -----------------------------------------------------------
def _derive_aes_key(shared_secret: bytes, header: bytes) -> bytes:
    """HKDF-SHA256: turn the ML-KEM shared secret into a 256-bit AES key.

    The whole header (version, suite, recipient fingerprint, KEM ciphertext) is
    mixed in, so the key only works for exactly this package. No salt is used:
    the ML-KEM secret is already uniformly random and is new for every package.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=KDF_LABEL + b"\x00" + header,
    ).derive(shared_secret)


# ---- Encrypt / decrypt ----------------------------------------------------------
@_no_fallback
def encrypt_for_recipient(plaintext: bytes, recipient_public_key: MLKEM768PublicKey,
                          filename: str = "file") -> bytes:
    """Encrypt bytes for a recipient and return the transfer package (bytes).

    Only the recipient's PUBLIC key is needed (and accepted).
    """
    if isinstance(recipient_public_key, MLKEM768PrivateKey):
        raise TypeError(
            "Give the recipient's PUBLIC key, not a private key. "
            "A private key must never leave the receiving side."
        )
    if not isinstance(recipient_public_key, MLKEM768PublicKey):
        raise TypeError("recipient_public_key must be an ML-KEM-768 public key.")

    shared_secret, kem_ciphertext = recipient_public_key.encapsulate()
    if len(shared_secret) != SHARED_SECRET_SIZE or len(kem_ciphertext) != KEM_CIPHERTEXT_SIZE:
        raise TransferError("The ML-KEM library returned unexpected sizes. Stopping.")

    header = _PREFIX.pack(
        MAGIC, VERSION, SUITE_MLKEM768_HKDF_SHA256_AES256GCM,
        _fingerprint_bytes(recipient_public_key),
    ) + kem_ciphertext

    aes_key = _derive_aes_key(shared_secret, header)
    return header + file_crypto.encrypt_bytes(plaintext, aes_key, filename=filename)


@_no_fallback
def decrypt_package(package: bytes, recipient_private_key: MLKEM768PrivateKey) -> DecryptedFile:
    """Open a transfer package with the recipient's private key.

    Raises WrongRecipientError if it was made for a different key, or
    TransferError if it is damaged, changed, or not a QShield package.
    Nothing is returned unless every check passes.
    """
    if not isinstance(recipient_private_key, MLKEM768PrivateKey):
        raise TypeError("recipient_private_key must be an ML-KEM-768 private key.")
    if not isinstance(package, (bytes, bytearray, memoryview)):
        raise TypeError("package must be bytes.")
    package = bytes(package)

    if len(package) < HEADER_SIZE:
        raise TransferError("This is too short to be a QShield transfer package.")

    magic, version, suite, fingerprint = _PREFIX.unpack_from(package, 0)
    if magic != MAGIC:
        raise TransferError("This is not a QShield transfer package.")
    if version != VERSION:
        raise TransferError(f"Unsupported package version: {version}.")
    if suite != SUITE_MLKEM768_HKDF_SHA256_AES256GCM:
        raise TransferError(f"Unsupported algorithm suite: {suite}.")

    own_fingerprint = _fingerprint_bytes(recipient_private_key.public_key())
    if not hmac.compare_digest(fingerprint, own_fingerprint):
        raise WrongRecipientError(
            "This package was made for a different recipient key. "
            "Ask the sender to encrypt it again with your public key."
        )

    header = package[:HEADER_SIZE]
    kem_ciphertext = header[_PREFIX.size:]
    # ML-KEM never raises on a damaged ciphertext. It quietly returns a
    # different secret, so the AES-GCM check below is what catches the damage.
    shared_secret = recipient_private_key.decapsulate(kem_ciphertext)
    aes_key = _derive_aes_key(shared_secret, header)

    try:
        return file_crypto.decrypt_bytes(package[HEADER_SIZE:], aes_key)
    except DecryptionError:
        raise TransferError(
            "Could not open the package: it was changed or damaged, "
            "or it was not made for this recipient key."
        ) from None


# ---- Files on disk ------------------------------------------------------------
def encrypt_file_for_recipient(input_path, output_path, recipient_public_key: MLKEM768PublicKey,
                               overwrite: bool = False) -> Path:
    """Read a file, encrypt it for the recipient, and write the package."""
    input_path, output_path = Path(input_path), Path(output_path)
    package = encrypt_for_recipient(input_path.read_bytes(), recipient_public_key,
                                    filename=input_path.name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb" if overwrite else "xb") as f:  # "xb": never overwrite
        f.write(package)
    return output_path


def decrypt_package_file(package_path, output_dir, recipient_private_key: MLKEM768PrivateKey,
                         overwrite: bool = False) -> Path:
    """Open a package file into output_dir. Written only after every check passes."""
    result = decrypt_package(Path(package_path).read_bytes(), recipient_private_key)
    return file_crypto.write_decrypted_file(result, output_dir, overwrite)
