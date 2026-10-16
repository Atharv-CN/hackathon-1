"""Send a file to a recipient with ML-KEM + HKDF-SHA256 + AES-256-GCM (three suites).

THE IDEA (think of a padlock)
  1. The receiver makes a key pair. The PUBLIC key is like an open padlock:
     it can be handed to anyone. The PRIVATE key is the only key that opens
     it, and it never leaves the receiver's side.
  2. The sender uses the public key to make a brand-new shared secret plus a
     "locked box" (the KEM ciphertext) that only the receiver's private key
     can open. ML-KEM (NIST FIPS 203) is a key-establishment algorithm designed
     to resist quantum computers. It is done by the `cryptography` library
     (OpenSSL), not by code in this file.
  3. Now both sides know the same secret. HKDF-SHA256 (RFC 5869) turns it into
     a 256-bit AES key. The whole package header is mixed into this step.
  4. The file is encrypted with AES-256-GCM (core/file_crypto.py).

THE THREE SUITES (the receiver picks one when making the key pair)
  suite 1  ML-KEM-768 only. No hybrid. (The original QShield format.)
  suite 2  HYBRID: X25519 + ML-KEM-768. Two secrets are made at the same time
           and BOTH go into the HKDF input (ML-KEM secret first, then the
           X25519 secret, 32 + 32 bytes). An attacker has to break both. So if
           a flaw is found in the newer algorithm (ML-KEM), the older, heavily
           studied X25519 still protects against attackers who use ordinary
           computers. (A future quantum computer breaks X25519, so against a
           quantum attacker the protection comes from ML-KEM alone.)
  suite 3  ML-KEM-1024 only (higher security level, bigger keys). It is the
           same algorithm family as suite 1, so it is NOT a hedge against a
           flaw in ML-KEM itself. It only adds safety margin.
  A package records its suite in the header. A key only opens packages of its
  own suite, so nobody can trick the receiver into a weaker suite.

WHY THE PRIVATE KEY STAYS WITH THE RECEIVER
  The sender functions only accept a PUBLIC key (a private key is refused).
  Nothing in the package is secret key material: it holds only the locked box.

PACKAGE LAYOUT (version 1). Every field has a fixed size for its suite.
  +-------+---------+-------+---------------------+------------------+-----------------+
  | magic | version | suite | recipient key       | KEM ciphertext   | encrypted file  |
  | QSHK  | 1 byte  | 1 byte| fingerprint         | (the locked box) | (a file_crypto  |
  | 4 B   |         |       | SHA-256, 32 bytes   | see sizes below  |  container)     |
  +-------+---------+-------+---------------------+------------------+-----------------+
  KEM ciphertext: suite 1 = 1088 bytes (ML-KEM-768 box).
                  suite 2 = 1120 bytes (32-byte X25519 sender key + 1088-byte ML-KEM-768 box).
                  suite 3 = 1568 bytes (ML-KEM-1024 box).
  A new "suite" number is how future versions can change algorithms without
  confusing old packages. The recipient fingerprint tells the receiver which key
  the package is for. It is only a label: the real protection is that the AES key
  cannot be derived without the right private key. The fingerprint is a hash of
  the WHOLE public key (for suite 2, both halves), and it is mixed into the key
  derivation together with the KEM ciphertext.

KEY FILES
  Suites 1 and 3: one password-protected PKCS#8 PEM block.
  Suite 2: two password-protected PKCS#8 PEM blocks in one file (X25519 first,
  then ML-KEM-768), both protected by the same password.
  Public key text: suite 1 is plain text (unchanged). Suites 2 and 3 start with
  "QS2:" or "QS3:" so the app knows which suite a pasted key belongs to.

PACKAGE VERSIONS
  - Version 1 (suite 1): one AES-GCM message. encrypt_for_recipient() /
    decrypt_package() work on complete `bytes`, so version 1 is whole-file, in memory,
    and limited to ~2 GB. It is frozen: old packages and the golden test vector open.
  - Version 2 (suite 2): STREAM construction, bounded memory, no 2 GB limit.
    encrypt_stream_for_recipient() / decrypt_package_stream() work on file objects;
    encrypt_file_for_recipient() / decrypt_package_file() use it for files on disk.
    decrypt_package() also opens version 2 packages, but because it RETURNS bytes
    that call necessarily holds the whole file in memory.
  The reader dispatches on the validated version byte. A version 2 package is never
  handed to the version 1 code (or the other way round) and unknown versions fail.

IMPORTANT LIMITS - please read
  - NO SENDER IDENTITY. Anyone who has the recipient's public key can make a
    valid package. The receiver cannot tell who sent it. (Digital signatures
    would be needed for that. They are not built.)
  - CHECK THE PUBLIC KEY. If an attacker swaps the receiver's public key for
    their own, the sender would encrypt for the attacker. Compare key
    fingerprints over a second channel (phone call, in person) before trusting
    a public key. Use public_key_fingerprint().
  - NO FORWARD SECRECY for the long-term key. Whoever steals the receiver's
    private key later can open packages saved earlier. That is expected for
    stored files. For live channels use core/session.py, which adds an
    ephemeral-KEM handshake with forward secrecy.
  - The file name, exact size and creation time are inside the encrypted part
    (container version 2). What stays visible: the suite, the recipient key
    fingerprint and the total package length. Optional padding hides the size
    (padding="padme" or a block size, see core/file_crypto.py).
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
import io
import os
import stat
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto
from core.file_crypto import DecryptedFile, DecryptionError

# ---- Format constants (version 1) -------------------------------------------
MAGIC = b"QSHK"                  # marks "this is a QShield key-transfer package"
VERSION = 1

# Algorithm suites. All three use HKDF-SHA256 and AES-256-GCM after the KEM step.
SUITE_MLKEM768_HKDF_SHA256_AES256GCM = 1   # ML-KEM-768 only (no hybrid)
SUITE_X25519_MLKEM768_HKDF_SHA256_AES256GCM = 2   # hybrid
SUITE_MLKEM1024_HKDF_SHA256_AES256GCM = 3  # ML-KEM-1024 only
SUITE_MLKEM768 = SUITE_MLKEM768_HKDF_SHA256_AES256GCM
SUITE_HYBRID_X25519_MLKEM768 = SUITE_X25519_MLKEM768_HKDF_SHA256_AES256GCM
SUITE_MLKEM1024 = SUITE_MLKEM1024_HKDF_SHA256_AES256GCM

PUBLIC_KEY_SIZE = 1184           # ML-KEM-768 public key (FIPS 203)
KEM_CIPHERTEXT_SIZE = 1088       # ML-KEM-768 ciphertext  (FIPS 203)
SHARED_SECRET_SIZE = 32          # ML-KEM shared secret (FIPS 203)
FINGERPRINT_SIZE = 32            # SHA-256 of the recipient's public key
AES_KEY_SIZE = 32                # AES-256
X25519_KEY_SIZE = 32             # X25519 public key / shared secret (RFC 7748)

# magic (4 bytes), version (1), suite (1), recipient fingerprint (32)
_PREFIX = struct.Struct(">4sBB32s")
HEADER_SIZE = _PREFIX.size + KEM_CIPHERTEXT_SIZE   # suite 1: 38 + 1088 = 1126


@dataclass(frozen=True)
class _Suite:
    number: int
    name: str
    public_key_size: int
    kem_ciphertext_size: int
    # Written into the key derivation so keys made for QShield can never be
    # confused with keys made for something else (or for another suite).
    kdf_label: bytes

    @property
    def header_size(self) -> int:
        return _PREFIX.size + self.kem_ciphertext_size


SUITES = {
    1: _Suite(1, "ML-KEM-768", PUBLIC_KEY_SIZE, KEM_CIPHERTEXT_SIZE,
              b"QShield v1: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"),
    2: _Suite(2, "X25519 + ML-KEM-768 (hybrid)", X25519_KEY_SIZE + PUBLIC_KEY_SIZE,
              X25519_KEY_SIZE + KEM_CIPHERTEXT_SIZE,
              b"QShield v1: X25519 + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"),
    3: _Suite(3, "ML-KEM-1024", 1568, 1568,
              b"QShield v1: ML-KEM-1024 + HKDF-SHA256 + AES-256-GCM"),
}
KDF_LABEL = SUITES[1].kdf_label  # kept for older code and tests

# Public-key text: suite 1 has no prefix (so old keys keep working).
_TEXT_PREFIXES = {2: "QS2:", 3: "QS3:"}


def suite_name(suite: int) -> str:
    """Human-readable name of a suite number, e.g. 'ML-KEM-768'."""
    if suite not in SUITES:
        raise ValueError(f"Unknown algorithm suite: {suite}.")
    return SUITES[suite].name


# ---- Hybrid key objects (suite 2) -------------------------------------------
@dataclass(frozen=True)
class HybridPublicKey:
    """Public half of a suite-2 key: an X25519 key plus an ML-KEM-768 key. Safe to share."""

    x25519: X25519PublicKey
    mlkem: MLKEM768PublicKey

    def public_bytes_raw(self) -> bytes:
        """32 bytes (X25519) followed by 1184 bytes (ML-KEM-768) = 1216 bytes."""
        return self.x25519.public_bytes_raw() + self.mlkem.public_bytes_raw()


@dataclass(frozen=True)
class HybridPrivateKey:
    """Private half of a suite-2 key. Keep it on the receiving side."""

    x25519: X25519PrivateKey
    mlkem: MLKEM768PrivateKey

    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(self.x25519.public_key(), self.mlkem.public_key())

# ---- Streaming packages (version 2) -------------------------------------------
# Same outer header as version 1 (magic, version, suite, recipient fingerprint, KEM
# ciphertext), but version = 2 and suite = 2, followed by a streaming body:
#   outer header (1126 B) | segment size (4) | metadata length (4) | metadata JSON
#   | STREAM header (40 B: length, salt, nonce prefix) | AES-256-GCM segments
# Keys: ML-KEM shared secret (32 B, fresh per package)
#         --HKDF-SHA256(salt = STREAM salt, info = label | 0x00 | outer header | envelope)-->
#       one AES-256 key for every segment. Nothing else is derived and nothing is stored.
# Segments, nonces, the final-segment flag and the 2**32 segment limit follow the STREAM
# construction exactly as described in core/file_crypto.py.
# Version 1 packages are untouched and still open; the reader picks the path from the
# validated version byte and never falls back from one to the other.
VERSION_STREAM = 2
SUITE_MLKEM768_HKDF_SHA256_AES256GCM_STREAM = 2
KDF_LABEL_STREAM = b"QShield v2 stream: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM-STREAM"
_LEGACY_MAX_PACKAGE = file_crypto.MAX_PLAINTEXT_SIZE + file_crypto.MAX_METADATA_SIZE + HEADER_SIZE + 64


# ---- Errors -----------------------------------------------------------------
class TransferError(DecryptionError):
    """The package could not be opened (changed, damaged, or not for this key).

    It is a kind of DecryptionError, so `except DecryptionError` catches it too.
    """


class WrongRecipientError(TransferError):
    """The package was made for a different recipient key."""


class PostQuantumUnavailableError(RuntimeError):
    """ML-KEM is not available. QShield will NOT fall back to ordinary encryption."""


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
                "ML-KEM. QShield will NOT fall back to ordinary encryption. "
                "Install a newer 'cryptography' (see requirements.txt)."
            ) from None

    return wrapper


# ---- Which suite does a key belong to? ---------------------------------------
def _is_private_key(key) -> bool:
    return isinstance(key, (MLKEM768PrivateKey, MLKEM1024PrivateKey, HybridPrivateKey))


def suite_of(key) -> int:
    """The suite number (1, 2 or 3) a public or private key belongs to."""
    if isinstance(key, (MLKEM768PublicKey, MLKEM768PrivateKey)):
        return 1
    if isinstance(key, (HybridPublicKey, HybridPrivateKey)):
        return 2
    if isinstance(key, (MLKEM1024PublicKey, MLKEM1024PrivateKey)):
        return 3
    raise TypeError("Not a QShield key (expected ML-KEM-768, hybrid X25519 + ML-KEM-768, or ML-KEM-1024).")


# ---- Recipient keys ----------------------------------------------------------
@_no_fallback
def generate_recipient_keypair(suite: int = SUITE_MLKEM768):
    """Make a new recipient key pair. Keep the returned PRIVATE key on the
    receiving side. Get the public half with `.public_key()`.

    suite 1 (default) = ML-KEM-768, suite 2 = X25519 + ML-KEM-768, suite 3 = ML-KEM-1024.
    """
    if suite == 1:
        return MLKEM768PrivateKey.generate()
    if suite == 2:
        return HybridPrivateKey(X25519PrivateKey.generate(), MLKEM768PrivateKey.generate())
    if suite == 3:
        return MLKEM1024PrivateKey.generate()
    raise ValueError(f"Unknown algorithm suite: {suite}. Choose 1, 2 or 3.")


def _fingerprint_bytes(public_key) -> bytes:
    return hashlib.sha256(public_key.public_bytes_raw()).digest()


def public_key_fingerprint(public_key, pretty: bool = False) -> str:
    """A short ID of a public key (SHA-256, in hex). Compare it with the
    receiver over a second channel to be sure you have the right key.
    pretty=True groups it in blocks of 4 so it is easier to read aloud."""
    digest = _fingerprint_bytes(public_key).hex()
    if pretty:
        return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
    return digest


def public_key_to_bytes(public_key) -> bytes:
    """The public key as raw bytes (suite 1: 1184, suite 2: 1216, suite 3: 1568). Safe to share."""
    suite_of(public_key)  # refuses things that are not QShield keys
    return public_key.public_bytes_raw()


@_no_fallback
def public_key_from_bytes(data: bytes, suite: int = SUITE_MLKEM768):
    """Rebuild a public key from raw bytes. `suite` says which kind (default 1)."""
    if suite not in SUITES:
        raise ValueError(f"Unknown algorithm suite: {suite}.")
    data = bytes(data)
    if len(data) != SUITES[suite].public_key_size:
        raise ValueError(
            f"A {SUITES[suite].name} public key must be {SUITES[suite].public_key_size} bytes."
        )
    if suite == 1:
        return MLKEM768PublicKey.from_public_bytes(data)
    if suite == 2:
        return HybridPublicKey(
            X25519PublicKey.from_public_bytes(data[:X25519_KEY_SIZE]),
            MLKEM768PublicKey.from_public_bytes(data[X25519_KEY_SIZE:]),
        )
    return MLKEM1024PublicKey.from_public_bytes(data)


def public_key_to_text(public_key) -> str:
    """The public key as copy-and-paste text (URL-safe base64). Safe to share.
    Suites 2 and 3 start with 'QS2:' / 'QS3:'; suite 1 has no prefix."""
    prefix = _TEXT_PREFIXES.get(suite_of(public_key), "")
    return prefix + base64.urlsafe_b64encode(public_key_to_bytes(public_key)).decode("ascii")


def public_key_from_text(text: str):
    """Rebuild a public key from the text made by public_key_to_text()."""
    compact = "".join(text.split())
    suite = SUITE_MLKEM768
    for number, prefix in _TEXT_PREFIXES.items():
        if compact.startswith(prefix):
            suite, compact = number, compact[len(prefix):]
            break
    cleaned = compact.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        data = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("That is not a valid public key. Copy the whole key again.") from None
    return public_key_from_bytes(data, suite)


# ---- Keeping the private key safe on the receiving side ------------------------
def _password_bytes(password) -> bytes:
    data = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not data:
        raise ValueError("A password is required to protect the private key file.")
    return data


def _protected_pkcs8(key, password: bytes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def private_key_to_protected_pem(private_key, password) -> bytes:
    """Return the private key as password-protected PKCS#8 PEM bytes.

    Suites 1 and 3 give one PEM block. Suite 2 gives two blocks (X25519, then
    ML-KEM-768), both protected by the same password.

    The PEM is encrypted. It is safe to download or keep in memory. Never print
    it in logs or show it on the sender's screen.
    """
    if not _is_private_key(private_key):
        raise TypeError("private_key must be a QShield private key (ML-KEM-768, hybrid, or ML-KEM-1024).")
    pw = _password_bytes(password)
    if isinstance(private_key, HybridPrivateKey):
        return _protected_pkcs8(private_key.x25519, pw) + _protected_pkcs8(private_key.mlkem, pw)
    return _protected_pkcs8(private_key, pw)


_PEM_BLOCK = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)


@_no_fallback
def load_private_key_from_bytes(data: bytes, password):
    """Load a private key from PEM bytes made by private_key_to_protected_pem().

    The kind of key (suite 1, 2 or 3) is read from the file itself.
    """
    pw = _password_bytes(password)
    blocks = _PEM_BLOCK.findall(bytes(data))
    if not blocks or len(blocks) > 2:
        raise ValueError("This key file is not a QShield private key.")
    try:
        keys = [serialization.load_pem_private_key(block, pw) for block in blocks]
    except (ValueError, TypeError):
        raise ValueError("Could not open the key file: wrong password, or the file is damaged.") from None

    if len(keys) == 1 and isinstance(keys[0], (MLKEM768PrivateKey, MLKEM1024PrivateKey)):
        return keys[0]
    if (len(keys) == 2 and isinstance(keys[0], X25519PrivateKey)
            and isinstance(keys[1], MLKEM768PrivateKey)):
        return HybridPrivateKey(keys[0], keys[1])
    raise ValueError("This key file is not a QShield private key (ML-KEM-768, X25519 + ML-KEM-768, or ML-KEM-1024).")


def save_private_key(private_key, path, password, overwrite: bool = False) -> Path:
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


def load_private_key(path, password):
    """Load a private key saved by save_private_key()."""
    return load_private_key_from_bytes(Path(path).read_bytes(), password)


# ---- The KEM step: make / recover the shared secret --------------------------------
def _encapsulate(public_key) -> tuple[int, bytes, bytes]:
    """Return (suite, key material for HKDF, KEM ciphertext) for a public key.

    Suite 2 runs X25519 and ML-KEM-768 side by side. The HKDF input is the
    ML-KEM secret followed by the X25519 secret, so BOTH are needed.
    """
    if isinstance(public_key, MLKEM768PublicKey):
        secret, ciphertext = public_key.encapsulate()
        return 1, secret, ciphertext
    if isinstance(public_key, HybridPublicKey):
        ephemeral = X25519PrivateKey.generate()
        try:
            x_secret = ephemeral.exchange(public_key.x25519)
        except ValueError:
            raise ValueError("The receiver's public key is not valid (bad X25519 part).") from None
        pq_secret, pq_ciphertext = public_key.mlkem.encapsulate()
        ciphertext = ephemeral.public_key().public_bytes_raw() + pq_ciphertext
        return 2, pq_secret + x_secret, ciphertext
    if isinstance(public_key, MLKEM1024PublicKey):
        secret, ciphertext = public_key.encapsulate()
        return 3, secret, ciphertext
    raise TypeError(
        "recipient_public_key must be an ML-KEM-768, hybrid X25519 + ML-KEM-768, "
        "or ML-KEM-1024 public key."
    )


def _decapsulate(private_key, kem_ciphertext: bytes) -> bytes:
    """Recover the HKDF input for a private key (the mirror of _encapsulate)."""
    if isinstance(private_key, MLKEM768PrivateKey):
        return private_key.decapsulate(kem_ciphertext)
    if isinstance(private_key, HybridPrivateKey):
        sender_x = X25519PublicKey.from_public_bytes(kem_ciphertext[:X25519_KEY_SIZE])
        try:
            x_secret = private_key.x25519.exchange(sender_x)
        except ValueError:
            raise TransferError("Could not open the package: it was changed or damaged.") from None
        pq_secret = private_key.mlkem.decapsulate(kem_ciphertext[X25519_KEY_SIZE:])
        return pq_secret + x_secret
    return private_key.decapsulate(kem_ciphertext)  # ML-KEM-1024


# ---- Key derivation -----------------------------------------------------------
def _derive_aes_key(shared_secret: bytes, header: bytes, suite: int = SUITE_MLKEM768) -> bytes:
    """HKDF-SHA256: turn the KEM secret(s) into a 256-bit AES key.

    For suite 2 the input is the ML-KEM secret and the X25519 secret joined
    together (64 bytes). The whole header (version, suite, recipient fingerprint,
    KEM ciphertext) is mixed in, so the key only works for exactly this package
    and this suite. No salt is used: the secrets are uniformly random and new for
    every package.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=SUITES[suite].kdf_label + b"\x00" + header,
    ).derive(shared_secret)


# ---- Encrypt / decrypt ----------------------------------------------------------
@_no_fallback
def encrypt_for_recipient(plaintext: bytes, recipient_public_key,
                          filename: str = "file", padding=None) -> bytes:
    """Encrypt bytes for a recipient and return the transfer package (bytes).

    Only the recipient's PUBLIC key is needed (and accepted). The suite is the
    one the key was made for. The file name, size and time are inside the
    encrypted part. `padding` (None, "padme", or a block size in bytes) hides
    the size; see core/file_crypto.py.
    """
    if _is_private_key(recipient_public_key):
        raise TypeError(
            "Give the recipient's PUBLIC key, not a private key. "
            "A private key must never leave the receiving side."
        )

    suite, kem_secret, kem_ciphertext = _encapsulate(recipient_public_key)
    info = SUITES[suite]
    if len(kem_ciphertext) != info.kem_ciphertext_size:
        raise TransferError("The ML-KEM library returned unexpected sizes. Stopping.")

    header = _PREFIX.pack(
        MAGIC, VERSION, suite, _fingerprint_bytes(recipient_public_key),
    ) + kem_ciphertext

    aes_key = _derive_aes_key(kem_secret, header, suite)
    return header + file_crypto.encrypt_bytes(plaintext, aes_key, filename=filename, padding=padding)


def package_suite(package: bytes) -> int:
    """Read the suite number from a package header (1, 2 or 3).

    Raises TransferError if this is not a QShield package or the suite is unknown.
    This only reads a label; it opens nothing.
    """
    package = bytes(package)
    if len(package) < _PREFIX.size:
        raise TransferError("This is too short to be a QShield transfer package.")
    magic, version, suite, _ = _PREFIX.unpack_from(package, 0)
    if magic != MAGIC:
        raise TransferError("This is not a QShield transfer package.")
    if version != VERSION:
        raise TransferError(f"Unsupported package version: {version}.")
    if suite not in SUITES:
        raise TransferError(f"Unsupported algorithm suite: {suite}.")
    return suite


@_no_fallback
def decrypt_package(package: bytes, recipient_private_key) -> DecryptedFile:
    """Open a transfer package with the recipient's private key.

    Raises WrongRecipientError if it was made for a different key, or
    TransferError if it is damaged, changed, or not a QShield package.
    Nothing is returned unless every check passes.
    """
    if not _is_private_key(recipient_private_key):
        raise TypeError("recipient_private_key must be a QShield private key "
                        "(ML-KEM-768, hybrid X25519 + ML-KEM-768, or ML-KEM-1024).")
    if not isinstance(package, (bytes, bytearray, memoryview)):
        raise TypeError("package must be bytes.")
    package = bytes(package)

    suite = package_suite(package)   # checks magic, version and that the suite is known
    key_suite = suite_of(recipient_private_key)
    if suite != key_suite:
        raise TransferError(
            f"This package uses algorithm suite {suite} ({SUITES[suite].name}) but your "
            f"key is for suite {key_suite} ({SUITES[key_suite].name}). Use the matching "
            "key file. If you did, the package was changed."
        )
    header_size = SUITES[suite].header_size
    if len(package) < header_size:
        raise TransferError("This is too short to be a QShield transfer package.")

magic, version, suite, fingerprint = _PREFIX.unpack_from(package, 0)

if magic != MAGIC:
    raise TransferError("This is not a QShield transfer package.")

if version == VERSION_STREAM:
    if suite != SUITE_MLKEM768_HKDF_SHA256_AES256GCM_STREAM:
        raise TransferError(
            f"Unsupported algorithm suite for package version {version}: {suite}."
        )

    if suite_of(recipient_private_key) != suite:
        raise TransferError("This package requires a matching recipient key.")

    sink = io.BytesIO()
    result = _decrypt_stream_package(
        io.BytesIO(package), sink, recipient_private_key
    )
    return DecryptedFile(
        filename=result.filename,
        data=sink.getvalue(),
        metadata=result.metadata,
    )

if version != VERSION:
    raise TransferError(f"Unsupported package version: {version}.")
    own_fingerprint = _fingerprint_bytes(recipient_private_key.public_key())
    if not hmac.compare_digest(fingerprint, own_fingerprint):
        raise WrongRecipientError(
            "This package was made for a different recipient key. "
            "Ask the sender to encrypt it again with your public key."
        )

    header = package[:header_size]
    kem_ciphertext = header[_PREFIX.size:]
    # ML-KEM never raises on a damaged ciphertext. It quietly returns a
    # different secret, so the AES-GCM check below is what catches the damage.
    kem_secret = _decapsulate(recipient_private_key, kem_ciphertext)
    aes_key = _derive_aes_key(kem_secret, header, suite)

    try:
        return file_crypto.decrypt_bytes(package[header_size:], aes_key)
    except DecryptionError:
        raise TransferError(
            "Could not open the package: it was changed or damaged, "
            "or it was not made for this recipient key."
        ) from None


# ---- Streaming recipient packages (version 2) ----------------------------------
def _stream_context(outer_header: bytes, envelope: bytes) -> bytes:
    """HKDF `info` for a version 2 package: binds the whole outer header (version, suite,
    recipient fingerprint, KEM ciphertext) and the envelope (segment size, metadata)."""
    return KDF_LABEL_STREAM + b"\x00" + outer_header + envelope


@_no_fallback
def encrypt_stream_for_recipient(src, dst, recipient_public_key: MLKEM768PublicKey,
                                 filename: str = "file", *, size=None,
                                 segment_size: int = file_crypto.DEFAULT_SEGMENT_SIZE) -> int:
    """Encrypt a binary file-like `src` for a recipient, writing a version 2 package to `dst`.

    Bounded memory (a few segments). Only the recipient's PUBLIC key is accepted. Returns
    the number of plaintext bytes. If `size` is given and the input differs, ValueError is
    raised and the caller must discard `dst` (encrypt_file_for_recipient does).
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

    outer = _PREFIX.pack(
        MAGIC, VERSION_STREAM, SUITE_MLKEM768_HKDF_SHA256_AES256GCM_STREAM,
        _fingerprint_bytes(recipient_public_key),
    ) + kem_ciphertext
    envelope = file_crypto.pack_stream_envelope(
        segment_size, file_crypto.build_stream_metadata(filename, size)
    )
    dst.write(outer + envelope)
    total = file_crypto.encrypt_stream_body(
        src, dst, shared_secret, _stream_context(outer, envelope), segment_size
    )
    if size is not None and total != size:
        raise ValueError("The input changed size while it was being encrypted.")
    return total


@_no_fallback
def _decrypt_stream_package(src, dst, recipient_private_key: MLKEM768PrivateKey):
    if not isinstance(recipient_private_key, MLKEM768PrivateKey):
        raise TypeError("recipient_private_key must be an ML-KEM-768 private key.")
    try:
        outer = file_crypto._read_up_to(src, HEADER_SIZE)
        if len(outer) < HEADER_SIZE:
            raise TransferError("This is too short to be a QShield transfer package.")
        magic, version, suite, fingerprint = _PREFIX.unpack_from(outer, 0)
        if magic != MAGIC:
            raise TransferError("This is not a QShield transfer package.")
        if version != VERSION_STREAM:
            raise TransferError(f"Unsupported package version: {version}.")
        if suite != SUITE_MLKEM768_HKDF_SHA256_AES256GCM_STREAM:
            raise TransferError(f"Unsupported algorithm suite for package version {version}: {suite}.")
        if not hmac.compare_digest(fingerprint, _fingerprint_bytes(recipient_private_key.public_key())):
            raise WrongRecipientError(
                "This package was made for a different recipient key. "
                "Ask the sender to encrypt it again with your public key."
            )
        segment_size, metadata_bytes, envelope = file_crypto.read_stream_envelope(src)
        # ML-KEM never raises on a damaged ciphertext (it returns a different secret), so
        # the first segment's authentication tag is what catches a damaged KEM ciphertext.
        shared_secret = recipient_private_key.decapsulate(outer[_PREFIX.size:])
        total = file_crypto.decrypt_stream_body(
            src, dst, shared_secret, _stream_context(outer, envelope), segment_size
        )
        filename, metadata = file_crypto.parse_stream_metadata(metadata_bytes, total)
    except TransferError:
        raise
    except DecryptionError as exc:
        raise TransferError(str(exc)) from None
    return file_crypto.DecryptedStream(filename=filename, metadata=metadata, size=total)


def decrypt_package_stream(src, dst, recipient_private_key: MLKEM768PrivateKey):
    """Decrypt a version 2 package from a binary file-like `src`, writing plaintext to `dst`.

    WARNING: `dst` receives chunks before the end of the stream is verified. If this raises,
    discard whatever was written. decrypt_package_file() does that safely.
    """
    return _decrypt_stream_package(src, dst, recipient_private_key)


# ---- Files on disk ------------------------------------------------------------
def encrypt_file_for_recipient(
    input_path,
    output_path,
    recipient_public_key,
    overwrite: bool = False,
    padding=None,
) -> Path:
    """Encrypt a file for a recipient and write the package."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    package = encrypt_for_recipient(
        input_path.read_bytes(),
        recipient_public_key,
        filename=input_path.name,
        padding=padding,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not overwrite and (
        output_path.exists() or output_path.is_symlink()
    ):
        raise FileExistsError(str(output_path))

    with open(output_path, "xb" if not overwrite else "wb") as dst:
        dst.write(package)

    return output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(input_path, "rb") as src:
        st = os.fstat(src.fileno())
        size = st.st_size if stat.S_ISREG(st.st_mode) else None   # pipes/FIFOs: length unknown in advance
        out, temp_path = file_crypto.create_private_temp(output_path.parent)
        try:
            with out:
                encrypt_stream_for_recipient(
                    src, out, recipient_public_key, input_path.name,
                    size=size, segment_size=segment_size,
                )
                file_crypto.sync_temp(out)
            file_crypto.publish(temp_path, output_path, overwrite)
        except BaseException:
            file_crypto._discard(temp_path)
            raise
    return output_path


def decrypt_package_file(package_path, output_dir, recipient_private_key,
                         overwrite: bool = False) -> Path:
    """Open a package file into output_dir. Published only after every check passes.

    Version 2 (streaming) packages are decrypted incrementally into a private temporary file
    (bounded memory) and published only after the final segment and the end of the file
    verify. Version 1 packages are opened in memory as before, and refused if the file is
    larger than that format can hold. Unknown versions are refused; there is no fallback."""
    with open(Path(package_path), "rb") as src:
        head = src.read(5)
        src.seek(0)
        if len(head) == 5 and head[:4] == MAGIC and head[4] == VERSION_STREAM:
            return file_crypto.decrypt_to_directory(
                src, output_dir, overwrite,
                lambda s, d: _decrypt_stream_package(s, d, recipient_private_key),
            )
        if os.fstat(src.fileno()).st_size > _LEGACY_MAX_PACKAGE:
            raise TransferError("This is too large to be a version 1 QShield package.")
        # Everything else (version 1, damaged, or unsupported) goes through decrypt_package,
        # which accepts only what it recognises and raises a clear error otherwise.
        result = decrypt_package(src.read(), recipient_private_key)
    return file_crypto.write_decrypted_file(result, output_dir, overwrite)
