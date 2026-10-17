"""Hybrid digital signatures: Ed25519 + ML-DSA-65 (NIST FIPS 204).

WHY THIS FILE EXISTS
  ML-KEM (core/pq_transfer.py) keeps a file SECRET, but it cannot prove WHO
  sent it: anyone who has a recipient's public key can build a valid package.
  Signatures close that gap. A sender signs, and the receiver checks the
  signature against a sender key it already trusts.

WHY TWO ALGORITHMS ("hybrid")
  - ML-DSA-65 is the post-quantum signature standard (FIPS 204, lattice based).
    Ed25519 is classical, and has had 15+ years of scrutiny.
  - BOTH signatures are made over the same message, and BOTH must verify.
    A forger has to break Ed25519 AND ML-DSA. If someone finds a flaw in the
    young algorithm, Ed25519 still protects you. If a quantum computer breaks
    Ed25519, ML-DSA still protects you.
  - There is NO "either one is enough" mode and no silent fallback. If the
    installed `cryptography` cannot do ML-DSA, this module STOPS with
    SignatureUnavailableError. It never verifies with Ed25519 alone.

WHAT THIS MODULE DOES NOT DO
  - It does not decide WHICH sender keys you trust. That decision belongs to
    the application (see core/signed_transfer.py, `trusted_senders`).
    Check a sender's fingerprint over a second channel before trusting it.
  - It does not protect against a stolen private key. Use a strong password
    and store the key file somewhere safe. There is no key revocation yet.
  - Python cannot reliably erase secrets from memory. Key material may stay in
    process memory until the garbage collector and the OS reclaim it.
  - No independent security audit has been done.

IDENTITY FORMATS (all fixed size, strictly parsed)

  Public identity ("QSPK", 1990 bytes) - safe to share:
    +-------+---------+-------+----------------------+-------------------------+
    | magic | version | suite | Ed25519 public key   | ML-DSA-65 public key    |
    | QSPK  | 1 byte  | 1 byte| 32 bytes             | 1952 bytes              |
    +-------+---------+-------+----------------------+-------------------------+
  Its FINGERPRINT is SHA-256 over a fixed label plus all of these bytes, so it
  commits to BOTH public keys. Read the fingerprint aloud to confirm a key.

  Private identity file ("QSSK") - password protected:
    prefix (magic, version, KDF id, scrypt log2(N), r, p, salt, nonce)
    + the public identity (so the file says whose key it is)
    + AES-256-GCM( Ed25519 seed || ML-DSA seed )
  The key is made from the password with scrypt (default: 128 MiB, N=2**17).
  The prefix and the public identity are authenticated (GCM "AAD"), so any
  change to them makes the file fail to open.

SIGNATURE SUITE 1 = Ed25519 + ML-DSA-65. A new suite number is how a future
version can change algorithms without confusing old data.
"""

import base64
import binascii
import hashlib
import hmac
import os
import struct
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core.file_crypto import DecryptionError

# ---- Constants ---------------------------------------------------------------
SIG_SUITE_ED25519_MLDSA65 = 1

ED25519_PUBLIC_SIZE = 32
ED25519_SEED_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
MLDSA65_PUBLIC_SIZE = 1952
MLDSA65_SEED_SIZE = 32
MLDSA65_SIGNATURE_SIZE = 3309

# Signature size for each suite. Parsing is strict: no other length is accepted.
SIGNATURE_SIZES = {
    SIG_SUITE_ED25519_MLDSA65: ED25519_SIGNATURE_SIZE + MLDSA65_SIGNATURE_SIZE,
}

PUBLIC_MAGIC = b"QSPK"
PUBLIC_VERSION = 1
_PUBLIC_PREFIX = struct.Struct(">4sBB")
PUBLIC_IDENTITY_SIZE = _PUBLIC_PREFIX.size + ED25519_PUBLIC_SIZE + MLDSA65_PUBLIC_SIZE  # 1990

# ML-DSA has a built-in "context string" (FIPS 204). We use it as one extra layer
# of domain separation, on top of the label that is already inside every message.
MLDSA_CONTEXT = b"QShield-v2-hybrid-signature"

_FINGERPRINT_LABEL = b"QShield identity fingerprint v1\x00"

# ---- Private identity file constants --------------------------------------------
PRIVATE_MAGIC = b"QSSK"
PRIVATE_VERSION = 1
KDF_SCRYPT = 1
_PRIVATE_PREFIX = struct.Struct(">4sBBBBB16s12s")   # 4+1+1+1+1+1+16+12 = 37 bytes
_SALT_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16
_SECRET_BLOB_SIZE = ED25519_SEED_SIZE + MLDSA65_SEED_SIZE
PRIVATE_FILE_SIZE = _PRIVATE_PREFIX.size + PUBLIC_IDENTITY_SIZE + _SECRET_BLOB_SIZE + _TAG_SIZE

DEFAULT_SCRYPT_LOG2_N = 17       # N = 131072, r = 8  ->  128 MiB of memory
SCRYPT_R = 8
SCRYPT_P = 1
# Accepted range when LOADING. Lower bound: refuse files protected too weakly.
# Upper bound: a damaged or hostile file cannot make us allocate gigabytes.
MIN_SCRYPT_LOG2_N = 14
MAX_SCRYPT_LOG2_N = 20
MIN_PASSWORD_LENGTH = 10


# ---- Errors ---------------------------------------------------------------------
class SignatureError(DecryptionError):
    """A signature check failed.

    It is a kind of DecryptionError, so existing `except DecryptionError`
    handlers (for example in the Streamlit app) treat it as a security warning.
    """


class InvalidSignatureError(SignatureError):
    """The signature does not match. The message was changed, or it was not
    signed by the key it claims to come from."""


class SignatureUnavailableError(RuntimeError):
    """ML-DSA is not available. QShield will NOT fall back to Ed25519 alone."""


# ---- ML-DSA backend (the one place that touches the library) ----------------------
def _mldsa_classes():
    """Return (MLDSA65PrivateKey, MLDSA65PublicKey) from `cryptography`.

    `cryptography` 47+ ships ML-DSA. Whether it works also depends on the
    cryptography build (its crypto backend). If it is missing we stop with a
    clear error. We never quietly drop to a classical-only signature.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey
    except (ImportError, AttributeError):
        raise SignatureUnavailableError(
            "This installation of the 'cryptography' library does not provide "
            "ML-DSA-65. QShield will NOT fall back to classical-only signatures. "
            "Install a newer 'cryptography' (see requirements.txt)."
        ) from None


def _unavailable() -> SignatureUnavailableError:
    return SignatureUnavailableError(
        "The cryptography backend in use does not support ML-DSA-65. QShield will "
        "NOT fall back to classical-only signatures. Install a 'cryptography' "
        "build whose backend supports ML-DSA (see requirements.txt)."
    )


# ---- Small helpers -----------------------------------------------------------------
def _pretty(hex_text: str) -> str:
    return " ".join(hex_text[i:i + 4] for i in range(0, len(hex_text), 4))


def _b64_decode_text(text: str, what: str) -> bytes:
    cleaned = "".join(str(text).split()).replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"That is not a valid {what}. Copy the whole text again.") from None


def _password_bytes(password, *, creating: bool) -> bytes:
    if not isinstance(password, str):
        raise TypeError("The password must be text.")
    # NFKC so the same typed password gives the same bytes on every device.
    normalized = unicodedata.normalize("NFKC", password)
    if creating and len(normalized) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Use a password of at least {MIN_PASSWORD_LENGTH} characters to protect the signing key."
        )
    if not normalized:
        raise ValueError("A password is required.")
    return normalized.encode("utf-8")


# ---- Public identity ---------------------------------------------------------------
class PublicIdentity:
    """A sender's PUBLIC verification keys (Ed25519 + ML-DSA-65). Safe to share."""

    __slots__ = ("_suite", "_ed_bytes", "_ml_bytes", "_ed_key", "_ml_key", "_bundle", "_fp")

    def __init__(self, ed25519_public: bytes, mldsa_public: bytes, suite: int = SIG_SUITE_ED25519_MLDSA65):
        if suite != SIG_SUITE_ED25519_MLDSA65:
            raise ValueError(f"Unsupported signature suite: {suite}.")
        ed_bytes, ml_bytes = bytes(ed25519_public), bytes(mldsa_public)
        if len(ed_bytes) != ED25519_PUBLIC_SIZE or len(ml_bytes) != MLDSA65_PUBLIC_SIZE:
            raise ValueError("The public identity has the wrong size.")
        _, ml_public_cls = _mldsa_classes()
        try:
            self._ed_key = ed25519.Ed25519PublicKey.from_public_bytes(ed_bytes)
            self._ml_key = ml_public_cls.from_public_bytes(ml_bytes)
        except UnsupportedAlgorithm:
            raise _unavailable() from None
        except ValueError:
            raise ValueError("The public identity contains an invalid key.") from None
        self._suite = suite
        self._ed_bytes, self._ml_bytes = ed_bytes, ml_bytes
        self._bundle = _PUBLIC_PREFIX.pack(PUBLIC_MAGIC, PUBLIC_VERSION, suite) + ed_bytes + ml_bytes
        self._fp = hashlib.sha256(_FINGERPRINT_LABEL + self._bundle).digest()

    # -- identity --
    @property
    def suite(self) -> int:
        return self._suite

    def to_bytes(self) -> bytes:
        """The public identity as 1990 raw bytes. Safe to share."""
        return self._bundle

    def fingerprint_bytes(self) -> bytes:
        return self._fp

    def fingerprint(self, pretty: bool = False) -> str:
        """SHA-256 fingerprint covering BOTH public keys. Compare it with the
        sender over a second channel (phone, in person) before trusting a key."""
        digest = self._fp.hex()
        return _pretty(digest) if pretty else digest

    def to_text(self) -> str:
        """The public identity as copy-and-paste text (URL-safe base64)."""
        return base64.urlsafe_b64encode(self._bundle).decode("ascii")

    def __eq__(self, other):
        return isinstance(other, PublicIdentity) and hmac.compare_digest(self._bundle, other._bundle)

    def __hash__(self):
        return hash(self._bundle)

    def __repr__(self):
        return f"PublicIdentity(fingerprint={self.fingerprint()[:16]}...)"

    # -- parsing --
    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicIdentity":
        data = bytes(data)
        if len(data) != PUBLIC_IDENTITY_SIZE:
            raise ValueError("That is not a valid public identity (wrong length).")
        magic, version, suite = _PUBLIC_PREFIX.unpack_from(data, 0)
        if magic != PUBLIC_MAGIC:
            raise ValueError("That is not a QShield public identity.")
        if version != PUBLIC_VERSION:
            raise ValueError(f"Unsupported public identity version: {version}.")
        body = data[_PUBLIC_PREFIX.size:]
        return cls(body[:ED25519_PUBLIC_SIZE], body[ED25519_PUBLIC_SIZE:], suite)

    @classmethod
    def from_text(cls, text: str, expected_fingerprint: str | None = None) -> "PublicIdentity":
        """Rebuild a public identity from shared text.

        Pass `expected_fingerprint` (the one the sender read to you over a
        second channel) to make sure nobody swapped the key on the way.
        """
        identity = cls.from_bytes(_b64_decode_text(text, "public identity"))
        if expected_fingerprint is not None:
            wanted = "".join(str(expected_fingerprint).split()).lower()
            if not hmac.compare_digest(wanted, identity.fingerprint()):
                raise ValueError(
                    "The fingerprint does not match this public identity. "
                    "Do NOT trust this key: it may have been swapped."
                )
        return identity

    # -- verification --
    def verify(self, message: bytes, signature: bytes) -> None:
        """Check a hybrid signature. Returns None on success.

        BOTH the Ed25519 and the ML-DSA-65 signature must be valid. Raises
        InvalidSignatureError otherwise (it does not say which half failed).
        """
        signature = bytes(signature)
        if len(signature) != SIGNATURE_SIZES[self._suite]:
            raise InvalidSignatureError("The signature has the wrong size.")
        ed_sig = signature[:ED25519_SIGNATURE_SIZE]
        ml_sig = signature[ED25519_SIGNATURE_SIZE:]

        # Run BOTH checks every time (no early exit on the first failure).
        try:
            self._ed_key.verify(ed_sig, message)
            ed_ok = True
        except InvalidSignature:
            ed_ok = False
        try:
            self._ml_key.verify(ml_sig, message, MLDSA_CONTEXT)
            ml_ok = True
        except InvalidSignature:
            ml_ok = False
        except UnsupportedAlgorithm:
            raise _unavailable() from None
        except ValueError:
            ml_ok = False

        if not (ed_ok and ml_ok):
            raise InvalidSignatureError(
                "The signature is not valid: the message was changed, or it was "
                "not signed by this sender."
            )


# ---- Signing identity (has the PRIVATE keys) -----------------------------------------
class SigningIdentity:
    """A sender's PRIVATE signing keys plus the matching public identity.

    Keep this on the sender's own device. Save it only in password-protected
    form (see save_signing_identity). The private keys are never part of a
    package, and repr() never shows them.
    """

    __slots__ = ("_ed", "_ml", "public")

    def __init__(self, ed_private, ml_private):
        self._ed = ed_private
        self._ml = ml_private
        self.public = PublicIdentity(
            ed_private.public_key().public_bytes_raw(),
            ml_private.public_key().public_bytes_raw(),
        )

    def __repr__(self):
        return f"SigningIdentity(fingerprint={self.public.fingerprint()[:16]}..., private keys hidden)"

    def __reduce__(self):  # refuse pickling: it would write private keys somewhere by accident
        raise TypeError("A SigningIdentity cannot be pickled. Use save_signing_identity().")

    def sign(self, message: bytes) -> bytes:
        """Make a hybrid signature (Ed25519 signature + ML-DSA-65 signature)."""
        message = bytes(message)
        try:
            ed_sig = self._ed.sign(message)
            ml_sig = self._ml.sign(message, MLDSA_CONTEXT)
        except UnsupportedAlgorithm:
            raise _unavailable() from None
        signature = ed_sig + ml_sig
        if len(signature) != SIGNATURE_SIZES[SIG_SUITE_ED25519_MLDSA65]:
            raise SignatureError("The signing library returned an unexpected signature size. Stopping.")
        # Verify our own signature before releasing it. This catches hardware
        # faults and key mix-ups, which can otherwise leak key material.
        self.public.verify(message, signature)
        return signature

    def _secret_blob(self) -> bytes:
        return self._ed.private_bytes_raw() + self._ml.private_bytes_raw()


def generate_signing_identity() -> SigningIdentity:
    """Make a brand-new sender identity (fresh Ed25519 key + fresh ML-DSA-65 key)."""
    ml_private_cls, _ = _mldsa_classes()
    try:
        return SigningIdentity(ed25519.Ed25519PrivateKey.generate(), ml_private_cls.generate())
    except UnsupportedAlgorithm:
        raise _unavailable() from None


def _identity_from_secret_blob(blob: bytes) -> SigningIdentity:
    if len(blob) != _SECRET_BLOB_SIZE:
        raise ValueError("The key file content is invalid.")
    ml_private_cls, _ = _mldsa_classes()
    try:
        ed_private = ed25519.Ed25519PrivateKey.from_private_bytes(blob[:ED25519_SEED_SIZE])
        ml_private = ml_private_cls.from_seed_bytes(blob[ED25519_SEED_SIZE:])
    except UnsupportedAlgorithm:
        raise _unavailable() from None
    return SigningIdentity(ed_private, ml_private)


# ---- Password-protected private identity files ----------------------------------------
def _derive_file_key(password: bytes, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** log2_n, r=r, p=p).derive(password)


def signing_identity_to_protected_bytes(identity: SigningIdentity, password,
                                        scrypt_log2_n: int = DEFAULT_SCRYPT_LOG2_N) -> bytes:
    """Return the identity as a password-protected file (bytes).

    The file is encrypted, so it is safe to download or store. Never print it
    in logs or show it on the receiver's screen.
    """
    if not isinstance(identity, SigningIdentity):
        raise TypeError("identity must be a SigningIdentity.")
    if not MIN_SCRYPT_LOG2_N <= scrypt_log2_n <= MAX_SCRYPT_LOG2_N:
        raise ValueError("scrypt_log2_n is outside the allowed range.")
    pw = _password_bytes(password, creating=True)
    salt, nonce = os.urandom(_SALT_SIZE), os.urandom(_NONCE_SIZE)
    prefix = _PRIVATE_PREFIX.pack(
        PRIVATE_MAGIC, PRIVATE_VERSION, KDF_SCRYPT, scrypt_log2_n, SCRYPT_R, SCRYPT_P, salt, nonce
    )
    aad = prefix + identity.public.to_bytes()
    key = _derive_file_key(pw, salt, scrypt_log2_n, SCRYPT_R, SCRYPT_P)
    return aad + AESGCM(key).encrypt(nonce, identity._secret_blob(), aad)


def load_signing_identity_from_bytes(data: bytes, password) -> SigningIdentity:
    """Open a file made by signing_identity_to_protected_bytes()."""
    data = bytes(data)
    wrong = ValueError("Could not open the identity file: wrong password, or the file is damaged.")
    if len(data) != PRIVATE_FILE_SIZE:
        raise ValueError("This is not a QShield signing identity file (wrong size).")
    magic, version, kdf, log2_n, r, p, salt, nonce = _PRIVATE_PREFIX.unpack_from(data, 0)
    if magic != PRIVATE_MAGIC:
        raise ValueError("This is not a QShield signing identity file.")
    if version != PRIVATE_VERSION or kdf != KDF_SCRYPT:
        raise ValueError("Unsupported identity file version.")
    # Check the cost settings BEFORE the expensive key derivation (see constants).
    if not (MIN_SCRYPT_LOG2_N <= log2_n <= MAX_SCRYPT_LOG2_N and r == SCRYPT_R and p == SCRYPT_P):
        raise ValueError("The identity file has unsupported password-protection settings.")

    aad_len = _PRIVATE_PREFIX.size + PUBLIC_IDENTITY_SIZE
    aad, ciphertext = data[:aad_len], data[aad_len:]
    key = _derive_file_key(_password_bytes(password, creating=False), salt, log2_n, r, p)
    try:
        blob = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise wrong from None

    identity = _identity_from_secret_blob(blob)
    # The public identity stored in the file must match the secret keys inside.
    if not hmac.compare_digest(aad[_PRIVATE_PREFIX.size:], identity.public.to_bytes()):
        raise ValueError("The identity file is inconsistent. Do not use it.")
    return identity


def read_public_identity_from_protected_bytes(data: bytes) -> PublicIdentity:
    """Read ONLY the public identity out of a protected file (no password needed).

    The result is not verified (nothing secret is unlocked). Use it to show
    "whose key is this file?". Check the fingerprint before relying on it.
    """
    data = bytes(data)
    if len(data) != PRIVATE_FILE_SIZE or data[:4] != PRIVATE_MAGIC:
        raise ValueError("This is not a QShield signing identity file.")
    return PublicIdentity.from_bytes(data[_PRIVATE_PREFIX.size:_PRIVATE_PREFIX.size + PUBLIC_IDENTITY_SIZE])


def save_signing_identity(identity: SigningIdentity, path, password, overwrite: bool = False,
                          scrypt_log2_n: int = DEFAULT_SCRYPT_LOG2_N) -> Path:
    """Save the identity to a password-protected file on the sender's device.

    The file is created readable by its owner only (Linux and macOS), and an
    existing file is never replaced unless overwrite=True.
    """
    blob = signing_identity_to_protected_bytes(identity, password, scrypt_log2_n)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    flags |= getattr(os, "O_BINARY", 0)  # Windows only; harmless elsewhere
    with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
        f.write(blob)
    return path


def load_signing_identity(path, password) -> SigningIdentity:
    """Load an identity saved by save_signing_identity()."""
    return load_signing_identity_from_bytes(Path(path).read_bytes(), password)
