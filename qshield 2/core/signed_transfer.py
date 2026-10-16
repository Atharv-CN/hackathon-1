"""Send a file that is BOTH secret AND provably from one specific sender.

  ML-KEM-768 + HKDF-SHA256 + AES-256-GCM   -> only the recipient can read it
  Ed25519 + ML-DSA-65 (hybrid signature)   -> only the sender could have made it

This is "package version 2". Version 1 (core/pq_transfer.py) stays exactly as it
was and is never touched by this file. A v1 package is UNSIGNED.

PACKAGE LAYOUT (version 2)
  +--------------------------------------------+---------+--------------------+
  | header, 1126 bytes (same shape as v1)      | nonce   | AES-256-GCM        |
  |  QSHK | version=2 | KEM suite | recipient  | 12 B    | ciphertext + tag   |
  |  4 B  | 1 B       | 1 B       | key fp 32 B|         | of the PAYLOAD     |
  |  + ML-KEM-768 ciphertext, 1088 B           |         |                    |
  +--------------------------------------------+---------+--------------------+
  The whole header is the AES-GCM "additional data" AND is mixed into the key, so
  changing any byte of it makes opening fail.

  PAYLOAD (this is what gets encrypted, so none of it is visible on the wire)
    "QSIP" | version | signature suite | sender fingerprint (32 B) | created_at (8 B)
    | name length (2 B) | file name | hybrid signature | file bytes
  Compared with v1, the file NAME, its SIZE and the sender's identity are now
  hidden inside the encryption instead of being readable.

WHAT IS SIGNED (the "to-be-signed" bytes, see _build_tbs)
  a fixed label, the signature suite, the sender fingerprint, the HASH of the whole
  header (which holds the recipient's key fingerprint and the unique ML-KEM
  ciphertext), the creation time, the file name, the file length and a SHA3-512 hash
  of the file. Consequences:
    - Signature covers the data:    changing the file, name or time breaks it.
    - Bound to ONE recipient:       Bob cannot re-encrypt Alice's signed file for
                                    Carol and make it look like Alice sent it to
                                    Carol ("surreptitious forwarding").
    - Bound to ONE package:         a signature cannot be copied into another
                                    package, because the header is different.
    - Bound to the sender's keys:   the fingerprint covers both public keys.
  The signature is INSIDE the encryption (sign-then-encrypt), so an outsider
  learns nothing about who sent it, and cannot test guesses about the file
  from a visible signature.

HOW A RECEIVER CHECKS IT (decrypt_and_verify)
  1. Right recipient key?  2. AES-GCM opens?  3. Sender fingerprint is one of the
  `trusted_senders` YOU passed in (an embedded key is never trusted)?  4. BOTH
  signatures verify?  5. File name is safe?  6. (optional) not too old?
  Only after all of these pass is any file content returned.

IMPORTANT LIMITS - please read
  - TRUST IS YOURS TO ESTABLISH. A signature only proves "made by the holder of
    this key". You must confirm the sender's fingerprint over a second channel.
  - NO REVOCATION. If a sender's key is stolen, you must stop trusting it yourself.
  - REPLAY. The same package can be delivered twice. Use `package_id` and
    `max_age_seconds` if your application needs to detect that.
  - The clock in `created_at` is whatever the sender's computer says.
  - NO FORWARD SECRECY for the recipient's long-term ML-KEM key (same as v1).
  - Total size is visible. Whole files are processed in memory (about 2 GB max).
  - NO DENIABILITY. The recipient can show a third party proof that the sender signed it.
  - No independent security audit has been done.
  - There is NO fallback: a missing ML-KEM or ML-DSA stops with an error. A v1
    (unsigned) package is REJECTED by decrypt_and_verify, never accepted quietly.
"""

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto, pq_transfer
from core.file_crypto import DecryptedFile
from core.pq_transfer import (
    PostQuantumUnavailableError,
    TransferError,
    WrongRecipientError,
)
from core.signatures import (
    SIGNATURE_SIZES,
    InvalidSignatureError,
    PublicIdentity,
    SignatureError,
    SigningIdentity,
)

# ---- Format constants ---------------------------------------------------------
MAGIC = pq_transfer.MAGIC                      # same "QSHK" marker as v1
VERSION_SIGNED = 2
KEM_SUITE = pq_transfer.SUITE_MLKEM768_HKDF_SHA256_AES256GCM
KEM_CIPHERTEXT_SIZE = pq_transfer.KEM_CIPHERTEXT_SIZE
FINGERPRINT_SIZE = pq_transfer.FINGERPRINT_SIZE
HEADER_SIZE = pq_transfer.HEADER_SIZE          # 1126, identical layout to v1
NONCE_SIZE = 12
TAG_SIZE = 16
AES_KEY_SIZE = pq_transfer.AES_KEY_SIZE
SHARED_SECRET_SIZE = pq_transfer.SHARED_SECRET_SIZE

# magic (4), version (1), KEM suite (1), recipient key fingerprint (32)
_PREFIX = struct.Struct(">4sBB32s")

PAYLOAD_MAGIC = b"QSIP"
PAYLOAD_VERSION = 1
# magic, version, signature suite, sender fingerprint, created_at, name length
_PAYLOAD_PREFIX = struct.Struct(">4sBB32sQH")
MAX_NAME_BYTES = 255
MAX_PAYLOAD_SIZE = 2 ** 31 - 1   # the most AES-GCM in `cryptography` accepts in one call

# Different from the v1 label, so a v1 key can never be confused with a v2 key.
KDF_LABEL = b"QShield v2: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM, hybrid-signed package"
TBS_LABEL = b"QShield v2 signed package\x00"

DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300


# ---- Errors ------------------------------------------------------------------------
class UnsignedPackageError(TransferError):
    """The package is a version 1 (UNSIGNED) package. It was refused on purpose."""


class UnknownSenderError(SignatureError):
    """The package is signed by someone who is not in `trusted_senders`."""


class StalePackageError(SignatureError):
    """The package is older than `max_age_seconds`, or dated in the future."""


@dataclass(frozen=True)
class VerifiedFile:
    """What you get back after a package passed EVERY check."""

    filename: str                 # cleaned: never contains folders like ../
    data: bytes                   # the original file contents
    sender: PublicIdentity        # the trusted identity whose signature verified
    sender_fingerprint: str       # hex fingerprint of `sender`
    created_at: int               # signed Unix time (seconds), set by the sender
    package_id: str               # unique per package; use it to detect replays


# ---- Helpers ---------------------------------------------------------------------------
def _clean_filename(name: str) -> str:
    """Same rule as core/file_crypto.py: keep only the last path part."""
    name = str(name).replace("\x00", "").replace("\\", "/").split("/")[-1].strip()
    return name if name not in ("", ".", "..") else "decrypted_file"


def _name_bytes_for_signing(filename: str) -> bytes:
    name = _clean_filename(filename)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ValueError("The file name contains control characters.")
    raw = name.encode("utf-8")
    if len(raw) > MAX_NAME_BYTES:
        raise ValueError(f"The file name is too long (limit {MAX_NAME_BYTES} bytes).")
    return raw


def _derive_key(shared_secret: bytes, header: bytes) -> bytes:
    """HKDF-SHA256: ML-KEM shared secret -> 256-bit AES key, bound to the whole header."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=KDF_LABEL + b"\x00" + header,
    ).derive(shared_secret)


def _build_tbs(sig_suite: int, sender_fp: bytes, header: bytes, created_at: int,
               name: bytes, data: bytes) -> bytes:
    """The exact bytes that get signed. Every field has a fixed size or a length
    prefix, so two different inputs can never produce the same bytes."""
    return b"".join((
        TBS_LABEL,
        bytes([sig_suite]),
        sender_fp,                                   # 32 bytes
        hashlib.sha3_512(header).digest(),           # 64 bytes: recipient + this package
        struct.pack(">Q", created_at),
        struct.pack(">H", len(name)), name,
        struct.pack(">Q", len(data)),
        hashlib.sha3_512(data).digest(),             # 64 bytes
    ))


def _build_payload(sig_suite: int, sender_fp: bytes, created_at: int, name: bytes,
                   signature: bytes, data: bytes) -> bytes:
    return (
        _PAYLOAD_PREFIX.pack(PAYLOAD_MAGIC, PAYLOAD_VERSION, sig_suite, sender_fp, created_at, len(name))
        + name + signature + data
    )


@dataclass
class _Payload:
    sig_suite: int
    sender_fp: bytes
    created_at: int
    name: bytes
    signature: bytes
    data: bytes


def _parse_payload(payload: bytes) -> _Payload:
    """Strictly parse the decrypted payload. Only called AFTER AES-GCM succeeded."""
    bad = TransferError("The package content is malformed.")
    if len(payload) < _PAYLOAD_PREFIX.size:
        raise bad
    magic, version, sig_suite, sender_fp, created_at, name_len = _PAYLOAD_PREFIX.unpack_from(payload, 0)
    if magic != PAYLOAD_MAGIC or version != PAYLOAD_VERSION:
        raise bad
    if sig_suite not in SIGNATURE_SIZES:
        raise TransferError(f"Unsupported signature suite: {sig_suite}.")
    if name_len > MAX_NAME_BYTES:
        raise bad
    sig_size = SIGNATURE_SIZES[sig_suite]
    name_end = _PAYLOAD_PREFIX.size + name_len
    sig_end = name_end + sig_size
    if len(payload) < sig_end:
        raise bad
    return _Payload(
        sig_suite=sig_suite,
        sender_fp=sender_fp,
        created_at=created_at,
        name=payload[_PAYLOAD_PREFIX.size:name_end],
        signature=payload[name_end:sig_end],
        data=payload[sig_end:],
    )


def _coerce_trusted(trusted_senders) -> list:
    if isinstance(trusted_senders, PublicIdentity):
        return [trusted_senders]
    if trusted_senders is None:
        raise ValueError("trusted_senders is required: say whose signatures you accept.")
    try:
        items = list(trusted_senders)
    except TypeError:
        raise TypeError("trusted_senders must be a PublicIdentity or a list of them.") from None
    if not items:
        raise ValueError("trusted_senders is empty: no signature could ever be accepted.")
    if not all(isinstance(item, PublicIdentity) for item in items):
        raise TypeError("trusted_senders must contain only PublicIdentity objects.")
    return items


def _package_id(header: bytes) -> str:
    return hashlib.sha3_256(header).hexdigest()


# ---- Sign + encrypt ----------------------------------------------------------------------
def sign_and_encrypt(plaintext: bytes, recipient_public_key: MLKEM768PublicKey,
                     sender_identity: SigningIdentity, filename: str = "file",
                     created_at: int | None = None) -> bytes:
    """Sign a file with the sender's identity and encrypt it for one recipient.

    Needs the recipient's PUBLIC key (a private key is refused) and the sender's
    SigningIdentity. Returns the version 2 package (bytes).
    `created_at` (Unix seconds) defaults to now; override it only in tests.
    """
    if isinstance(recipient_public_key, MLKEM768PrivateKey):
        raise TypeError(
            "Give the recipient's PUBLIC key, not a private key. "
            "A private key must never leave the receiving side."
        )
    if not isinstance(recipient_public_key, MLKEM768PublicKey):
        raise TypeError("recipient_public_key must be an ML-KEM-768 public key.")
    if not isinstance(sender_identity, SigningIdentity):
        raise TypeError("sender_identity must be a SigningIdentity.")
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes.")
    plaintext = bytes(plaintext)

    name = _name_bytes_for_signing(filename)
    created_at = int(time.time()) if created_at is None else int(created_at)
    if not 0 <= created_at < 2 ** 63:
        raise ValueError("created_at is out of range.")
    sig_suite = sender_identity.public.suite
    if len(plaintext) + _PAYLOAD_PREFIX.size + MAX_NAME_BYTES + SIGNATURE_SIZES[sig_suite] > MAX_PAYLOAD_SIZE:
        raise ValueError("File is too large for this module.")

    try:
        shared_secret, kem_ciphertext = recipient_public_key.encapsulate()
    except UnsupportedAlgorithm:
        raise PostQuantumUnavailableError(
            "This installation of the 'cryptography' library does not support "
            "ML-KEM-768. QShield will NOT fall back to ordinary encryption."
        ) from None
    if len(shared_secret) != SHARED_SECRET_SIZE or len(kem_ciphertext) != KEM_CIPHERTEXT_SIZE:
        raise TransferError("The ML-KEM library returned unexpected sizes. Stopping.")

    header = _PREFIX.pack(
        MAGIC, VERSION_SIGNED, KEM_SUITE,
        bytes.fromhex(pq_transfer.public_key_fingerprint(recipient_public_key)),
    ) + kem_ciphertext

    sender_fp = sender_identity.public.fingerprint_bytes()
    tbs = _build_tbs(sig_suite, sender_fp, header, created_at, name, plaintext)
    signature = sender_identity.sign(tbs)          # verifies its own result before returning
    payload = _build_payload(sig_suite, sender_fp, created_at, name, signature, plaintext)

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(_derive_key(shared_secret, header)).encrypt(nonce, payload, header)
    return header + nonce + ciphertext


# ---- Decrypt + verify ---------------------------------------------------------------------
def decrypt_and_verify(package: bytes, recipient_private_key: MLKEM768PrivateKey,
                       trusted_senders, *, max_age_seconds: int | None = None,
                       now: int | None = None,
                       max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS) -> VerifiedFile:
    """Open a version 2 package and check who signed it.

    `trusted_senders` (required) is a PublicIdentity or a list of them: the
    senders whose signatures you accept. Their fingerprints must have been
    confirmed over a second channel.

    Raises:
      UnsignedPackageError  the package is version 1 (no signature)
      WrongRecipientError   it was made for a different recipient key
      TransferError         damaged, changed, or not a QShield package
      UnknownSenderError    signed by someone who is not trusted
      InvalidSignatureError the signature does not match
      StalePackageError     older than max_age_seconds (or dated in the future)
    All of these are also DecryptionError. Nothing is returned unless EVERY
    check passes.
    """
    if not isinstance(recipient_private_key, MLKEM768PrivateKey):
        raise TypeError("recipient_private_key must be an ML-KEM-768 private key.")
    if not isinstance(package, (bytes, bytearray, memoryview)):
        raise TypeError("package must be bytes.")
    trusted = _coerce_trusted(trusted_senders)
    package = bytes(package)

    if len(package) < HEADER_SIZE:
        raise TransferError("This is too short to be a QShield transfer package.")
    magic, version, suite, fingerprint = _PREFIX.unpack_from(package, 0)
    if magic != MAGIC:
        raise TransferError("This is not a QShield transfer package.")
    if version == pq_transfer.VERSION:
        raise UnsignedPackageError(
            "This package is NOT signed (version 1), so its sender cannot be verified. "
            "It was refused. Ask the sender to use a signing identity."
        )
    if version != VERSION_SIGNED:
        raise TransferError(f"Unsupported package version: {version}.")
    if suite != KEM_SUITE:
        raise TransferError(f"Unsupported algorithm suite: {suite}.")
    if len(package) < HEADER_SIZE + NONCE_SIZE + TAG_SIZE + _PAYLOAD_PREFIX.size:
        raise TransferError("The package is cut short or damaged.")

    own_fingerprint = bytes.fromhex(pq_transfer.public_key_fingerprint(recipient_private_key.public_key()))
    if not hmac.compare_digest(fingerprint, own_fingerprint):
        raise WrongRecipientError(
            "This package was made for a different recipient key. "
            "Ask the sender to encrypt it again with your public key."
        )

    header = package[:HEADER_SIZE]
    nonce = package[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
    ciphertext = package[HEADER_SIZE + NONCE_SIZE:]
    try:
        # ML-KEM never raises on a damaged ciphertext (it returns a different
        # secret), so the AES-GCM check below is what catches the damage.
        shared_secret = recipient_private_key.decapsulate(header[_PREFIX.size:])
        payload = AESGCM(_derive_key(shared_secret, header)).decrypt(nonce, ciphertext, header)
    except UnsupportedAlgorithm:
        raise PostQuantumUnavailableError(
            "This installation of the 'cryptography' library does not support "
            "ML-KEM-768. QShield will NOT fall back to ordinary encryption."
        ) from None
    except InvalidTag:
        raise TransferError(
            "Could not open the package: it was changed or damaged, "
            "or it was not made for this recipient key."
        ) from None

    parsed = _parse_payload(payload)

    sender = next(
        (t for t in trusted if hmac.compare_digest(t.fingerprint_bytes(), parsed.sender_fp)), None
    )
    if sender is None:
        raise UnknownSenderError(
            "The package opened, but it is signed by someone who is not in your "
            "trusted senders. No file contents were released."
        )
    if sender.suite != parsed.sig_suite:
        raise InvalidSignatureError("The signature suite does not match the sender's key.")

    tbs = _build_tbs(parsed.sig_suite, parsed.sender_fp, header, parsed.created_at, parsed.name, parsed.data)
    sender.verify(tbs, parsed.signature)           # BOTH halves must be valid

    # ---- Checks that only make sense after the signature is proven ----
    try:
        name = parsed.name.decode("utf-8")
    except UnicodeDecodeError:
        raise TransferError("The signed file name is not valid text.") from None
    if (_clean_filename(name) != name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)):
        raise TransferError("The signed file name is not safe.")

    if max_age_seconds is not None:
        current = int(time.time()) if now is None else int(now)
        age = current - parsed.created_at
        if age > max_age_seconds:
            raise StalePackageError("This package is older than your limit allows.")
        if age < -max_clock_skew_seconds:
            raise StalePackageError("This package is dated in the future.")

    return VerifiedFile(
        filename=name,
        data=parsed.data,
        sender=sender,
        sender_fingerprint=sender.fingerprint(),
        created_at=parsed.created_at,
        package_id=_package_id(header),
    )


# ---- Files on disk -------------------------------------------------------------------------
def sign_and_encrypt_file(input_path, output_path, recipient_public_key: MLKEM768PublicKey,
                          sender_identity: SigningIdentity, overwrite: bool = False) -> Path:
    """Read a file, sign + encrypt it for the recipient, and write the package."""
    input_path, output_path = Path(input_path), Path(output_path)
    package = sign_and_encrypt(input_path.read_bytes(), recipient_public_key, sender_identity,
                               filename=input_path.name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb" if overwrite else "xb") as f:  # "xb": never overwrite
        f.write(package)
    return output_path


def decrypt_and_verify_file(package_path, output_dir, recipient_private_key: MLKEM768PrivateKey,
                            trusted_senders, overwrite: bool = False, **checks) -> Path:
    """Open a package file into output_dir. Written only after EVERY check passes."""
    result = decrypt_and_verify(Path(package_path).read_bytes(), recipient_private_key,
                                trusted_senders, **checks)
    return file_crypto.write_decrypted_file(
        DecryptedFile(filename=result.filename, data=result.data, metadata={}), output_dir, overwrite
    )
