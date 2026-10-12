"""Encrypt and decrypt files with AES-256-GCM.

All the cryptography is done by the well-known `cryptography` library
(its AESGCM class). This file contains NO home-made algorithms. It only:
  1. makes a random key and a fresh random nonce,
  2. packs the pieces into one "container" of bytes,
  3. unpacks and checks them again.

WHAT AES-256-GCM GIVES YOU
  - Secrecy:   without the key, the file contents cannot be read.
  - Integrity: if even one bit of the container is changed, decryption fails.
               Nothing is returned and no file is written.

THE CONTAINER LAYOUT (everything is plain bytes)
  +---------+-----------+--------------+-----------+-----------+-------------------+
  | magic   | version   | metadata len | nonce     | metadata  | ciphertext + tag  |
  | 4 bytes | 1 byte    | 4 bytes      | 12 bytes  | JSON text | file size + 16    |
  +---------+-----------+--------------+-----------+-----------+-------------------+
  The first three fields plus the metadata are the "authenticated metadata".
  They are passed to AES-GCM as AAD (additional authenticated data), so they
  cannot be changed without decryption failing.

IMPORTANT LIMITS - please read
  - Metadata is AUTHENTICATED but NOT ENCRYPTED. The file name is visible to
    anyone who has the container. Only the file CONTENTS are secret.
  - The file size is not hidden.
  - Anyone who has the key can create a valid container. This module does not
    prove WHO sent a file.
  - It does not share keys. How the sender safely gives the key to the
    receiver is a separate problem that is not solved here.
  - The nonce is random (96 bits). That is safe for a very large number of
    files per key (NIST advises staying below 2**32). Best practice: use a
    NEW key for each transfer. generate_key() makes that easy.
  - Whole files are processed in memory. This is fine for the demo's 25 MB
    upload limit but is not meant for huge files.
  - Nothing here is claimed to be quantum-resistant.
"""

import base64
import binascii
import json
import os
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Format constants -------------------------------------------------------
MAGIC = b"QSHD"          # marks "this is a QShield encrypted file"
VERSION = 1              # lets future versions change the format safely
KEY_SIZE = 32            # 32 bytes = 256 bits = AES-256
NONCE_SIZE = 12          # 96 bits: the standard size for AES-GCM
TAG_SIZE = 16            # AES-GCM adds a 16-byte authentication tag
MAX_METADATA_SIZE = 64 * 1024
MAX_PLAINTEXT_SIZE = 2**31 - 1   # the most the library accepts in one call

# magic (4 bytes), version (1 byte), metadata length (4 bytes, big-endian)
_PREFIX = struct.Struct(">4sBI")


class DecryptionError(Exception):
    """Decryption failed.

    Possible reasons: wrong key, the file was changed or damaged, or it is
    not a QShield file. AES-GCM cannot tell these apart, and that is fine.
    """


@dataclass
class DecryptedFile:
    """What you get back after a successful decryption."""

    filename: str      # cleaned: never contains folders like ../
    data: bytes        # the original file contents
    metadata: dict     # the authenticated metadata (all values checked)


# ---- Keys -------------------------------------------------------------------
def generate_key() -> bytes:
    """Make a brand-new random 256-bit key (uses the operating system's secure
    random number generator). Keys are NEVER written in the source code."""
    return AESGCM.generate_key(bit_length=256)


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        # The message deliberately does not include the key itself.
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes (256 bits).")


def key_to_text(key: bytes) -> str:
    """Turn a key into text that can be copied and pasted (URL-safe base64)."""
    _check_key(key)
    return base64.urlsafe_b64encode(bytes(key)).decode("ascii")


def key_from_text(text: str) -> bytes:
    """Turn pasted key text back into the 32-byte key."""
    cleaned = "".join(text.split()).replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        key = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("That is not a valid key. Copy the whole key again.") from None
    _check_key(key)
    return key


# ---- Helpers ----------------------------------------------------------------
def _safe_filename(name: str) -> str:
    """Keep only the last part of a path so a file name can never point to
    another folder (for example '../../evil.txt' becomes 'evil.txt')."""
    name = str(name).replace("\x00", "").replace("\\", "/").split("/")[-1].strip()
    return name if name not in ("", ".", "..") else "decrypted_file"


def _build_aad(prefix: bytes, metadata_bytes: bytes) -> bytes:
    """The authenticated metadata: the fixed prefix plus the metadata text."""
    return prefix + metadata_bytes


# ---- Encrypt / decrypt bytes -------------------------------------------------
def encrypt_bytes(plaintext: bytes, key: bytes, filename: str = "file") -> bytes:
    """Encrypt bytes and return the container (see the layout at the top)."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise ValueError("File is too large for this module.")
    _check_key(key)

    metadata = {
        "filename": _safe_filename(filename),
        "original_size": len(plaintext),
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    metadata_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")

    prefix = _PREFIX.pack(MAGIC, VERSION, len(metadata_bytes))
    nonce = os.urandom(NONCE_SIZE)  # a NEW random nonce for every encryption
    ciphertext = AESGCM(bytes(key)).encrypt(
        nonce, bytes(plaintext), _build_aad(prefix, metadata_bytes)
    )
    return prefix + nonce + metadata_bytes + ciphertext


def decrypt_bytes(container: bytes, key: bytes) -> DecryptedFile:
    """Check and decrypt a container. Raises DecryptionError if anything is
    wrong. Data is only returned after the authentication check has passed."""
    _check_key(key)
    container = bytes(container)

    if len(container) < _PREFIX.size + NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("This is too short to be a QShield encrypted file.")

    magic, version, metadata_len = _PREFIX.unpack_from(container, 0)
    if magic != MAGIC:
        raise DecryptionError("This is not a QShield encrypted file.")
    if version != VERSION:
        raise DecryptionError(f"Unsupported file version: {version}.")
    if metadata_len > MAX_METADATA_SIZE:
        raise DecryptionError("The file header is invalid.")

    nonce_start = _PREFIX.size
    metadata_start = nonce_start + NONCE_SIZE
    ciphertext_start = metadata_start + metadata_len
    if len(container) < ciphertext_start + TAG_SIZE:
        raise DecryptionError("The file is cut short or damaged.")

    nonce = container[nonce_start:metadata_start]
    metadata_bytes = container[metadata_start:ciphertext_start]
    aad = _build_aad(container[:_PREFIX.size], metadata_bytes)

    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, container[ciphertext_start:], aad)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed: wrong key, or the file was changed or damaged."
        ) from None

    # Only now, after authentication passed, is the metadata read as JSON.
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        filename = _safe_filename(metadata["filename"])
    except (ValueError, KeyError, TypeError):
        raise DecryptionError("The file's metadata is not valid.") from None

    return DecryptedFile(filename=filename, data=plaintext, metadata=metadata)


# ---- Encrypt / decrypt files on disk ----------------------------------------
def encrypt_file(input_path, output_path, key: bytes, overwrite: bool = False) -> Path:
    """Read a file, encrypt it, and write the container to output_path."""
    input_path, output_path = Path(input_path), Path(output_path)
    container = encrypt_bytes(input_path.read_bytes(), key, filename=input_path.name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb" if overwrite else "xb") as f:  # "xb": never overwrite
        f.write(container)
    return output_path


def write_decrypted_file(result: DecryptedFile, output_dir, overwrite: bool = False) -> Path:
    """Save an already-decrypted file into output_dir and return its path.

    The file name is checked so the file can only land inside output_dir, and an
    existing file is never replaced unless overwrite=True.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / result.filename
    if output_path.resolve().parent != output_dir.resolve():
        raise DecryptionError("The file name inside the container is not safe.")

    with open(output_path, "wb" if overwrite else "xb") as f:
        f.write(result.data)
    return output_path


def decrypt_file(input_path, output_dir, key: bytes, overwrite: bool = False) -> Path:
    """Decrypt a container file into output_dir and return the new file's path.

    The result is written only AFTER authentication succeeds, so a changed or
    wrong-key file never leaves a half-decrypted file behind.
    """
    result = decrypt_bytes(Path(input_path).read_bytes(), key)
    return write_decrypted_file(result, output_dir, overwrite)
