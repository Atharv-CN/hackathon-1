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
  - The ORIGINAL container (version 1, magic QSHD) is processed in memory with
    one AES-GCM call, so it is limited to ~2 GB and is meant for small files.
    It is kept so old files still open. The bytes functions encrypt_bytes() /
    decrypt_bytes() are inherently whole-file (they take and return `bytes`).
  - Nothing here is claimed to be quantum-resistant.

STREAMING FORMAT (magic QSHS, version 1) - for files of any practical size
  encrypt_stream / decrypt_stream / encrypt_file / decrypt_file use the STREAM
  construction as documented for Google Tink's AES-GCM-HKDF Streaming AEAD
  (https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming),
  AES-256 profile. Only `cryptography` primitives are used (AESGCM, HKDF).
  Interoperability with Tink's own library has NOT been verified.

  File layout:
    QShield envelope (authenticated, not encrypted)
      magic "QSHS" (4) | version 1 (1) | suite 1 (1)
      | ciphertext segment size (4, big-endian) | metadata length (4) | metadata JSON
    STREAM header (40 bytes, exactly as in the construction)
      header length = 40 (1) | salt (32, random per stream) | nonce prefix (7, random per stream)
    Segments, each AES-256-GCM(plaintext chunk) + 16-byte tag, no per-segment AAD
      segment 0 is (segment size - 40) bytes long on the wire, every later
      non-final segment is exactly `segment size` bytes, the final one is
      1..segment size bytes (an empty file is one segment holding only a tag).

  Key derivation (one level):  aes_key = HKDF-SHA256(ikm = the caller's 32-byte key,
      salt = stream salt, info = "QShield stream v1 ..." label + the whole envelope).
  So the envelope (version, suite, segment size, file name, size...) is bound to
  the key: change any envelope byte, the salt or the key and nothing decrypts.

  Nonce for segment i (12 bytes):  nonce prefix (7) | i as 4-byte big-endian | flag (1)
      flag = 0 for every segment except the last, 1 for the last.
  The final flag is never read from the file: the reader works it out from
  where the data actually ends (one segment of look-ahead). A cut-off stream
  therefore fails authentication instead of looking complete. At most
  2**32 segments are allowed (rejected before a nonce could repeat).

  Memory: a few segments (default segment size 1 MiB) no matter how big the file is.
  decrypt_stream() writes each segment as soon as its own tag verifies, but the
  stream is only trustworthy once the function RETURNS. The file functions
  therefore write to a private temporary file and publish it only at the end.
"""

import base64
import binascii
import io
import json
import os
import stat
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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

# ---- Streaming format constants (magic QSHS, version 1) ---------------------
STREAM_MAGIC = b"QSHS"
STREAM_VERSION = 1
STREAM_SUITE_AES256GCM_HKDF_SHA256 = 1
STREAM_SALT_SIZE = 32                 # AES-256 profile: salt as long as the key
STREAM_NONCE_PREFIX_SIZE = 7          # 7 + 4 (segment number) + 1 (final flag) = 12
STREAM_HEADER_SIZE = 1 + STREAM_SALT_SIZE + STREAM_NONCE_PREFIX_SIZE   # 40
DEFAULT_SEGMENT_SIZE = 1024 * 1024    # ciphertext segment size (1 MiB)
MIN_SEGMENT_SIZE = 256
MAX_SEGMENT_SIZE = 16 * 1024 * 1024   # bounds what a reader will buffer
MAX_SEGMENT_COUNT = 2**32             # segment numbers 0 .. 2**32 - 1
# magic, version, suite, ciphertext segment size, metadata length
_STREAM_PREFIX = struct.Struct(">4sBBII")
# segment size, metadata length (used inside recipient packages)
_STREAM_ENVELOPE = struct.Struct(">II")
STREAM_CONTEXT_STANDALONE = b"QShield stream v1: AES-256-GCM-HKDF-SHA256 standalone\x00"
_LEGACY_MAX_CONTAINER = MAX_PLAINTEXT_SIZE + MAX_METADATA_SIZE + 64


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

    if container[:4] == STREAM_MAGIC:  # new streaming format: dispatch by magic
        sink = io.BytesIO()
        result = decrypt_stream(io.BytesIO(container), sink, key)
        return DecryptedFile(filename=result.filename, data=sink.getvalue(), metadata=result.metadata)

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


# ---- STREAM engine (shared by standalone files and recipient packages) ----------
@dataclass
class DecryptedStream:
    """Result of a successful streaming decryption. The plaintext went to the sink."""

    filename: str      # cleaned: never contains folders like ../
    metadata: dict     # the authenticated metadata
    size: int          # number of plaintext bytes written to the sink


def _random_bytes(n: int) -> bytes:
    """The only source of salts and nonce prefixes. (A named function so tests can
    pin it to check the construction against fixed values.)"""
    return os.urandom(n)


def _check_segment_size(segment_size) -> None:
    if (
        not isinstance(segment_size, int)
        or isinstance(segment_size, bool)
        or not MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE
    ):
        raise ValueError(
            f"The segment size must be between {MIN_SEGMENT_SIZE} and {MAX_SEGMENT_SIZE} bytes."
        )


def _derive_stream_key(main_key: bytes, salt: bytes, associated_data: bytes) -> bytes:
    """HKDF-SHA256 as the construction specifies: ikm = key, salt = stream salt,
    info = associated data (here: QShield's context label + immutable envelope)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, info=associated_data
    ).derive(bytes(main_key))


def _segment_nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + index.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def _read_up_to(src, n: int) -> bytes:
    """Read n bytes, or fewer ONLY if the end of the input was reached."""
    parts, remaining = [], n
    while remaining > 0:
        chunk = src.read(remaining)
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("The input must be opened in binary mode.")
        if len(chunk) > remaining:
            raise ValueError("The input returned more data than was asked for.")
        parts.append(bytes(chunk))
        remaining -= len(chunk)
    return parts[0] if len(parts) == 1 else b"".join(parts)


def _read_exact(src, n: int, what: str) -> bytes:
    data = _read_up_to(src, n)
    if len(data) != n:
        raise DecryptionError(f"The file is cut short or damaged ({what}).")
    return data


def encrypt_stream_body(src, dst, main_key: bytes, associated_data: bytes, segment_size: int) -> int:
    """Write the STREAM header and all segments for `src` to `dst`. Returns the number of
    plaintext bytes read.

    LOW-LEVEL: the caller has already written (and must have put into
    `associated_data`) its own envelope. `main_key` is the input key material for
    HKDF (a 32-byte key). Holds about three segments in memory at any time.
    """
    _check_key(main_key)
    _check_segment_size(segment_size)
    salt = _random_bytes(STREAM_SALT_SIZE)
    prefix = _random_bytes(STREAM_NONCE_PREFIX_SIZE)
    aead = AESGCM(_derive_stream_key(main_key, salt, associated_data))

    dst.write(bytes([STREAM_HEADER_SIZE]) + salt + prefix)

    first_capacity = segment_size - STREAM_HEADER_SIZE - TAG_SIZE   # segment 0 is shortened by the header
    capacity = segment_size - TAG_SIZE
    current = _read_up_to(src, first_capacity)
    index, total = 0, 0
    while True:
        # Look ahead: a full chunk is "final" only if no more data follows it.
        # A short chunk means the input already ended.
        full = len(current) == (first_capacity if index == 0 else capacity)
        upcoming = _read_up_to(src, capacity) if full else b""
        final = not upcoming
        if index >= MAX_SEGMENT_COUNT:
            raise ValueError("This stream has too many segments (the 2**32 limit was reached).")
        dst.write(aead.encrypt(_segment_nonce(prefix, index, final), current, None))
        total += len(current)
        if final:
            return total
        current, index = upcoming, index + 1


def decrypt_stream_body(src, dst, main_key: bytes, associated_data: bytes, segment_size: int) -> int:
    """Read the STREAM header and all segments from `src`, writing each verified chunk to
    `dst`. Returns the number of plaintext bytes written.

    Raises DecryptionError on ANY problem: bad header, wrong key, a changed, missing,
    repeated or reordered segment, a missing final segment, or extra data at the end.
    Chunks are written as soon as their own tag verifies; the stream is only fully
    authenticated when this function returns without an error.
    """
    _check_key(main_key)
    _check_segment_size(segment_size)
    header = _read_exact(src, STREAM_HEADER_SIZE, "stream header")
    if header[0] != STREAM_HEADER_SIZE:
        raise DecryptionError("The stream header is invalid.")
    salt = header[1:1 + STREAM_SALT_SIZE]
    prefix = header[1 + STREAM_SALT_SIZE:]
    aead = AESGCM(_derive_stream_key(main_key, salt, associated_data))

    first_size = segment_size - STREAM_HEADER_SIZE   # ciphertext bytes in segment 0
    current = _read_up_to(src, first_size)
    if not current:
        raise DecryptionError("The file is cut short: there is no final segment.")
    index, total = 0, 0
    while True:
        full = len(current) == (first_size if index == 0 else segment_size)
        upcoming = _read_up_to(src, segment_size) if full else b""
        final = not upcoming
        if index >= MAX_SEGMENT_COUNT:
            raise DecryptionError("The stream has too many segments.")
        if len(current) < TAG_SIZE:
            raise DecryptionError("The file is cut short or damaged (segment too small).")
        try:
            plaintext = aead.decrypt(_segment_nonce(prefix, index, final), current, None)
        except InvalidTag:
            raise DecryptionError(
                "Decryption failed: wrong key, or the file was changed, damaged or cut short."
            ) from None
        if final and index > 0 and not plaintext:
            raise DecryptionError("The stream ends with an empty segment.")  # never produced by encryption
        dst.write(plaintext)
        total += len(plaintext)
        if final:
            return total
        current, index = upcoming, index + 1


def build_stream_metadata(filename: str, size) -> bytes:
    """Canonical metadata JSON for a stream. `size` may be None if unknown in advance."""
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise ValueError("size must be a non-negative integer or None.")
    metadata = {
        "filename": _safe_filename(filename),
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if size is not None:
        metadata["original_size"] = size
    data = json.dumps(metadata, sort_keys=True).encode("utf-8")
    if len(data) > MAX_METADATA_SIZE:
        raise ValueError("The file name is too long.")
    return data


def pack_stream_envelope(segment_size: int, metadata_bytes: bytes) -> bytes:
    _check_segment_size(segment_size)
    return _STREAM_ENVELOPE.pack(segment_size, len(metadata_bytes)) + metadata_bytes


def read_stream_envelope(src):
    """Read and VALIDATE (segment size, metadata) before using any length. Returns
    (segment_size, metadata_bytes, envelope_bytes). Raises DecryptionError."""
    raw = _read_exact(src, _STREAM_ENVELOPE.size, "header")
    segment_size, metadata_len = _STREAM_ENVELOPE.unpack(raw)
    if not MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE or metadata_len > MAX_METADATA_SIZE:
        raise DecryptionError("The file header is invalid.")
    metadata_bytes = _read_exact(src, metadata_len, "metadata")
    return segment_size, metadata_bytes, raw + metadata_bytes


def parse_stream_metadata(metadata_bytes: bytes, plaintext_size: int):
    """Read the metadata AFTER the stream authenticated. Returns (filename, metadata)."""
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        if not isinstance(metadata["filename"], str):   # strict: the old format's str() leniency is not carried over
            raise TypeError("filename must be text")
        filename = _safe_filename(metadata["filename"])
        declared = metadata.get("original_size")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise DecryptionError("The file's metadata is not valid.") from None
    if declared is not None and (
        not isinstance(declared, int) or isinstance(declared, bool) or declared != plaintext_size
    ):
        raise DecryptionError("The decrypted size does not match the size in the header.")
    return filename, metadata


# ---- Standalone streaming API --------------------------------------------------
def encrypt_stream(src, dst, key: bytes, filename: str = "file", *, size=None,
                   segment_size: int = DEFAULT_SEGMENT_SIZE) -> int:
    """Encrypt a binary file-like `src` into a binary file-like `dst`, one segment at a time.

    Memory use is a few segments however large `src` is. Returns the plaintext byte count.
    `size` (if known) is written into the authenticated header and checked at the end;
    if the input turns out to have a different length, ValueError is raised and the
    caller must discard `dst` (encrypt_file does this for you).
    """
    _check_key(key)
    _check_segment_size(segment_size)
    metadata_bytes = build_stream_metadata(filename, size)
    envelope = _STREAM_PREFIX.pack(
        STREAM_MAGIC, STREAM_VERSION, STREAM_SUITE_AES256GCM_HKDF_SHA256,
        segment_size, len(metadata_bytes),
    ) + metadata_bytes
    dst.write(envelope)
    total = encrypt_stream_body(src, dst, key, STREAM_CONTEXT_STANDALONE + envelope, segment_size)
    if size is not None and total != size:
        raise ValueError("The input changed size while it was being encrypted.")
    return total


def decrypt_stream(src, dst, key: bytes) -> DecryptedStream:
    """Decrypt a streaming container from `src`, writing plaintext to `dst`.

    WARNING: `dst` receives chunks before the end of the stream is verified. If this raises,
    discard whatever was written. decrypt_file() does that safely; use it for files.
    """
    _check_key(key)
    prefix = _read_exact(src, _STREAM_PREFIX.size, "header")
    magic, version, suite, segment_size, metadata_len = _STREAM_PREFIX.unpack(prefix)
    if magic != STREAM_MAGIC:
        raise DecryptionError("This is not a QShield streaming file.")
    if version != STREAM_VERSION:
        raise DecryptionError(f"Unsupported file version: {version}.")
    if suite != STREAM_SUITE_AES256GCM_HKDF_SHA256:
        raise DecryptionError(f"Unsupported algorithm suite: {suite}.")
    if not MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE or metadata_len > MAX_METADATA_SIZE:
        raise DecryptionError("The file header is invalid.")
    metadata_bytes = _read_exact(src, metadata_len, "metadata")
    envelope = prefix + metadata_bytes
    total = decrypt_stream_body(src, dst, key, STREAM_CONTEXT_STANDALONE + envelope, segment_size)
    filename, metadata = parse_stream_metadata(metadata_bytes, total)
    return DecryptedStream(filename=filename, metadata=metadata, size=total)


# ---- Safe file output (used by every file-path workflow) -----------------------------
def create_private_temp(directory) -> tuple:
    """Securely create a temporary file in `directory` (owner-only, never pre-existing).
    Returns (file object opened for writing, path)."""
    fd, name = tempfile.mkstemp(dir=directory, prefix=".qshield-", suffix=".tmp")
    try:
        return os.fdopen(fd, "wb"), Path(name)
    except BaseException:
        os.close(fd)
        _discard(Path(name))
        raise


def _discard(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass  # best effort: never hide the original error


def publish(temp_path: Path, final_path: Path, overwrite: bool) -> None:
    """Move a finished temp file to its final name. Without overwrite=True an existing
    file (or symlink) is never replaced: the hard link either succeeds or fails atomically."""
    if overwrite:
        os.replace(temp_path, final_path)
        return
    try:
        os.link(temp_path, final_path)
    except FileExistsError:
        raise
    except (OSError, AttributeError, NotImplementedError):
        # File system without hard links: best effort (small race window).
        if final_path.exists() or final_path.is_symlink():
            raise FileExistsError(str(final_path)) from None
        os.rename(temp_path, final_path)
        return
    os.unlink(temp_path)


def decrypt_to_directory(src, output_dir, overwrite: bool, decrypt_into) -> Path:
    """Run `decrypt_into(src, temp_file)` and publish the result in output_dir only if
    it succeeded completely. On ANY failure the temp file is deleted and an existing
    destination is left untouched. Returns the final path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out, temp_path = create_private_temp(output_dir)
    try:
        with out:
            result = decrypt_into(src, out)
            sync_temp(out)
        final_path = output_dir / result.filename
        if final_path.resolve().parent != output_dir.resolve():
            raise DecryptionError("The file name inside the container is not safe.")
        publish(temp_path, final_path, overwrite)
        return final_path
    except BaseException:
        _discard(temp_path)
        raise


def sync_temp(f) -> None:
    """Flush a temp file all the way to disk before it is published."""
    f.flush()
    os.fsync(f.fileno())


# ---- Encrypt / decrypt files on disk ----------------------------------------
def encrypt_file(input_path, output_path, key: bytes, overwrite: bool = False, *,
                 segment_size: int = DEFAULT_SEGMENT_SIZE) -> Path:
    """Encrypt a file with the STREAMING format. Bounded memory, any practical size.

    The output is written to a private temporary file and moved into place only when
    complete, so a failure never leaves a partial output. An existing output is never
    replaced unless overwrite=True."""
    input_path, output_path = Path(input_path), Path(output_path)
    if not overwrite and (output_path.exists() or output_path.is_symlink()):
        raise FileExistsError(str(output_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(input_path, "rb") as src:
        st = os.fstat(src.fileno())
        size = st.st_size if stat.S_ISREG(st.st_mode) else None   # pipes/FIFOs: length unknown in advance
        out, temp_path = create_private_temp(output_path.parent)
        try:
            with out:
                encrypt_stream(src, out, key, input_path.name, size=size, segment_size=segment_size)
                sync_temp(out)
            publish(temp_path, output_path, overwrite)
        except BaseException:
            _discard(temp_path)
            raise
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

    Dispatches on the file's magic bytes:
      - streaming format (QSHS): decrypted incrementally into a private temporary file that
        is published only after every segment, the final segment and the end of the file
        have been verified. Bounded memory.
      - original format (QSHD, version 1): decrypted in memory (it cannot be streamed; it is
        one AES-GCM message) and refused if the file is larger than that format allows.
    A failed or tampered file never leaves anything behind.
    """
    _check_key(key)
    with open(Path(input_path), "rb") as src:
        head = src.read(4)
        src.seek(0)
        if head == STREAM_MAGIC:
            return decrypt_to_directory(src, output_dir, overwrite, lambda s, d: decrypt_stream(s, d, key))
        if head == MAGIC:
            if os.fstat(src.fileno()).st_size > _LEGACY_MAX_CONTAINER:
                raise DecryptionError("This is too large to be a version 1 QShield file.")
            return write_decrypted_file(decrypt_bytes(src.read(), key), output_dir, overwrite)
    raise DecryptionError("This is not a QShield encrypted file.")
