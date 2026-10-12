"""Automated tests for core/file_crypto.py.

Run them from the qshield folder with:   pytest
(Add -v to see every test name.)
"""

import inspect
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.file_crypto import (
    DecryptionError,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_key,
    key_from_text,
    key_to_text,
)

SECRET = b"SUPER-SECRET-MARKER-12345 " * 10


@pytest.fixture
def key():
    return generate_key()


# =============================================================================
# 1. Files can be encrypted and recovered
# =============================================================================
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000, 1024 * 1024, 2 * 1024 * 1024])
def test_round_trip_bytes_of_many_sizes(key, size):
    original = os.urandom(size)
    container = encrypt_bytes(original, key, filename="data.bin")
    result = decrypt_bytes(container, key)
    assert result.data == original
    assert result.filename == "data.bin"
    assert result.metadata["original_size"] == size


def test_round_trip_file_on_disk(tmp_path, key):
    original = os.urandom(50_000)  # binary data, not text
    source = tmp_path / "photo.jpg"
    source.write_bytes(original)

    encrypted = encrypt_file(source, tmp_path / "photo.jpg.qshield", key)
    recovered = decrypt_file(encrypted, tmp_path / "out", key)

    assert recovered.name == "photo.jpg"
    assert recovered.read_bytes() == original
    assert encrypted.read_bytes() != original


def test_contents_are_not_visible_in_the_container(key):
    container = encrypt_bytes(SECRET, key, filename="plan.txt")
    assert b"SUPER-SECRET-MARKER" not in container


def test_container_size_is_header_plus_data_plus_16_byte_tag(key):
    container = encrypt_bytes(b"x" * 100, key, filename="a.txt")
    _, _, metadata_len = struct.unpack(">4sBI", container[:9])
    assert len(container) == 9 + 12 + metadata_len + 100 + 16


# =============================================================================
# 2. Modified ciphertext is rejected
# =============================================================================
def test_every_single_bit_change_is_rejected(key):
    """Flip EACH bit of EACH byte (header, nonce, metadata, data, tag) one at a
    time. Every single change must be caught."""
    container = encrypt_bytes(b"A" * 40, key, filename="report.txt")
    for position in range(len(container)):
        for bit in range(8):
            damaged = bytearray(container)
            damaged[position] ^= 1 << bit
            try:
                decrypt_bytes(bytes(damaged), key)
            except DecryptionError:
                continue
            pytest.fail(f"Change at byte {position}, bit {bit} was NOT rejected")


def test_truncated_container_is_rejected_at_every_length(key):
    container = encrypt_bytes(b"A" * 40, key, filename="report.txt")
    for length in range(len(container)):
        with pytest.raises(DecryptionError):
            decrypt_bytes(container[:length], key)


def test_extra_bytes_added_to_the_end_are_rejected(key):
    container = encrypt_bytes(b"hello", key)
    with pytest.raises(DecryptionError):
        decrypt_bytes(container + b"\x00", key)


def test_wrong_key_is_rejected(key):
    container = encrypt_bytes(SECRET, key)
    with pytest.raises(DecryptionError):
        decrypt_bytes(container, generate_key())


def test_random_bytes_are_not_accepted_as_a_container(key):
    with pytest.raises(DecryptionError):
        decrypt_bytes(os.urandom(500), key)


def test_tampered_file_on_disk_is_rejected_and_nothing_is_written(tmp_path, key):
    source = tmp_path / "secret.txt"
    source.write_bytes(SECRET)
    encrypted = encrypt_file(source, tmp_path / "secret.txt.qshield", key)

    damaged = bytearray(encrypted.read_bytes())
    damaged[-5] ^= 0xFF  # change one byte near the end
    encrypted.write_bytes(bytes(damaged))

    out_dir = tmp_path / "out"
    with pytest.raises(DecryptionError):
        decrypt_file(encrypted, out_dir, key)
    assert not out_dir.exists() or list(out_dir.iterdir()) == []


# =============================================================================
# 3. Metadata is authenticated
# =============================================================================
def test_changing_the_filename_in_the_header_is_rejected(key):
    container = encrypt_bytes(b"payroll", key, filename="report.txt")
    assert b"report.txt" in container  # the name is visible (NOT encrypted)
    forged = container.replace(b"report.txt", b"report.exe", 1)  # same length
    assert forged != container and len(forged) == len(container)
    with pytest.raises(DecryptionError):
        decrypt_bytes(forged, key)


def test_metadata_is_visible_but_contents_are_not(key):
    """Documents the honest truth: metadata is authenticated, not secret."""
    container = encrypt_bytes(SECRET, key, filename="visible-name.txt")
    assert b"visible-name.txt" in container
    assert b"SUPER-SECRET-MARKER" not in container


def test_unsafe_filenames_are_cleaned(tmp_path, key):
    for evil in ["../../evil.txt", "..\\..\\evil.txt", "/etc/passwd", "..", ""]:
        result = decrypt_bytes(encrypt_bytes(b"x", key, filename=evil), key)
        assert "/" not in result.filename and "\\" not in result.filename
        assert result.filename not in ("", ".", "..")

    container = encrypt_bytes(b"data", key, filename="../../evil.txt")
    source = tmp_path / "evil.qshield"
    source.write_bytes(container)
    out_dir = tmp_path / "a" / "b" / "out"
    written = decrypt_file(source, out_dir, key)
    assert written.parent == out_dir
    assert not (tmp_path / "evil.txt").exists()


# =============================================================================
# 4. Nonces and keys are random, never hardcoded
# =============================================================================
def test_every_encryption_uses_a_new_random_nonce(key):
    nonces = set()
    for _ in range(2000):
        container = encrypt_bytes(b"same data every time", key)
        nonces.add(container[9:21])  # the 12 nonce bytes
    assert len(nonces) == 2000


def test_same_file_and_key_give_different_containers(key):
    a = encrypt_bytes(SECRET, key, filename="f.txt")
    b = encrypt_bytes(SECRET, key, filename="f.txt")
    assert a != b


def test_generated_keys_are_256_bits_and_unique():
    keys = {generate_key() for _ in range(200)}
    assert len(keys) == 200
    assert all(len(k) == 32 for k in keys)


def test_no_function_has_a_default_key():
    """A key must always be passed in. There is no built-in fallback key."""
    for func in (encrypt_bytes, decrypt_bytes, encrypt_file, decrypt_file):
        assert inspect.signature(func).parameters["key"].default is inspect.Parameter.empty


@pytest.mark.parametrize("bad_key", [b"", b"short", b"x" * 16, b"x" * 31, b"x" * 33, "x" * 32, None])
def test_keys_of_the_wrong_size_or_type_are_refused(bad_key):
    with pytest.raises(ValueError):
        encrypt_bytes(b"data", bad_key)
    with pytest.raises(ValueError):
        decrypt_bytes(b"x" * 100, bad_key)


def test_key_text_round_trip(key):
    assert key_from_text(key_to_text(key)) == key
    assert key_from_text("  " + key_to_text(key) + " \n") == key  # pasted with spaces


@pytest.mark.parametrize("bad_text", ["", "not a key!", "AAAA", "A" * 100])
def test_bad_key_text_is_refused(bad_text):
    with pytest.raises(ValueError):
        key_from_text(bad_text)


# =============================================================================
# 5. It is standard AES-256-GCM (no custom crypto)
# =============================================================================
def test_container_can_be_decrypted_with_the_library_directly(key):
    """Take the container apart by hand and use the `cryptography` library
    ourselves. This proves the module uses ordinary AES-256-GCM and that the
    metadata really is the authenticated data."""
    container = encrypt_bytes(SECRET, key, filename="plan.txt")

    magic, version, metadata_len = struct.unpack(">4sBI", container[:9])
    nonce = container[9:21]
    metadata = container[21:21 + metadata_len]
    ciphertext_and_tag = container[21 + metadata_len:]

    assert magic == b"QSHD" and version == 1 and len(nonce) == 12
    assert len(key) == 32  # AES-256
    aad = container[:9] + metadata
    assert AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad) == SECRET

    # Same data with the metadata left out of the check must FAIL.
    with pytest.raises(Exception):
        AESGCM(key).decrypt(nonce, ciphertext_and_tag, b"")


# =============================================================================
# 6. File-level safety
# =============================================================================
def test_existing_files_are_not_overwritten_by_default(tmp_path, key):
    source = tmp_path / "a.txt"
    source.write_bytes(b"new data")
    target = tmp_path / "a.txt.qshield"
    target.write_bytes(b"IMPORTANT, DO NOT LOSE")

    with pytest.raises(FileExistsError):
        encrypt_file(source, target, key)
    assert target.read_bytes() == b"IMPORTANT, DO NOT LOSE"

    encrypt_file(source, target, key, overwrite=True)  # allowed when asked
    assert target.read_bytes() != b"IMPORTANT, DO NOT LOSE"


def test_text_instead_of_bytes_is_refused(key):
    with pytest.raises(TypeError):
        encrypt_bytes("this is a str, not bytes", key)
