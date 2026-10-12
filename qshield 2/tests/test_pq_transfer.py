"""Automated tests for core/pq_transfer.py (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM).

Run them from the qshield folder with:   pytest
"""

import base64
import json
import os
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM1024PrivateKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto
from core import pq_transfer as pq
from core.file_crypto import DecryptionError

SECRET = b"SUPER-SECRET-MARKER-12345 " * 10
GOLDEN = Path(__file__).parent / "data" / "golden_package_v1.json"


@pytest.fixture
def recipient():
    """The receiver's key pair. The private key stays in the test, i.e. 'on the receiving side'."""
    return pq.generate_recipient_keypair()


@pytest.fixture
def recipient_public(recipient):
    return recipient.public_key()


# =============================================================================
# 1. Successful encryption and decryption
# =============================================================================
@pytest.mark.parametrize("size", [0, 1, 1000, 1024 * 1024])
def test_round_trip_of_many_sizes(recipient, size):
    original = os.urandom(size)
    package = pq.encrypt_for_recipient(original, recipient.public_key(), filename="data.bin")
    result = pq.decrypt_package(package, recipient)
    assert result.data == original
    assert result.filename == "data.bin"
    assert result.metadata["original_size"] == size


def test_round_trip_when_the_sender_only_has_the_public_key_as_text(recipient):
    """The realistic flow: the receiver shares the key as text, the sender never sees the private key."""
    shared_text = pq.public_key_to_text(recipient.public_key())
    sender_copy = pq.public_key_from_text(shared_text)
    package = pq.encrypt_for_recipient(SECRET, sender_copy, filename="plan.txt")
    assert pq.decrypt_package(package, recipient).data == SECRET


def test_round_trip_file_on_disk(tmp_path, recipient):
    original = os.urandom(50_000)
    source = tmp_path / "photo.jpg"
    source.write_bytes(original)

    package_path = pq.encrypt_file_for_recipient(source, tmp_path / "photo.jpg.qshield", recipient.public_key())
    recovered = pq.decrypt_package_file(package_path, tmp_path / "out", recipient)

    assert recovered.name == "photo.jpg"
    assert recovered.read_bytes() == original
    assert package_path.read_bytes() != original


def test_contents_are_not_visible_in_the_package(recipient_public):
    package = pq.encrypt_for_recipient(SECRET, recipient_public, filename="plan.txt")
    assert b"SUPER-SECRET-MARKER" not in package


def test_package_header_is_versioned_and_labelled(recipient, recipient_public):
    package = pq.encrypt_for_recipient(b"data", recipient_public)
    magic, version, suite, fingerprint = struct.unpack(">4sBB32s", package[:38])
    assert magic == b"QSHK"
    assert version == 1
    assert suite == 1  # ML-KEM-768 + HKDF-SHA256 + AES-256-GCM
    assert fingerprint.hex() == pq.public_key_fingerprint(recipient_public)
    assert pq.HEADER_SIZE == 38 + 1088
    assert package[pq.HEADER_SIZE:pq.HEADER_SIZE + 4] == b"QSHD"  # the inner AES-GCM container


def test_every_package_uses_fresh_randomness(recipient_public):
    """New ML-KEM randomness every time: no two packages share a locked box."""
    kem_ciphertexts = {
        pq.encrypt_for_recipient(b"same data every time", recipient_public)[38:pq.HEADER_SIZE]
        for _ in range(200)
    }
    assert len(kem_ciphertexts) == 200


def test_same_file_and_key_give_different_packages(recipient_public):
    a = pq.encrypt_for_recipient(SECRET, recipient_public, filename="f.txt")
    b = pq.encrypt_for_recipient(SECRET, recipient_public, filename="f.txt")
    assert a != b


def test_package_follows_the_documented_scheme(recipient, recipient_public):
    """Open a package by hand using only the library and the documented recipe.

    This proves the package is: ML-KEM-768 secret -> HKDF-SHA256 -> AES-256-GCM key.
    The label is typed out here on purpose: it is part of the frozen version-1 format.
    """
    package = pq.encrypt_for_recipient(SECRET, recipient_public, filename="plan.txt")

    header, inner = package[:1126], package[1126:]
    kem_ciphertext = header[38:]
    assert len(kem_ciphertext) == 1088

    shared_secret = recipient.decapsulate(kem_ciphertext)
    assert len(shared_secret) == 32

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QShield v1: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM" + b"\x00" + header,
    ).derive(shared_secret)

    assert file_crypto.decrypt_bytes(inner, aes_key).data == SECRET


def test_version_1_golden_package_still_opens():
    """A package saved today must open with future code. If this fails, version 1 was broken."""
    vector = json.loads(GOLDEN.read_text())
    private_key = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"]))
    result = pq.decrypt_package(base64.b64decode(vector["package_base64"]), private_key)
    assert result.data.decode() == vector["plaintext_utf8"]
    assert result.filename == vector["filename"]


# =============================================================================
# 2. Corrupted packages are rejected
# =============================================================================
def test_every_single_bit_change_is_rejected(recipient, recipient_public):
    """Flip EACH bit of EACH byte of the whole package, one at a time: the header,
    the fingerprint, the ML-KEM ciphertext, and the encrypted file. All must fail."""
    package = pq.encrypt_for_recipient(b"A" * 20, recipient_public, filename="r.txt")
    for position in range(len(package)):
        for bit in range(8):
            damaged = bytearray(package)
            damaged[position] ^= 1 << bit
            try:
                pq.decrypt_package(bytes(damaged), recipient)
            except pq.TransferError:
                continue
            pytest.fail(f"Change at byte {position}, bit {bit} was NOT rejected")


def test_damaged_kem_ciphertext_is_caught_even_though_ml_kem_does_not_complain(recipient, recipient_public):
    """ML-KEM never raises on a bad ciphertext (it hands back a different secret).
    QShield must still reject the package, because the AES key will be wrong."""
    package = pq.encrypt_for_recipient(SECRET, recipient_public)
    damaged = bytearray(package)
    damaged[38 + 500] ^= 0x01  # inside the 1088-byte KEM ciphertext

    kem_ciphertext = bytes(damaged[38:pq.HEADER_SIZE])
    original_secret = recipient.decapsulate(package[38:pq.HEADER_SIZE])
    assert recipient.decapsulate(kem_ciphertext) != original_secret  # no error, just a different secret

    with pytest.raises(pq.TransferError) as info:
        pq.decrypt_package(bytes(damaged), recipient)
    assert not isinstance(info.value, pq.WrongRecipientError)


def test_damaged_encrypted_file_part_is_rejected(recipient, recipient_public):
    package = bytearray(pq.encrypt_for_recipient(SECRET, recipient_public))
    package[-1] ^= 0xFF  # the very last byte: part of the AES-GCM tag
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(package), recipient)


def test_truncated_package_is_rejected_at_every_length(recipient, recipient_public):
    package = pq.encrypt_for_recipient(b"A" * 20, recipient_public, filename="r.txt")
    for length in range(len(package)):
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(package[:length], recipient)


def test_extra_bytes_at_the_end_are_rejected(recipient, recipient_public):
    package = pq.encrypt_for_recipient(b"hello", recipient_public)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(package + b"\x00", recipient)


def test_mixing_parts_of_two_packages_is_rejected(recipient, recipient_public):
    """Same recipient, two different packages: header from one + file from the other."""
    a = pq.encrypt_for_recipient(b"file A", recipient_public, filename="a.txt")
    b = pq.encrypt_for_recipient(b"file B", recipient_public, filename="b.txt")
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(a[:pq.HEADER_SIZE] + b[pq.HEADER_SIZE:], recipient)


def test_random_bytes_and_empty_input_are_not_packages(recipient):
    for junk in (b"", os.urandom(10), os.urandom(5000)):
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(junk, recipient)


def test_unknown_version_or_suite_is_refused(recipient, recipient_public):
    package = bytearray(pq.encrypt_for_recipient(b"data", recipient_public))

    wrong_version = bytearray(package); wrong_version[4] = 2
    with pytest.raises(pq.TransferError, match="version"):
        pq.decrypt_package(bytes(wrong_version), recipient)

    wrong_suite = bytearray(package); wrong_suite[5] = 2
    with pytest.raises(pq.TransferError, match="suite"):
        pq.decrypt_package(bytes(wrong_suite), recipient)

    wrong_magic = bytearray(package); wrong_magic[0] ^= 1
    with pytest.raises(pq.TransferError, match="not a QShield"):
        pq.decrypt_package(bytes(wrong_magic), recipient)


def test_corrupted_package_file_on_disk_is_rejected_and_nothing_is_written(tmp_path, recipient):
    source = tmp_path / "secret.txt"
    source.write_bytes(SECRET)
    package_path = pq.encrypt_file_for_recipient(source, tmp_path / "secret.qshield", recipient.public_key())

    damaged = bytearray(package_path.read_bytes())
    damaged[700] ^= 0xFF
    package_path.write_bytes(bytes(damaged))

    out_dir = tmp_path / "out"
    with pytest.raises(pq.TransferError):
        pq.decrypt_package_file(package_path, out_dir, recipient)
    assert not out_dir.exists() or list(out_dir.iterdir()) == []


def test_transfer_errors_are_also_decryption_errors(recipient, recipient_public):
    """So code can use one `except DecryptionError` for both encryption layers."""
    assert issubclass(pq.TransferError, DecryptionError)
    assert issubclass(pq.WrongRecipientError, pq.TransferError)


# =============================================================================
# 3. Incorrect recipient keys are rejected
# =============================================================================
def test_wrong_recipient_private_key_is_rejected_with_a_clear_error(recipient_public):
    package = pq.encrypt_for_recipient(SECRET, recipient_public)
    someone_else = pq.generate_recipient_keypair()
    with pytest.raises(pq.WrongRecipientError, match="different recipient key"):
        pq.decrypt_package(package, someone_else)


def test_wrong_key_is_rejected_even_if_the_fingerprint_label_is_forged(recipient, recipient_public):
    """The fingerprint is only a label. Even if an attacker rewrites it to match
    the wrong key, the AES key still cannot be derived, so decryption fails."""
    package = bytearray(pq.encrypt_for_recipient(SECRET, recipient_public))
    someone_else = pq.generate_recipient_keypair()

    package[6:38] = bytes.fromhex(pq.public_key_fingerprint(someone_else.public_key()))
    with pytest.raises(pq.TransferError) as info:
        pq.decrypt_package(bytes(package), someone_else)
    assert not isinstance(info.value, pq.WrongRecipientError)  # it got past the label, then failed the real check

    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(package), recipient)  # and the true owner also refuses a forged package


def test_many_wrong_keys_all_fail(recipient_public):
    package = pq.encrypt_for_recipient(SECRET, recipient_public)
    for _ in range(25):
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(package, pq.generate_recipient_keypair())


def test_package_made_for_an_attacker_key_cannot_be_opened_by_the_real_recipient(recipient):
    attacker = pq.generate_recipient_keypair()
    package = pq.encrypt_for_recipient(SECRET, attacker.public_key())
    with pytest.raises(pq.WrongRecipientError):
        pq.decrypt_package(package, recipient)


def test_keys_of_other_algorithms_or_types_are_refused(recipient, recipient_public):
    package = pq.encrypt_for_recipient(b"data", recipient_public)

    with pytest.raises(TypeError):
        pq.encrypt_for_recipient(b"data", MLKEM1024PrivateKey.generate().public_key())  # ML-KEM-1024, not 768
    with pytest.raises(TypeError):
        pq.decrypt_package(package, MLKEM1024PrivateKey.generate())
    with pytest.raises(TypeError):
        pq.encrypt_for_recipient(b"data", b"x" * 1184)  # raw bytes are not a key object
    with pytest.raises(TypeError):
        pq.decrypt_package(package, recipient_public)  # a public key cannot decrypt
    with pytest.raises(TypeError):
        pq.decrypt_package("not bytes", recipient)


def test_bad_public_keys_are_refused():
    for bad in (b"", b"x" * 1183, b"x" * 1185):
        with pytest.raises(ValueError):
            pq.public_key_from_bytes(bad)
    for bad_text in ("", "not a key!", "AAAA"):
        with pytest.raises(ValueError):
            pq.public_key_from_text(bad_text)


# =============================================================================
# 4. The private key stays on the receiving side
# =============================================================================
def test_the_sender_side_refuses_a_private_key(recipient):
    with pytest.raises(TypeError, match="PUBLIC key"):
        pq.encrypt_for_recipient(b"data", recipient)


def test_package_contains_no_private_key_material(recipient, recipient_public):
    seed = recipient.private_bytes_raw()  # the private key (64-byte seed)
    package = pq.encrypt_for_recipient(SECRET, recipient_public, filename="plan.txt")
    assert seed not in package
    for start in range(0, len(seed) - 16 + 1):  # not even a 16-byte slice of it
        assert seed[start:start + 16] not in package


def test_shared_public_key_text_contains_no_private_key_material(recipient):
    seed = recipient.private_bytes_raw()
    assert seed not in pq.public_key_to_bytes(recipient.public_key())
    assert base64.urlsafe_b64encode(seed).decode() not in pq.public_key_to_text(recipient.public_key())


def test_private_key_can_be_saved_encrypted_and_loaded_again(tmp_path, recipient, recipient_public):
    path = pq.save_private_key(recipient, tmp_path / "me.key", "correct horse battery")
    content = path.read_bytes()

    assert b"ENCRYPTED PRIVATE KEY" in content
    assert recipient.private_bytes_raw() not in content
    assert base64.b64encode(recipient.private_bytes_raw()) not in content

    loaded = pq.load_private_key(path, "correct horse battery")
    assert pq.public_key_fingerprint(loaded.public_key()) == pq.public_key_fingerprint(recipient_public)

    package = pq.encrypt_for_recipient(SECRET, recipient_public)
    assert pq.decrypt_package(package, loaded).data == SECRET


def test_private_key_file_needs_the_right_password(tmp_path, recipient):
    path = pq.save_private_key(recipient, tmp_path / "me.key", "right password")
    with pytest.raises(ValueError):
        pq.load_private_key(path, "wrong password")
    with pytest.raises(ValueError):
        pq.save_private_key(recipient, tmp_path / "other.key", "")  # empty password refused


def test_private_key_file_is_never_overwritten_by_accident(tmp_path, recipient):
    path = pq.save_private_key(recipient, tmp_path / "me.key", "pw")
    with pytest.raises(FileExistsError):
        pq.save_private_key(pq.generate_recipient_keypair(), path, "pw")
    # still the original key
    assert pq.load_private_key(path, "pw").public_key().public_bytes_raw() == recipient.public_key().public_bytes_raw()


@pytest.mark.skipif(os.name != "posix", reason="file permission bits only apply on Linux/macOS")
def test_private_key_file_is_readable_only_by_its_owner(tmp_path, recipient):
    path = pq.save_private_key(recipient, tmp_path / "me.key", "pw")
    assert (path.stat().st_mode & 0o777) == 0o600


def test_wrong_kind_of_key_file_is_refused(tmp_path):
    other = tmp_path / "junk.key"
    other.write_bytes(b"this is not a key file")
    with pytest.raises(ValueError):
        pq.load_private_key(other, "pw")


# =============================================================================
# 5. Keys, fingerprints, sizes
# =============================================================================
def test_sizes_match_the_ml_kem_768_standard(recipient, recipient_public):
    assert len(pq.public_key_to_bytes(recipient_public)) == pq.PUBLIC_KEY_SIZE == 1184
    shared_secret, ciphertext = recipient_public.encapsulate()
    assert len(ciphertext) == pq.KEM_CIPHERTEXT_SIZE == 1088
    assert len(shared_secret) == pq.SHARED_SECRET_SIZE == 32


def test_fingerprints_are_stable_unique_and_readable(recipient_public):
    other = pq.generate_recipient_keypair().public_key()
    fp = pq.public_key_fingerprint(recipient_public)
    assert fp == pq.public_key_fingerprint(recipient_public)
    assert len(fp) == 64
    assert fp != pq.public_key_fingerprint(other)
    pretty = pq.public_key_fingerprint(recipient_public, pretty=True)
    assert pretty.replace(" ", "") == fp and pretty.count(" ") == 15


def test_public_key_text_round_trip(recipient_public):
    text = pq.public_key_to_text(recipient_public)
    same = pq.public_key_from_text("  " + text + " \n")  # pasted with spaces
    assert pq.public_key_fingerprint(same) == pq.public_key_fingerprint(recipient_public)


# =============================================================================
# 6. No silent fallback to ordinary encryption
# =============================================================================
def test_if_ml_kem_is_unavailable_we_stop_instead_of_falling_back(monkeypatch, recipient_public):
    """Pretend the crypto library cannot do ML-KEM. QShield must refuse, loudly,
    and must NOT go on to encrypt the file some other way."""

    class FakeKeyWithoutMlKem:
        def public_bytes_raw(self):
            return b"\x00" * 1184

        def encapsulate(self):
            raise UnsupportedAlgorithm("ML-KEM is not supported by this build")

    def must_not_be_called(*args, **kwargs):
        raise AssertionError("Fell back to ordinary encryption!")

    monkeypatch.setattr(pq, "MLKEM768PublicKey", FakeKeyWithoutMlKem)
    monkeypatch.setattr(file_crypto, "encrypt_bytes", must_not_be_called)

    with pytest.raises(pq.PostQuantumUnavailableError, match="NOT fall back"):
        pq.encrypt_for_recipient(b"secret", FakeKeyWithoutMlKem())


def test_if_key_generation_is_unavailable_we_stop(monkeypatch):
    class FakeKeyClass:
        @staticmethod
        def generate():
            raise UnsupportedAlgorithm("ML-KEM is not supported by this build")

    monkeypatch.setattr(pq, "MLKEM768PrivateKey", FakeKeyClass)
    with pytest.raises(pq.PostQuantumUnavailableError):
        pq.generate_recipient_keypair()


def test_existing_aes_gcm_module_still_refuses_tampering(recipient_public):
    """The inner layer keeps its own protection: a package is two checks, not one."""
    key = file_crypto.generate_key()
    container = file_crypto.encrypt_bytes(b"x" * 10, key, filename="a.txt")
    damaged = bytearray(container); damaged[-1] ^= 1
    with pytest.raises(DecryptionError):
        file_crypto.decrypt_bytes(bytes(damaged), key)
