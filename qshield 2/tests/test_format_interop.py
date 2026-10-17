"""Tests that the package formats from the different features coexist safely.

QShield now has four package shapes that all start with the marker "QSHK":
  version 1, suites 1-3   whole-file packages (hybrid, ML-KEM-1024, padding, hidden metadata)
  version 2, suite 2      STREAMING packages (ML-KEM-768 only, bounded memory)
  version 2, suite 1      SIGNED packages (core/signed_transfer.py)
Each reader must open its own kind and refuse the others cleanly, never mis-parse them.

Run from the qshield folder with:   pytest
"""

import io
import os
import struct

import pytest

from core import pq_transfer as pq
from core import signatures, signed_transfer
from core.file_crypto import DecryptionError

DATA = os.urandom(20_000)


@pytest.fixture(scope="module")
def sender_identity():
    return signatures.generate_signing_identity()


def _stream_package(private_key, data=DATA, name="s.bin"):
    out = io.BytesIO()
    pq.encrypt_stream_for_recipient(io.BytesIO(data), out, private_key.public_key(), name, size=len(data))
    return out.getvalue()


# =============================================================================
# 1. The three version-2/1 shapes are told apart and refuse each other
# =============================================================================
def test_header_bytes_of_each_format():
    key = pq.generate_recipient_keypair(1)
    v1 = pq.encrypt_for_recipient(b"x", key.public_key())
    stream = _stream_package(key)
    assert (v1[4], v1[5]) == (1, 1)
    assert (stream[4], stream[5]) == (2, 2)
    ident = signatures.generate_signing_identity()
    signed = signed_transfer.sign_and_encrypt(b"x", key.public_key(), ident, filename="a.txt")
    assert (signed[4], signed[5]) == (2, 1)       # same version byte as streaming, different suite byte


def test_signed_package_is_refused_by_the_plain_readers(sender_identity):
    key = pq.generate_recipient_keypair(1)
    signed = signed_transfer.sign_and_encrypt(DATA, key.public_key(), sender_identity, filename="a.txt")
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(signed, key)
    with pytest.raises(pq.TransferError):
        pq.package_suite(signed)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package_stream(io.BytesIO(signed), io.BytesIO(), key)


def test_signed_package_file_is_refused_by_decrypt_package_file(tmp_path, sender_identity):
    key = pq.generate_recipient_keypair(1)
    path = tmp_path / "signed.qshield"
    path.write_bytes(signed_transfer.sign_and_encrypt(DATA, key.public_key(), sender_identity, filename="a.txt"))
    with pytest.raises(pq.TransferError):
        pq.decrypt_package_file(path, tmp_path / "out", key)
    assert not (tmp_path / "out").exists() or list((tmp_path / "out").iterdir()) == []


def test_streaming_and_plain_packages_are_refused_by_the_signed_reader(sender_identity):
    key = pq.generate_recipient_keypair(1)
    trusted = [sender_identity.public]
    for package in (_stream_package(key), pq.encrypt_for_recipient(DATA, key.public_key())):
        with pytest.raises(DecryptionError):
            signed_transfer.decrypt_and_verify(package, key, trusted)


def test_signed_and_streaming_packages_with_the_version_byte_swapped_do_not_open(sender_identity):
    key = pq.generate_recipient_keypair(1)
    signed = bytearray(signed_transfer.sign_and_encrypt(b"hello", key.public_key(), sender_identity, filename="a.txt"))
    stream = bytearray(_stream_package(key, b"hello"))
    signed[5] = 2     # pretend the signed package is a streaming one
    stream[5] = 1     # pretend the streaming package is a signed one
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(signed), key)
    with pytest.raises(DecryptionError):
        signed_transfer.decrypt_and_verify(bytes(stream), key, [sender_identity.public])


def test_package_suite_reports_the_key_a_package_needs():
    keys = {s: pq.generate_recipient_keypair(s) for s in (1, 2, 3)}
    for suite, key in keys.items():
        assert pq.package_suite(pq.encrypt_for_recipient(b"x", key.public_key())) == suite
    assert pq.package_suite(_stream_package(keys[1])) == 1      # streaming packages need an ML-KEM-768 key


# =============================================================================
# 2. Streaming packages and the other suites
# =============================================================================
def test_streaming_package_opens_in_memory_with_a_suite_1_key():
    key = pq.generate_recipient_keypair(1)
    result = pq.decrypt_package(_stream_package(key), key)
    assert result.data == DATA and result.filename == "s.bin"


@pytest.mark.parametrize("suite", [2, 3])
def test_streaming_package_is_refused_by_keys_of_other_suites(suite):
    stream = _stream_package(pq.generate_recipient_keypair(1))
    with pytest.raises(pq.TransferError, match="suite"):
        pq.decrypt_package(stream, pq.generate_recipient_keypair(suite))


def test_streaming_package_for_the_wrong_suite_1_key_is_a_wrong_recipient():
    stream = _stream_package(pq.generate_recipient_keypair(1))
    with pytest.raises(pq.WrongRecipientError):
        pq.decrypt_package(stream, pq.generate_recipient_keypair(1))


@pytest.mark.parametrize("suite", [2, 3])
def test_streaming_encryption_refuses_keys_of_other_suites(suite):
    key = pq.generate_recipient_keypair(suite)
    with pytest.raises(TypeError):
        pq.encrypt_stream_for_recipient(io.BytesIO(b"x"), io.BytesIO(), key.public_key(), "a")


# =============================================================================
# 3. encrypt_file_for_recipient picks the right format
# =============================================================================
def _version_byte(path):
    return path.read_bytes()[4]


def test_files_for_suite_1_keys_use_streaming_by_default(tmp_path):
    key = pq.generate_recipient_keypair(1)
    (tmp_path / "f.bin").write_bytes(DATA)
    out = pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "f.qshield", key.public_key())
    assert _version_byte(out) == 2
    assert pq.decrypt_package_file(out, tmp_path / "o", key).read_bytes() == DATA


@pytest.mark.parametrize("suite", [2, 3])
def test_files_for_hybrid_and_1024_keys_use_version_1_and_round_trip(tmp_path, suite):
    key = pq.generate_recipient_keypair(suite)
    (tmp_path / "f.bin").write_bytes(DATA)
    out = pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "f.qshield", key.public_key())
    assert _version_byte(out) == 1 and out.read_bytes()[5] == suite
    assert pq.decrypt_package_file(out, tmp_path / "o", key).read_bytes() == DATA


@pytest.mark.parametrize("padding", ["padme", 4096])
def test_padding_selects_version_1_and_hides_the_name(tmp_path, padding):
    key = pq.generate_recipient_keypair(1)
    (tmp_path / "Salaries-2026.xlsx").write_bytes(DATA)
    out = pq.encrypt_file_for_recipient(tmp_path / "Salaries-2026.xlsx", tmp_path / "p.qshield",
                                        key.public_key(), padding=padding)
    assert _version_byte(out) == 1
    assert b"Salaries" not in out.read_bytes()
    assert pq.decrypt_package_file(out, tmp_path / "o", key).name == "Salaries-2026.xlsx"


def test_streaming_option_is_checked(tmp_path):
    (tmp_path / "f.bin").write_bytes(DATA)
    hybrid = pq.generate_recipient_keypair(2)
    plain = pq.generate_recipient_keypair(1)
    with pytest.raises(ValueError, match="streaming"):
        pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "a", hybrid.public_key(), streaming=True)
    with pytest.raises(ValueError, match="streaming"):
        pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "b", plain.public_key(),
                                      padding="padme", streaming=True)
    out = pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "c", plain.public_key(), streaming=False)
    assert _version_byte(out) == 1
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def test_existing_output_is_never_replaced_in_any_format(tmp_path):
    (tmp_path / "f.bin").write_bytes(DATA)
    for suite in (1, 2):
        key = pq.generate_recipient_keypair(suite)
        target = tmp_path / f"t{suite}.qshield"
        target.write_bytes(b"PRECIOUS")
        with pytest.raises(FileExistsError):
            pq.encrypt_file_for_recipient(tmp_path / "f.bin", target, key.public_key())
        assert target.read_bytes() == b"PRECIOUS"
        pq.encrypt_file_for_recipient(tmp_path / "f.bin", target, key.public_key(), overwrite=True)
        assert target.read_bytes() != b"PRECIOUS"


def test_no_temporary_files_are_left_behind(tmp_path):
    (tmp_path / "f.bin").write_bytes(DATA)
    for suite in (1, 2, 3):
        key = pq.generate_recipient_keypair(suite)
        pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / f"o{suite}.qshield", key.public_key())
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.bin", "o1.qshield", "o2.qshield", "o3.qshield"]


def test_damaged_version_1_package_file_writes_nothing(tmp_path):
    key = pq.generate_recipient_keypair(2)
    (tmp_path / "f.bin").write_bytes(DATA)
    out = pq.encrypt_file_for_recipient(tmp_path / "f.bin", tmp_path / "f.qshield", key.public_key())
    damaged = bytearray(out.read_bytes())
    damaged[2000] ^= 1
    out.write_bytes(bytes(damaged))
    with pytest.raises(pq.TransferError):
        pq.decrypt_package_file(out, tmp_path / "o", key)
    assert not (tmp_path / "o").exists() or list((tmp_path / "o").iterdir()) == []
