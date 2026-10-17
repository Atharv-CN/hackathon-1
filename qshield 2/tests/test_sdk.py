"""Integration tests for the public device-local SDK."""

import os

import pytest

from core import pq_transfer as pq
from qshield_sdk import create_keys, decrypt_file, encrypt_file, get_fingerprint


def test_sdk_two_program_file_flow_and_tamper_rejection(tmp_path):
    keys = create_keys(tmp_path / "receiver.pem", tmp_path / "receiver.pub", "unique test password")
    assert keys.suite == 4
    assert keys.public_key_text.startswith("QS4:")
    assert keys.public_key_path.read_text().strip() == keys.public_key_text
    assert get_fingerprint(keys.public_key_text) == keys.fingerprint
    if os.name == "posix":
        assert keys.private_key_path.stat().st_mode & 0o777 == 0o600

    original = tmp_path / "confidential.txt"
    original.write_bytes(b"QShield SDK test data")
    package = tmp_path / "delivery.qshield"
    pasted_key = keys.public_key_path.read_text()
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        encrypt_file(original, package, pasted_key, expected_fingerprint="0" * 64)
    assert not package.exists()
    with pytest.raises(ValueError, match="full 64-digit"):
        encrypt_file(original, package, pasted_key, expected_fingerprint=keys.fingerprint[:16])
    assert not package.exists()

    encrypt_file(original, package, pasted_key,
                 expected_fingerprint=get_fingerprint(pasted_key, pretty=True))
    assert pq.package_suite(package.read_bytes()) == 4
    assert b"confidential.txt" not in package.read_bytes()
    with pytest.raises(FileExistsError):
        encrypt_file(original, package, pasted_key, expected_fingerprint=keys.fingerprint)
    output = decrypt_file(package, keys.private_key_path, "unique test password", tmp_path / "recovered")
    assert output.read_bytes() == original.read_bytes()

    damaged = bytearray(package.read_bytes())
    damaged[-1] ^= 1
    (tmp_path / "damaged.qshield").write_bytes(damaged)
    with pytest.raises(pq.TransferError):
        decrypt_file(tmp_path / "damaged.qshield", keys.private_key_path,
                     "unique test password", tmp_path / "failed")
    assert not (tmp_path / "failed" / original.name).exists()


def test_sdk_requires_explicit_legacy_choice(tmp_path):
    with pytest.raises(ValueError, match="allow_legacy"):
        create_keys(tmp_path / "old.pem", tmp_path / "old.pub", "password", suite=1)
    assert not (tmp_path / "old.pem").exists()

    old = create_keys(tmp_path / "old.pem", tmp_path / "old.pub", "password",
                      suite=1, allow_legacy=True)
    sample = tmp_path / "sample.txt"
    sample.write_text("compatibility")
    package = tmp_path / "old.qshield"
    with pytest.raises(ValueError, match="allow_legacy"):
        encrypt_file(sample, package, old.public_key_text, expected_fingerprint=old.fingerprint)
    assert not package.exists()
    encrypt_file(sample, package, old.public_key_text,
                 expected_fingerprint=old.fingerprint, allow_legacy=True)
    assert package.read_bytes()[4:6] == b"\x01\x01"  # padded v1, not metadata-leaking stream
    assert decrypt_file(package, old.private_key_path, "password", tmp_path / "out").read_text() == "compatibility"


def test_sdk_never_overwrites_key_files_or_recovered_file(tmp_path):
    first = create_keys(tmp_path / "receiver.pem", tmp_path / "receiver.pub", "password")
    with pytest.raises(FileExistsError):
        create_keys(first.private_key_path, tmp_path / "other.pub", "password")
    with pytest.raises(FileExistsError):
        create_keys(tmp_path / "other.pem", first.public_key_path, "password")
    assert not (tmp_path / "other.pem").exists()

    source = tmp_path / "source.txt"
    source.write_text("first")
    package = tmp_path / "p.qshield"
    encrypt_file(source, package, first.public_key_text, expected_fingerprint=first.fingerprint)
    recovered = decrypt_file(package, first.private_key_path, "password", tmp_path / "out")
    recovered.write_text("existing file")
    with pytest.raises(FileExistsError):
        decrypt_file(package, first.private_key_path, "password", tmp_path / "out")
    assert recovered.read_text() == "existing file"
