"""Tests for hidden metadata (file name, size, time) and optional padding.

Run them from the qshield folder with:   pytest
"""

import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import file_crypto as fc
from core import pq_transfer as pq
from core.transfer_flow import (
    create_recipient_key_bundle,
    decrypt_uploaded_package,
    encrypt_uploaded_file,
    package_download_name,
)

NAME = "Quarterly-Salaries-2026-CONFIDENTIAL.xlsx"
YEAR = str(datetime.now(timezone.utc).year).encode()
GOLDEN = Path(__file__).parent / "data" / "golden_container_v2.json"


@pytest.fixture
def key():
    return fc.generate_key()


def _payload(container, key):
    """Open a version-2 container by hand, for inspection."""
    return AESGCM(key).decrypt(container[5:17], container[17:], container[:5])


def _forge(key, payload):
    """Build a validly-encrypted container around ANY payload (what a malicious sender could do)."""
    prefix, nonce = struct.pack(">4sB", b"QSHD", 2), os.urandom(12)
    return prefix + nonce + AESGCM(key).encrypt(nonce, payload, prefix)


def _meta(**fields):
    base = {"filename": "a.txt", "original_size": 3, "created_utc": "2026-01-01T00:00:00+00:00"}
    base.update(fields)
    raw = json.dumps(base).encode()
    return struct.pack(">I", len(raw)) + raw


# =============================================================================
# 1. Name, size and time are not visible
# =============================================================================
@pytest.mark.parametrize("padding", [None, "padme", 4096])
def test_container_shows_no_name_size_or_time(key, padding):
    data = b"SECRET-BODY-" * 1000
    container = fc.encrypt_bytes(data, key, filename=NAME, padding=padding)
    assert container[:5] == b"QSHD\x02"
    for visible_clue in (NAME.encode(), b"Salaries", b".xlsx", b"filename", b"original_size",
                         b"created_utc", YEAR, b"SECRET-BODY"):
        assert visible_clue not in container


def test_name_size_and_time_come_back_after_decryption(key):
    before = datetime.now(timezone.utc).replace(microsecond=0)
    result = fc.decrypt_bytes(fc.encrypt_bytes(b"x" * 1234, key, filename=NAME), key)
    assert result.filename == NAME
    assert result.metadata["original_size"] == 1234
    created = datetime.fromisoformat(result.metadata["created_utc"])
    assert before <= created <= datetime.now(timezone.utc)
    assert result.padding_size == 0


def test_two_files_of_the_same_length_look_alike(key):
    a = fc.encrypt_bytes(b"a" * 500, key, filename="aaaa.txt")
    b = fc.encrypt_bytes(b"b" * 500, key, filename="bbbb.txt")
    assert len(a) == len(b) and a[:5] == b[:5]


@pytest.mark.parametrize("suite", [1, 2, 3])
def test_transfer_package_shows_no_name_size_or_time(suite):
    private = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"BODY" * 5000, private.public_key(), filename=NAME, padding="padme")
    for visible_clue in (NAME.encode(), b"Salaries", b"filename", b"created_utc", YEAR, b"BODY"):
        assert visible_clue not in package
    result = pq.decrypt_package(package, private)
    assert result.filename == NAME and result.data == b"BODY" * 5000


def test_the_download_name_can_hide_the_real_name():
    plain = package_download_name(NAME)
    hidden = package_download_name(NAME, hide_name=True)
    assert plain == NAME + ".qshield"            # old behaviour unchanged by default
    assert hidden.endswith(".qshield") and hidden.startswith("qshield-")
    assert "Salaries" not in hidden and "xlsx" not in hidden
    assert len({package_download_name(NAME, hide_name=True) for _ in range(50)}) == 50


# =============================================================================
# 2. Old (version 1) containers still open
# =============================================================================
def test_legacy_version_1_container_still_opens(key):
    legacy = fc._encrypt_bytes_v1(b"old data", key, filename="old.txt")
    assert legacy[4] == 1 and b"old.txt" in legacy     # v1 really did leak the name
    result = fc.decrypt_bytes(legacy, key)
    assert result.data == b"old data" and result.filename == "old.txt" and result.padding_size == 0


def test_legacy_container_inside_a_package_still_opens():
    """The saved version-1 package (made before this change) must keep opening."""
    import base64
    vector = json.loads((Path(__file__).parent / "data" / "golden_package_v1.json").read_text())
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    private = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"]))
    package = base64.b64decode(vector["package_base64"])
    assert package[pq.HEADER_SIZE + 4] == 1            # inner container version 1
    assert pq.decrypt_package(package, private).data.decode() == vector["plaintext_utf8"]


def test_version_2_golden_container_still_opens():
    """A container saved today must open with future code. If this fails, version 2 was broken."""
    vector = json.loads(GOLDEN.read_text())
    result = fc.decrypt_bytes(bytes.fromhex(vector["container_hex"]), bytes.fromhex(vector["key_hex"]))
    assert result.data.decode() == vector["plaintext_utf8"]
    assert result.filename == vector["filename"]
    assert result.padding_size == vector["padding_size"]


def test_unknown_versions_are_refused(key):
    container = bytearray(fc.encrypt_bytes(b"x", key))
    for bad in (0, 3, 99):
        container[4] = bad
        with pytest.raises(fc.DecryptionError, match="version"):
            fc.decrypt_bytes(bytes(container), key)


# =============================================================================
# 3. Padding
# =============================================================================
def test_padme_rule_properties():
    seen = {}
    for length in list(range(2, 5000)) + list(range(5000, 3_000_000, 997)):
        padded = fc.padme_length(length)
        assert padded >= length
        assert padded <= length * 1.125                    # overhead at most 12.5%
        assert fc.padme_length(padded) == padded           # already-padded sizes stay put
        seen.setdefault(padded, 0)
    assert fc.padme_length(0) == 0 and fc.padme_length(1) == 1
    # Few distinct sizes: far fewer groups than lengths.
    assert len(seen) < 2500


def test_padme_known_values():
    # Worked examples of the published algorithm.
    assert fc.padme_length(9) == 10
    assert fc.padme_length(100) == 104
    assert fc.padme_length(1000) == 1024     # E=9, S=4, 5 low bits cleared
    assert fc.padme_length(1025) == 1088     # E=10, S=4, 6 low bits cleared
    assert fc.padme_length(1088) == 1088


def test_padded_length_options_and_errors():
    assert fc.padded_length(1000, None) == 1000 and fc.padded_length(1000, "none") == 1000
    assert fc.padded_length(1000, 512) == 1024 and fc.padded_length(1024, 512) == 1024
    assert fc.padded_length(0, 512) == 0
    for bad in (0, -5, 2**31, 1.5, "big", True, [4096]):
        with pytest.raises(ValueError):
            fc.padded_length(10, bad)


@pytest.mark.parametrize("padding", ["padme", 1, 100, 4096])
@pytest.mark.parametrize("size", [0, 1, 777, 50_000])
def test_padded_round_trip(key, padding, size):
    data = os.urandom(size)
    container = fc.encrypt_bytes(data, key, filename="f.bin", padding=padding)
    result = fc.decrypt_bytes(container, key)
    assert result.data == data and result.metadata["original_size"] == size
    payload = _payload(container, key)
    assert len(payload) == fc.padded_length(len(payload) - result.padding_size, padding)
    assert result.padding_size == len(payload) - (4 + (struct.unpack(">I", payload[:4])[0]) + size)


def test_padding_makes_different_sizes_look_the_same(key):
    sizes = [1_000, 1_500, 30_000, 65_000]
    lengths = {len(fc.encrypt_bytes(os.urandom(n), key, filename="f.bin", padding=1 << 20)) for n in sizes}
    assert len(lengths) == 1                               # all under 1 MB: one size
    unpadded = {len(fc.encrypt_bytes(os.urandom(n), key, filename="f.bin")) for n in sizes}
    assert len(unpadded) == len(sizes)                     # without padding, every size shows


def test_padding_hides_the_file_name_length_too(key):
    a = fc.encrypt_bytes(b"x" * 100, key, filename="a.txt", padding=4096)
    b = fc.encrypt_bytes(b"x" * 100, key, filename="a-much-longer-file-name-than-before.txt", padding=4096)
    assert len(a) == len(b)


def test_padding_is_encrypted_not_a_visible_run_of_zeros(key):
    container = fc.encrypt_bytes(b"tiny", key, filename="t.txt", padding=1 << 16)
    assert len(container) > 65_000
    assert b"\x00" * 64 not in container
    assert _payload(container, key).endswith(b"\x00" * 60_000)   # zeros exist only INSIDE the encryption


def test_padme_overhead_on_a_real_size(key):
    data = os.urandom(1_000_003)
    container = fc.encrypt_bytes(data, key, filename="f.bin", padding="padme")
    assert len(container) <= (len(data) + 200) * 1.125 + 40


def test_bad_padding_is_refused_before_anything_is_encrypted(key):
    with pytest.raises(ValueError):
        fc.encrypt_bytes(b"x", key, padding="large")
    with pytest.raises(ValueError):
        fc.encrypt_bytes(b"x", key, padding=0)


def test_every_bit_change_is_rejected_with_padding(key):
    container = fc.encrypt_bytes(b"A" * 20, key, filename="r.txt", padding=256)
    for position in range(len(container)):
        for bit in range(8):
            damaged = bytearray(container)
            damaged[position] ^= 1 << bit
            with pytest.raises(fc.DecryptionError):
                fc.decrypt_bytes(bytes(damaged), key)


def test_truncated_and_extended_padded_containers_are_rejected(key):
    container = fc.encrypt_bytes(b"A" * 20, key, filename="r.txt", padding=256)
    for length in range(0, len(container), 7):
        with pytest.raises(fc.DecryptionError):
            fc.decrypt_bytes(container[:length], key)
    with pytest.raises(fc.DecryptionError):
        fc.decrypt_bytes(container + b"\x00", key)


# =============================================================================
# 4. A malicious sender (valid key, bad payload) cannot smuggle things in
# =============================================================================
def test_padding_must_be_all_zeros(key):
    payload = _meta() + b"abc" + b"\x00\x00\x01\x00"
    with pytest.raises(fc.DecryptionError, match="metadata"):
        fc.decrypt_bytes(_forge(key, payload), key)
    assert fc.decrypt_bytes(_forge(key, _meta() + b"abc" + b"\x00" * 4), key).data == b"abc"


@pytest.mark.parametrize("fields", [
    {"original_size": 10},            # claims more data than exists
    {"original_size": -1},
    {"original_size": "3"},
    {"original_size": True},
    {"original_size": 3.0},
])
def test_lying_size_in_the_metadata_is_refused(key, fields):
    with pytest.raises(fc.DecryptionError):
        fc.decrypt_bytes(_forge(key, _meta(**fields) + b"abc"), key)


def test_other_broken_payloads_are_refused(key):
    broken = [
        b"",                                          # no metadata length
        b"\x00\x00",                                  # truncated length field
        struct.pack(">I", 999) + b"{}",               # metadata length past the end
        struct.pack(">I", 2) + b"{}" + b"abc",        # no filename / size keys
        struct.pack(">I", 5) + b"[1,2]"[:5] + b"x",   # not an object
        struct.pack(">I", 3) + b"\xff\xfe\xfd",       # not UTF-8
        struct.pack(">I", fc.MAX_METADATA_SIZE + 1) + b"x" * (fc.MAX_METADATA_SIZE + 1),
    ]
    for payload in broken:
        with pytest.raises(fc.DecryptionError):
            fc.decrypt_bytes(_forge(key, payload), key)


def test_a_malicious_filename_is_still_cleaned(key):
    result = fc.decrypt_bytes(_forge(key, _meta(filename="../../etc/passwd") + b"abc"), key)
    assert result.filename == "passwd"


# =============================================================================
# 5. End to end (packages, app flow, disk)
# =============================================================================
@pytest.mark.parametrize("suite", [1, 2, 3])
@pytest.mark.parametrize("padding", [None, "padme", 1 << 16])
def test_package_round_trip_with_padding(suite, padding):
    private = pq.generate_recipient_keypair(suite)
    data = os.urandom(12_345)
    package = pq.encrypt_for_recipient(data, private.public_key(), filename="photo.jpg", padding=padding)
    result = pq.decrypt_package(package, private)
    assert result.data == data and result.filename == "photo.jpg"


@pytest.mark.parametrize("suite", [1, 2, 3])
def test_padded_packages_of_different_sizes_have_the_same_length(suite):
    private = pq.generate_recipient_keypair(suite)
    lengths = {len(pq.encrypt_for_recipient(os.urandom(n), private.public_key(),
                                            filename="f", padding=1 << 20)) for n in (10, 5_000, 900_000)}
    assert len(lengths) == 1


@pytest.mark.parametrize("suite", [2, 3])
def test_every_bit_change_in_a_padded_package_is_rejected(suite):
    private = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"A" * 20, private.public_key(), filename="r.txt", padding=128)
    for position in range(0, len(package), 3):
        for bit in (0, 5):
            damaged = bytearray(package)
            damaged[position] ^= 1 << bit
            with pytest.raises(pq.TransferError):
                pq.decrypt_package(bytes(damaged), private)


def test_app_flow_with_padding_and_a_hidden_download_name():
    bundle = create_recipient_key_bundle("pw", 2)
    data = b"report body " * 400
    package = encrypt_uploaded_file(data, NAME, bundle.public_text, padding="padme")
    download = package_download_name(NAME, hide_name=True)
    assert NAME not in download and NAME.encode() not in package
    result = decrypt_uploaded_package(package, bundle.protected_pem, "pw")
    assert result.filename == NAME and result.data == data


def test_files_on_disk_with_padding(tmp_path, key):
    source = tmp_path / NAME
    source.write_bytes(os.urandom(3000))
    sealed = fc.encrypt_file(source, tmp_path / "x.qshield", key, padding=1 << 14)
    assert NAME.encode() not in sealed.read_bytes()
    assert len(sealed.read_bytes()) > 1 << 14
    assert fc.decrypt_file(sealed, tmp_path / "out", key).read_bytes() == source.read_bytes()
    assert (tmp_path / "out" / NAME).exists()

    private = pq.generate_recipient_keypair(1)
    package_path = pq.encrypt_file_for_recipient(source, tmp_path / "p.qshield", private.public_key(), padding="padme")
    assert NAME.encode() not in package_path.read_bytes()
    assert pq.decrypt_package_file(package_path, tmp_path / "out2", private).name == NAME
