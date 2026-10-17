"""Tests for the three algorithm suites in core/pq_transfer.py.

  suite 1  ML-KEM-768 only (no hybrid)
  suite 2  X25519 + ML-KEM-768, both secrets combined in the HKDF input
  suite 3  ML-KEM-1024 only

Run them from the qshield folder with:   pytest
"""

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM1024PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_1024

from core import file_crypto
from core import pq_transfer as pq
from core.transfer_flow import (
    create_recipient_key_bundle,
    decrypt_uploaded_package,
    encrypt_uploaded_file,
)

SECRET = b"SUPER-SECRET-MARKER-12345 " * 10
GOLDEN = Path(__file__).parent / "data" / "golden_package_v1_suites.json"
ALL_SUITES = [1, 2, 3]
KEM_CT_SIZES = {1: 1088, 2: 1120, 3: 1568}
PUBLIC_SIZES = {1: 1184, 2: 1216, 3: 1568}


def _kdf(label: bytes, ikm: bytes, header: bytes) -> bytes:
    """The documented key derivation, written out independently of the module."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=label + b"\x00" + header).derive(ikm)


# =============================================================================
# Round trips, sizes, labels (all suites)
# =============================================================================
@pytest.mark.parametrize("suite", ALL_SUITES)
@pytest.mark.parametrize("size", [0, 1, 5000])
def test_round_trip(suite, size):
    key = pq.generate_recipient_keypair(suite)
    original = os.urandom(size)
    package = pq.encrypt_for_recipient(original, key.public_key(), filename="d.bin")
    assert pq.decrypt_package(package, key).data == original
    assert pq.package_suite(package) == suite == pq.suite_of(key) == pq.suite_of(key.public_key())


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_sizes_labels_and_header(suite):
    key = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"data", key.public_key())
    assert len(pq.public_key_to_bytes(key.public_key())) == PUBLIC_SIZES[suite]
    assert package[:4] == b"QSHK" and package[4] == 1 and package[5] == suite
    assert pq.SUITES[suite].kem_ciphertext_size == KEM_CT_SIZES[suite]
    assert pq.SUITES[suite].header_size == 38 + KEM_CT_SIZES[suite]
    assert SECRET not in package


def test_default_suite_is_still_ml_kem_768_only():
    """No hybrid unless the receiver asks for it."""
    assert isinstance(pq.generate_recipient_keypair(), MLKEM768PrivateKey)
    assert pq.package_suite(pq.encrypt_for_recipient(b"x", pq.generate_recipient_keypair().public_key())) == 1
    assert pq.public_key_from_text(pq.public_key_to_text(pq.generate_recipient_keypair().public_key())).__class__.__name__ \
        == "MLKEM768PublicKey"


def test_unknown_suite_is_refused_at_key_generation():
    for bad in (0, 5, 255):
        with pytest.raises(ValueError):
            pq.generate_recipient_keypair(bad)


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_kdf_labels_are_different_per_suite(suite):
    labels = {s.kdf_label for s in pq.SUITES.values()}
    assert len(labels) == 4
    assert pq.SUITES[suite].kdf_label.startswith(b"QShield v1: ")


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_fingerprint_covers_the_whole_public_key(suite):
    a, b = pq.generate_recipient_keypair(suite), pq.generate_recipient_keypair(suite)
    assert pq.public_key_fingerprint(a.public_key()) != pq.public_key_fingerprint(b.public_key())
    assert len(pq.public_key_fingerprint(a.public_key())) == 64


def test_hybrid_fingerprint_changes_if_either_half_changes():
    a = pq.generate_recipient_keypair(2)
    other_x = pq.HybridPublicKey(X25519PrivateKey.generate().public_key(), a.mlkem.public_key())
    other_pq = pq.HybridPublicKey(a.x25519.public_key(), MLKEM768PrivateKey.generate().public_key())
    fp = pq.public_key_fingerprint(a.public_key())
    assert fp != pq.public_key_fingerprint(other_x)
    assert fp != pq.public_key_fingerprint(other_pq)


# =============================================================================
# Corruption and wrong keys (suites 2 and 3; suite 1 is covered in test_pq_transfer.py)
# =============================================================================
@pytest.mark.parametrize("suite", [2, 3])
def test_every_single_bit_change_is_rejected(suite):
    key = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"A" * 20, key.public_key(), filename="r.txt")
    for position in range(len(package)):
        for bit in range(8):
            damaged = bytearray(package)
            damaged[position] ^= 1 << bit
            try:
                pq.decrypt_package(bytes(damaged), key)
            except pq.TransferError:
                continue
            pytest.fail(f"suite {suite}: change at byte {position}, bit {bit} was NOT rejected")


@pytest.mark.parametrize("suite", [2, 3])
def test_truncated_and_extended_packages_are_rejected(suite):
    key = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"A" * 20, key.public_key(), filename="r.txt")
    for length in range(len(package)):
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(package[:length], key)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(package + b"\x00", key)


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_wrong_recipient_key_is_rejected(suite):
    key = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(SECRET, key.public_key())
    with pytest.raises(pq.WrongRecipientError, match="different recipient key"):
        pq.decrypt_package(package, pq.generate_recipient_keypair(suite))


@pytest.mark.parametrize("suite", [2, 3])
def test_wrong_key_is_rejected_even_if_the_fingerprint_label_is_forged(suite):
    key = pq.generate_recipient_keypair(suite)
    other = pq.generate_recipient_keypair(suite)
    package = bytearray(pq.encrypt_for_recipient(SECRET, key.public_key()))
    package[6:38] = bytes.fromhex(pq.public_key_fingerprint(other.public_key()))
    with pytest.raises(pq.TransferError) as info:
        pq.decrypt_package(bytes(package), other)
    assert not isinstance(info.value, pq.WrongRecipientError)


@pytest.mark.parametrize("package_suite, key_suite", [(a, b) for a in ALL_SUITES for b in ALL_SUITES if a != b])
def test_a_key_only_opens_packages_of_its_own_suite(package_suite, key_suite):
    package = pq.encrypt_for_recipient(SECRET, pq.generate_recipient_keypair(package_suite).public_key())
    with pytest.raises(pq.TransferError, match="suite"):
        pq.decrypt_package(package, pq.generate_recipient_keypair(key_suite))


@pytest.mark.parametrize("real, claimed", [(2, 1), (2, 3), (3, 1), (3, 2), (1, 2), (1, 3)])
def test_changing_the_suite_label_cannot_downgrade_a_package(real, claimed):
    """An attacker flips the suite byte to make the receiver use another suite. Always refused."""
    key = pq.generate_recipient_keypair(real)
    package = bytearray(pq.encrypt_for_recipient(SECRET, key.public_key()))
    package[5] = claimed
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(package), key)


@pytest.mark.parametrize("suite", [1, 3])
def test_unknown_suite_number_is_refused(suite):
    key = pq.generate_recipient_keypair(suite)
    package = bytearray(pq.encrypt_for_recipient(b"x", key.public_key()))
    for bad in (0, 5, 200):
        package[5] = bad
        with pytest.raises(pq.TransferError, match="suite"):
            pq.decrypt_package(bytes(package), key)


def test_the_sender_side_refuses_private_keys_of_every_suite():
    for suite in ALL_SUITES:
        with pytest.raises(TypeError, match="PUBLIC key"):
            pq.encrypt_for_recipient(b"data", pq.generate_recipient_keypair(suite))


# =============================================================================
# Hybrid (suite 2): both secrets really are combined in the HKDF input
# =============================================================================
def _split_hybrid(package, key):
    header = package[:pq.SUITES[2].header_size]
    inner = package[pq.SUITES[2].header_size:]
    ct = header[38:]
    sender_x_public, pq_ct = ct[:32], ct[32:]
    x_secret = key.x25519.exchange(X25519PublicKey.from_public_bytes(sender_x_public))
    pq_secret = key.mlkem.decapsulate(pq_ct)
    return header, inner, pq_secret, x_secret


def test_hybrid_key_is_hkdf_of_mlkem_secret_then_x25519_secret():
    """Rebuild the AES key by hand: HKDF input = ML-KEM secret (32) + X25519 secret (32)."""
    key = pq.generate_recipient_keypair(2)
    package = pq.encrypt_for_recipient(b"hybrid works", key.public_key(), filename="h.txt")
    header, inner, pq_secret, x_secret = _split_hybrid(package, key)
    assert len(pq_secret) == len(x_secret) == 32

    label = b"QShield v1: X25519 + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"
    aes_key = _kdf(label, pq_secret + x_secret, header)
    assert file_crypto.decrypt_bytes(inner, aes_key).data == b"hybrid works"


def test_hybrid_key_cannot_be_derived_from_only_one_of_the_two_secrets():
    """The point of a hybrid: knowing just ML-KEM's secret, or just X25519's secret, is not enough."""
    key = pq.generate_recipient_keypair(2)
    package = pq.encrypt_for_recipient(b"hybrid works", key.public_key())
    header, inner, pq_secret, x_secret = _split_hybrid(package, key)
    label = pq.SUITES[2].kdf_label
    for partial in (pq_secret, x_secret, x_secret + pq_secret, pq_secret + bytes(32), bytes(32) + x_secret):
        with pytest.raises(file_crypto.DecryptionError):
            file_crypto.decrypt_bytes(inner, _kdf(label, partial, header))


def test_hybrid_needs_both_private_halves():
    """Right ML-KEM half + wrong X25519 half (and the reverse) must not open the package,
    even when the attacker forges the fingerprint label to match their own key."""
    key = pq.generate_recipient_keypair(2)
    package = bytearray(pq.encrypt_for_recipient(SECRET, key.public_key()))
    for forged in (pq.HybridPrivateKey(X25519PrivateKey.generate(), key.mlkem),
                   pq.HybridPrivateKey(key.x25519, MLKEM768PrivateKey.generate())):
        forged_package = bytearray(package)
        forged_package[6:38] = bytes.fromhex(pq.public_key_fingerprint(forged.public_key()))
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(bytes(forged_package), forged)
        with pytest.raises(pq.WrongRecipientError):  # unforged: label gives it away
            pq.decrypt_package(bytes(package), forged)


def test_hybrid_each_package_uses_a_fresh_x25519_sender_key():
    key = pq.generate_recipient_keypair(2)
    a = pq.encrypt_for_recipient(b"x", key.public_key())
    b = pq.encrypt_for_recipient(b"x", key.public_key())
    assert a[38:70] != b[38:70]


def test_hybrid_rejects_a_low_order_x25519_point_cleanly():
    """An all-zero X25519 sender key would give an all-zero secret. It must be refused, not accepted."""
    key = pq.generate_recipient_keypair(2)
    package = bytearray(pq.encrypt_for_recipient(SECRET, key.public_key()))
    package[38:70] = bytes(32)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(package), key)


def test_sender_refuses_a_hybrid_public_key_with_a_low_order_x25519_part():
    key = pq.generate_recipient_keypair(2)
    bad = pq.HybridPublicKey(X25519PublicKey.from_public_bytes(bytes(32)), key.mlkem.public_key())
    with pytest.raises(ValueError):
        pq.encrypt_for_recipient(b"x", bad)


def test_package_contains_no_private_key_material_in_any_suite():
    for suite in ALL_SUITES:
        key = pq.generate_recipient_keypair(suite)
        parts = [key.x25519.private_bytes_raw(), key.mlkem.private_bytes_raw()] if suite == 2 \
            else [key.private_bytes_raw()]
        package = pq.encrypt_for_recipient(SECRET, key.public_key(), filename="plan.txt")
        text = pq.public_key_to_text(key.public_key()).encode()
        for secret in parts:
            for start in range(0, len(secret) - 16 + 1):
                assert secret[start:start + 16] not in package
                assert secret[start:start + 16] not in pq.public_key_to_bytes(key.public_key())
                assert base64.urlsafe_b64encode(secret) not in text


# =============================================================================
# Key text and key files
# =============================================================================
@pytest.mark.parametrize("suite", ALL_SUITES)
def test_public_key_text_round_trip_and_prefix(suite):
    key = pq.generate_recipient_keypair(suite)
    text = pq.public_key_to_text(key.public_key())
    assert text.startswith({1: "", 2: "QS2:", 3: "QS3:"}[suite])
    same = pq.public_key_from_text("  " + text[:20] + "\n" + text[20:] + " ")  # pasted with spaces and a line break
    assert pq.public_key_fingerprint(same) == pq.public_key_fingerprint(key.public_key())
    assert pq.suite_of(same) == suite


def test_suite_1_public_key_text_has_no_prefix_so_old_keys_still_work():
    key = pq.generate_recipient_keypair(1)
    text = pq.public_key_to_text(key.public_key())
    assert text == base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).decode()


def test_bad_public_key_text_is_refused():
    h = pq.generate_recipient_keypair(2).public_key()
    body = pq.public_key_to_text(h)[4:]
    s3 = pq.public_key_to_text(pq.generate_recipient_keypair(3).public_key())[4:]
    for bad in ("QS2:", "QS3:", "QS2:AAAA", "QS9:" + body,
                "QS3:" + body,        # a suite-2 key labelled as suite 3
                "QS2:" + s3,          # a suite-3 key labelled as suite 2
                body,                 # a suite-2 key with its label removed (wrong size for suite 1)
                s3):                  # same for suite 3
        with pytest.raises(ValueError):
            pq.public_key_from_text(bad)


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_protected_pem_round_trip_and_suite_is_read_from_the_file(suite):
    key = pq.generate_recipient_keypair(suite)
    pem = pq.private_key_to_protected_pem(key, "correct horse battery")
    assert pem.count(b"BEGIN ENCRYPTED PRIVATE KEY") == (2 if suite == 2 else 1)
    loaded = pq.load_private_key_from_bytes(pem, "correct horse battery")
    assert pq.suite_of(loaded) == suite
    assert pq.public_key_fingerprint(loaded.public_key()) == pq.public_key_fingerprint(key.public_key())
    package = pq.encrypt_for_recipient(SECRET, key.public_key())
    assert pq.decrypt_package(package, loaded).data == SECRET


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_protected_pem_does_not_contain_raw_private_key_and_needs_the_password(suite):
    key = pq.generate_recipient_keypair(suite)
    pem = pq.private_key_to_protected_pem(key, "right")
    raws = [key.x25519.private_bytes_raw(), key.mlkem.private_bytes_raw()] if suite == 2 else [key.private_bytes_raw()]
    for raw in raws:
        assert raw not in pem and base64.b64encode(raw) not in pem
    with pytest.raises(ValueError):
        pq.load_private_key_from_bytes(pem, "wrong")
    with pytest.raises(ValueError):
        pq.private_key_to_protected_pem(key, "")


def test_hybrid_key_file_that_is_not_exactly_x25519_then_mlkem768_is_refused():
    x, m = X25519PrivateKey.generate(), MLKEM768PrivateKey.generate()
    one = pq._protected_pkcs8
    pw = b"pw"
    for bad in (one(m, pw) + one(x, pw),                         # wrong order
                one(x, pw),                                      # lone X25519 key
                one(x, pw) + one(x, pw),                         # two X25519 keys
                one(x, pw) + one(m, pw) + one(m, pw),            # three blocks
                one(x, pw) + one(m, pw) + one(x, pw)):  # extra block
        with pytest.raises(ValueError):
            pq.load_private_key_from_bytes(bad, "pw")
    # Different passwords on the two halves: refused as "wrong password"
    with pytest.raises(ValueError):
        pq.load_private_key_from_bytes(one(x, b"a") + one(m, b"b"), "a")


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_save_and_load_key_file(tmp_path, suite):
    key = pq.generate_recipient_keypair(suite)
    path = pq.save_private_key(key, tmp_path / "me.key", "pw")
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        pq.save_private_key(key, path, "pw")
    loaded = pq.load_private_key(path, "pw")
    package = pq.encrypt_for_recipient(SECRET, key.public_key())
    assert pq.decrypt_package(package, loaded).data == SECRET


# =============================================================================
# On-disk helpers, the app flow, and "no silent fallback"
# =============================================================================
@pytest.mark.parametrize("suite", ALL_SUITES)
def test_file_round_trip_on_disk(tmp_path, suite):
    key = pq.generate_recipient_keypair(suite)
    original = os.urandom(20_000)
    source = tmp_path / "photo.jpg"
    source.write_bytes(original)
    package_path = pq.encrypt_file_for_recipient(source, tmp_path / "p.qshield", key.public_key())
    assert pq.decrypt_package_file(package_path, tmp_path / "out", key).read_bytes() == original


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_app_flow_for_every_suite(suite):
    bundle = create_recipient_key_bundle("correct horse battery", suite)
    assert bundle.suite == suite and bundle.suite_name == pq.suite_name(suite)
    package = encrypt_uploaded_file(SECRET, "notes.txt", bundle.public_text)
    assert pq.package_suite(package) == suite
    assert SECRET not in package
    result = decrypt_uploaded_package(package, bundle.protected_pem, "correct horse battery")
    assert result.data == SECRET and result.filename == "notes.txt"
    with pytest.raises(ValueError):
        decrypt_uploaded_package(package, bundle.protected_pem, "wrong")


def test_app_flow_default_suite_is_1():
    assert create_recipient_key_bundle("pw").suite == 1


def test_app_refuses_a_key_of_another_suite():
    one = create_recipient_key_bundle("pw", 1)
    two = create_recipient_key_bundle("pw", 2)
    package = encrypt_uploaded_file(SECRET, "n.txt", two.public_text)
    with pytest.raises(pq.TransferError):
        decrypt_uploaded_package(package, one.protected_pem, "pw")


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_if_ml_kem_is_unavailable_we_stop_instead_of_falling_back(monkeypatch, suite):
    key = pq.generate_recipient_keypair(suite)
    package = pq.encrypt_for_recipient(b"x", key.public_key())

    def unsupported(*args, **kwargs):
        raise UnsupportedAlgorithm("no ML-KEM in this build")

    def must_not_be_called(*args, **kwargs):
        raise AssertionError("Fell back to ordinary encryption!")

    monkeypatch.setattr(file_crypto, "encrypt_bytes", must_not_be_called)
    monkeypatch.setattr(pq, "_encapsulate", unsupported)
    with pytest.raises(pq.PostQuantumUnavailableError, match="NOT fall back"):
        pq.encrypt_for_recipient(b"secret", key.public_key())

    monkeypatch.setattr(pq, "_decapsulate", unsupported)
    with pytest.raises(pq.PostQuantumUnavailableError):
        pq.decrypt_package(package, key)


@pytest.mark.parametrize("suite", [2, 3])
def test_key_generation_stops_if_unavailable(monkeypatch, suite):
    class Fake:
        @staticmethod
        def generate():
            raise UnsupportedAlgorithm("no ML-KEM in this build")

    monkeypatch.setattr(pq, "MLKEM768PrivateKey", Fake)
    monkeypatch.setattr(pq, "MLKEM1024PrivateKey", Fake)
    with pytest.raises(pq.PostQuantumUnavailableError):
        pq.generate_recipient_keypair(suite)


# =============================================================================
# Frozen format and a second opinion
# =============================================================================
def test_version_1_suite_2_and_3_golden_packages_still_open():
    """Packages saved today must open with future code. If this fails, the format changed."""
    vectors = json.loads(GOLDEN.read_text())
    for name, v in vectors.items():
        package = base64.b64decode(v["package_base64"])
        if name == "suite2":
            key = pq.HybridPrivateKey(
                X25519PrivateKey.from_private_bytes(bytes.fromhex(v["x25519_private_hex"])),
                MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(v["mlkem768_seed_hex"])),
            )
        else:
            key = MLKEM1024PrivateKey.from_seed_bytes(bytes.fromhex(v["mlkem1024_seed_hex"]))
        result = pq.decrypt_package(package, key)
        assert pq.package_suite(package) == v["suite"]
        assert result.data.decode() == v["plaintext_utf8"]
        assert result.filename == v["filename"]


def test_suite_3_package_can_be_opened_with_an_independent_ml_kem_1024():
    seed = os.urandom(64)
    key = MLKEM1024PrivateKey.from_seed_bytes(seed)
    reference_public, reference_private = ML_KEM_1024.key_derive(seed)
    assert reference_public == key.public_key().public_bytes_raw()

    package = pq.encrypt_for_recipient(b"opened with a second implementation", key.public_key(), filename="n.txt")
    size = pq.SUITES[3].header_size
    header, inner = package[:size], package[size:]
    shared = ML_KEM_1024.decaps(reference_private, header[38:])
    aes_key = _kdf(b"QShield v1: ML-KEM-1024 + HKDF-SHA256 + AES-256-GCM", shared, header)
    assert file_crypto.decrypt_bytes(inner, aes_key).data == b"opened with a second implementation"


def test_suite_2_mlkem_half_opens_with_independent_ml_kem_768():
    from kyber_py.ml_kem import ML_KEM_768
    seed = os.urandom(64)
    key = pq.HybridPrivateKey(X25519PrivateKey.generate(), MLKEM768PrivateKey.from_seed_bytes(seed))
    package = pq.encrypt_for_recipient(b"hybrid, second opinion", key.public_key())
    size = pq.SUITES[2].header_size
    header, inner = package[:size], package[size:]
    ct = header[38:]
    _, reference_private = ML_KEM_768.key_derive(seed)
    pq_secret = ML_KEM_768.decaps(reference_private, ct[32:])
    x_secret = key.x25519.exchange(X25519PublicKey.from_public_bytes(ct[:32]))
    aes_key = _kdf(pq.SUITES[2].kdf_label, pq_secret + x_secret, header)
    assert file_crypto.decrypt_bytes(inner, aes_key).data == b"hybrid, second opinion"
