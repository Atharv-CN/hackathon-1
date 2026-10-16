"""Automated tests for core/signatures.py (hybrid Ed25519 + ML-DSA-65 signatures).

Run them from the qshield folder with:   pytest
"""

import os
import stat
import time

import pytest

from core import signatures as sig
from core.file_crypto import DecryptionError

PASSWORD = "correct horse battery staple"
FAST = sig.MIN_SCRYPT_LOG2_N          # cheapest allowed password hashing, keeps tests quick
MESSAGE = b"the message that gets signed"


@pytest.fixture(scope="module")
def alice():
    return sig.generate_signing_identity()


@pytest.fixture(scope="module")
def bob():
    return sig.generate_signing_identity()


# =============================================================================
# 1. Signing and verifying
# =============================================================================
def test_sign_and_verify_round_trip(alice):
    signature = alice.sign(MESSAGE)
    assert len(signature) == sig.SIGNATURE_SIZES[sig.SIG_SUITE_ED25519_MLDSA65]
    assert alice.public.verify(MESSAGE, signature) is None


def test_empty_and_large_messages(alice):
    for message in (b"", os.urandom(2 * 1024 * 1024)):
        assert alice.public.verify(message, alice.sign(message)) is None


def test_changed_message_is_rejected(alice):
    signature = alice.sign(MESSAGE)
    with pytest.raises(sig.InvalidSignatureError):
        alice.public.verify(MESSAGE + b"!", signature)
    with pytest.raises(sig.InvalidSignatureError):
        alice.public.verify(b"x" + MESSAGE[1:], signature)


def test_signature_from_another_identity_is_rejected(alice, bob):
    with pytest.raises(sig.InvalidSignatureError):
        alice.public.verify(MESSAGE, bob.sign(MESSAGE))


def test_any_single_bit_change_in_the_signature_is_rejected(alice):
    """Covers the Ed25519 half and the ML-DSA half (sampled across the whole thing)."""
    signature = alice.sign(MESSAGE)
    positions = list(range(0, 64)) + list(range(64, len(signature), 37)) + [len(signature) - 1]
    for pos in positions:
        damaged = bytearray(signature)
        damaged[pos] ^= 0x01
        with pytest.raises(sig.InvalidSignatureError):
            alice.public.verify(MESSAGE, bytes(damaged))


def test_wrong_signature_sizes_are_rejected(alice):
    signature = alice.sign(MESSAGE)
    for bad in (b"", signature[:-1], signature + b"\x00", signature[:64], signature[64:]):
        with pytest.raises(sig.InvalidSignatureError):
            alice.public.verify(MESSAGE, bad)


# =============================================================================
# 2. HYBRID: BOTH halves must be valid
# =============================================================================
def test_valid_ed25519_half_alone_is_not_enough(alice):
    signature = alice.sign(MESSAGE)
    ed_half, ml_half = signature[:sig.ED25519_SIGNATURE_SIZE], signature[sig.ED25519_SIGNATURE_SIZE:]
    forged = ed_half + bytes(len(ml_half))                 # real Ed25519, empty ML-DSA
    with pytest.raises(sig.InvalidSignatureError):
        alice.public.verify(MESSAGE, forged)


def test_valid_mldsa_half_alone_is_not_enough(alice):
    signature = alice.sign(MESSAGE)
    ed_half, ml_half = signature[:sig.ED25519_SIGNATURE_SIZE], signature[sig.ED25519_SIGNATURE_SIZE:]
    forged = bytes(len(ed_half)) + ml_half                 # empty Ed25519, real ML-DSA
    with pytest.raises(sig.InvalidSignatureError):
        alice.public.verify(MESSAGE, forged)


def test_halves_from_different_signers_cannot_be_mixed(alice, bob):
    a, b = alice.sign(MESSAGE), bob.sign(MESSAGE)
    cut = sig.ED25519_SIGNATURE_SIZE
    for mixed in (a[:cut] + b[cut:], b[:cut] + a[cut:]):
        for identity in (alice, bob):
            with pytest.raises(sig.InvalidSignatureError):
                identity.public.verify(MESSAGE, mixed)


def test_identity_built_from_two_different_identities_verifies_neither(alice, bob):
    mixed = sig.PublicIdentity(
        alice.public.to_bytes()[6:6 + sig.ED25519_PUBLIC_SIZE],
        bob.public.to_bytes()[6 + sig.ED25519_PUBLIC_SIZE:],
    )
    for signer in (alice, bob):
        with pytest.raises(sig.InvalidSignatureError):
            mixed.verify(MESSAGE, signer.sign(MESSAGE))


def test_no_fallback_when_ml_dsa_is_unavailable(alice, monkeypatch):
    """If the ML-DSA backend stops working, verification must STOP, never pass on Ed25519 alone."""
    from cryptography.exceptions import UnsupportedAlgorithm

    class _NoMlDsa:
        def verify(self, *args, **kwargs):
            raise UnsupportedAlgorithm("ML-DSA unavailable")

    signature = alice.sign(MESSAGE)
    monkeypatch.setattr(alice.public, "_ml_key", _NoMlDsa())
    with pytest.raises(sig.SignatureUnavailableError):
        alice.public.verify(MESSAGE, signature)


def test_building_identities_stops_when_ml_dsa_is_missing(monkeypatch):
    def _missing():
        raise sig.SignatureUnavailableError("no ML-DSA")

    monkeypatch.setattr(sig, "_mldsa_classes", _missing)
    with pytest.raises(sig.SignatureUnavailableError):
        sig.generate_signing_identity()


def test_signature_errors_are_decryption_errors(alice):
    """So existing `except DecryptionError` handlers show a security warning."""
    assert issubclass(sig.SignatureError, DecryptionError)
    with pytest.raises(DecryptionError):
        alice.public.verify(MESSAGE, bytes(sig.SIGNATURE_SIZES[1]))


# =============================================================================
# 3. Public identity: format, fingerprint, text
# =============================================================================
def test_public_identity_has_the_documented_size_and_layout(alice):
    data = alice.public.to_bytes()
    assert len(data) == sig.PUBLIC_IDENTITY_SIZE == 1990
    assert data[:4] == b"QSPK" and data[4] == 1 and data[5] == 1


def test_public_identity_round_trips_as_bytes_and_text(alice):
    assert sig.PublicIdentity.from_bytes(alice.public.to_bytes()) == alice.public
    assert sig.PublicIdentity.from_text(alice.public.to_text()) == alice.public


def test_public_identity_text_tolerates_whitespace_and_line_breaks(alice):
    text = alice.public.to_text()
    wrapped = "\n".join(text[i:i + 60] for i in range(0, len(text), 60))
    assert sig.PublicIdentity.from_text("  " + wrapped + "\n") == alice.public


@pytest.mark.parametrize("bad", ["", "not base64 !!!", "AAAA"])
def test_bad_public_identity_text_is_rejected(bad):
    with pytest.raises(ValueError):
        sig.PublicIdentity.from_text(bad)


def test_public_identity_strict_parsing(alice):
    data = alice.public.to_bytes()
    for bad in (data[:-1], data + b"\x00", b"", data[:100]):
        with pytest.raises(ValueError):
            sig.PublicIdentity.from_bytes(bad)
    with pytest.raises(ValueError):                         # wrong magic
        sig.PublicIdentity.from_bytes(b"XXXX" + data[4:])
    with pytest.raises(ValueError):                         # unknown version
        sig.PublicIdentity.from_bytes(data[:4] + b"\x09" + data[5:])
    with pytest.raises(ValueError):                         # unknown signature suite
        sig.PublicIdentity.from_bytes(data[:5] + b"\x09" + data[6:])


def test_fingerprint_is_stable_and_commits_to_both_keys(alice, bob):
    assert alice.public.fingerprint() == sig.PublicIdentity.from_bytes(alice.public.to_bytes()).fingerprint()
    assert len(alice.public.fingerprint()) == 64
    assert alice.public.fingerprint() != bob.public.fingerprint()
    assert " " in alice.public.fingerprint(pretty=True)
    assert alice.public.fingerprint(pretty=True).replace(" ", "") == alice.public.fingerprint()
    ed_a = alice.public.to_bytes()[6:6 + sig.ED25519_PUBLIC_SIZE]
    ml_a = alice.public.to_bytes()[6 + sig.ED25519_PUBLIC_SIZE:]
    ed_b = bob.public.to_bytes()[6:6 + sig.ED25519_PUBLIC_SIZE]
    ml_b = bob.public.to_bytes()[6 + sig.ED25519_PUBLIC_SIZE:]
    swapped_ed = sig.PublicIdentity(ed_b, ml_a).fingerprint()
    swapped_ml = sig.PublicIdentity(ed_a, ml_b).fingerprint()
    assert len({alice.public.fingerprint(), swapped_ed, swapped_ml}) == 3


def test_fingerprint_pinning_catches_a_swapped_key(alice, bob):
    text = alice.public.to_text()
    pretty = alice.public.fingerprint(pretty=True)
    assert sig.PublicIdentity.from_text(text, expected_fingerprint=pretty) == alice.public
    assert sig.PublicIdentity.from_text(text, expected_fingerprint=pretty.upper()) == alice.public
    with pytest.raises(ValueError, match="fingerprint does not match"):
        sig.PublicIdentity.from_text(text, expected_fingerprint=bob.public.fingerprint())


def test_signing_identity_never_shows_or_pickles_its_private_keys(alice):
    import pickle

    secret = alice._secret_blob()
    assert secret.hex() not in repr(alice) and secret not in repr(alice).encode()
    with pytest.raises(TypeError):
        pickle.dumps(alice)


# =============================================================================
# 4. Password-protected private identity file
# =============================================================================
@pytest.fixture(scope="module")
def protected(alice):
    return sig.signing_identity_to_protected_bytes(alice, PASSWORD, scrypt_log2_n=FAST)


def test_protected_file_round_trip(alice, protected):
    assert len(protected) == sig.PRIVATE_FILE_SIZE
    loaded = sig.load_signing_identity_from_bytes(protected, PASSWORD)
    assert loaded.public == alice.public
    assert alice.public.verify(MESSAGE, loaded.sign(MESSAGE)) is None      # same keys


def test_protected_file_does_not_contain_the_private_keys(alice, protected):
    secret = alice._secret_blob()
    assert secret not in protected
    assert secret[:32] not in protected and secret[32:] not in protected
    for start in range(0, len(secret) - 8 + 1, 4):
        assert secret[start:start + 8] not in protected


def test_each_protected_file_is_different(alice):
    first = sig.signing_identity_to_protected_bytes(alice, PASSWORD, scrypt_log2_n=FAST)
    second = sig.signing_identity_to_protected_bytes(alice, PASSWORD, scrypt_log2_n=FAST)
    assert first != second                                  # fresh salt and nonce each time


def test_wrong_password_is_rejected(protected):
    with pytest.raises(ValueError, match="wrong password"):
        sig.load_signing_identity_from_bytes(protected, "a completely different password")


def test_password_is_normalised_the_same_way_everywhere(alice):
    composed, decomposed = "pass\u00e9word-long-enough", "passe\u0301word-long-enough"
    blob = sig.signing_identity_to_protected_bytes(alice, composed, scrypt_log2_n=FAST)
    assert sig.load_signing_identity_from_bytes(blob, decomposed).public == alice.public


def test_short_or_empty_passwords_are_refused_when_creating(alice):
    for bad in ("", "short", "123456789"):
        with pytest.raises(ValueError):
            sig.signing_identity_to_protected_bytes(alice, bad, scrypt_log2_n=FAST)
    with pytest.raises(TypeError):
        sig.signing_identity_to_protected_bytes(alice, b"bytes-not-text-password", scrypt_log2_n=FAST)


def test_changing_any_header_or_public_part_makes_the_file_fail(protected):
    """The prefix and the public identity are authenticated, so they cannot be edited."""
    header_len = sig._PRIVATE_PREFIX.size + sig.PUBLIC_IDENTITY_SIZE
    positions = list(range(0, sig._PRIVATE_PREFIX.size)) + list(range(sig._PRIVATE_PREFIX.size, header_len, 61))
    for pos in positions:
        damaged = bytearray(protected)
        damaged[pos] ^= 0x01
        with pytest.raises(ValueError):
            sig.load_signing_identity_from_bytes(bytes(damaged), PASSWORD)


def test_changing_the_encrypted_part_makes_the_file_fail(protected):
    start = sig._PRIVATE_PREFIX.size + sig.PUBLIC_IDENTITY_SIZE
    for pos in range(start, len(protected), 9):
        damaged = bytearray(protected)
        damaged[pos] ^= 0x01
        with pytest.raises(ValueError):
            sig.load_signing_identity_from_bytes(bytes(damaged), PASSWORD)


def test_wrong_sizes_and_markers_are_rejected(protected):
    for bad in (b"", protected[:-1], protected + b"\x00"):
        with pytest.raises(ValueError):
            sig.load_signing_identity_from_bytes(bad, PASSWORD)
    with pytest.raises(ValueError):
        sig.load_signing_identity_from_bytes(b"XXXX" + protected[4:], PASSWORD)


def test_hostile_cost_settings_are_refused_before_any_expensive_work(protected):
    """A damaged or hostile file must not be able to demand gigabytes of memory."""
    log2_offset = 6
    for hostile in (31, 30, 25, sig.MAX_SCRYPT_LOG2_N + 1, sig.MIN_SCRYPT_LOG2_N - 1, 0):
        data = bytearray(protected)
        data[log2_offset] = hostile
        started = time.monotonic()
        with pytest.raises(ValueError, match="unsupported"):
            sig.load_signing_identity_from_bytes(bytes(data), PASSWORD)
        assert time.monotonic() - started < 2.0


def test_creating_with_out_of_range_cost_settings_is_refused(alice):
    for bad in (sig.MIN_SCRYPT_LOG2_N - 1, sig.MAX_SCRYPT_LOG2_N + 1):
        with pytest.raises(ValueError):
            sig.signing_identity_to_protected_bytes(alice, PASSWORD, scrypt_log2_n=bad)


def test_public_identity_can_be_read_without_the_password(alice, protected):
    assert sig.read_public_identity_from_protected_bytes(protected) == alice.public
    with pytest.raises(ValueError):
        sig.read_public_identity_from_protected_bytes(b"nope")


def test_file_is_private_and_never_overwritten(alice, tmp_path):
    path = tmp_path / "sub" / "identity.qsk"
    sig.save_signing_identity(alice, path, PASSWORD, scrypt_log2_n=FAST)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sig.load_signing_identity(path, PASSWORD).public == alice.public
    with pytest.raises(FileExistsError):
        sig.save_signing_identity(alice, path, PASSWORD, scrypt_log2_n=FAST)
    sig.save_signing_identity(alice, path, PASSWORD, overwrite=True, scrypt_log2_n=FAST)
    assert sig.load_signing_identity(path, PASSWORD).public == alice.public
