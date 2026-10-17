"""Automated tests for core/signed_transfer.py (hybrid-signed, ML-KEM-encrypted packages).

Run them from the qshield folder with:   pytest

Several tests play the ATTACKER. Where the attacker is a recipient (who legitimately
holds the AES key), the helpers below open and re-seal a package the way such an
attacker could. That shows what the signature protects even then.
"""

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import pq_transfer as pq
from core import signatures as sig
from core import signed_transfer as st
from core.file_crypto import DecryptionError

SECRET = b"SUPER-SECRET-MARKER-12345 " * 10
NOW = 1_800_000_000
GOLDEN = Path(__file__).parent / "data" / "golden_signed_package_v2.json"


@pytest.fixture(scope="module")
def alice():          # the real sender
    return sig.generate_signing_identity()


@pytest.fixture(scope="module")
def mallory():        # an attacker with an identity of her own
    return sig.generate_signing_identity()


@pytest.fixture(scope="module")
def other_sender():   # a second, honest, trusted sender
    return sig.generate_signing_identity()


@pytest.fixture
def bob():            # the recipient
    return pq.generate_recipient_keypair()


@pytest.fixture
def carol():          # a different recipient
    return pq.generate_recipient_keypair()


def make(bob, alice, data=SECRET, name="plan.txt", **kwargs):
    return st.sign_and_encrypt(data, bob.public_key(), alice, filename=name, **kwargs)


# ---- attacker toolkit -----------------------------------------------------------
def open_raw(package, recipient):
    """What a RECIPIENT can do: open the package and see the raw parts."""
    header = package[:st.HEADER_SIZE]
    key = st._derive_key(recipient.decapsulate(header[st._PREFIX.size:]), header)
    nonce = package[st.HEADER_SIZE:st.HEADER_SIZE + st.NONCE_SIZE]
    payload = AESGCM(key).decrypt(nonce, package[st.HEADER_SIZE + st.NONCE_SIZE:], header)
    return header, key, st._parse_payload(payload)


def seal_raw(header, key, payload):
    """Encrypt an arbitrary payload under a known header and key (valid AES-GCM, no valid signature)."""
    nonce = os.urandom(st.NONCE_SIZE)
    return header + nonce + AESGCM(key).encrypt(nonce, payload, header)


def rebuild(parsed, **changes):
    fields = dict(sig_suite=parsed.sig_suite, sender_fp=parsed.sender_fp, created_at=parsed.created_at,
                  name=parsed.name, signature=parsed.signature, data=parsed.data)
    fields.update(changes)
    return st._build_payload(**fields)


def signed_package_for(recipient_public, signer, *, claimed_fp=None, name=b"x.txt", data=b"payload",
                       created_at=NOW):
    """Build a package the long way, so a test can choose WHO signs and WHAT is claimed."""
    ss, kem_ct = recipient_public.encapsulate()
    header = st._PREFIX.pack(st.MAGIC, st.VERSION_SIGNED, st.KEM_SUITE,
                             bytes.fromhex(pq.public_key_fingerprint(recipient_public))) + kem_ct
    fp = claimed_fp if claimed_fp is not None else signer.public.fingerprint_bytes()
    tbs = st._build_tbs(signer.public.suite, fp, header, created_at, name, data)
    payload = st._build_payload(signer.public.suite, fp, created_at, name, signer.sign(tbs), data)
    return seal_raw(header, st._derive_key(ss, header), payload), header, st._derive_key(ss, header)


# =============================================================================
# 1. Successful signing, encryption, verification
# =============================================================================
@pytest.mark.parametrize("size", [0, 1, 1000, 1024 * 1024])
def test_round_trip_of_many_sizes(bob, alice, size):
    original = os.urandom(size)
    result = st.decrypt_and_verify(make(bob, alice, original, "data.bin"), bob, alice.public)
    assert result.data == original
    assert result.filename == "data.bin"


def test_result_names_the_verified_sender(bob, alice):
    result = st.decrypt_and_verify(make(bob, alice, created_at=NOW), bob, alice.public)
    assert result.sender == alice.public
    assert result.sender_fingerprint == alice.public.fingerprint()
    assert result.created_at == NOW
    assert len(result.package_id) == 64


def test_works_with_the_real_text_based_flow(bob, alice):
    """The realistic flow: keys and identities travel as text and nothing else is shared."""
    recipient_public = pq.public_key_from_text(pq.public_key_to_text(bob.public_key()))
    trusted = sig.PublicIdentity.from_text(alice.public.to_text(),
                                           expected_fingerprint=alice.public.fingerprint(pretty=True))
    package = st.sign_and_encrypt(SECRET, recipient_public, alice, filename="plan.txt")
    assert st.decrypt_and_verify(package, bob, trusted).data == SECRET


def test_several_trusted_senders_are_supported(bob, alice, other_sender):
    for signer in (alice, other_sender):
        result = st.decrypt_and_verify(make(bob, signer), bob, [alice.public, other_sender.public])
        assert result.sender == signer.public


def test_every_package_is_different_and_has_its_own_id(bob, alice):
    first, second = make(bob, alice), make(bob, alice)
    assert first != second
    ids = {st.decrypt_and_verify(p, bob, alice.public).package_id for p in (first, second)}
    assert len(ids) == 2


def test_package_has_the_documented_layout(bob, alice):
    package = make(bob, alice)
    assert package[:4] == b"QSHK" and package[4] == 2 and package[5] == 1
    assert package[6:38] == bytes.fromhex(pq.public_key_fingerprint(bob.public_key()))
    assert st.HEADER_SIZE == 1126


def test_unicode_file_names_survive(bob, alice):
    result = st.decrypt_and_verify(make(bob, alice, name="r\u00e9sum\u00e9 \u2603.txt"), bob, alice.public)
    assert result.filename == "r\u00e9sum\u00e9 \u2603.txt"


# =============================================================================
# 2. Confidentiality is at least as good as version 1
# =============================================================================
def test_nothing_readable_leaks_into_the_package(bob, alice):
    package = make(bob, alice, SECRET, name="very-secret-name.pdf")
    assert SECRET[:20] not in package
    assert b"very-secret-name" not in package          # v1 left the name readable, v2 hides it
    assert alice.public.fingerprint_bytes() not in package   # sender identity is hidden too
    assert alice.public.to_bytes()[6:6 + 32] not in package


def test_private_keys_never_appear_in_a_package(bob, alice):
    package = make(bob, alice)
    seed = bob.private_bytes_raw()
    assert seed not in package
    secret = alice._secret_blob()
    assert secret[:32] not in package and secret[32:] not in package


def test_a_private_key_is_refused_in_place_of_a_public_key(bob, alice):
    with pytest.raises(TypeError):
        st.sign_and_encrypt(SECRET, bob, alice)
    with pytest.raises(TypeError):
        st.sign_and_encrypt(SECRET, bob.public_key(), alice.public)      # not a SigningIdentity


# =============================================================================
# 3. THE FIX: forged packages are rejected
# =============================================================================
def test_package_from_an_untrusted_sender_is_rejected(bob, alice, mallory):
    """Mallory has Bob's public key and her own identity. Bob only trusts Alice."""
    with pytest.raises(st.UnknownSenderError):
        st.decrypt_and_verify(make(bob, mallory), bob, alice.public)


def test_unsigned_version_1_package_is_refused_not_accepted(bob, alice):
    """Downgrade attack: strip the signature by sending a plain v1 package."""
    v1 = pq.encrypt_for_recipient(SECRET, bob.public_key(), filename="plan.txt")
    with pytest.raises(st.UnsignedPackageError):
        st.decrypt_and_verify(v1, bob, alice.public)


def test_signed_package_does_not_open_through_the_unsigned_v1_function(bob, alice):
    """The old function must never hand out data from a v2 package without checking the signature."""
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(make(bob, alice), bob)


def test_impersonation_claiming_alices_identity_but_signing_with_hers_fails(bob, alice, mallory):
    forged, _, _ = signed_package_for(bob.public_key(), mallory,
                                      claimed_fp=alice.public.fingerprint_bytes())
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(forged, bob, alice.public)


def test_changed_file_content_breaks_the_signature(bob, alice):
    """Even someone who holds the AES key (the recipient!) cannot change the file."""
    header, key, parsed = open_raw(make(bob, alice), bob)
    tampered = seal_raw(header, key, rebuild(parsed, data=parsed.data + b"extra"))
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(tampered, bob, alice.public)
    tampered = seal_raw(header, key, rebuild(parsed, data=b"X" + parsed.data[1:]))
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(tampered, bob, alice.public)


def test_changed_file_name_or_time_breaks_the_signature(bob, alice):
    header, key, parsed = open_raw(make(bob, alice, created_at=NOW), bob)
    for change in (dict(name=b"evil.exe"), dict(created_at=NOW + 1), dict(created_at=0)):
        with pytest.raises(st.InvalidSignatureError):
            st.decrypt_and_verify(seal_raw(header, key, rebuild(parsed, **change)), bob, alice.public)


def test_swapping_the_claimed_sender_to_another_trusted_sender_fails(bob, alice, other_sender):
    header, key, parsed = open_raw(make(bob, alice), bob)
    swapped = seal_raw(header, key, rebuild(parsed, sender_fp=other_sender.public.fingerprint_bytes()))
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(swapped, bob, [alice.public, other_sender.public])


def test_surreptitious_forwarding_is_blocked(bob, carol, alice):
    """Bob receives a signed file from Alice, then re-encrypts it for Carol, keeping Alice's
    signature, so it looks as if Alice sent it to Carol. The signature names the recipient
    package, so Carol rejects it."""
    _, _, parsed = open_raw(make(bob, alice), bob)
    ss, kem_ct = carol.public_key().encapsulate()
    header = st._PREFIX.pack(st.MAGIC, st.VERSION_SIGNED, st.KEM_SUITE,
                             bytes.fromhex(pq.public_key_fingerprint(carol.public_key()))) + kem_ct
    forwarded = seal_raw(header, st._derive_key(ss, header), rebuild(parsed))
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(forwarded, carol, alice.public)


def test_a_signature_cannot_be_moved_into_a_different_package_for_the_same_recipient(bob, alice):
    """Same recipient, new KEM ciphertext: the signed header hash no longer matches."""
    _, _, parsed = open_raw(make(bob, alice), bob)
    ss, kem_ct = bob.public_key().encapsulate()
    header = st._PREFIX.pack(st.MAGIC, st.VERSION_SIGNED, st.KEM_SUITE,
                             bytes.fromhex(pq.public_key_fingerprint(bob.public_key()))) + kem_ct
    moved = seal_raw(header, st._derive_key(ss, header), rebuild(parsed))
    with pytest.raises(st.InvalidSignatureError):
        st.decrypt_and_verify(moved, bob, alice.public)


def test_both_signature_halves_are_required_inside_a_package(bob, alice):
    header, key, parsed = open_raw(make(bob, alice), bob)
    cut = sig.ED25519_SIGNATURE_SIZE
    ed_only = parsed.signature[:cut] + bytes(len(parsed.signature) - cut)
    ml_only = bytes(cut) + parsed.signature[cut:]
    for broken in (ed_only, ml_only, bytes(len(parsed.signature))):
        with pytest.raises(st.InvalidSignatureError):
            st.decrypt_and_verify(seal_raw(header, key, rebuild(parsed, signature=broken)), bob, alice.public)


def test_no_downgrade_to_ed25519_when_ml_dsa_is_unavailable(bob, alice, monkeypatch):
    from cryptography.exceptions import UnsupportedAlgorithm

    class _NoMlDsa:
        def verify(self, *args, **kwargs):
            raise UnsupportedAlgorithm("ML-DSA unavailable")

    package = make(bob, alice)
    monkeypatch.setattr(alice.public, "_ml_key", _NoMlDsa())
    with pytest.raises(sig.SignatureUnavailableError):
        st.decrypt_and_verify(package, bob, alice.public)


def test_unsafe_signed_file_names_are_refused(bob, alice):
    """Alice's signature is genuine, but the name tries to escape the output folder."""
    for bad in (b"../../evil.txt", b"a/b.txt", b"..", b"", b"nul\x00.txt", b"line\nbreak.txt"):
        package, _, _ = signed_package_for(bob.public_key(), alice, name=bad)
        with pytest.raises(pq.TransferError):
            st.decrypt_and_verify(package, bob, alice.public)


def test_file_names_are_cleaned_by_the_sender(bob, alice):
    result = st.decrypt_and_verify(make(bob, alice, name="../../etc/passwd"), bob, alice.public)
    assert result.filename == "passwd"
    with pytest.raises(ValueError):
        make(bob, alice, name="bad\nname.txt")
    with pytest.raises(ValueError):
        make(bob, alice, name="a" * 300)


def test_signed_bytes_depend_on_every_field_and_cannot_be_confused(alice, other_sender):
    """The to-be-signed bytes commit to EVERYTHING that matters, with unambiguous field borders.

    Binding the sender fingerprint (which covers both public keys) also defends against
    "duplicate signature key selection": one signature that verifies under two keys."""
    base = dict(sig_suite=1, sender_fp=alice.public.fingerprint_bytes(), header=b"H" * st.HEADER_SIZE,
                created_at=NOW, name=b"a.txt", data=b"data")
    reference = st._build_tbs(**base)
    changes = dict(
        sig_suite=2,
        sender_fp=other_sender.public.fingerprint_bytes(),
        header=b"G" + b"H" * (st.HEADER_SIZE - 1),
        created_at=NOW + 1,
        name=b"b.txt",
        data=b"Data",
    )
    for field, value in changes.items():
        assert st._build_tbs(**dict(base, **{field: value})) != reference, field
    # Moving a byte between the name and the data must not give the same bytes.
    assert st._build_tbs(**dict(base, name=b"ab", data=b"c")) != st._build_tbs(**dict(base, name=b"a", data=b"bc"))


# =============================================================================
# 4. Damage, wrong keys, truncation
# =============================================================================
def test_changing_any_single_bit_anywhere_in_the_package_is_rejected(bob, alice):
    package = make(bob, alice, b"small file", "a.txt")
    for pos in range(len(package)):
        damaged = bytearray(package)
        damaged[pos] ^= 0x01
        with pytest.raises(DecryptionError):
            st.decrypt_and_verify(bytes(damaged), bob, alice.public)


def test_truncated_and_extended_packages_are_rejected(bob, alice):
    package = make(bob, alice)
    for bad in (b"", package[:10], package[:st.HEADER_SIZE], package[:st.HEADER_SIZE + 20],
                package[:-1], package + b"\x00", package[:len(package) // 2]):
        with pytest.raises(DecryptionError):
            st.decrypt_and_verify(bad, bob, alice.public)


def test_wrong_recipient_cannot_open_it(bob, carol, alice):
    with pytest.raises(st.WrongRecipientError):
        st.decrypt_and_verify(make(bob, alice), carol, alice.public)


def test_a_forged_recipient_label_still_cannot_open_it(bob, carol, alice):
    package = bytearray(make(bob, alice))
    package[6:38] = bytes.fromhex(pq.public_key_fingerprint(carol.public_key()))
    with pytest.raises(DecryptionError):
        st.decrypt_and_verify(bytes(package), carol, alice.public)


def test_unknown_version_suite_and_marker_are_rejected(bob, alice):
    package = make(bob, alice)
    for index, value in ((4, 3), (4, 0), (5, 2), (5, 0)):
        damaged = bytearray(package)
        damaged[index] = value
        with pytest.raises(pq.TransferError):
            st.decrypt_and_verify(bytes(damaged), bob, alice.public)
    with pytest.raises(pq.TransferError):
        st.decrypt_and_verify(b"XXXX" + package[4:], bob, alice.public)


def test_not_a_package_at_all(bob, alice):
    with pytest.raises(pq.TransferError):
        st.decrypt_and_verify(os.urandom(5000), bob, alice.public)


# =============================================================================
# 5. Required trust settings
# =============================================================================
def test_you_must_say_whom_you_trust(bob, alice):
    package = make(bob, alice)
    with pytest.raises(ValueError):
        st.decrypt_and_verify(package, bob, [])
    with pytest.raises(ValueError):
        st.decrypt_and_verify(package, bob, None)
    with pytest.raises(TypeError):
        st.decrypt_and_verify(package, bob, [alice.public.to_text()])
    with pytest.raises(TypeError):
        st.decrypt_and_verify(package, bob, alice.public.to_text())
    with pytest.raises(TypeError):
        st.decrypt_and_verify(package, bob.public_key(), alice.public)
    with pytest.raises(TypeError):
        st.decrypt_and_verify("not bytes", bob, alice.public)


def test_nothing_is_released_when_any_check_fails(bob, alice, mallory):
    """The error carries no file contents."""
    with pytest.raises(st.UnknownSenderError) as caught:
        st.decrypt_and_verify(make(bob, mallory, SECRET), bob, alice.public)
    assert SECRET[:20] not in str(caught.value).encode()


# =============================================================================
# 6. Freshness (optional replay defence)
# =============================================================================
def test_max_age_accepts_fresh_and_rejects_old_packages(bob, alice):
    package = make(bob, alice, created_at=NOW)
    assert st.decrypt_and_verify(package, bob, alice.public, max_age_seconds=60, now=NOW + 30).data == SECRET
    with pytest.raises(st.StalePackageError):
        st.decrypt_and_verify(package, bob, alice.public, max_age_seconds=60, now=NOW + 61)


def test_packages_dated_in_the_future_are_rejected(bob, alice):
    package = make(bob, alice, created_at=NOW + 3600)
    with pytest.raises(st.StalePackageError):
        st.decrypt_and_verify(package, bob, alice.public, max_age_seconds=60, now=NOW)
    small_skew = make(bob, alice, created_at=NOW + 100)
    assert st.decrypt_and_verify(small_skew, bob, alice.public, max_age_seconds=60, now=NOW).data == SECRET


def test_age_is_not_checked_unless_asked(bob, alice):
    old = make(bob, alice, created_at=1)
    assert st.decrypt_and_verify(old, bob, alice.public).created_at == 1


# =============================================================================
# 7. Files on disk
# =============================================================================
def test_file_round_trip_never_overwrites(bob, alice, tmp_path):
    source = tmp_path / "report.txt"
    source.write_bytes(SECRET)
    package_path = st.sign_and_encrypt_file(source, tmp_path / "report.txt.qshield", bob.public_key(), alice)
    with pytest.raises(FileExistsError):
        st.sign_and_encrypt_file(source, package_path, bob.public_key(), alice)
    out_dir = tmp_path / "out"
    opened = st.decrypt_and_verify_file(package_path, out_dir, bob, alice.public)
    assert opened.read_bytes() == SECRET and opened.name == "report.txt"
    with pytest.raises(FileExistsError):
        st.decrypt_and_verify_file(package_path, out_dir, bob, alice.public)


def test_nothing_is_written_when_verification_fails(bob, alice, mallory, tmp_path):
    package_path = tmp_path / "bad.qshield"
    package_path.write_bytes(make(bob, mallory))
    out_dir = tmp_path / "out"
    with pytest.raises(st.UnknownSenderError):
        st.decrypt_and_verify_file(package_path, out_dir, bob, alice.public)
    assert not out_dir.exists() or not any(out_dir.iterdir())


# =============================================================================
# 7b. The helpers the app (or any other software) calls
# =============================================================================
def test_helper_flow_from_keys_to_verified_file():
    from core import transfer_flow as flow

    receiver = flow.create_recipient_key_bundle("receiver password 123")
    sender = flow.create_sender_identity_bundle("sender password 4567")
    assert b"ENCRYPTED PRIVATE KEY" in receiver.protected_pem
    assert sender.protected_file.startswith(b"QSSK")

    trusted = flow.trusted_sender_from_text(sender.public_text, expected_fingerprint=sender.fingerprint_pretty)
    package = flow.sign_and_encrypt_uploaded_file(
        SECRET, "plan.txt", receiver.public_text, sender.protected_file, "sender password 4567")
    result = flow.verify_uploaded_package(package, receiver.protected_pem, "receiver password 123", trusted)
    assert result.data == SECRET and result.filename == "plan.txt"
    assert result.sender_fingerprint == sender.fingerprint


def test_helper_flow_rejects_wrong_passwords_and_unsigned_packages():
    from core import transfer_flow as flow

    receiver = flow.create_recipient_key_bundle("receiver password 123")
    sender = flow.create_sender_identity_bundle("sender password 4567")
    trusted = flow.trusted_sender_from_text(sender.public_text)

    with pytest.raises(ValueError):          # wrong password for the sender's identity file
        flow.sign_and_encrypt_uploaded_file(SECRET, "a.txt", receiver.public_text,
                                            sender.protected_file, "not the right password")
    package = flow.sign_and_encrypt_uploaded_file(SECRET, "a.txt", receiver.public_text,
                                                  sender.protected_file, "sender password 4567")
    with pytest.raises(ValueError):          # wrong password for the receiver's key
        flow.verify_uploaded_package(package, receiver.protected_pem, "wrong password", trusted)

    unsigned = flow.encrypt_uploaded_file(SECRET, "a.txt", receiver.public_text)     # the old, v1 flow
    with pytest.raises(st.UnsignedPackageError):
        flow.verify_uploaded_package(unsigned, receiver.protected_pem, "receiver password 123", trusted)


def test_helper_flow_catches_a_swapped_sender_key():
    from core import transfer_flow as flow

    real = flow.create_sender_identity_bundle("sender password 4567")
    attacker = flow.create_sender_identity_bundle("attacker password 89")
    with pytest.raises(ValueError, match="fingerprint does not match"):
        flow.trusted_sender_from_text(attacker.public_text, expected_fingerprint=real.fingerprint_pretty)


# =============================================================================
# 8. Format 2 is frozen: a saved package must keep opening
# =============================================================================
def test_version_2_golden_package_still_opens():
    """Created once with tests/make_golden_signed_v2.py. Its keys are PUBLIC test keys."""
    if not GOLDEN.exists():
        pytest.skip("Run `python tests/make_golden_signed_v2.py` once and commit the JSON file it writes.")
    vector = json.loads(GOLDEN.read_text())
    recipient = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(vector["recipient_private_key_seed_hex"]))
    sender_public = sig.PublicIdentity.from_bytes(bytes.fromhex(vector["sender_public_identity_hex"]))
    package = bytes.fromhex(vector["package_hex"])
    result = st.decrypt_and_verify(package, recipient, sender_public)
    assert result.data == vector["plaintext_utf8"].encode()
    assert result.filename == vector["filename"]
    assert result.created_at == vector["created_at"]
    assert result.sender_fingerprint == vector["sender_fingerprint"]
