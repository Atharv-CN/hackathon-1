"""End-to-end relay key authentication with real ML-KEM-768 (needs a recent `cryptography`).

Includes the ORIGINAL ATTACK: before the fix a relay-supplied key was used as-is.
"""

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")

import base64

from core import identity
from core.identity import KeyAuthError
from core.pq_transfer import PUBLIC_KEY_SIZE, public_key_to_bytes, public_key_from_text
from core.transfer_flow import (
    create_identity_bundle,
    create_recipient_key_bundle,
    decrypt_uploaded_package,
    encrypt_for_verified_key,
    encrypt_uploaded_file,
    open_identity_bundle,
    sign_key_bundle,
)
from core.key_directory import fetch_authenticated_receiver_key
from core.trust_store import TrustStore
from tests.test_key_authentication import FakeRelay

DATA = b"qshield-demo-test-file-not-real-secrets\n"


def test_kem_key_size_constant_matches_pq_transfer():
    assert identity.KEM_PUBLIC_KEY_SIZE == PUBLIC_KEY_SIZE


def test_original_attack_succeeded_before_the_fix_and_fails_now():
    victim_keys = create_recipient_key_bundle("victim-pw")
    victim_id = create_identity_bundle("id-pw")
    attacker_keys = create_recipient_key_bundle("attacker-pw")
    attacker_id = create_identity_bundle("atk-pw")

    # BEFORE: the old flow encrypted for whatever key the relay returned.
    relay_returned = attacker_keys.public_text            # malicious relay swaps the key
    package = encrypt_uploaded_file(DATA, "plan.txt", relay_returned)   # still exists, manual path
    assert decrypt_uploaded_package(package, attacker_keys.protected_pem, "attacker-pw").data == DATA  # attacker reads it

    # AFTER: the sender holds the victim's QShield ID; the attacker's bundle cannot satisfy it.
    forged, _ = sign_key_bundle(attacker_id.protected_pem, "atk-pw", attacker_keys.public_text)
    fake = FakeRelay()
    fake.put("code", "keybundle", forged)
    with pytest.raises(KeyAuthError) as info:
        fetch_authenticated_receiver_key("code", victim_id.qshield_id, TrustStore(), relay_get=fake.get)
    assert info.value.code == "bad_signature"


def test_legitimate_register_retrieve_rotate_and_communicate():
    keys = create_recipient_key_bundle("pw")
    ident = create_identity_bundle("id-pw")
    restored = open_identity_bundle(ident.protected_pem, "id-pw")
    assert restored.qshield_id == ident.qshield_id

    fake, store = FakeRelay(), TrustStore()
    envelope, seq = sign_key_bundle(ident.protected_pem, "id-pw", keys.public_text)
    fake.put("c1", "keybundle", envelope)
    verified = fetch_authenticated_receiver_key("c1", ident.qshield_id, store, relay_get=fake.get)
    package = encrypt_for_verified_key(DATA, "plan.txt", verified)
    assert decrypt_uploaded_package(package, keys.protected_pem, "pw").data == DATA

    # Rotation: new ML-KEM key, higher number, old key revoked.
    new_keys = create_recipient_key_bundle("pw2")
    old_id = identity.key_id_for(public_key_to_bytes(public_key_from_text(keys.public_text)))
    envelope2, seq2 = sign_key_bundle(ident.protected_pem, "id-pw", new_keys.public_text, previous_seq=seq, revoked_key_ids=[old_id])
    fake.put("c2", "keybundle", envelope2)
    rotated = fetch_authenticated_receiver_key("c2", ident.qshield_id, store, relay_get=fake.get)
    assert rotated.rotated and seq2 > seq
    assert decrypt_uploaded_package(encrypt_for_verified_key(DATA, "p", rotated), new_keys.protected_pem, "pw2").data == DATA

    # Old bundle replayed by the relay afterwards is rejected.
    with pytest.raises(KeyAuthError) as info:
        fetch_authenticated_receiver_key("c1", ident.qshield_id, store, relay_get=fake.get)
    assert info.value.code in {"rollback", "revoked"}


def test_only_verified_keys_can_be_used_for_authenticated_encryption():
    keys = create_recipient_key_bundle("pw")
    with pytest.raises(TypeError):
        encrypt_for_verified_key(DATA, "x", public_key_from_text(keys.public_text))
