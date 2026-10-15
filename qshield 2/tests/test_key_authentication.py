"""Adversarial tests for relay public-key authentication (core/identity.py, trust_store.py).

These tests need only Ed25519, not ML-KEM: the KEM public key is treated as 1184 opaque
bytes here. The ML-KEM end-to-end tests are in test_key_authentication_e2e.py.
All keys are generated fresh for the test; there are no real secrets.
"""

import base64
import json
import logging
import os
import stat

import pytest

import relay
from core import identity
from core.identity import KeyAuthError
from core.trust_store import TrustStore, TrustStoreError

NOW = 1_800_000_000


def kem_key(tag: int = 1) -> bytes:
    return bytes([tag]) * identity.KEM_PUBLIC_KEY_SIZE


def make(signer, kem=None, seq=1, now=NOW, **kw):
    return identity.create_key_bundle(signer, kem or kem_key(), seq=seq, now=now, **kw)


def verify(envelope, expected, store=None, now=NOW + 10):
    return identity.verify_key_bundle(envelope, expected, store or TrustStore(), now=now)


def code_of(call):
    with pytest.raises(KeyAuthError) as info:
        call()
    return info.value.code


def unpack(envelope):
    outer = json.loads(envelope)
    return outer, json.loads(base64.urlsafe_b64decode(outer["payload"] + "=="))


def repack(outer, claims):
    raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    outer = dict(outer, payload=base64.urlsafe_b64encode(raw).decode().rstrip("="))
    return json.dumps(outer).encode()


@pytest.fixture
def alice():
    return identity.generate_identity()


@pytest.fixture
def mallory():
    return identity.generate_identity()


# ---- acceptance ---------------------------------------------------------------------
def test_valid_bundle_for_intended_peer_is_accepted(alice):
    result = verify(make(alice), identity.identity_id(alice))
    assert result.kem_public_key == kem_key()
    assert result.identity == identity.identity_id(alice)
    assert result.key_id == identity.key_id_for(kem_key())
    assert result.rotated is False


def test_qshield_id_roundtrip_and_typo_detection(alice):
    qsid = identity.identity_id(alice)
    assert identity.normalize_identity_id(qsid.lower().replace("-", " ")) == qsid
    typo = qsid[:-1] + ("A" if qsid[-1] != "A" else "B")
    assert code_of(lambda: identity.parse_identity_id(typo)) == "invalid_id"
    assert code_of(lambda: identity.parse_identity_id("hello")) == "invalid_id"
    assert code_of(lambda: identity.parse_identity_id(qsid[:20])) == "invalid_id"


# ---- substitution by the relay -----------------------------------------------------------
def test_modified_public_key_is_rejected(alice):
    outer, claims = unpack(make(alice))
    claims["kem_public_key"] = base64.urlsafe_b64encode(kem_key(9)).decode().rstrip("=")
    claims["key_id"] = identity.key_id_for(kem_key(9))
    assert code_of(lambda: verify(repack(outer, claims), identity.identity_id(alice))) == "bad_signature"


def test_modified_identity_is_rejected(alice, mallory):
    outer, claims = unpack(make(alice))
    claims["identity"] = identity.identity_id(mallory)
    assert code_of(lambda: verify(repack(outer, claims), identity.identity_id(alice))) == "bad_signature"


def test_attacker_signs_with_own_key_claiming_victim_identity(alice, mallory):
    forged = make(mallory, kem_key(66))  # names Mallory; relay presents it as Alice's
    assert code_of(lambda: verify(forged, identity.identity_id(alice))) == "bad_signature"
    outer, claims = unpack(forged)
    claims["identity"] = identity.identity_id(alice)
    assert code_of(lambda: verify(repack(outer, claims), identity.identity_id(alice))) == "bad_signature"


def test_relay_cannot_replace_both_bundle_and_verifying_key(alice, mallory):
    """The verifying key comes from the QShield ID the user holds, not from the bundle."""
    attacker_bundle = make(mallory, kem_key(66))
    assert code_of(lambda: verify(attacker_bundle, identity.identity_id(alice))) == "bad_signature"
    # It is only accepted by someone who was (wrongly) given Mallory's ID.
    assert verify(attacker_bundle, identity.identity_id(mallory)).kem_public_key == kem_key(66)


def test_invalid_signature_is_rejected(alice):
    outer, _ = unpack(make(alice))
    sig = bytearray(base64.urlsafe_b64decode(outer["signature"] + "=="))
    sig[0] ^= 1
    outer["signature"] = base64.urlsafe_b64encode(bytes(sig)).decode().rstrip("=")
    assert code_of(lambda: verify(json.dumps(outer).encode(), identity.identity_id(alice))) == "bad_signature"


def test_signature_for_another_domain_is_rejected(alice):
    outer, claims = unpack(make(alice))
    payload = base64.urlsafe_b64decode(outer["payload"] + "==")
    other = alice.sign(b"QShield something else v1\x00" + payload)
    outer["signature"] = base64.urlsafe_b64encode(other).decode().rstrip("=")
    assert code_of(lambda: verify(json.dumps(outer).encode(), identity.identity_id(alice))) == "bad_signature"
    bare = alice.sign(payload)  # no domain at all
    outer["signature"] = base64.urlsafe_b64encode(bare).decode().rstrip("=")
    assert code_of(lambda: verify(json.dumps(outer).encode(), identity.identity_id(alice))) == "bad_signature"


def test_signed_object_with_wrong_purpose_or_type_is_rejected(alice):
    def resign(mutate):
        _, claims = unpack(make(alice))
        mutate(claims)
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        sig = alice.sign(identity.SIGNING_DOMAIN + payload)
        return json.dumps({
            "qshield_key_bundle": 1,
            "payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
            "signature": base64.urlsafe_b64encode(sig).decode().rstrip("="),
        }).encode()

    for mutate in (
        lambda c: c.update(purpose="something-else"),
        lambda c: c.update(typ="other"),
        lambda c: c.update(v=2),
        lambda c: c.update(kem_alg="ML-KEM-1024"),
    ):
        assert code_of(lambda: verify(resign(mutate), identity.identity_id(alice))) == "unsupported"


# ---- malformed / incomplete / time ------------------------------------------------------------
def test_malformed_and_incomplete_bundles_are_rejected(alice):
    qsid = identity.identity_id(alice)
    good = make(alice)
    outer, claims = unpack(good)
    cases = [
        b"", b"{}", b"not json", b"[]", b"null", b"\xff\xfe", b"{" + b"x" * 10,
        b"x" * (identity.MAX_ENVELOPE_BYTES + 1),
        json.dumps({k: v for k, v in outer.items() if k != "signature"}).encode(),
        json.dumps(dict(outer, extra=1)).encode(),
        json.dumps(dict(outer, signature="AAAA")).encode(),
        json.dumps(dict(outer, payload="!!!")).encode(),
    ]
    for bad in cases:
        assert code_of(lambda: verify(bad, qsid)) in {"malformed", "legacy_unsigned"}, bad[:30]


def signed_with_claims(signer, mutate):
    _, claims = unpack(make(signer))
    mutate(claims)
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    sig = signer.sign(identity.SIGNING_DOMAIN + payload)
    return json.dumps({
        "qshield_key_bundle": 1,
        "payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        "signature": base64.urlsafe_b64encode(sig).decode().rstrip("="),
    }).encode()


def test_validly_signed_but_ill_formed_claims_are_rejected(alice):
    qsid = identity.identity_id(alice)
    short_key = base64.urlsafe_b64encode(b"x" * 10).decode().rstrip("=")
    mutations = [
        lambda c: c.pop("seq"),
        lambda c: c.update(extra="x"),
        lambda c: c.update(seq=True),
        lambda c: c.update(seq=0),
        lambda c: c.update(seq="1"),
        lambda c: c.update(seq=1.5),
        lambda c: c.update(kem_public_key=short_key),
        lambda c: c.update(key_id="0" * 64),
        lambda c: c.update(expires_at=c["issued_at"]),
        lambda c: c.update(expires_at=c["issued_at"] + identity.MAX_VALIDITY_SECONDS + 1),
        lambda c: c.update(revoked_key_ids="abc"),
        lambda c: c.update(revoked_key_ids=[c["key_id"]]),
        lambda c: c.update(revoked_key_ids=["short"]),
    ]
    for mutate in mutations:
        assert code_of(lambda: verify(signed_with_claims(alice, mutate), qsid)) == "malformed"


def test_duplicate_json_keys_are_rejected(alice):
    payload = b'{"typ":"a","typ":"qshield-key-bundle"}'
    sig = alice.sign(identity.SIGNING_DOMAIN + payload)
    env = json.dumps({
        "qshield_key_bundle": 1,
        "payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        "signature": base64.urlsafe_b64encode(sig).decode().rstrip("="),
    }).encode()
    assert code_of(lambda: verify(env, identity.identity_id(alice))) == "malformed"


def test_expired_and_future_bundles_are_rejected(alice):
    qsid = identity.identity_id(alice)
    env = make(alice, validity_seconds=100)
    assert verify(env, qsid, now=NOW + 99)
    assert code_of(lambda: verify(env, qsid, now=NOW + 100)) == "expired"
    assert code_of(lambda: verify(env, qsid, now=NOW + 5000)) == "expired"
    assert code_of(lambda: verify(env, qsid, now=NOW - identity.CLOCK_SKEW_SECONDS - 5)) == "not_yet_valid"


# ---- rollback / replay / rotation / revocation ------------------------------------------------
def test_rollback_to_older_bundle_is_rejected(alice):
    qsid, store = identity.identity_id(alice), TrustStore()
    old, new = make(alice, kem_key(1), seq=5), make(alice, kem_key(2), seq=6)
    verify(old, qsid, store)
    verify(new, qsid, store)
    assert code_of(lambda: verify(old, qsid, store)) == "rollback"


def test_same_number_different_key_is_rejected(alice):
    qsid, store = identity.identity_id(alice), TrustStore()
    verify(make(alice, kem_key(1), seq=5), qsid, store)
    assert code_of(lambda: verify(make(alice, kem_key(2), seq=5), qsid, store)) == "equivocation"
    assert verify(make(alice, kem_key(1), seq=5), qsid, store).rotated is False  # idempotent replay of the same bundle


def test_legitimate_rotation_is_accepted_and_reported(alice):
    qsid, store = identity.identity_id(alice), TrustStore()
    first = verify(make(alice, kem_key(1), seq=1), qsid, store)
    second = verify(make(alice, kem_key(2), seq=2), qsid, store)
    assert second.rotated is True and second.previous_key_id == first.key_id
    assert second.kem_public_key == kem_key(2)


def test_revoked_key_is_never_accepted_again(alice):
    qsid, store = identity.identity_id(alice), TrustStore()
    bad_id = identity.key_id_for(kem_key(1))
    verify(make(alice, kem_key(1), seq=1), qsid, store)
    verify(make(alice, kem_key(2), seq=2, revoked_key_ids=[bad_id]), qsid, store)
    # A relay (or attacker holding the leaked old key) re-presents it with a bigger number.
    assert code_of(lambda: verify(make(alice, kem_key(1), seq=9), qsid, store)) == "revoked"
    assert store.get(qsid)["revoked"] == [bad_id]


def test_failed_verification_records_nothing(alice, mallory):
    qsid, store = identity.identity_id(alice), TrustStore()
    code_of(lambda: verify(make(mallory), qsid, store))
    assert store.get(qsid) is None


def test_different_identity_with_same_key_is_not_confused(alice, mallory):
    store = TrustStore()
    verify(make(alice, kem_key(1), seq=50), identity.identity_id(alice), store)
    assert verify(make(mallory, kem_key(1), seq=1), identity.identity_id(mallory), store)  # separate pin


# ---- trust store ---------------------------------------------------------------------------------
def test_trust_store_persists_and_survives_restart(alice, tmp_path):
    path, qsid = tmp_path / "trust.json", identity.identity_id(alice)
    verify(make(alice, kem_key(1), seq=7), qsid, TrustStore(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert code_of(lambda: verify(make(alice, kem_key(1), seq=3), qsid, TrustStore(path))) == "rollback"


def test_corrupt_or_tampered_trust_store_fails_closed(tmp_path):
    path = tmp_path / "trust.json"
    for content in (b"garbage", b"{}", b'{"version":1,"contacts":{"x":{"seq":"1"}}}', b'{"version":2,"contacts":{}}'):
        path.write_bytes(content)
        with pytest.raises(TrustStoreError):
            TrustStore(path)


def test_forget_is_explicit_and_resets_memory(alice):
    qsid, store = identity.identity_id(alice), TrustStore()
    verify(make(alice, seq=9), qsid, store)
    store.forget(qsid)
    assert store.get(qsid) is None


# ---- relay path: codes, legacy, downgrade ----------------------------------------------------------
class FakeRelay:
    """Stands in for the untrusted relay. It stores anything and returns anything."""

    def __init__(self):
        self.rows = {}

    def put(self, code, kind, data):
        self.rows[(code, kind)] = data

    def get(self, code, kind):
        data = self.rows.get((code, kind))
        return (data, "name") if data is not None else (None, None)


def fetch(fake, code, expected, store=None):
    from core.key_directory import fetch_authenticated_receiver_key
    return fetch_authenticated_receiver_key(code, expected, store or TrustStore(), relay_get=fake.get, now=NOW + 10)


def test_unknown_short_code_cannot_establish_identity(alice):
    assert code_of(lambda: fetch(FakeRelay(), "nope", identity.identity_id(alice))) == "not_found"


def test_code_without_expected_identity_is_refused():
    assert code_of(lambda: fetch(FakeRelay(), "abc", "")) == "invalid_id"


def test_relay_returning_attacker_bundle_cannot_impersonate_peer(alice, mallory):
    fake = FakeRelay()
    fake.put("c1", "keybundle", make(mallory, kem_key(66)))
    assert code_of(lambda: fetch(fake, "c1", identity.identity_id(alice))) == "bad_signature"


def test_legacy_unsigned_key_cannot_bypass_verification(alice):
    qsid = identity.identity_id(alice)
    raw_key_text = base64.urlsafe_b64encode(kem_key(66)).decode().encode()
    fake = FakeRelay()
    fake.put("c1", "pubkey", raw_key_text)                 # downgrade: old-style kind
    assert code_of(lambda: fetch(fake, "c1", qsid)) == "legacy_unsigned"
    fake.put("c2", "keybundle", raw_key_text)              # raw key smuggled into the new kind
    assert code_of(lambda: fetch(fake, "c2", qsid)) == "legacy_unsigned"
    fake.put("c3", "keybundle", kem_key(66))               # raw bytes
    assert code_of(lambda: fetch(fake, "c3", qsid)) in {"legacy_unsigned", "malformed"}


def test_relay_module_refuses_to_publish_unsigned_keys():
    with pytest.raises(ValueError):
        relay.put("pubkey", b"anything")
    with pytest.raises(ValueError):
        relay.put("bogus", b"x")


# ---- secrets ---------------------------------------------------------------------------------------
def test_no_private_key_material_in_bundles_or_logs(alice, mallory):
    from cryptography.hazmat.primitives import serialization

    secret = alice.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Capture()
    identity.security_log.addHandler(handler)
    identity.security_log.setLevel(logging.DEBUG)
    try:
        env = make(alice)
        code_of(lambda: verify(make(mallory), identity.identity_id(alice)))
        verify(env, identity.identity_id(alice))
    finally:
        identity.security_log.removeHandler(handler)
    blob = env + "\n".join(records).encode()
    assert secret not in blob and base64.urlsafe_b64encode(secret).rstrip(b"=") not in blob
    assert records and all("kem_public_key" not in r for r in records)


def test_identity_key_file_is_password_protected(alice):
    pem = identity.identity_to_protected_pem(alice, "pw")
    assert b"ENCRYPTED PRIVATE KEY" in pem
    assert identity.identity_id(identity.load_identity_from_pem(pem, "pw")) == identity.identity_id(alice)
    with pytest.raises(ValueError):
        identity.load_identity_from_pem(pem, "wrong")
    with pytest.raises(ValueError):
        identity.identity_to_protected_pem(alice, "")
