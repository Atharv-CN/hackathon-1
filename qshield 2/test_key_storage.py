import json
import os
import stat
import struct

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

import key_storage as ks
from core import pq_transfer as pq

# Small, fast parameters for tests only.
FAST_ARGON = {"m_kib": 64, "t": 1, "p": 1}
FAST_SCRYPT = {"n": 1 << 10, "r": 8, "p": 1}


@pytest.fixture(scope="module")
def key():
    return pq.generate_recipient_keypair()


def _pp(pw="correct horse", kdf="argon2id", params=None):
    return ks.PassphraseProvider(pw, kdf=kdf, params=params or (FAST_ARGON if kdf == "argon2id" else FAST_SCRYPT))


def _same(a, b):
    return a.public_key().public_bytes_raw() == b.public_key().public_bytes_raw()


# ---- KDF correctness ----------------------------------------------------------
def test_argon2id_matches_rfc9106_vector():
    # RFC 9106 section 5.3 (Argon2id): confirms memory_cost is in KiB.
    tag = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32,
                   ad=b"\x04" * 12, secret=b"\x03" * 8).derive(b"\x01" * 32)
    assert tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


# ---- Round trips ---------------------------------------------------------------
@pytest.mark.parametrize("kdf", ["argon2id", "scrypt"])
def test_passphrase_round_trip(key, kdf):
    blob = ks.dumps_private_key(key, _pp(kdf=kdf))
    assert _same(ks.loads_private_key(blob, _pp(kdf=kdf)), key)


def test_default_parameters_round_trip(key):
    p = ks.PassphraseProvider("pw")           # real defaults (64 MiB)
    assert _same(ks.loads_private_key(ks.dumps_private_key(key, p), p), key)


def test_wrong_passphrase_is_refused(key):
    blob = ks.dumps_private_key(key, _pp("right"))
    with pytest.raises(ks.KeyStorageError, match="wrong password"):
        ks.loads_private_key(blob, _pp("wrong"))


def test_empty_passphrase_is_refused(key):
    with pytest.raises(ks.KeyStorageError):
        ks.dumps_private_key(key, ks.PassphraseProvider("", params=FAST_ARGON))


def test_file_does_not_contain_seed_or_public_key_plaintext(key):
    blob = ks.dumps_private_key(key, _pp())
    assert key.private_bytes_raw() not in blob


def test_each_save_uses_fresh_salt_and_nonce(key):
    a, b = ks.dumps_private_key(key, _pp()), ks.dumps_private_key(key, _pp())
    assert a != b


# ---- Header is authenticated ---------------------------------------------------
def _rebuild(blob, mutate):
    magic, ver, hlen = struct.unpack_from(">4sBH", blob, 0)
    off = 7
    header = json.loads(blob[off:off + hlen])
    rest = blob[off + hlen:]
    mutate(header)
    h = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return struct.pack(">4sBH", magic, ver, len(h)) + h + rest


def test_changing_kdf_parameters_breaks_authentication(key):
    blob = ks.dumps_private_key(key, _pp())
    bad = _rebuild(blob, lambda h: h["pp"].__setitem__("t", 2))
    with pytest.raises(ks.KeyStorageError):
        ks.loads_private_key(bad, _pp())


def test_changing_fingerprint_breaks_authentication(key):
    blob = ks.dumps_private_key(key, _pp())
    bad = _rebuild(blob, lambda h: h.__setitem__("fp", "00" * 32))
    with pytest.raises(ks.KeyStorageError):
        ks.loads_private_key(bad, _pp())


def test_flipped_ciphertext_bit_is_refused(key):
    blob = bytearray(ks.dumps_private_key(key, _pp()))
    blob[-1] ^= 1
    with pytest.raises(ks.KeyStorageError):
        ks.loads_private_key(bytes(blob), _pp())


def test_truncated_and_foreign_files_are_refused(key):
    blob = ks.dumps_private_key(key, _pp())
    for bad in (b"", b"QSKF", blob[:20], b"NOPE" + blob[4:]):
        with pytest.raises(ks.KeyStorageError):
            ks.loads_private_key(bad, _pp())


# ---- Hostile parameters are capped ---------------------------------------------
def test_hostile_argon2_memory_is_rejected_before_deriving(key):
    blob = ks.dumps_private_key(key, _pp())
    bad = _rebuild(blob, lambda h: h["pp"].__setitem__("m_kib", 1 << 30))
    with pytest.raises(ks.KeyStorageError, match="allowed range"):
        ks.loads_private_key(bad, _pp())


def test_hostile_scrypt_memory_is_rejected(key):
    blob = ks.dumps_private_key(key, _pp(kdf="scrypt"))
    bad = _rebuild(blob, lambda h: h["pp"].update({"n": 1 << 24, "r": 32}))
    with pytest.raises(ks.KeyStorageError):
        ks.loads_private_key(bad, _pp(kdf="scrypt"))


def test_bad_parameters_are_refused_at_save_time():
    with pytest.raises(ks.KeyStorageError):
        ks.PassphraseProvider("pw", params={"m_kib": 1 << 30, "t": 3, "p": 4})
    with pytest.raises(ks.KeyStorageError):
        ks.PassphraseProvider("pw", kdf="scrypt", params={"n": 1000, "r": 8, "p": 1})


# ---- Provider mismatch ----------------------------------------------------------
def test_wrong_provider_type_is_refused(key):
    blob = ks.dumps_private_key(key, _pp())
    with pytest.raises(ks.KeyStorageError, match="provider"):
        ks.loads_private_key(blob, ks.KeyringProvider(keyring_module=FakeKeyring()))


# ---- Keyring provider (fake backend) ---------------------------------------------
class FakeKeyring:
    def __init__(self):
        self.store = {}

    def set_password(self, service, user, pw):
        self.store[(service, user)] = pw

    def get_password(self, service, user):
        return self.store.get((service, user))


def test_keyring_round_trip_and_missing_entry(key):
    kr = FakeKeyring()
    p = ks.KeyringProvider(keyring_module=kr)
    blob = ks.dumps_private_key(key, p)
    assert _same(ks.loads_private_key(blob, p), key)
    assert len(kr.store) == 1
    kr.store.clear()
    with pytest.raises(ks.KeyStorageError, match="not found"):
        ks.loads_private_key(blob, p)


def test_keychain_entry_is_not_the_private_key(key):
    kr = FakeKeyring()
    ks.dumps_private_key(key, ks.KeyringProvider(keyring_module=kr))
    (stored,) = kr.store.values()
    import base64
    assert base64.b64decode(stored) != key.private_bytes_raw()


# ---- Envelope provider (fake KMS) -------------------------------------------------
class FakeKms:
    """Stands in for a real KMS. Binds the context like an encryption context."""
    wrapper_id = "fake-kms:test"

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aead = AESGCM(os.urandom(32))
        self.contexts = []

    def wrap(self, data_key, context):
        self.contexts.append(context)
        n = os.urandom(12)
        return n + self._aead.encrypt(n, data_key, context)

    def unwrap(self, blob, context):
        return self._aead.decrypt(blob[:12], blob[12:], context)


def test_envelope_round_trip_binds_context(key):
    kms = FakeKms()
    p = ks.EnvelopeProvider(kms)
    blob = ks.dumps_private_key(key, p)
    assert _same(ks.loads_private_key(blob, p), key)
    assert key.public_key() and b"ML-KEM-768" in kms.contexts[0]


def test_envelope_rejects_other_wrapper(key):
    blob = ks.dumps_private_key(key, ks.EnvelopeProvider(FakeKms()))
    other = FakeKms()
    other.wrapper_id = "other"
    with pytest.raises(ks.KeyStorageError, match="different key service"):
        ks.loads_private_key(blob, ks.EnvelopeProvider(other))


# ---- Files on disk ------------------------------------------------------------------
def test_save_and_load_file_with_owner_only_permissions(tmp_path, key):
    path = ks.save_private_key_file(key, tmp_path / "me.qskf", _pp())
    assert _same(ks.load_private_key_file(path, _pp()), key)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_existing_file_is_not_overwritten_unless_asked(tmp_path, key):
    path = tmp_path / "me.qskf"
    ks.save_private_key_file(key, path, _pp())
    with pytest.raises(FileExistsError):
        ks.save_private_key_file(key, path, _pp())
    other = pq.generate_recipient_keypair()
    ks.save_private_key_file(other, path, _pp(), overwrite=True)
    assert _same(ks.load_private_key_file(path, _pp()), other)
    assert [p.name for p in tmp_path.iterdir()] == ["me.qskf"]       # no temp leftovers


# ---- Migration ------------------------------------------------------------------------
def test_legacy_pem_migrates_and_still_decrypts_packages(key):
    legacy = pq.private_key_to_protected_pem(key, "old password")
    assert ks.is_legacy_pem(legacy)
    new_blob = ks.migrate_legacy_pem(legacy, "old password", _pp("new password"))
    assert not ks.is_legacy_pem(new_blob)
    opened = ks.loads_private_key(new_blob, _pp("new password"))
    pkg = pq.encrypt_for_recipient(b"hello", key.public_key(), filename="a.txt")
    assert pq.decrypt_package(pkg, opened).data == b"hello"


def test_migration_with_wrong_old_password_fails(key):
    legacy = pq.private_key_to_protected_pem(key, "old")
    with pytest.raises(ValueError):
        ks.migrate_legacy_pem(legacy, "nope", _pp())
