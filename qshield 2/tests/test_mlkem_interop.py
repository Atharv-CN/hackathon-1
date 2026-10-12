"""Second opinion on ML-KEM-768.

The app uses the `cryptography` library (OpenSSL) for ML-KEM-768. Here we check it
against a completely separate implementation, `kyber-py` (pure Python, written
from the FIPS 203 document). If the two ever disagree, one of them is wrong and
this file fails loudly.

kyber-py is used ONLY in these tests. It is not part of the app.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

from core import file_crypto
from core import pq_transfer as pq

TRIALS = 25


def test_same_seed_gives_the_same_public_key_in_both_implementations():
    for _ in range(TRIALS):
        seed = os.urandom(64)
        reference_public, _ = ML_KEM_768.key_derive(seed)
        library_public = MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
        assert reference_public == library_public


def test_library_locks_and_the_independent_implementation_unlocks():
    for _ in range(TRIALS):
        seed = os.urandom(64)
        reference_public, reference_private = ML_KEM_768.key_derive(seed)
        secret, ciphertext = MLKEM768PublicKey.from_public_bytes(reference_public).encapsulate()
        assert ML_KEM_768.decaps(reference_private, ciphertext) == secret


def test_independent_implementation_locks_and_the_library_unlocks():
    for _ in range(TRIALS):
        seed = os.urandom(64)
        reference_public, _ = ML_KEM_768.key_derive(seed)
        secret, ciphertext = ML_KEM_768.encaps(reference_public)
        assert MLKEM768PrivateKey.from_seed_bytes(seed).decapsulate(ciphertext) == secret


def test_both_implementations_react_the_same_way_to_a_damaged_ciphertext():
    seed = os.urandom(64)
    reference_public, reference_private = ML_KEM_768.key_derive(seed)
    secret, ciphertext = ML_KEM_768.encaps(reference_public)

    damaged = bytearray(ciphertext)
    damaged[10] ^= 0x04
    from_reference = ML_KEM_768.decaps(reference_private, bytes(damaged))
    from_library = MLKEM768PrivateKey.from_seed_bytes(seed).decapsulate(bytes(damaged))

    assert from_reference == from_library  # same "implicit rejection" value
    assert from_reference != secret        # and not the real secret


def test_a_qshield_package_can_be_opened_using_the_independent_ml_kem():
    """Make a package with QShield, then open its locked box with kyber-py instead
    of the library, derive the key by hand, and read the file. This shows the
    package contains a genuine ML-KEM-768 ciphertext."""
    seed = os.urandom(64)
    private_key = MLKEM768PrivateKey.from_seed_bytes(seed)
    package = pq.encrypt_for_recipient(b"opened with a second implementation", private_key.public_key(),
                                       filename="note.txt")

    header, inner = package[:pq.HEADER_SIZE], package[pq.HEADER_SIZE:]
    _, reference_private = ML_KEM_768.key_derive(seed)
    shared_secret = ML_KEM_768.decaps(reference_private, header[38:])

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QShield v1: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM" + b"\x00" + header,
    ).derive(shared_secret)

    assert file_crypto.decrypt_bytes(inner, aes_key).data == b"opened with a second implementation"
