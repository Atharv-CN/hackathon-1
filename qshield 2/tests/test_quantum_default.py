"""Suite-4 and local workflow security regression tests."""

import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM1024PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_1024

from core import file_crypto, pq_transfer as pq
from qshield_local import main


def test_suite4_round_trip_and_key_file():
    key = pq.generate_recipient_keypair(4)
    public = key.public_key()
    assert pq.suite_of(key) == pq.suite_of(public) == 4
    text = pq.public_key_to_text(public)
    assert text.startswith("QS4:")
    assert len(pq.public_key_to_bytes(public)) == 1600
    imported = pq.public_key_from_text(text)
    pem = pq.private_key_to_protected_pem(key, "long password")
    assert pem.count(b"BEGIN ENCRYPTED PRIVATE KEY") == 2
    restored = pq.load_private_key_from_bytes(pem, "long password")
    assert pq.public_key_fingerprint(imported) == pq.public_key_fingerprint(restored.public_key())
    package = pq.encrypt_for_recipient(b"private marker", imported, filename="hidden.txt", padding="padme")
    assert package[:6] == b"QSHK\x01\x04"
    assert b"hidden.txt" not in package and b"private marker" not in package
    assert pq.decrypt_package(package, restored).data == b"private marker"
    with pytest.raises(ValueError):
        pq.load_private_key_from_bytes(pem, "wrong password")


def test_suite4_requires_both_secrets_with_independent_mlkem_decapsulation():
    seed = os.urandom(64)
    key = pq.HybridPrivateKey(pq.X25519PrivateKey.generate(), MLKEM1024PrivateKey.from_seed_bytes(seed))
    package = pq.encrypt_for_recipient(b"combined", key.public_key())
    header = package[:pq.SUITES[4].header_size]
    ciphertext = header[38:]
    _, reference_private = ML_KEM_1024.key_derive(seed)
    pq_secret = ML_KEM_1024.decaps(reference_private, ciphertext[32:])
    x_secret = key.x25519.exchange(X25519PublicKey.from_public_bytes(ciphertext[:32]))

    def derived(material):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=pq.SUITES[4].kdf_label + b"\x00" + header).derive(material)

    inner = package[len(header):]
    assert file_crypto.decrypt_bytes(inner, derived(pq_secret + x_secret)).data == b"combined"
    for partial in (pq_secret, x_secret, pq_secret + bytes(32), bytes(32) + x_secret):
        with pytest.raises(file_crypto.DecryptionError):
            file_crypto.decrypt_bytes(inner, derived(partial))


def test_suite4_rejects_wrong_key_suite_and_tampering():
    key = pq.generate_recipient_keypair(4)
    package = pq.encrypt_for_recipient(b"secret", key.public_key())
    for other_suite in (1, 2, 3):
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(package, pq.generate_recipient_keypair(other_suite))
        downgraded = bytearray(package)
        downgraded[5] = other_suite
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(downgraded, key)
    with pytest.raises(pq.WrongRecipientError):
        pq.decrypt_package(package, pq.generate_recipient_keypair(4))
    for offset in (5, 38, len(package) - 1):
        tampered = bytearray(package)
        tampered[offset] ^= 1
        with pytest.raises(pq.TransferError):
            pq.decrypt_package(tampered, key)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(package[:-1], key)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(package + b"\x00", key)
    low_order = bytearray(package)
    low_order[38:70] = bytes(32)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(low_order, key)


def test_local_cli_requires_verified_fingerprint_and_preserves_output_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "a long unique test password")
    key_file, public_file = tmp_path / "receiver.pem", tmp_path / "receiver.pub"
    main(["keygen", "--private-key", str(key_file), "--public-key", str(public_file)])
    key = pq.load_private_key(key_file, "a long unique test password")
    assert pq.suite_of(key) == 4
    source = tmp_path / "notes.txt"
    source.write_bytes(b"test content")
    package = tmp_path / "delivery.qshield"
    base = ["encrypt", str(source), "--public-key", str(public_file), "--output", str(package)]
    with pytest.raises(SystemExit):
        main(base + ["--fingerprint", "0" * 64])
    assert not package.exists()
    main(base + ["--fingerprint", pq.public_key_fingerprint(key.public_key())])
    assert pq.package_suite(package.read_bytes()) == 4
    out_dir = tmp_path / "opened"
    main(["decrypt", str(package), "--private-key", str(key_file), "--output-dir", str(out_dir)])
    assert (out_dir / "notes.txt").read_bytes() == b"test content"
    damaged = tmp_path / "damaged.qshield"
    data = bytearray(package.read_bytes())
    data[-1] ^= 1
    damaged.write_bytes(data)
    with pytest.raises(SystemExit):
        main(["decrypt", str(damaged), "--private-key", str(key_file), "--output-dir", str(tmp_path / "bad")])
    assert not (tmp_path / "bad" / "notes.txt").exists()
