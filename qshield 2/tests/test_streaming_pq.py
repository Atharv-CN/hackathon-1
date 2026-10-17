"""Tests for streaming recipient packages (version 2): ML-KEM-768 + HKDF-SHA256 + AES-256-GCM STREAM.

Needs a `cryptography` build with ML-KEM. Small segments (256 bytes) make boundaries cheap:
the first segment holds 200 plaintext bytes and every later one 240.
"""

import io
import os
import struct
from pathlib import Path

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto as fc
from core import pq_transfer as pq

SEG = 256
FIRST = SEG - 40 - 16
REST = SEG - 16
SIZES = [0, 1, FIRST - 1, FIRST, FIRST + 1, FIRST + REST, FIRST + REST + 1, FIRST + 5 * REST + 7]


@pytest.fixture
def recipient():
    return pq.generate_recipient_keypair()


def make(data, recipient, seg=SEG, name="f.bin", size="auto"):
    out = io.BytesIO()
    pq.encrypt_stream_for_recipient(io.BytesIO(data), out, recipient.public_key(), name,
                                    size=len(data) if size == "auto" else size, segment_size=seg)
    return out.getvalue()


def open_pkg(blob, recipient):
    sink = io.BytesIO()
    pq.decrypt_package_stream(io.BytesIO(blob), sink, recipient)
    return sink.getvalue()


def refused(blob, recipient, exc=pq.TransferError):
    with pytest.raises(exc):
        open_pkg(blob, recipient)


def parts(blob):
    outer = blob[:pq.HEADER_SIZE]
    mlen = struct.unpack(">I", blob[pq.HEADER_SIZE + 4:pq.HEADER_SIZE + 8])[0]
    env_end = pq.HEADER_SIZE + 8 + mlen
    return outer, blob[pq.HEADER_SIZE:env_end], blob[env_end:env_end + 40], blob[env_end + 40:]


# ============================ round trips ============================
@pytest.mark.parametrize("size", SIZES)
def test_streaming_package_round_trip(recipient, size):
    data = os.urandom(size)
    blob = make(data, recipient)
    assert blob[:4] == b"QSHK" and blob[4] == 2 and blob[5] == 2
    assert open_pkg(blob, recipient) == data


def test_default_segment_size_round_trip(recipient):
    data = os.urandom(3 * 1024 * 1024 + 17)
    out = io.BytesIO()
    pq.encrypt_stream_for_recipient(io.BytesIO(data), out, recipient.public_key(), "big.bin", size=len(data))
    assert open_pkg(out.getvalue(), recipient) == data


def test_bytes_api_opens_version_2_and_version_1_packages(recipient):
    data = os.urandom(1000)
    v2 = make(data, recipient, name="two.bin")
    result = pq.decrypt_package(v2, recipient)
    assert result.data == data and result.filename == "two.bin" and result.metadata["original_size"] == 1000
    v1 = pq.encrypt_for_recipient(data, recipient.public_key(), filename="one.bin")
    assert v1[4] == 1 and pq.decrypt_package(v1, recipient).data == data


def test_sender_needs_only_the_public_key_and_refuses_a_private_key(recipient):
    text = pq.public_key_to_text(recipient.public_key())
    out = io.BytesIO()
    pq.encrypt_stream_for_recipient(io.BytesIO(b"hello"), out, pq.public_key_from_text(text), "h.txt")
    assert open_pkg(out.getvalue(), recipient) == b"hello"
    with pytest.raises(TypeError):
        pq.encrypt_stream_for_recipient(io.BytesIO(b"x"), io.BytesIO(), recipient)


def test_wrong_recipient_is_refused_with_a_clear_error(recipient):
    blob = make(b"secret" * 100, recipient)
    other = pq.generate_recipient_keypair()
    refused(blob, other, pq.WrongRecipientError)


# ============================ key hierarchy ============================
def test_key_hierarchy_matches_the_documentation(recipient):
    """Re-derive by hand: shared secret --HKDF(salt, info = label|0|outer|envelope)--> AES key."""
    data = os.urandom(FIRST + REST + 40)
    blob = make(data, recipient)
    outer, envelope, header, body = parts(blob)
    shared = recipient.decapsulate(outer[pq._PREFIX.size:])
    assert header[0] == 40
    salt, prefix = header[1:33], header[33:]
    info = pq.KDF_LABEL_STREAM + b"\x00" + outer + envelope
    aead = AESGCM(HKDF(hashes.SHA256(), 32, salt, info).derive(shared))
    first, rest = body[:SEG - 40], body[SEG - 40:]
    segs = [first] + [rest[i:i + SEG] for i in range(0, len(rest), SEG)]
    plain = b""
    for i, s in enumerate(segs):
        plain += aead.decrypt(prefix + i.to_bytes(4, "big") + (b"\x01" if i == len(segs) - 1 else b"\x00"), s, None)
    assert plain == data
    assert shared not in blob


# ============================ tampering ============================
def test_every_bit_change_in_header_kem_ciphertext_envelope_and_stream_header_is_refused(recipient):
    blob = make(os.urandom(FIRST + REST + 5), recipient)
    _, envelope, header, _ = parts(blob)
    covered = pq.HEADER_SIZE + len(envelope) + len(header)
    for i in range(covered):            # magic, version, suite, fingerprint, KEM ct, segment size, metadata, salt, prefix
        damaged = bytearray(blob)
        damaged[i] ^= 0x01
        refused(bytes(damaged), recipient, (pq.TransferError, pq.WrongRecipientError))


def test_damaged_kem_ciphertext_is_caught(recipient):
    blob = make(os.urandom(500), recipient)
    for i in (pq._PREFIX.size, pq._PREFIX.size + 500, pq.HEADER_SIZE - 1):
        damaged = bytearray(blob)
        damaged[i] ^= 0x40
        refused(bytes(damaged), recipient)


def test_segment_tampering_removal_reordering_duplication_and_truncation(recipient):
    data = os.urandom(FIRST + 4 * REST + 3)
    blob = make(data, recipient, size=None)   # no declared size: only the AEAD can notice
    outer, envelope, header, body = parts(blob)
    head = outer + envelope + header
    segs = [body[:SEG - 40]] + [body[SEG - 40:][i:i + SEG] for i in range(0, len(body) - (SEG - 40), SEG)]
    assert b"".join(segs) == body
    refused(head + b"".join(segs[:2] + segs[3:]), recipient)
    refused(head + b"".join([segs[0], segs[2], segs[1]] + segs[3:]), recipient)
    refused(head + b"".join(segs[:2] + [segs[1]] + segs[2:]), recipient)
    refused(head + b"".join(segs[:-1]), recipient)
    other = make(data, recipient, size=None)
    refused(head + other[len(head):], recipient)                    # body of another package
    for n in list(range(0, pq.HEADER_SIZE + 60)) + list(range(len(blob) - 3 * SEG, len(blob))):
        refused(blob[:n], recipient)                                # header, KEM ct, envelope, segments, end
    for extra in (b"\x00", os.urandom(16), os.urandom(SEG)):
        refused(blob + extra, recipient)                            # trailing data
    last = bytearray(blob)
    last[-1] ^= 1
    refused(bytes(last), recipient)


def test_unsupported_version_suite_and_invalid_lengths(recipient):
    blob = make(os.urandom(300), recipient)

    def patched(offset, value, fmt):
        b = bytearray(blob)
        struct.pack_into(fmt, b, offset, value)
        return bytes(b)

    refused(patched(4, 3, ">B"), recipient)                         # unknown version
    refused(patched(4, 0, ">B"), recipient)
    refused(patched(5, 1, ">B"), recipient)                         # version 2 with the version 1 suite
    refused(patched(5, 3, ">B"), recipient)
    refused(patched(pq.HEADER_SIZE, 0, ">I"), recipient)            # segment size 0
    refused(patched(pq.HEADER_SIZE, 2**32 - 1, ">I"), recipient)
    refused(patched(pq.HEADER_SIZE + 4, 2**32 - 1, ">I"), recipient)   # metadata length


def test_downgrade_between_version_1_and_2_is_impossible(recipient):
    data = os.urandom(600)
    v2 = bytearray(make(data, recipient))
    v2[4], v2[5] = 1, 1                                             # pretend it is version 1
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(v2), recipient)
    v1 = bytearray(pq.encrypt_for_recipient(data, recipient.public_key(), filename="a"))
    v1[4], v1[5] = 2, 2                                             # pretend a version 1 body is a stream
    with pytest.raises(pq.TransferError):
        pq.decrypt_package(bytes(v1), recipient)
    v1[4], v1[5] = 2, 1
    with pytest.raises(pq.TransferError, match="version"):
        pq.decrypt_package(bytes(v1), recipient)


def test_malformed_metadata_in_a_validly_keyed_package_is_refused(recipient):
    """Even with the right keys, bad metadata (or a size that does not match) is rejected."""
    pub = recipient.public_key()
    shared, kem_ct = pub.encapsulate()
    for meta in (b"not json", b'{"filename":"a","original_size":99}', b'{"filename":5}'):
        outer = pq._PREFIX.pack(pq.MAGIC, 2, 2, pq._fingerprint_bytes(pub)) + kem_ct
        envelope = fc.pack_stream_envelope(SEG, meta)
        out = io.BytesIO(outer + envelope)
        out.seek(0, 2)
        fc.encrypt_stream_body(io.BytesIO(b"hello"), out, shared, pq._stream_context(outer, envelope), SEG)
        refused(out.getvalue(), recipient)


# ============================ files on disk ============================
def leftovers(d: Path):
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_file_round_trip_uses_streaming_and_never_read_bytes(recipient, tmp_path, monkeypatch):
    data = os.urandom(2 * 1024 * 1024 + 99)
    src = tmp_path / "photo.jpg"
    src.write_bytes(data)

    def boom(self):
        raise AssertionError("Path.read_bytes() must not be used by the streaming file workflow")

    monkeypatch.setattr(Path, "read_bytes", boom)
    package = pq.encrypt_file_for_recipient(src, tmp_path / "photo.jpg.qshield", recipient.public_key())
    with open(package, "rb") as f:
        assert f.read(6)[4:] == bytes([2, 2])
    out = pq.decrypt_package_file(package, tmp_path / "out", recipient)
    with open(out, "rb") as f:
        assert f.read() == data
    assert leftovers(tmp_path / "out") == ["photo.jpg"]


def test_file_workflow_opens_legacy_version_1_package_files(recipient, tmp_path):
    data = os.urandom(5000)
    path = tmp_path / "old.qshield"
    path.write_bytes(pq.encrypt_for_recipient(data, recipient.public_key(), filename="old.bin"))
    assert pq.decrypt_package_file(path, tmp_path / "out", recipient).read_bytes() == data


def test_failed_package_file_publishes_nothing_and_keeps_existing_files(recipient, tmp_path):
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(3000))
    package = pq.encrypt_file_for_recipient(src, tmp_path / "doc.qshield", recipient.public_key(), segment_size=SEG)
    good = package.read_bytes()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "doc.txt").write_bytes(b"PRECIOUS")
    damaged = bytearray(good)
    damaged[-2] ^= 1                                                # earlier segments verify; the last does not
    for variant in (bytes(damaged), good[:-SEG], good + b"x"):
        bad = tmp_path / "bad.qshield"
        bad.write_bytes(variant)
        for overwrite in (False, True):
            with pytest.raises(pq.TransferError):
                pq.decrypt_package_file(bad, out_dir, recipient, overwrite=overwrite)
            assert leftovers(out_dir) == ["doc.txt"] and (out_dir / "doc.txt").read_bytes() == b"PRECIOUS"
    other = pq.generate_recipient_keypair()
    with pytest.raises(pq.WrongRecipientError):
        pq.decrypt_package_file(package, out_dir, other)
    assert leftovers(out_dir) == ["doc.txt"]


def test_package_file_no_overwrite_by_default(recipient, tmp_path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"data" * 50)
    target = tmp_path / "a.qshield"
    target.write_bytes(b"IMPORTANT")
    with pytest.raises(FileExistsError):
        pq.encrypt_file_for_recipient(src, target, recipient.public_key())
    assert target.read_bytes() == b"IMPORTANT" and leftovers(tmp_path) == ["a.qshield", "a.txt"]
    pq.encrypt_file_for_recipient(src, target, recipient.public_key(), overwrite=True)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_bytes(b"KEEP")
    with pytest.raises(FileExistsError):
        pq.decrypt_package_file(target, out_dir, recipient)
    assert (out_dir / "a.txt").read_bytes() == b"KEEP" and leftovers(out_dir) == ["a.txt"]


def test_oversized_version_1_package_file_is_refused_without_reading_it(recipient, tmp_path, monkeypatch):
    path = tmp_path / "x.qshield"
    path.write_bytes(b"QSHK\x01\x01" + b"\x00" * 100)
    monkeypatch.setattr(pq, "_LEGACY_MAX_PACKAGE", 10)
    with pytest.raises(pq.TransferError):
        pq.decrypt_package_file(path, tmp_path / "out", recipient)


def test_app_glue_streams_from_an_upload_handle_and_can_make_version_1(recipient):
    from core.transfer_flow import encrypt_stream_to_package
    data = os.urandom(5000)
    handle = io.BytesIO(data)
    v2 = encrypt_stream_to_package(handle, "up.bin", len(data), recipient.public_key())
    v1 = encrypt_stream_to_package(handle, "up.bin", len(data), recipient.public_key(), legacy=True)
    assert v2[4] == 2 and v1[4] == 1
    assert pq.decrypt_package(v2, recipient).data == data == pq.decrypt_package(v1, recipient).data
