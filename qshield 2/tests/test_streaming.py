"""Tests for the STREAM (Tink AES-GCM-HKDF style) streaming format in core/file_crypto.py.

These need only AES-GCM and HKDF, not ML-KEM. Small segment sizes (256 bytes) are used so every
boundary case is cheap: with 256-byte segments the first segment holds 200 plaintext bytes
(256 - 40 header - 16 tag) and every later one holds 240.
"""

import hashlib
import io
import os
import queue
import struct
import threading
import tracemalloc
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import file_crypto as fc
from core.file_crypto import DecryptionError

SEG = 256
FIRST = SEG - fc.STREAM_HEADER_SIZE - fc.TAG_SIZE   # 200
REST = SEG - fc.TAG_SIZE                            # 240


def key():
    return fc.generate_key()


def enc(data: bytes, k: bytes, seg: int = SEG, filename="f.bin", size="auto") -> bytes:
    out = io.BytesIO()
    fc.encrypt_stream(io.BytesIO(data), out, k, filename,
                      size=len(data) if size == "auto" else size, segment_size=seg)
    return out.getvalue()


def dec(blob: bytes, k: bytes) -> bytes:
    sink = io.BytesIO()
    fc.decrypt_stream(io.BytesIO(blob), sink, k)
    return sink.getvalue()


def rejected(blob: bytes, k: bytes) -> None:
    with pytest.raises(DecryptionError):
        dec(blob, k)


def layout(blob: bytes, seg: int = SEG):
    """(envelope, stream header, [segments]) of a streaming container."""
    mlen = struct.unpack(">I", blob[10:14])[0]
    env_end = fc._STREAM_PREFIX.size + mlen
    head_end = env_end + fc.STREAM_HEADER_SIZE
    body = blob[head_end:]
    segs = [body[: seg - fc.STREAM_HEADER_SIZE]]
    rest = body[seg - fc.STREAM_HEADER_SIZE:]
    segs += [rest[i:i + seg] for i in range(0, len(rest), seg)]
    return blob[:env_end], blob[env_end:head_end], segs


SIZES = [0, 1, 2, FIRST - 1, FIRST, FIRST + 1, FIRST + REST - 1, FIRST + REST, FIRST + REST + 1,
         FIRST + 3 * REST, FIRST + 3 * REST + 17, FIRST + 7 * REST - 1]


# ============================ 1. Correct round trips ============================
@pytest.mark.parametrize("size", SIZES)
def test_round_trip_at_every_chunk_boundary(size):
    k, data = key(), os.urandom(size)
    blob = enc(data, k)
    assert dec(blob, k) == data
    _, _, segs = layout(blob)
    expected = 1 if size <= FIRST else 1 + -(-(size - FIRST) // REST)   # exact multiple: NO extra empty segment
    assert len(segs) == expected
    assert sum(len(s) - fc.TAG_SIZE for s in segs) == size


def test_default_segment_size_is_one_mebibyte_and_round_trips():
    assert fc.DEFAULT_SEGMENT_SIZE == 1024 * 1024
    k = key()
    first = fc.DEFAULT_SEGMENT_SIZE - fc.STREAM_HEADER_SIZE - fc.TAG_SIZE
    for size in (0, 1, first - 1, first, first + 1, first + (fc.DEFAULT_SEGMENT_SIZE - 16) * 2 + 5):
        data = os.urandom(size)
        out = io.BytesIO()
        fc.encrypt_stream(io.BytesIO(data), out, k, "x.bin", size=size)
        assert dec(out.getvalue(), k) == data


def test_metadata_is_returned_and_unknown_size_is_allowed():
    k, data = key(), os.urandom(500)
    blob = enc(data, k, filename="../../evil.txt", size=None)
    sink = io.BytesIO()
    info = fc.decrypt_stream(io.BytesIO(blob), sink, k)
    assert info.filename == "evil.txt" and info.size == 500 and "original_size" not in info.metadata


def test_wrong_key_is_rejected():
    rejected(enc(os.urandom(700), key()), key())
    rejected(enc(b"", key()), key())                       # also for an empty file


def test_bytes_api_dispatches_to_streaming_format():
    k, data = key(), os.urandom(900)
    result = fc.decrypt_bytes(enc(data, k), k)
    assert result.data == data and result.filename == "f.bin"


# ============================ 2. The construction itself ============================
def reference_encrypt(plaintext: bytes, main_key: bytes, associated_data: bytes, seg: int,
                      salt: bytes, prefix: bytes) -> bytes:
    """Independent whole-buffer implementation of the documented AES-GCM-HKDF streaming construction
    (AES-256 profile), written separately from core/file_crypto.py."""
    derived = HKDF(hashes.SHA256(), 32, salt, associated_data).derive(main_key)
    aead = AESGCM(derived)
    first_cap, other_cap = seg - 40 - 16, seg - 16
    chunks = [plaintext[:first_cap]]
    rest = plaintext[first_cap:]
    chunks += [rest[i:i + other_cap] for i in range(0, len(rest), other_cap)]
    out = bytes([40]) + salt + prefix                               # header: length, salt, nonce prefix
    for i, chunk in enumerate(chunks):
        last = i == len(chunks) - 1
        nonce = prefix + i.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        out += aead.encrypt(nonce, chunk, None)                     # no per-segment AAD
    return out


@pytest.mark.parametrize("size", [0, 1, FIRST, FIRST + 1, FIRST + REST, 5 * REST + 3])
def test_output_matches_an_independent_implementation_of_the_construction(monkeypatch, size):
    salt, prefix = bytes(range(32)), bytes(range(100, 107))
    monkeypatch.setattr(fc, "_random_bytes", lambda n: {32: salt, 7: prefix}[n])
    k, data = key(), os.urandom(size)
    blob = enc(data, k, filename="ref.bin")
    envelope, header, _ = layout(blob)
    assert header == bytes([40]) + salt + prefix and len(header) == 40
    assert envelope[:4] == b"QSHS" and envelope[4] == 1 and envelope[5] == 1
    expected = envelope + reference_encrypt(data, k, fc.STREAM_CONTEXT_STANDALONE + envelope, SEG, salt, prefix)
    assert blob == expected


def test_every_stream_gets_a_fresh_salt_and_nonce_prefix():
    k, data = key(), os.urandom(100)
    headers = {layout(enc(data, k))[1] for _ in range(50)}
    assert len(headers) == 50
    assert all(h[0] == 40 for h in headers)


def test_no_raw_key_or_plaintext_in_the_container():
    k, data = key(), b"SECRET-MARKER-0123456789" * 40
    blob = enc(data, k)
    assert k not in blob and b"SECRET-MARKER" not in blob


# ============================ 3. Tampering ============================
def test_every_single_bit_change_in_header_and_envelope_is_rejected():
    k = key()
    blob = enc(os.urandom(FIRST + REST + 5), k)            # three segments
    envelope, header, _ = layout(blob)
    for i in range(len(envelope) + len(header)):           # magic, version, suite, sizes, metadata, hdr length, salt, nonce prefix
        damaged = bytearray(blob)
        damaged[i] ^= 0x01
        rejected(bytes(damaged), k)


def test_corruption_in_first_middle_and_last_chunks_and_every_tag():
    k = key()
    blob = enc(os.urandom(FIRST + 3 * REST + 9), k)        # five segments
    envelope, header, segs = layout(blob)
    start = len(envelope) + len(header)
    offsets, pos = [], start
    for s in segs:
        offsets.append((pos, len(s)))
        pos += len(s)
    for pos, length in offsets:
        for where in (0, length // 2, length - 1):          # first byte, middle, last byte (inside the tag)
            damaged = bytearray(blob)
            damaged[pos + where] ^= 0x80
            rejected(bytes(damaged), k)


def test_removed_reordered_duplicated_and_transplanted_segments_are_rejected():
    k = key()
    blob = enc(os.urandom(FIRST + 4 * REST + 9), k, size=None)
    envelope, header, segs = layout(blob)
    head = envelope + header

    def build(parts):
        return head + b"".join(parts)

    rejected(build(segs[:2] + segs[3:]), k)                              # middle removed
    rejected(build(segs[1:]), k)                                         # first removed
    rejected(build(segs[:-1]), k)                                        # last removed
    rejected(build([segs[0], segs[2], segs[1]] + segs[3:]), k)           # two swapped
    rejected(build(segs[:2] + [segs[2], segs[2]] + segs[3:]), k)         # duplicated
    rejected(build(segs + [segs[-1]]), k)                                # final duplicated
    other = enc(os.urandom(FIRST + 4 * REST + 9), k)                     # another stream, same key
    other_segs = layout(other)[2]
    rejected(build(segs[:2] + [other_segs[2]] + segs[3:]), k)            # transplanted
    rejected(head + b"".join(other_segs), k)                             # body of another stream


def test_truncation_at_every_length_is_rejected():
    k = key()
    blob = enc(os.urandom(FIRST + 2 * REST + 11), k, size=None)   # no declared size: only the AEAD can notice
    for n in range(len(blob)):          # header, inside a segment, between segments, one byte short
        rejected(blob[:n], k)
    assert dec(blob, k)                  # and the whole thing is fine


def test_truncation_exactly_between_full_segments_is_rejected():
    k = key()
    blob = enc(os.urandom(FIRST + 2 * REST), k, size=None)          # ends exactly on a segment boundary
    envelope, header, segs = layout(blob)
    assert len(segs) == 3 and all(len(s) == SEG for s in segs[1:])
    rejected(envelope + header + segs[0] + segs[1], k)   # final segment cut away: segment 1 now looks last


def test_missing_or_wrong_final_indication_is_rejected():
    k = key()
    data = os.urandom(FIRST + REST + 30)
    salt, prefix = os.urandom(32), os.urandom(7)

    def make(flags):
        meta = b'{"filename":"a.bin"}'
        envelope = fc._STREAM_PREFIX.pack(b"QSHS", 1, 1, SEG, len(meta)) + meta
        aead = AESGCM(HKDF(hashes.SHA256(), 32, salt, fc.STREAM_CONTEXT_STANDALONE + envelope).derive(k))
        chunks = [data[:FIRST], data[FIRST:FIRST + REST], data[FIRST + REST:]]
        body = b"".join(aead.encrypt(prefix + i.to_bytes(4, "big") + bytes([f]), c, None)
                        for i, (c, f) in enumerate(zip(chunks, flags)))
        return envelope + bytes([40]) + salt + prefix + body

    assert dec(make([0, 0, 1]), k) == data                # the correct flags work (sanity)
    rejected(make([0, 0, 0]), k)                          # last segment never marked final
    rejected(make([0, 1, 1]), k)                          # a middle segment wrongly marked final
    rejected(make([1, 0, 1]), k)
    rejected(make([0, 0, 1])[:-1], k)


def test_unexpected_bytes_after_the_final_segment_are_rejected():
    k = key()
    for size in (10, FIRST + REST):                       # short final segment, and a full final segment
        blob = enc(os.urandom(size), k, size=None)
        for extra in (b"\x00", os.urandom(16), os.urandom(SEG), os.urandom(3 * SEG + 5)):
            rejected(blob + extra, k)
    blob = enc(os.urandom(50), k, size=None)
    rejected(blob + layout(enc(os.urandom(50), k, size=None))[2][0], k)   # a whole valid-looking segment from elsewhere


def test_an_empty_stream_body_and_garbage_are_rejected():
    k = key()
    envelope, header, _ = layout(enc(b"", k))
    rejected(envelope + header, k)                        # header but no segments: no final segment
    for junk in (b"", b"QSHS", os.urandom(300), b"\x00" * 100):
        rejected(junk, k)


def test_unsupported_version_suite_and_invalid_lengths_are_rejected_before_reading_them():
    k = key()
    blob = enc(os.urandom(300), k)

    def patched(offset, value, fmt):
        b = bytearray(blob)
        struct.pack_into(fmt, b, offset, value)
        return bytes(b)

    rejected(patched(4, 2, ">B"), k)                      # unknown version
    rejected(patched(4, 0, ">B"), k)
    rejected(patched(5, 2, ">B"), k)                      # unknown suite
    for bad in (0, 1, fc.MIN_SEGMENT_SIZE - 1, fc.MAX_SEGMENT_SIZE + 1, 2**32 - 1):
        rejected(patched(6, bad, ">I"), k)                # segment size out of range
    rejected(patched(10, fc.MAX_METADATA_SIZE + 1, ">I"), k)
    rejected(patched(10, 2**32 - 1, ">I"), k)             # metadata length: never allocated or read

    class Counting(io.BytesIO):
        asked = 0
        def read(self, n=-1):
            Counting.asked += max(n, 0)
            return super().read(n)

    Counting.asked = 0
    with pytest.raises(DecryptionError):
        fc.decrypt_stream(Counting(patched(10, 2**32 - 1, ">I")), io.BytesIO(), k)
    assert Counting.asked < 1000                          # the attacker's length was never used to read


def test_header_length_byte_must_be_forty():
    k = key()
    envelope, header, segs = layout(enc(b"x" * 300, k))
    for bad in (0, 39, 41, 255):
        rejected(envelope + bytes([bad]) + header[1:] + b"".join(segs), k)


def test_malformed_or_inconsistent_metadata_is_rejected_even_when_validly_encrypted():
    k = key()

    def stream_with_metadata(meta: bytes, data=b"hello"):
        envelope = fc._STREAM_PREFIX.pack(b"QSHS", 1, 1, SEG, len(meta)) + meta
        out = io.BytesIO(envelope)
        out.seek(0, 2)
        fc.encrypt_stream_body(io.BytesIO(data), out, k, fc.STREAM_CONTEXT_STANDALONE + envelope, SEG)
        return out.getvalue()

    assert dec(stream_with_metadata(b'{"filename":"a.txt"}'), k) == b"hello"
    for meta in (b"not json", b"[]", b"{}", b'{"filename":5}', b'\xff\xfe',
                 b'{"filename":"a","original_size":6}', b'{"filename":"a","original_size":"5"}',
                 b'{"filename":"a","original_size":true}'):
        rejected(stream_with_metadata(meta), k)


def test_counter_overflow_is_rejected_before_a_nonce_could_repeat(monkeypatch):
    k = key()
    data = os.urandom(FIRST + 3 * REST)                   # four segments: numbers 0..3
    blob = enc(data, k)
    monkeypatch.setattr(fc, "MAX_SEGMENT_COUNT", 4)
    assert dec(blob, k) == data                           # exactly at the limit is fine
    assert enc(data, k)
    monkeypatch.setattr(fc, "MAX_SEGMENT_COUNT", 3)       # a fifth number would be needed: refuse
    rejected(blob, k)                                     # reader refuses segment number 3
    with pytest.raises(ValueError):
        enc(data, k)                                      # writer refuses to emit it


def test_segment_counter_limit_is_the_documented_2_to_the_32():
    assert fc.MAX_SEGMENT_COUNT == 2**32                  # 4-byte counter: numbers 0 .. 2**32 - 1


def test_bad_arguments_are_refused():
    k = key()
    for seg in (0, 255, fc.MAX_SEGMENT_SIZE + 1, True, "1024", 1.5):
        with pytest.raises(ValueError):
            fc.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), k, segment_size=seg)
    with pytest.raises(ValueError):
        fc.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), b"short")
    with pytest.raises(ValueError):
        fc.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), k, size=-1)
    with pytest.raises(ValueError):
        fc.encrypt_stream(io.BytesIO(b"abc"), io.BytesIO(), k, size=5)    # input shorter than declared
    with pytest.raises(TypeError):
        fc.encrypt_stream(io.StringIO("text"), io.BytesIO(), k)


# ============================ 4. Compatibility and downgrade ============================
def test_version_1_containers_still_decrypt_by_bytes_and_by_file(tmp_path):
    k, data = key(), os.urandom(5000)
    legacy = fc.encrypt_bytes(data, k, filename="old.bin")
    assert legacy[:4] == b"QSHD" and fc.decrypt_bytes(legacy, k).data == data
    path = tmp_path / "old.qshield"
    path.write_bytes(legacy)
    assert fc.decrypt_file(path, tmp_path / "out", k).read_bytes() == data


def test_streaming_container_cannot_be_downgraded_to_legacy_handling():
    k = key()
    blob = enc(os.urandom(400), k)
    for fake_magic in (b"QSHD",):
        forged = fake_magic + blob[4:]
        with pytest.raises(DecryptionError):
            fc.decrypt_bytes(forged, k)
    legacy_style = b"QSHD" + bytes([1]) + blob[5:]
    with pytest.raises(DecryptionError):
        fc.decrypt_bytes(legacy_style, k)
    legacy = fc.encrypt_bytes(b"data", k)
    with pytest.raises(DecryptionError):                  # and a legacy file is not accepted by the stream reader
        fc.decrypt_stream(io.BytesIO(legacy), io.BytesIO(), k)
    with pytest.raises(DecryptionError):
        fc.decrypt_stream(io.BytesIO(b"QSHS" + legacy[4:]), io.BytesIO(), k)


def test_oversized_legacy_file_is_refused_without_reading_it(tmp_path, monkeypatch):
    path = tmp_path / "big.qshield"
    path.write_bytes(b"QSHD" + b"\x01" * 60)
    monkeypatch.setattr(fc, "_LEGACY_MAX_CONTAINER", 10)
    with pytest.raises(DecryptionError):
        fc.decrypt_file(path, tmp_path / "out", key())


# ============================ 5. File workflow safety ============================
def leftovers(directory: Path):
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


def test_file_round_trip_with_streaming_format(tmp_path):
    k, data = key(), os.urandom(3 * 1024 * 1024 + 123)
    src = tmp_path / "photo.jpg"
    src.write_bytes(data)
    packed = fc.encrypt_file(src, tmp_path / "photo.jpg.qshield", k)
    assert packed.read_bytes()[:4] == b"QSHS"
    out = fc.decrypt_file(packed, tmp_path / "out", k)
    assert out.name == "photo.jpg" and out.read_bytes() == data
    assert leftovers(tmp_path / "out") == ["photo.jpg"]


def test_file_workflows_never_call_read_bytes(tmp_path, monkeypatch):
    k, data = key(), os.urandom(5000)
    src = tmp_path / "a.bin"
    src.write_bytes(data)

    def boom(self):
        raise AssertionError("Path.read_bytes() must not be used by the streaming file workflow")

    monkeypatch.setattr(Path, "read_bytes", boom)
    packed = fc.encrypt_file(src, tmp_path / "a.qshield", k, segment_size=SEG)
    out = fc.decrypt_file(packed, tmp_path / "out", k)
    assert open(out, "rb").read() == data


def test_tampered_or_truncated_file_publishes_nothing_and_leaves_no_temp_files(tmp_path):
    k = key()
    src = tmp_path / "s.bin"
    src.write_bytes(os.urandom(FIRST + 5 * REST + 3))
    packed = fc.encrypt_file(src, tmp_path / "s.qshield", k, segment_size=SEG)
    good = packed.read_bytes()
    out_dir = tmp_path / "out"

    damaged = bytearray(good)
    damaged[-1] ^= 1                                      # last tag: earlier chunks DID verify
    for variant in (bytes(damaged), good[:-REST], good + b"x", good[: len(good) // 2]):
        bad = tmp_path / "bad.qshield"
        bad.write_bytes(variant)
        with pytest.raises(DecryptionError):
            fc.decrypt_file(bad, out_dir, k)
        assert leftovers(out_dir) == []                   # no partial output, no .tmp file


def test_failed_decryption_leaves_an_existing_destination_untouched(tmp_path):
    k = key()
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(2000))
    packed = fc.encrypt_file(src, tmp_path / "doc.qshield", k, segment_size=SEG)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "doc.txt").write_bytes(b"PRECIOUS")
    bad = tmp_path / "bad.qshield"
    data = bytearray(packed.read_bytes())
    data[-3] ^= 1
    bad.write_bytes(bytes(data))
    for overwrite in (False, True):
        with pytest.raises(DecryptionError):
            fc.decrypt_file(bad, out_dir, k, overwrite=overwrite)
        assert (out_dir / "doc.txt").read_bytes() == b"PRECIOUS" and leftovers(out_dir) == ["doc.txt"]


def test_no_overwrite_by_default_for_encrypt_and_decrypt(tmp_path):
    k = key()
    src = tmp_path / "a.txt"
    src.write_bytes(b"new data" * 100)
    target = tmp_path / "a.txt.qshield"
    target.write_bytes(b"IMPORTANT")
    with pytest.raises(FileExistsError):
        fc.encrypt_file(src, target, k)
    assert target.read_bytes() == b"IMPORTANT"
    fc.encrypt_file(src, target, k, overwrite=True)
    assert target.read_bytes()[:4] == b"QSHS"

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_bytes(b"KEEP ME")
    with pytest.raises(FileExistsError):
        fc.decrypt_file(target, out_dir, k)
    assert (out_dir / "a.txt").read_bytes() == b"KEEP ME" and leftovers(out_dir) == ["a.txt"]
    fc.decrypt_file(target, out_dir, k, overwrite=True)
    assert (out_dir / "a.txt").read_bytes() == b"new data" * 100


def test_a_symlink_at_the_destination_is_not_followed_or_replaced(tmp_path):
    k = key()
    src = tmp_path / "a.txt"
    src.write_bytes(b"hello")
    packed = fc.encrypt_file(src, tmp_path / "a.qshield", k)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"VICTIM")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    try:
        (out_dir / "a.txt").symlink_to(victim)
    except (OSError, NotImplementedError):
        return
    with pytest.raises((FileExistsError, DecryptionError)):   # refused either way; never followed
        fc.decrypt_file(packed, out_dir, k)
    assert victim.read_bytes() == b"VICTIM" and leftovers(out_dir) == ["a.txt"]


def test_unsafe_filename_in_the_container_cannot_escape_the_output_folder(tmp_path):
    k = key()
    blob = enc(b"data", k, filename="../../../escape.txt")
    packed = tmp_path / "x.qshield"
    packed.write_bytes(blob)
    out = fc.decrypt_file(packed, tmp_path / "a" / "b", k)
    assert out.parent == (tmp_path / "a" / "b") and out.name == "escape.txt"
    assert not (tmp_path / "escape.txt").exists()


class FailingWriter(io.BytesIO):
    def __init__(self, fail_after):
        super().__init__()
        self.fail_after = fail_after

    def write(self, b):
        if self.tell() + len(b) > self.fail_after:
            raise OSError("disk full (simulated)")
        return super().write(b)


class FailingReader(io.BytesIO):
    def __init__(self, data, fail_after):
        super().__init__(data)
        self.fail_after = fail_after

    def read(self, n=-1):
        if self.tell() >= self.fail_after:
            raise OSError("read error (simulated)")
        return super().read(n)


def test_write_and_read_errors_propagate_and_clean_up(tmp_path, monkeypatch):
    k = key()
    with pytest.raises(OSError):
        fc.encrypt_stream(io.BytesIO(os.urandom(2000)), FailingWriter(500), k, segment_size=SEG)
    with pytest.raises(OSError):
        fc.encrypt_stream(FailingReader(os.urandom(2000), 450), io.BytesIO(), k, segment_size=SEG)

    src = tmp_path / "s.bin"
    src.write_bytes(os.urandom(2000))
    real = fc.create_private_temp

    def failing_temp(directory):
        f, path = real(directory)
        f.close()
        return FailingTempFile(path), path

    class FailingTempFile:
        def __init__(self, path):
            self.path, self.count = path, 0
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def write(self, b):
            self.count += 1
            if self.count > 2:
                raise OSError("disk full (simulated)")
        def flush(self): pass
        def fileno(self): raise OSError("none")

    monkeypatch.setattr(fc, "create_private_temp", failing_temp)
    with pytest.raises(OSError):
        fc.encrypt_file(src, tmp_path / "s.qshield", k, segment_size=SEG)
    assert leftovers(tmp_path) == ["s.bin"]               # no output, no temp file


def test_failure_while_publishing_leaves_no_temp_file(tmp_path, monkeypatch):
    k = key()
    src = tmp_path / "s.bin"
    src.write_bytes(b"data" * 100)
    packed = fc.encrypt_file(src, tmp_path / "s.qshield", k)

    def boom(*a, **kw):
        raise OSError("cannot publish (simulated)")

    monkeypatch.setattr(fc, "publish", boom)
    with pytest.raises(OSError):
        fc.decrypt_file(packed, tmp_path / "out", k)
    assert leftovers(tmp_path / "out") == []


def test_a_pipe_or_fifo_has_no_declared_size_and_still_encrypts(tmp_path):
    if not hasattr(os, "mkfifo"):
        return
    k, data = key(), os.urandom(3 * SEG + 5)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    def feed():
        with open(fifo, "wb") as f:
            f.write(data)

    t = threading.Thread(target=feed)
    t.start()
    packed = fc.encrypt_file(fifo, tmp_path / "pipe.qshield", k, segment_size=SEG)
    t.join()
    out = fc.decrypt_file(packed, tmp_path / "out", k)
    assert out.read_bytes() == data


def test_temp_file_is_private_and_unpredictable(tmp_path):
    f1, p1 = fc.create_private_temp(tmp_path)
    f2, p2 = fc.create_private_temp(tmp_path)
    try:
        assert p1 != p2 and p1.name.startswith(".qshield-")
        if os.name == "posix":
            assert (os.stat(p1).st_mode & 0o777) == 0o600
    finally:
        f1.close(); f2.close(); p1.unlink(); p2.unlink()


# ============================ 6. Memory and size ============================
class CountingReader:
    def __init__(self, total):
        self.remaining, self.max_request = total, 0

    def read(self, n):
        self.max_request = max(self.max_request, n)
        n = min(n, self.remaining)
        self.remaining -= n
        return bytes(n)


class CountingWriter:
    def __init__(self):
        self.max_write, self.total = 0, 0

    def write(self, b):
        self.max_write = max(self.max_write, len(b))
        self.total += len(b)


def test_reads_and_writes_are_bounded_by_the_segment_size():
    k = key()
    reader, writer = CountingReader(50 * 1024 * 1024), CountingWriter()
    fc.encrypt_stream(reader, writer, k, size=50 * 1024 * 1024)
    assert reader.max_request <= fc.DEFAULT_SEGMENT_SIZE
    assert writer.max_write <= fc.DEFAULT_SEGMENT_SIZE and writer.total > 50 * 1024 * 1024


def test_peak_memory_is_a_few_segments_not_the_file_size():
    k, total = key(), 48 * 1024 * 1024
    pipe, finished = PipeWriter(), []

    def producer():
        try:
            finished.append(fc.encrypt_stream(CountingReader(total), pipe, k, size=total))
        finally:
            pipe.q.put(None)

    tracemalloc.start()
    try:
        worker = threading.Thread(target=producer)
        worker.start()
        digest_sink = HashingSink()
        fc.decrypt_stream(pipe.reader(), digest_sink, k)
        worker.join()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert digest_sink.total == total and finished == [total]
    assert peak < 16 * 1024 * 1024, f"peak memory {peak} bytes"   # 48 MiB file, < 16 MiB peak


class PipeWriter:
    """Connects an encrypting thread to a decrypting reader through a small bounded queue."""

    def __init__(self):
        self.q = queue.Queue(maxsize=4)

    def write(self, b):
        self.q.put(bytes(b))

    def reader(self):
        pipe = self

        class R:
            buf = b""
            done = False
            def read(self, n):
                if not R.buf and not R.done:
                    item = pipe.q.get()
                    if item is None:
                        R.done = True
                    else:
                        R.buf = item
                out, R.buf = R.buf[:n], R.buf[n:]
                return out
        return R()


class HashingSink:
    def __init__(self):
        self.h, self.total = hashlib.sha256(), 0

    def write(self, b):
        self.h.update(b)
        self.total += len(b)


class PatternReader:
    """Deterministic plaintext generated on the fly; never held in memory."""

    BLOCK = bytes(range(256)) * 4096          # 1 MiB

    def __init__(self, total):
        self.remaining, self.h = total, hashlib.sha256()

    def read(self, n):
        n = min(n, self.remaining)
        self.remaining -= n
        out = self.BLOCK[:n]
        self.h.update(out)
        return out


def test_stream_larger_than_the_old_2_gib_single_buffer_limit():
    """Encrypts and decrypts 2 GiB + 12,345 bytes (more than the old single-buffer limit) through a
    bounded pipe. The plaintext is generated on the fly and the ciphertext is consumed as it is
    produced, so nothing near that size is ever held in memory or on disk (a few seconds on a
    modern machine). Set QSHIELD_SKIP_LARGE_TESTS=1 to skip it on a very slow machine."""
    if os.environ.get("QSHIELD_SKIP_LARGE_TESTS"):
        pytest.skip("QSHIELD_SKIP_LARGE_TESTS is set")
    total = fc.MAX_PLAINTEXT_SIZE + 1 + 12_345
    k, source, pipe, errors = key(), PatternReader(total), PipeWriter(), []

    def producer():
        try:
            fc.encrypt_stream(source, pipe, k, "huge.bin", size=total)
        except BaseException as exc:           # surface thread failures in the test
            errors.append(exc)
        finally:
            pipe.q.put(None)

    tracemalloc.start()
    try:
        worker = threading.Thread(target=producer)
        worker.start()
        sink = HashingSink()
        info = fc.decrypt_stream(pipe.reader(), sink, k)
        worker.join()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not errors
    assert info.size == total == sink.total and total > 2**31 - 1
    assert sink.h.hexdigest() == source.h.hexdigest()
    assert peak < 64 * 1024 * 1024, f"peak memory {peak} bytes"
