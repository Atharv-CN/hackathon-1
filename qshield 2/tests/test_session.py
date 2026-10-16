"""Tests for core/session.py: the forward-secret ephemeral-KEM session protocol.

Run them from the qshield folder with:   pytest
"""

import socket
import struct
import threading

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import pq_transfer as pq
from core import session as ss

ALL_SUITES = [1, 2, 3]


def handshake(server_key):
    """Run a whole handshake in memory. Returns (client_session, server_session, client_hello, server_hello)."""
    client = ss.ClientHandshake(server_key.public_key())
    client_hello = client.start()
    server_hello, server_session = ss.ServerHandshake(server_key).respond(client_hello)
    return client.finish(server_hello), server_session, client_hello, server_hello


@pytest.fixture(params=ALL_SUITES)
def server_key(request):
    return pq.generate_recipient_keypair(request.param)


# =============================================================================
# 1. It works
# =============================================================================
def test_messages_flow_both_ways(server_key):
    client, server, _, _ = handshake(server_key)
    for i in range(5):
        assert server.open(client.seal(b"hello %d" % i)) == b"hello %d" % i
        assert client.open(server.seal(b"reply %d" % i)) == b"reply %d" % i
    assert client.messages_sent == server.messages_received == 5
    assert client.suite == server.suite == pq.suite_of(server_key)


def test_empty_and_large_messages_and_aad(server_key):
    client, server, _, _ = handshake(server_key)
    assert server.open(client.seal(b"")) == b""
    big = bytes(range(256)) * 4000
    assert server.open(client.seal(big)) == big
    assert server.open(client.seal(b"x", aad=b"header-1"), aad=b"header-1") == b"x"
    with pytest.raises(ss.RecordError):
        server.open(client.seal(b"x", aad=b"header-1"), aad=b"header-2")


def test_oversize_messages_are_refused(server_key):
    client, _, _, _ = handshake(server_key)
    with pytest.raises(ValueError):
        client.seal(b"x" * (ss.MAX_PLAINTEXT + 1))


def test_one_server_object_serves_many_clients(server_key):
    server = ss.ServerHandshake(server_key)
    sessions = []
    for _ in range(3):
        client = ss.ClientHandshake(server_key.public_key())
        ch = client.start()
        server_hello, srv = server.respond(ch)
        sessions.append((client.finish(server_hello), srv))
    for c, s in sessions:
        assert s.open(c.seal(b"hi")) == b"hi"


def test_message_sizes_match_the_documented_layout(server_key):
    suite = pq.suite_of(server_key)
    _, _, client_hello, server_hello = handshake(server_key)
    info = pq.SUITES[suite]
    assert len(client_hello) == 38 + info.public_key_size + info.kem_ciphertext_size
    assert len(server_hello) == 6 + info.kem_ciphertext_size + 32
    assert client_hello[:4] == b"QSHC" and server_hello[:4] == b"QSHR"


# =============================================================================
# 2. FORWARD SECRECY: leaking the server's long-term key later does not open a past session
# =============================================================================
def test_leaked_long_term_key_does_not_open_a_recorded_session(server_key):
    """The attacker has: every byte on the wire AND the server's long-term PRIVATE key.
    They can recover the first secret, but the second one is gone, so the keys cannot be rebuilt.

    A control in the same test shows the attack code is sound: with the one-time key
    (which the real client deleted) the very same steps DO open the recording."""
    secret = b"top secret chat line"
    suite = pq.suite_of(server_key)
    info = pq.SUITES[suite]

    # --- a session happens, and the eavesdropper records the wire ---------------
    client = ss.ClientHandshake(server_key.public_key())
    client_hello = client.start()
    one_time_key_for_control = client._ephemeral_private  # the test peeks; the real client deletes it
    server_hello, server_session = ss.ServerHandshake(server_key).respond(client_hello)
    client_session = client.finish(server_hello)
    record = client_session.seal(secret)
    assert server_session.open(record) == secret
    client_session.close(); server_session.close()
    wire = client_hello + server_hello + record
    assert secret not in wire

    # --- later the server's long-term key leaks; the attacker does what the server can ---
    ct_static = client_hello[38 + info.public_key_size:]
    static_secret = pq._decapsulate(server_key, ct_static)
    transcript = ss._transcript_hash(client_hello, server_hello[:-32])

    def try_to_open(second_secret):
        key, _, _ = ss._derive(static_secret, second_secret, transcript)
        return AESGCM(key).decrypt(b"\x00" * 4 + record[:8], record[8:], record[:8])

    # Control: WITH the one-time key's secret, the steps work and reveal the message.
    true_second_secret = pq._decapsulate(one_time_key_for_control, server_hello[6:-32])
    assert try_to_open(true_second_secret) == secret

    # Attack: WITHOUT it, every guess fails.
    for guess in (b"", bytes(32), bytes(len(true_second_secret)), static_secret):
        with pytest.raises(Exception):
            try_to_open(guess)


def test_compare_static_packages_have_no_forward_secrecy():
    """For contrast: a stored .qshield package DOES open with the leaked long-term key.
    That is expected for stored files and is exactly what sessions fix for live channels."""
    key = pq.generate_recipient_keypair(1)
    package = pq.encrypt_for_recipient(b"stored file", key.public_key())
    assert pq.decrypt_package(package, key).data == b"stored file"


def test_client_does_not_keep_the_one_time_private_key(server_key):
    client = ss.ClientHandshake(server_key.public_key())
    hello = client.start()
    assert client._ephemeral_private is not None
    server_hello, _ = ss.ServerHandshake(server_key).respond(hello)
    client.finish(server_hello)
    assert client._ephemeral_private is None and client._static_secret is None


def test_one_time_key_is_deleted_even_if_the_handshake_fails(server_key):
    client = ss.ClientHandshake(server_key.public_key())
    client.start()
    with pytest.raises(ss.HandshakeError):
        client.finish(b"junk")
    assert client._ephemeral_private is None and client._static_secret is None


def test_every_session_has_fresh_keys_and_a_fresh_one_time_key(server_key):
    a_client, _, a_hello, _ = handshake(server_key)
    b_client, _, b_hello, _ = handshake(server_key)
    info = pq.SUITES[pq.suite_of(server_key)]
    assert a_hello[38:38 + info.public_key_size] != b_hello[38:38 + info.public_key_size]
    # Same plaintext, same counter: different sessions give different records.
    assert a_client.seal(b"same") != b_client.seal(b"same")


def test_later_server_key_theft_does_not_let_the_thief_replay_old_recordings(server_key):
    """The thief also cannot talk their way into an old session: a replayed ClientHello
    gives them a fresh handshake whose keys they do not know (they lack the one-time key)."""
    client, server, client_hello, _ = handshake(server_key)
    old_record = client.seal(b"old message")
    # Thief replays the old ClientHello to the real server:
    server_hello, new_server_session = ss.ServerHandshake(server_key).respond(client_hello)
    # The new session is unrelated to the old one: the old record does not open in it.
    with pytest.raises(ss.RecordError):
        new_server_session.open(old_record)


# =============================================================================
# 3. Wrong keys and attackers
# =============================================================================
@pytest.mark.parametrize("suite", ALL_SUITES)
def test_client_with_the_wrong_server_key_gets_no_session(suite):
    real, fake = pq.generate_recipient_keypair(suite), pq.generate_recipient_keypair(suite)
    client = ss.ClientHandshake(fake.public_key())
    hello = client.start()
    # The real server notices it is not the intended server:
    with pytest.raises(ss.HandshakeError, match="different server key"):
        ss.ServerHandshake(real).respond(hello)


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_impostor_server_cannot_pass_the_confirmation(suite):
    """An attacker without the server's private key answers with a well-formed ServerHello."""
    real, impostor = pq.generate_recipient_keypair(suite), pq.generate_recipient_keypair(suite)
    client = ss.ClientHandshake(real.public_key())
    hello = client.start()
    # Impostor rewrites the fingerprint so its own server object accepts the hello.
    forged = bytearray(hello)
    forged[6:38] = pq._fingerprint_bytes(impostor.public_key())
    try:
        server_hello, _ = ss.ServerHandshake(impostor).respond(bytes(forged))
    except ss.HandshakeError:
        return
    with pytest.raises(ss.HandshakeError, match="could not be verified"):
        client.finish(server_hello)


def test_a_key_of_another_suite_is_refused(server_key):
    suite = pq.suite_of(server_key)
    other = pq.generate_recipient_keypair({1: 2, 2: 3, 3: 1}[suite])
    client = ss.ClientHandshake(other.public_key())
    with pytest.raises(ss.HandshakeError, match="suite"):
        ss.ServerHandshake(server_key).respond(client.start())


def test_the_client_refuses_a_private_key_and_the_server_a_public_key(server_key):
    with pytest.raises(TypeError, match="PUBLIC"):
        ss.ClientHandshake(server_key)
    with pytest.raises(TypeError):
        ss.ServerHandshake(server_key.public_key())


def test_start_and_finish_can_only_be_used_once(server_key):
    client = ss.ClientHandshake(server_key.public_key())
    with pytest.raises(ss.HandshakeError, match="start"):
        client.finish(b"x")
    hello = client.start()
    with pytest.raises(ss.HandshakeError):
        client.start()
    server_hello, _ = ss.ServerHandshake(server_key).respond(hello)
    client.finish(server_hello)
    with pytest.raises(ss.HandshakeError):
        client.finish(server_hello)


# =============================================================================
# 4. Every damaged handshake byte is caught
# =============================================================================
def _attempt(server_key, client_hello=None, tamper_server_hello=None, tamper_client_hello=None):
    """Run a handshake with one message damaged. It must end in HandshakeError at some step."""
    client = ss.ClientHandshake(server_key.public_key())
    hello = client.start()
    if tamper_client_hello:
        hello = tamper_client_hello(hello)
    server_hello, _ = ss.ServerHandshake(server_key).respond(hello)
    if tamper_server_hello:
        server_hello = tamper_server_hello(server_hello)
    return client.finish(server_hello)


def _flip(data, position, bit):
    data = bytearray(data)
    data[position] ^= 1 << bit
    return bytes(data)


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_every_bit_of_the_client_hello_is_protected(suite):
    key = pq.generate_recipient_keypair(suite)
    client = ss.ClientHandshake(key.public_key())
    hello = client.start()
    server = ss.ServerHandshake(key)
    for position in range(len(hello)):
        for bit in (0, 3, 7):  # a spread of bits per byte keeps this test fast
            damaged = _flip(hello, position, bit)
            try:
                server_hello, _ = server.respond(damaged)
                fresh = ss.ClientHandshake.__new__(ss.ClientHandshake)  # reuse this client's state
                fresh.__dict__.update(client.__dict__)
                fresh.finish(server_hello)
            except ss.HandshakeError:
                continue
            pytest.fail(f"suite {suite}: damage at byte {position}, bit {bit} was NOT caught")


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_every_bit_of_the_server_hello_is_protected(suite):
    key = pq.generate_recipient_keypair(suite)
    client = ss.ClientHandshake(key.public_key())
    hello = client.start()
    server_hello, _ = ss.ServerHandshake(key).respond(hello)
    for position in range(len(server_hello)):
        for bit in (0, 3, 7):
            fresh = ss.ClientHandshake.__new__(ss.ClientHandshake)
            fresh.__dict__.update(client.__dict__)
            with pytest.raises(ss.HandshakeError):
                fresh.finish(_flip(server_hello, position, bit))


@pytest.mark.parametrize("suite", ALL_SUITES)
def test_truncated_and_extended_handshake_messages_are_refused(suite):
    key = pq.generate_recipient_keypair(suite)
    client = ss.ClientHandshake(key.public_key())
    hello = client.start()
    server = ss.ServerHandshake(key)
    for length in range(0, len(hello), 97):
        with pytest.raises(ss.HandshakeError):
            server.respond(hello[:length])
    with pytest.raises(ss.HandshakeError):
        server.respond(hello + b"\x00")
    server_hello, _ = server.respond(hello)
    for damaged in (server_hello[:-1], server_hello + b"\x00", b""):
        fresh = ss.ClientHandshake.__new__(ss.ClientHandshake)
        fresh.__dict__.update(client.__dict__)
        with pytest.raises(ss.HandshakeError):
            fresh.finish(damaged)


def test_junk_is_not_a_handshake(server_key):
    server = ss.ServerHandshake(server_key)
    import os
    for junk in (b"", os.urandom(7), os.urandom(5000)):
        with pytest.raises(ss.HandshakeError):
            server.respond(junk)
    with pytest.raises(TypeError):
        server.respond("text")


def test_hybrid_handshake_rejects_a_low_order_x25519_one_time_key():
    key = pq.generate_recipient_keypair(2)
    client = ss.ClientHandshake(key.public_key())
    hello = bytearray(client.start())
    hello[38:70] = bytes(32)  # the one-time key's X25519 part set to a low-order point
    with pytest.raises(ss.HandshakeError):
        ss.ServerHandshake(key).respond(bytes(hello))


# =============================================================================
# 5. The encrypted channel
# =============================================================================
def test_every_bit_of_a_record_is_protected(server_key):
    client, server, _, _ = handshake(server_key)
    record = client.seal(b"A" * 20, aad=b"a")
    for position in range(len(record)):
        for bit in range(8):
            with pytest.raises(ss.RecordError):
                server.open(_flip(record, position, bit), aad=b"a")
    assert server.open(record, aad=b"a") == b"A" * 20  # the genuine one still works afterwards


def test_replay_reorder_and_drop_are_detected(server_key):
    client, server, _, _ = handshake(server_key)
    r0, r1, r2 = client.seal(b"zero"), client.seal(b"one"), client.seal(b"two")
    with pytest.raises(ss.RecordError):      # r1 before r0 (re-ordered / r0 dropped)
        server.open(r1)
    assert server.open(r0) == b"zero"
    with pytest.raises(ss.RecordError):      # replay of r0
        server.open(r0)
    with pytest.raises(ss.RecordError):      # r2 while r1 is missing (dropped)
        server.open(r2)
    assert server.open(r1) == b"one" and server.open(r2) == b"two"


def test_a_message_cannot_be_reflected_back_to_its_sender(server_key):
    client, server, _, _ = handshake(server_key)
    record = client.seal(b"to the server")
    with pytest.raises(ss.RecordError):
        client.open(record)  # the two directions use different keys


def test_records_from_another_session_are_refused(server_key):
    a_client, a_server, _, _ = handshake(server_key)
    b_client, b_server, _, _ = handshake(server_key)
    with pytest.raises(ss.RecordError):
        b_server.open(a_client.seal(b"x"))


def test_too_short_and_wrong_type_records(server_key):
    _, server, _, _ = handshake(server_key)
    for short in (b"", b"x" * 23):
        with pytest.raises(ss.RecordError):
            server.open(short)
    with pytest.raises(TypeError):
        server.open("text")


def test_bad_record_does_not_break_the_session(server_key):
    client, server, _, _ = handshake(server_key)
    with pytest.raises(ss.RecordError):
        server.open(b"\x00" * 40)
    assert server.open(client.seal(b"still fine")) == b"still fine"


def test_closed_session_refuses_everything(server_key):
    client, server, _, _ = handshake(server_key)
    client.close()
    with pytest.raises(ss.SessionError):
        client.seal(b"x")
    with pytest.raises(ss.SessionError):
        client.open(b"x" * 40)


def test_session_stops_at_the_message_limit(server_key, monkeypatch):
    client, _, _, _ = handshake(server_key)
    monkeypatch.setattr(ss, "MAX_RECORDS", 2)
    client.seal(b"1"); client.seal(b"2")
    with pytest.raises(ss.SessionError, match="maximum"):
        client.seal(b"3")


def test_record_nonces_never_repeat(server_key):
    client, _, _, _ = handshake(server_key)
    seen = {client.seal(b"x")[:8] for _ in range(200)}
    assert len(seen) == 200


def test_session_errors_are_decryption_errors():
    from core.file_crypto import DecryptionError
    assert issubclass(ss.HandshakeError, ss.SessionError) and issubclass(ss.SessionError, DecryptionError)
    assert issubclass(ss.RecordError, ss.SessionError)


# =============================================================================
# 6. Over a real socket, and "no silent fallback"
# =============================================================================
@pytest.mark.parametrize("suite", ALL_SUITES)
def test_echo_over_a_socket(suite):
    key = pq.generate_recipient_keypair(suite)
    left, right = socket.socketpair()
    results = {}

    def server_side():
        with right:
            session = ss.server_accept(right, key)
            for _ in range(3):
                ss.write_frame(right, session.seal(b"echo: " + session.open(ss.read_frame(right))))

    thread = threading.Thread(target=server_side)
    thread.start()
    with left:
        session = ss.client_connect(left, key.public_key())
        replies = []
        for text in (b"one", b"two", b"three"):
            ss.write_frame(left, session.seal(text))
            replies.append(session.open(ss.read_frame(left)))
    thread.join(timeout=10)
    assert replies == [b"echo: one", b"echo: two", b"echo: three"]


def test_socket_frames_refuse_absurd_sizes_and_cut_connections():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack(">I", ss.MAX_FRAME + 1))
        with pytest.raises(ConnectionError):
            ss.read_frame(right)
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack(">I", 100) + b"short")
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ConnectionError):
            ss.read_frame(right)


def test_if_ml_kem_is_unavailable_the_handshake_stops(monkeypatch, server_key):
    from cryptography.exceptions import UnsupportedAlgorithm

    def unsupported(*args, **kwargs):
        raise UnsupportedAlgorithm("no ML-KEM in this build")

    monkeypatch.setattr(pq, "_encapsulate", unsupported)
    with pytest.raises(pq.PostQuantumUnavailableError, match="NOT fall back"):
        ss.ClientHandshake(server_key.public_key()).start()
