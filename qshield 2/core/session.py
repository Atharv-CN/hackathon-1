"""Forward-secret live sessions: an ephemeral-KEM handshake plus an encrypted channel.

WHY THIS EXISTS (read core/pq_transfer.py first)
  A .qshield package is encrypted to the receiver's long-term key. If that private
  key leaks later, every package ever saved can be opened. For STORED FILES that
  is expected. For a LIVE CHANNEL we can do better: this module gives FORWARD
  SECRECY. If the server's long-term private key leaks AFTER a session ended,
  the recorded traffic of that session still cannot be opened.

THE IDEA (think of a padlock that is thrown away)
  - The server has a long-term key pair (made with generate_recipient_keypair,
    any suite). The client already knows the server's PUBLIC key and has checked
    its fingerprint over a second channel.
  - For every session the client makes a brand-new, one-time ("ephemeral") key pair.
  - The client sends the one-time public key plus a locked box for the server's
    long-term key. The server answers with a locked box for the one-time key.
  - Both secrets go into HKDF-SHA256. Then the client DELETES the one-time private
    key. Nobody, not even the client, can open the second box again. So a thief who
    later steals the server's long-term key gets the first secret but never the
    second, and cannot rebuild the session keys.
  - After that, messages are protected with AES-256-GCM (one key per direction).

THE FLOW (2 messages, then data)
  client                                         server
  ------                                         ------
  make ephemeral key pair (E_pub, E_priv)
  ct_s, ss_s = Encapsulate(server long-term pub)
  ClientHello = header | E_pub | ct_s  ------->
                                                 ss_s = Decapsulate(long-term priv, ct_s)
                                                 ct_e, ss_e = Encapsulate(E_pub)
                                                 keys = HKDF(ss_s | ss_e, transcript)
                      <-------  ServerHello = header | ct_e | confirmation tag
  ss_e = Decapsulate(E_priv, ct_e)
  keys = HKDF(ss_s | ss_e, transcript)
  check the confirmation tag, then DELETE E_priv
  then both sides:  seal(...) / open(...)

  The "KEM" is whichever suite the server's key belongs to (1 = ML-KEM-768,
  2 = X25519 + ML-KEM-768 hybrid, 3 = ML-KEM-1024), reused from pq_transfer.py.
  No new cryptographic algorithms: ML-KEM / X25519, HKDF-SHA256, HMAC-SHA256 and
  AES-256-GCM, all from the `cryptography` library.

WHAT YOU GET
  - Forward secrecy against a later leak of the server's long-term key.
  - The client knows it is talking to the holder of the server's private key
    (only that holder can compute ss_s, and the confirmation tag proves it).
  - Every session has fresh keys; each direction has its own key.
  - Messages are checked for changes, replay, re-ordering and dropping.

IMPORTANT LIMITS - please read
  - THE CLIENT IS NOT AUTHENTICATED. Anyone can open a session with the server.
    The server learns nothing about who is on the other end. (Digital signatures
    or a client key would be needed. They are not built.)
  - CHECK THE SERVER'S PUBLIC KEY. If the client holds an attacker's key instead
    of the real one, it talks to the attacker. Compare fingerprints over a second
    channel (public_key_fingerprint()).
  - FORWARD SECRECY IS ONLY AS GOOD AS THE DELETION. The client forgets its
    one-time private key right after the handshake, and this code drops every
    reference to it. Python cannot guarantee the bytes are wiped from memory, and
    a thief who already controls the client's machine DURING the session wins.
  - If the server's long-term key is stolen BEFORE or DURING a session, the thief
    can impersonate the server for new sessions and read a live session (they hold
    ss_s and can also act as the server). Forward secrecy only protects past sessions.
  - If an attacker records a session and later breaks the ephemeral KEM itself
    (for example ML-KEM alone, in suite 1 or 3), and also steals the server key,
    they win. Suite 2 makes that harder: they would have to break both halves.
  - There is no re-keying: one handshake gives one session. Start a new handshake
    for a new session (a session stops after 2**32 messages).
  - Message sizes and timing are visible. This is a small teaching-sized protocol
    with no independent security audit. Do not use it for real secrets.
  - Not connected to the Streamlit app yet (it is a file-transfer demo).
"""

import hashlib
import hmac
import socket
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import pq_transfer as pq
from core.file_crypto import DecryptionError

# ---- Format constants (session protocol version 1) -------------------------------
MAGIC_CLIENT_HELLO = b"QSHC"
MAGIC_SERVER_HELLO = b"QSHR"
SESSION_VERSION = 1

FINGERPRINT_SIZE = pq.FINGERPRINT_SIZE
CONFIRM_SIZE = 32                  # HMAC-SHA256 tag
KEY_SIZE = 32                      # AES-256
RECORD_SEQ_SIZE = 8
GCM_TAG_SIZE = 16
MAX_RECORDS = 2 ** 32              # stop a session long before AES-GCM limits matter
MAX_PLAINTEXT = 16 * 1024 * 1024   # per message
MAX_FRAME = MAX_PLAINTEXT + RECORD_SEQ_SIZE + GCM_TAG_SIZE + 1024

# magic (4), version (1), suite (1), server key fingerprint (32)
_CLIENT_PREFIX = struct.Struct(">4sBB32s")
# magic (4), version (1), suite (1)
_SERVER_PREFIX = struct.Struct(">4sBB")

_KDF_LABEL = b"QShield session v1: ephemeral KEM + static KEM + HKDF-SHA256 + AES-256-GCM"
_CONFIRM_LABEL = b"QShield session v1: server finished"


class SessionError(DecryptionError):
    """Something about the session failed. Nothing is released to the caller."""


class HandshakeError(SessionError):
    """The handshake failed (damaged message, wrong server key, or an attacker)."""


class RecordError(SessionError):
    """A message was changed, replayed, re-ordered, dropped, or not for this session."""


# ---- Helpers ----------------------------------------------------------------------
def _client_hello_size(suite: int) -> int:
    info = pq.SUITES[suite]
    return _CLIENT_PREFIX.size + info.public_key_size + info.kem_ciphertext_size


def _server_hello_size(suite: int) -> int:
    return _SERVER_PREFIX.size + pq.SUITES[suite].kem_ciphertext_size + CONFIRM_SIZE


def _derive(static_secret: bytes, ephemeral_secret: bytes, transcript_hash: bytes):
    """Both KEM secrets in, three 256-bit keys out (client->server, server->client, confirm)."""
    block = HKDF(
        algorithm=hashes.SHA256(),
        length=3 * KEY_SIZE,
        salt=None,
        info=_KDF_LABEL + b"\x00" + transcript_hash,
    ).derive(static_secret + ephemeral_secret)
    return block[:KEY_SIZE], block[KEY_SIZE:2 * KEY_SIZE], block[2 * KEY_SIZE:]


def _confirmation(confirm_key: bytes, transcript_hash: bytes) -> bytes:
    return hmac.new(confirm_key, _CONFIRM_LABEL + transcript_hash, hashlib.sha256).digest()


def _transcript_hash(client_hello: bytes, server_hello_body: bytes) -> bytes:
    """Hash of everything both sides saw, so the keys only fit THIS exact handshake."""
    return hashlib.sha256(
        struct.pack(">II", len(client_hello), len(server_hello_body)) + client_hello + server_hello_body
    ).digest()


# ---- The encrypted channel ---------------------------------------------------------
class Session:
    """An established, forward-secret, two-way channel. Make one with a handshake.

    seal() turns a message into a record; open() turns a record back into the
    message. Records must be opened in the order they were sealed. A changed,
    replayed, re-ordered or dropped record raises RecordError, and the session
    keeps working afterwards (a bad record does not advance the counter).
    """

    def __init__(self, suite: int, send_key: bytes, recv_key: bytes, is_client: bool):
        self.suite = suite
        self.is_client = is_client
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_count = 0
        self._recv_count = 0
        self._closed = False

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack(">Q", seq)

    def _check_open(self) -> None:
        if self._closed:
            raise SessionError("This session is closed. Start a new handshake.")

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt one message. `aad` is extra data that is checked but not hidden."""
        self._check_open()
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes.")
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError("Message is too large. Send it in smaller pieces.")
        if self._send_count >= MAX_RECORDS:
            raise SessionError("This session has sent the maximum number of messages. Start a new handshake.")
        seq = struct.pack(">Q", self._send_count)
        body = self._send.encrypt(self._nonce(self._send_count), bytes(plaintext), seq + bytes(aad))
        self._send_count += 1
        return seq + body

    def open(self, record: bytes, aad: bytes = b"") -> bytes:
        """Decrypt one record. Raises RecordError unless it is the next genuine one."""
        self._check_open()
        if not isinstance(record, (bytes, bytearray, memoryview)):
            raise TypeError("record must be bytes.")
        record = bytes(record)
        if len(record) < RECORD_SEQ_SIZE + GCM_TAG_SIZE:
            raise RecordError("This is too short to be a session record.")
        (seq,) = struct.unpack_from(">Q", record, 0)
        if seq != self._recv_count:
            raise RecordError(
                f"Unexpected message number {seq} (expected {self._recv_count}): "
                "a message was replayed, re-ordered or dropped."
            )
        try:
            plaintext = self._recv.decrypt(
                self._nonce(seq), record[RECORD_SEQ_SIZE:], record[:RECORD_SEQ_SIZE] + bytes(aad)
            )
        except InvalidTag:
            raise RecordError("This message was changed or is not part of this session.") from None
        self._recv_count += 1
        return plaintext

    def close(self) -> None:
        """Forget the session keys. (Best effort: Python cannot wipe memory for you.)"""
        self._send = self._recv = None
        self._closed = True

    @property
    def messages_sent(self) -> int:
        return self._send_count

    @property
    def messages_received(self) -> int:
        return self._recv_count


# ---- Client side ---------------------------------------------------------------------
class ClientHandshake:
    """The client's half of the handshake.

        hs = ClientHandshake(server_public_key)
        hello = hs.start()                 # send this to the server
        session = hs.finish(server_hello)  # the server's answer
    """

    def __init__(self, server_public_key):
        if pq._is_private_key(server_public_key):
            raise TypeError("Give the server's PUBLIC key, not a private key.")
        self._suite = pq.suite_of(server_public_key)
        self._server_public_key = server_public_key
        self._ephemeral_private = None
        self._static_secret = None
        self._client_hello = None
        self._used = False

    @pq._no_fallback
    def start(self) -> bytes:
        """Make the one-time key pair and the ClientHello. Call once."""
        if self._client_hello is not None:
            raise HandshakeError("start() was already called. Use a new ClientHandshake.")
        self._ephemeral_private = pq.generate_recipient_keypair(self._suite)
        ephemeral_public = self._ephemeral_private.public_key()
        _, self._static_secret, ct_static = pq._encapsulate(self._server_public_key)
        self._client_hello = (
            _CLIENT_PREFIX.pack(
                MAGIC_CLIENT_HELLO, SESSION_VERSION, self._suite,
                pq._fingerprint_bytes(self._server_public_key),
            )
            + pq.public_key_to_bytes(ephemeral_public)
            + ct_static
        )
        return self._client_hello

    @pq._no_fallback
    def finish(self, server_hello: bytes) -> Session:
        """Check the ServerHello and return the Session. The one-time private key is
        deleted whether this succeeds or fails."""
        if self._client_hello is None:
            raise HandshakeError("Call start() first.")
        if self._used:
            raise HandshakeError("This handshake is finished. Use a new ClientHandshake.")
        self._used = True
        ephemeral_private, self._ephemeral_private = self._ephemeral_private, None
        static_secret, self._static_secret = self._static_secret, None
        try:
            if not isinstance(server_hello, (bytes, bytearray, memoryview)):
                raise TypeError("server_hello must be bytes.")
            server_hello = bytes(server_hello)
            suite = self._suite
            if len(server_hello) != _server_hello_size(suite):
                raise HandshakeError("The server's answer has the wrong size.")
            magic, version, hello_suite = _SERVER_PREFIX.unpack_from(server_hello, 0)
            if magic != MAGIC_SERVER_HELLO:
                raise HandshakeError("This is not a QShield session answer.")
            if version != SESSION_VERSION:
                raise HandshakeError(f"Unsupported session version: {version}.")
            if hello_suite != suite:
                raise HandshakeError("The server answered with a different algorithm suite.")

            body, tag = server_hello[:-CONFIRM_SIZE], server_hello[-CONFIRM_SIZE:]
            ct_ephemeral = body[_SERVER_PREFIX.size:]
            # ML-KEM never raises on a damaged box; the confirmation tag catches it.
            ephemeral_secret = pq._decapsulate(ephemeral_private, ct_ephemeral)
            transcript = _transcript_hash(self._client_hello, body)
            client_to_server, server_to_client, confirm_key = _derive(
                static_secret, ephemeral_secret, transcript
            )
            if not hmac.compare_digest(tag, _confirmation(confirm_key, transcript)):
                raise HandshakeError(
                    "The server could not be verified: wrong server key, or the "
                    "handshake was changed. No session was created."
                )
            return Session(suite, client_to_server, server_to_client, is_client=True)
        except pq.TransferError:
            raise HandshakeError("The handshake was damaged. No session was created.") from None
        finally:
            del ephemeral_private  # forward secrecy: the one-time key is gone for good


# ---- Server side ---------------------------------------------------------------------
class ServerHandshake:
    """The server's half. One object can answer many clients; it keeps no per-client state.

        server = ServerHandshake(server_private_key)
        server_hello, session = server.respond(client_hello)
    """

    def __init__(self, server_private_key):
        if not pq._is_private_key(server_private_key):
            raise TypeError("server_private_key must be a QShield private key.")
        self._private_key = server_private_key
        self._suite = pq.suite_of(server_private_key)
        self._fingerprint = pq._fingerprint_bytes(server_private_key.public_key())

    @pq._no_fallback
    def respond(self, client_hello: bytes) -> tuple[bytes, Session]:
        """Check a ClientHello. Returns (ServerHello to send back, the Session)."""
        if not isinstance(client_hello, (bytes, bytearray, memoryview)):
            raise TypeError("client_hello must be bytes.")
        client_hello = bytes(client_hello)
        if len(client_hello) < _CLIENT_PREFIX.size:
            raise HandshakeError("This is too short to be a QShield session request.")
        magic, version, suite, fingerprint = _CLIENT_PREFIX.unpack_from(client_hello, 0)
        if magic != MAGIC_CLIENT_HELLO:
            raise HandshakeError("This is not a QShield session request.")
        if version != SESSION_VERSION:
            raise HandshakeError(f"Unsupported session version: {version}.")
        if suite not in pq.SUITES:
            raise HandshakeError(f"Unsupported algorithm suite: {suite}.")
        if suite != self._suite:
            raise HandshakeError("The request uses a different algorithm suite than this server's key.")
        if len(client_hello) != _client_hello_size(suite):
            raise HandshakeError("The session request has the wrong size.")
        if not hmac.compare_digest(fingerprint, self._fingerprint):
            raise HandshakeError("This request was made for a different server key.")

        info = pq.SUITES[suite]
        offset = _CLIENT_PREFIX.size
        ephemeral_bytes = client_hello[offset:offset + info.public_key_size]
        ct_static = client_hello[offset + info.public_key_size:]
        try:
            ephemeral_public = pq.public_key_from_bytes(ephemeral_bytes, suite)
        except ValueError:
            raise HandshakeError("The session request holds an invalid one-time key.") from None

        try:
            static_secret = pq._decapsulate(self._private_key, ct_static)
        except pq.TransferError:
            raise HandshakeError("The session request was damaged.") from None
        try:
            _, ephemeral_secret, ct_ephemeral = pq._encapsulate(ephemeral_public)
        except ValueError:
            raise HandshakeError("The session request holds an invalid one-time key.") from None

        body = _SERVER_PREFIX.pack(MAGIC_SERVER_HELLO, SESSION_VERSION, suite) + ct_ephemeral
        transcript = _transcript_hash(client_hello, body)
        client_to_server, server_to_client, confirm_key = _derive(
            static_secret, ephemeral_secret, transcript
        )
        server_hello = body + _confirmation(confirm_key, transcript)
        return server_hello, Session(suite, server_to_client, client_to_server, is_client=False)


# ---- Optional: send messages over a socket (length-prefixed frames) ----------------------
def write_frame(sock: socket.socket, data: bytes) -> None:
    """Send one message with a 4-byte length in front, so the other side knows where it ends."""
    if len(data) > MAX_FRAME:
        raise ValueError("Frame is too large.")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _read_exactly(sock: socket.socket, count: int) -> bytes:
    chunks = []
    while count:
        chunk = sock.recv(count)
        if not chunk:
            raise ConnectionError("The connection closed in the middle of a message.")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def read_frame(sock: socket.socket) -> bytes:
    """Receive one length-prefixed message. Refuses absurd sizes."""
    (length,) = struct.unpack(">I", _read_exactly(sock, 4))
    if length > MAX_FRAME:
        raise ConnectionError("The other side announced a frame that is too large.")
    return _read_exactly(sock, length)


def client_connect(sock: socket.socket, server_public_key) -> Session:
    """Run the client handshake over a connected socket."""
    handshake = ClientHandshake(server_public_key)
    write_frame(sock, handshake.start())
    return handshake.finish(read_frame(sock))


def server_accept(sock: socket.socket, server_private_key) -> Session:
    """Run the server handshake over an accepted socket."""
    server_hello, session = ServerHandshake(server_private_key).respond(read_frame(sock))
    write_frame(sock, server_hello)
    return session
