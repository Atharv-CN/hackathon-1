"""Authenticated binding between a QShield identity and a receiver's ML-KEM key.

THE PROBLEM THIS SOLVES
  The relay hands out a receiver's public key for a short code. The relay is
  NOT trusted, and a short code proves nothing about who owns the key. A relay
  (or anyone who can write to it) could swap in its own key, and the sender
  would encrypt the file for the attacker.

THE DESIGN (no new algorithms: Ed25519 from the `cryptography` library)
  - A receiver has a long-term Ed25519 IDENTITY key. Its public half is
    written as a "QShield ID" (QSID1-...). The ID *is* the public key (plus a
    checksum), so nothing needs to be looked up to verify it.
  - The sender gets the receiver's QShield ID once, through a channel the relay
    does not control (chat, email, in person, a team wiki...). This is the
    trust anchor. The relay can never replace it.
  - The receiver publishes a SIGNED KEY BUNDLE: their ML-KEM-768 public key,
    signed with the identity key. The sender verifies the signature with the
    key decoded from the QShield ID they already hold - never with any key
    that arrived from the relay.

WHAT IS SIGNED
  signature = Ed25519( DOMAIN || payload_bytes )
  payload_bytes are carried verbatim next to the signature, so nobody has to
  re-serialize JSON to verify (no canonicalization ambiguity). The payload is a
  JSON object with exactly these fields:
    typ, v, purpose, identity, kem_alg, kem_public_key, key_id,
    seq, issued_at, expires_at, revoked_key_ids
  DOMAIN ("QShield key bundle v1\\0") stops a signature made for this purpose
  from being accepted as something else.

FAIL CLOSED
  Every problem raises KeyAuthError. Nothing here returns a key unless every
  check passed.

NOT PROVIDED (see docs/KEY_AUTHENTICATION.md)
  - How the sender first gets the QShield ID. If that channel is attacked,
    so is everything after it.
  - Freshness against a relay that replays an OLD, still-unexpired bundle to a
    sender who has never seen a newer one. Expiry limits this window.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:  # pragma: no cover
    from core.trust_store import TrustStore

# Security events go here. Never log keys, bundles or passwords.
security_log = logging.getLogger("qshield.security")

# ---- Constants -----------------------------------------------------------------
QSID_PREFIX = "QSID1"
_ID_KEY_SIZE = 32
_ID_CHECK_SIZE = 4
_ID_CHECK_LABEL = b"QShield identity id v1"

SIGNING_DOMAIN = b"QShield key bundle v1\x00"
BUNDLE_TYPE = "qshield-key-bundle"
BUNDLE_VERSION = 1
BUNDLE_PURPOSE = "file-encryption-recipient-key"
KEM_ALGORITHM = "ML-KEM-768"
KEM_PUBLIC_KEY_SIZE = 1184  # must equal core.pq_transfer.PUBLIC_KEY_SIZE (tested)

ENVELOPE_MARKER = "qshield_key_bundle"
MAX_ENVELOPE_BYTES = 8 * 1024
MAX_REVOKED_IDS = 16
DEFAULT_VALIDITY_SECONDS = 14 * 24 * 3600
MAX_VALIDITY_SECONDS = 90 * 24 * 3600
CLOCK_SKEW_SECONDS = 300

_PAYLOAD_FIELDS = frozenset(
    {
        "typ", "v", "purpose", "identity", "kem_alg", "kem_public_key",
        "key_id", "seq", "issued_at", "expires_at", "revoked_key_ids",
    }
)


# ---- Errors --------------------------------------------------------------------
class KeyAuthError(Exception):
    """A public key could not be authenticated. `code` is a stable machine-readable
    reason; the message is plain English for the user."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _short(identity: str | None) -> str:
    return (identity or "?")[:16]


def _fail(code: str, message: str, identity: str | None = None) -> KeyAuthError:
    security_log.warning("key authentication rejected: code=%s identity=%s", code, _short(identity))
    return KeyAuthError(code, message)


# ---- QShield ID ----------------------------------------------------------------
def _id_checksum(key_bytes: bytes) -> bytes:
    return hashlib.sha256(_ID_CHECK_LABEL + key_bytes).digest()[:_ID_CHECK_SIZE]


def identity_id_from_public_bytes(key_bytes: bytes) -> str:
    """Return the QShield ID text for a raw 32-byte Ed25519 public key."""
    if len(key_bytes) != _ID_KEY_SIZE:
        raise ValueError("An Ed25519 public key must be 32 bytes.")
    body = base64.b32encode(key_bytes + _id_checksum(key_bytes)).decode("ascii").rstrip("=")
    groups = [body[i:i + 5] for i in range(0, len(body), 5)]
    return QSID_PREFIX + "-" + "-".join(groups)


def _canonical_id_body(text: str) -> str:
    cleaned = "".join((text or "").split()).upper().replace("-", "")
    if not cleaned.startswith(QSID_PREFIX):
        raise _fail("invalid_id", "That is not a QShield ID. It should start with QSID1-.")
    return cleaned[len(QSID_PREFIX):]


def parse_identity_id(text: str) -> bytes:
    """Return the raw Ed25519 public key inside a QShield ID, or raise KeyAuthError.

    The checksum only catches typing mistakes. It is not a security feature."""
    body = _canonical_id_body(text)
    try:
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
    except (binascii.Error, ValueError):
        raise _fail("invalid_id", "That QShield ID has invalid characters. Copy it again.") from None
    if len(raw) != _ID_KEY_SIZE + _ID_CHECK_SIZE or base64.b32encode(raw).decode().rstrip("=") != body:
        raise _fail("invalid_id", "That QShield ID has the wrong length. Copy the whole ID.")
    key_bytes, check = raw[:_ID_KEY_SIZE], raw[_ID_KEY_SIZE:]
    if check != _id_checksum(key_bytes):
        raise _fail("invalid_id", "That QShield ID has a typo (the checksum does not match).")
    return key_bytes


def normalize_identity_id(text: str) -> str:
    """Canonical text form of a QShield ID (raises KeyAuthError if invalid)."""
    return identity_id_from_public_bytes(parse_identity_id(text))


# ---- Identity (signing) keys ---------------------------------------------------
def generate_identity() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def identity_id(private_key: Ed25519PrivateKey) -> str:
    return identity_id_from_public_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def _password_bytes(password) -> bytes:
    data = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not data:
        raise ValueError("A password is required to protect the identity key.")
    return data


def identity_to_protected_pem(private_key: Ed25519PrivateKey, password) -> bytes:
    """Password-protected PKCS#8 PEM. This is the only form that may be saved."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519 private key.")
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_password_bytes(password)),
    )


def load_identity_from_pem(data: bytes, password) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(bytes(data), _password_bytes(password))
    except (ValueError, TypeError):
        raise ValueError("Could not open the identity file: wrong password, or the file is damaged.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("This file is not a QShield identity key.")
    return key


# ---- Encoding helpers ----------------------------------------------------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text) -> bytes:
    """Strict, canonical base64url (no padding, no whitespace, no alternate forms)."""
    if not isinstance(text, str):
        raise ValueError("not text")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("bad base64") from None
    if _b64u(raw) != text:
        raise ValueError("non-canonical base64")
    return raw


def _strict_loads(raw: bytes):
    def reject_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def reject_constant(_):
        raise ValueError("non-finite number")

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def key_id_for(kem_public_key: bytes) -> str:
    """Same value as core.pq_transfer.public_key_fingerprint(...): SHA-256 hex."""
    return hashlib.sha256(kem_public_key).hexdigest()


# ---- Creating bundles (receiver side) ----------------------------------------
def create_key_bundle(
    identity_key: Ed25519PrivateKey,
    kem_public_key: bytes,
    *,
    seq: int,
    now: int | None = None,
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    revoked_key_ids=(),
) -> bytes:
    """Sign a bundle binding `kem_public_key` to the identity. Returns envelope bytes.

    seq must increase every time the receiver publishes a new bundle.
    List compromised or retired key IDs in `revoked_key_ids`.
    Only the PUBLIC key is ever passed in; no secret ends up in the bundle."""
    if not isinstance(identity_key, Ed25519PrivateKey):
        raise TypeError("identity_key must be an Ed25519 private key.")
    kem_public_key = bytes(kem_public_key)
    if len(kem_public_key) != KEM_PUBLIC_KEY_SIZE:
        raise ValueError("kem_public_key must be a raw ML-KEM-768 public key (1184 bytes).")
    if not _is_int(seq) or seq < 1:
        raise ValueError("seq must be a positive integer.")
    if not 0 < validity_seconds <= MAX_VALIDITY_SECONDS:
        raise ValueError("validity must be between 1 second and 90 days.")
    revoked = sorted({str(k) for k in revoked_key_ids})
    if len(revoked) > MAX_REVOKED_IDS:
        raise ValueError("Too many revoked key IDs in one bundle.")
    issued = int(time.time() if now is None else now)
    claims = {
        "typ": BUNDLE_TYPE,
        "v": BUNDLE_VERSION,
        "purpose": BUNDLE_PURPOSE,
        "identity": identity_id(identity_key),
        "kem_alg": KEM_ALGORITHM,
        "kem_public_key": _b64u(kem_public_key),
        "key_id": key_id_for(kem_public_key),
        "seq": seq,
        "issued_at": issued,
        "expires_at": issued + validity_seconds,
        "revoked_key_ids": revoked,
    }
    if claims["key_id"] in revoked:
        raise ValueError("A bundle cannot revoke its own key.")
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    signature = identity_key.sign(SIGNING_DOMAIN + payload)
    envelope = {ENVELOPE_MARKER: 1, "payload": _b64u(payload), "signature": _b64u(signature)}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("ascii")


# ---- Verifying bundles (sender side) -------------------------------------------
@dataclass(frozen=True)
class VerifiedKey:
    """A receiver key that passed every check. Safe to encrypt to."""

    identity: str
    kem_public_key: bytes
    key_id: str
    seq: int
    issued_at: int
    expires_at: int
    revoked_key_ids: tuple
    rotated: bool          # True if this replaced a different key we had seen before
    previous_key_id: str | None


def _open_envelope(envelope: bytes) -> tuple[bytes, bytes]:
    if not isinstance(envelope, (bytes, bytearray)):
        raise _fail("malformed", "The key bundle is not valid data.")
    envelope = bytes(envelope)
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise _fail("malformed", "The key bundle is too large.")
    if not envelope.startswith(b"{"):
        raise _fail(
            "legacy_unsigned",
            "This is not a signed key bundle (it looks like an old, unauthenticated "
            "public key). QShield will not use it. Ask the receiver to publish a signed bundle.",
        )
    try:
        outer = _strict_loads(envelope)
        if (
            not isinstance(outer, dict)
            or set(outer) != {ENVELOPE_MARKER, "payload", "signature"}
            or outer[ENVELOPE_MARKER] != 1
            or isinstance(outer[ENVELOPE_MARKER], bool)
        ):
            raise ValueError("bad envelope")
        payload = _b64u_decode(outer["payload"])
        signature = _b64u_decode(outer["signature"])
    except (ValueError, RecursionError):
        raise _fail("malformed", "The key bundle is damaged or not in the expected format.") from None
    if len(signature) != 64:
        raise _fail("malformed", "The key bundle signature has the wrong size.")
    return payload, signature


def verify_key_bundle(
    envelope: bytes,
    expected_identity: str,
    store: "TrustStore",
    *,
    now: int | None = None,
) -> VerifiedKey:
    """Authenticate a relay-supplied key bundle for the identity the user expects.

    `expected_identity` must come from the user (out of band), never from the
    relay. The verifying key is decoded from that ID, not from the bundle.
    Raises KeyAuthError for anything wrong; returns a VerifiedKey otherwise
    and records it in `store` (anti-rollback, key-change tracking)."""
    current = int(time.time() if now is None else now)
    expected = normalize_identity_id(expected_identity)
    verifier = Ed25519PublicKey.from_public_bytes(parse_identity_id(expected))

    payload, signature = _open_envelope(envelope)
    try:
        verifier.verify(signature, SIGNING_DOMAIN + payload)
    except InvalidSignature:
        raise _fail(
            "bad_signature",
            "The key bundle was NOT signed by the identity you expected. The relay may have "
            "substituted a different key, or the QShield ID is wrong. Do not send the file.",
            expected,
        ) from None

    # The signature is valid for the expected identity; now check what it says.
    try:
        claims = _strict_loads(payload)
    except (ValueError, RecursionError):
        raise _fail("malformed", "The signed key bundle content is damaged.", expected) from None
    if not isinstance(claims, dict) or set(claims) != _PAYLOAD_FIELDS:
        raise _fail("malformed", "The key bundle has missing or unexpected fields.", expected)

    if claims["typ"] != BUNDLE_TYPE or claims["purpose"] != BUNDLE_PURPOSE:
        raise _fail("unsupported", "This signed object is not a QShield key bundle for file encryption.", expected)
    if not _is_int(claims["v"]) or claims["v"] != BUNDLE_VERSION:
        raise _fail("unsupported", "Unsupported key bundle version.", expected)
    if claims["kem_alg"] != KEM_ALGORITHM:
        raise _fail("unsupported", "Unsupported key algorithm in the bundle.", expected)
    if claims["identity"] != expected:
        raise _fail("wrong_identity", "The key bundle names a different identity than expected.", expected)

    try:
        kem_public_key = _b64u_decode(claims["kem_public_key"])
    except ValueError:
        raise _fail("malformed", "The public key in the bundle is damaged.", expected) from None
    if len(kem_public_key) != KEM_PUBLIC_KEY_SIZE:
        raise _fail("malformed", "The public key in the bundle has the wrong size.", expected)
    if claims["key_id"] != key_id_for(kem_public_key):
        raise _fail("malformed", "The key ID in the bundle does not match its public key.", expected)

    seq, issued, expires = claims["seq"], claims["issued_at"], claims["expires_at"]
    if not (_is_int(seq) and seq >= 1 and _is_int(issued) and _is_int(expires)):
        raise _fail("malformed", "The bundle numbers are invalid.", expected)
    revoked = claims["revoked_key_ids"]
    if (
        not isinstance(revoked, list)
        or len(revoked) > MAX_REVOKED_IDS
        or any(not isinstance(k, str) or len(k) != 64 for k in revoked)
        or len(set(revoked)) != len(revoked)
    ):
        raise _fail("malformed", "The revoked-key list in the bundle is invalid.", expected)
    if claims["key_id"] in revoked:
        raise _fail("malformed", "The bundle revokes its own key.", expected)

    if expires <= issued or expires - issued > MAX_VALIDITY_SECONDS:
        raise _fail("malformed", "The bundle validity period is invalid.", expected)
    if issued > current + CLOCK_SKEW_SECONDS:
        raise _fail("not_yet_valid", "The key bundle is dated in the future. Check your clock.", expected)
    if expires <= current:
        raise _fail("expired", "The key bundle has expired. Ask the receiver to publish a new one.", expected)

    rotated, previous = store.accept_bundle(
        expected, seq=seq, key_id=claims["key_id"], revoked_key_ids=revoked,
        expires_at=expires, now=current,
    )
    if rotated:
        security_log.warning(
            "receiver key rotated: identity=%s old_key=%s new_key=%s",
            _short(expected), (previous or "?")[:12], claims["key_id"][:12],
        )
    return VerifiedKey(
        identity=expected,
        kem_public_key=kem_public_key,
        key_id=claims["key_id"],
        seq=seq,
        issued_at=issued,
        expires_at=expires,
        revoked_key_ids=tuple(revoked),
        rotated=rotated,
        previous_key_id=previous,
    )
