"""Private-key storage with explicit KDF parameters and pluggable providers.

WHY THIS EXISTS
  pq_transfer.private_key_to_protected_pem() uses BestAvailableEncryption. That
  gives you an encrypted PKCS#8 file whose KDF and parameters are chosen by the
  library, not by QShield. This module owns the file format instead:

  * the private key is stored as its 64-byte ML-KEM seed (FIPS 203 d || z),
  * encrypted with AES-256-GCM,
  * under a 32-byte key that comes from a PROVIDER:
      - PassphraseProvider: Argon2id (default) or scrypt, parameters in the header
      - KeyringProvider:    random key held in the OS keychain (via `keyring`)
      - EnvelopeProvider:   a data key wrapped by an external KMS / HSM that
                            YOU implement (see KeyWrapper)
  * the whole header is authenticated (AES-GCM associated data), so changing the
    parameters, the provider id or the key-type label makes decryption fail.

FILE LAYOUT (version 1)
  "QSKF" | version (1 byte) | header length (2 bytes, big endian)
  | header (canonical JSON) | nonce (12 bytes) | AES-256-GCM(seed) + tag

  header = {"kty": "ML-KEM-768", "fp": <sha256 of public key, hex>,
            "prov": <provider id>, "pp": <provider parameters>}
  Nothing secret is in the header.

LIMITS - please read
  * Parameters read from a file are capped (MAX_*) so a hostile key file cannot
    make the loader allocate gigabytes. Raise the caps deliberately if you need to.
  * "kty" is a plain string here. If your tagged key format (suite ID + key
    bytes) lands, put that tag in "kty" so it is bound by the AEAD.
  * Argon2id / scrypt defaults are starting points. Benchmark on your slowest
    supported device and set explicit values.
  * Cloud-KMS and HSM support is a HOOK (KeyWrapper). No AWS / GCP / Azure /
    PKCS#11 code is included, because none has been tested here.
  * Python cannot reliably wipe secrets from memory.
  * Not independently audited.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"QSKF"
FILE_VERSION = 1
KEY_TYPE = "ML-KEM-768"
SEED_SIZE = 64
AEAD_KEY_SIZE = 32
NONCE_SIZE = 12
_PREFIX = struct.Struct(">4sBH")
_MAX_HEADER = 4096

# Caps enforced when READING a file (defence against hostile parameters).
MAX_ARGON2_MEMORY_KIB = 1 << 20      # 1 GiB
MAX_ARGON2_ITERATIONS = 10
MAX_ARGON2_LANES = 16
MAX_SCRYPT_MEMORY_BYTES = 1 << 30    # 1 GiB  (128 * n * r)
MAX_SCRYPT_P = 16

# Starting points. Argon2id: RFC 9106 section 4 "second recommended option"
# (t=3, p=4, 64 MiB). scrypt: N=2^17, r=8, p=1.
DEFAULT_ARGON2ID = {"m_kib": 64 * 1024, "t": 3, "p": 4}
DEFAULT_SCRYPT = {"n": 1 << 17, "r": 8, "p": 1}


class KeyStorageError(ValueError):
    """The key file could not be read, written, or opened."""


# ---- Provider interface -------------------------------------------------------
class KeyProvider(Protocol):
    """Supplies the 32-byte AES key that protects the seed.

    `context` is bytes that identify the key being protected (key type and
    public-key fingerprint). Providers that can bind a context (for example a
    KMS "encryption context") should do so.
    """

    provider_id: str

    def new_key(self, context: bytes) -> tuple[bytes, dict]:
        """Return (aead_key, provider_params). provider_params must be
        JSON-serialisable and must NOT contain secrets."""
        ...

    def recover_key(self, params: dict, context: bytes) -> bytes:
        """Return the same aead_key again from the stored provider_params."""
        ...


# ---- KDF helpers --------------------------------------------------------------
def _int_param(params: dict, name: str, low: int, high: int) -> int:
    v = params.get(name)
    if not isinstance(v, int) or isinstance(v, bool) or not (low <= v <= high):
        raise KeyStorageError(f"KDF parameter {name!r} is missing or outside the allowed range.")
    return v


def derive_argon2id(passphrase: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    return Argon2id(
        salt=salt, length=AEAD_KEY_SIZE, iterations=t, lanes=p, memory_cost=m_kib
    ).derive(passphrase)


def derive_scrypt(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=AEAD_KEY_SIZE, n=n, r=r, p=p).derive(passphrase)


def _passphrase_bytes(value) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if not data:
        raise KeyStorageError("A passphrase is required to protect the private key file.")
    return data


# ---- Provider 1: passphrase ---------------------------------------------------
class PassphraseProvider:
    """Argon2id or scrypt over a passphrase. Parameters are stored in the header."""

    provider_id = "passphrase"

    def __init__(self, passphrase: Union[str, bytes, Callable[[], Union[str, bytes]]],
                 kdf: str = "argon2id", params: Optional[dict] = None):
        if kdf not in ("argon2id", "scrypt"):
            raise KeyStorageError("kdf must be 'argon2id' or 'scrypt'.")
        self._passphrase = passphrase
        self.kdf = kdf
        self.params = dict(params or (DEFAULT_ARGON2ID if kdf == "argon2id" else DEFAULT_SCRYPT))
        self._check(self.kdf, self.params)       # refuse bad parameters at save time too

    def _get(self) -> bytes:
        v = self._passphrase() if callable(self._passphrase) else self._passphrase
        return _passphrase_bytes(v)

    @staticmethod
    def _check(kdf: str, params: dict) -> None:
        if kdf == "argon2id":
            p = _int_param(params, "p", 1, MAX_ARGON2_LANES)
            _int_param(params, "m_kib", 8 * p, MAX_ARGON2_MEMORY_KIB)
            _int_param(params, "t", 1, MAX_ARGON2_ITERATIONS)
        elif kdf == "scrypt":
            n = _int_param(params, "n", 2, 1 << 24)
            r = _int_param(params, "r", 1, 32)
            _int_param(params, "p", 1, MAX_SCRYPT_P)
            if n & (n - 1):
                raise KeyStorageError("scrypt n must be a power of two.")
            if 128 * n * r > MAX_SCRYPT_MEMORY_BYTES:
                raise KeyStorageError("scrypt memory cost exceeds the allowed limit.")
        else:
            raise KeyStorageError("Unknown KDF in key file.")

    def _derive(self, kdf: str, salt: bytes, params: dict) -> bytes:
        self._check(kdf, params)
        pw = self._get()
        if kdf == "argon2id":
            return derive_argon2id(pw, salt, params["m_kib"], params["t"], params["p"])
        return derive_scrypt(pw, salt, params["n"], params["r"], params["p"])

    def new_key(self, context: bytes):
        salt = os.urandom(16)
        key = self._derive(self.kdf, salt, self.params)
        return key, {"kdf": self.kdf, "salt": salt.hex(), **self.params}

    def recover_key(self, params: dict, context: bytes) -> bytes:
        kdf = params.get("kdf")
        try:
            salt = bytes.fromhex(params["salt"])
        except (KeyError, ValueError, TypeError):
            raise KeyStorageError("Key file has an invalid salt.") from None
        if len(salt) < 8:
            raise KeyStorageError("Key file has an invalid salt.")
        names = ("m_kib", "t", "p") if kdf == "argon2id" else ("n", "r", "p")
        return self._derive(kdf, salt, {k: params.get(k) for k in names})


# ---- Provider 2: OS keychain --------------------------------------------------
class KeyringProvider:
    """Keeps a random 32-byte key in the OS keychain; the seed stays in the file.

    The seed itself is not put in the keychain: some backends limit secret size,
    and keeping the ciphertext in a file keeps the keychain entry small.
    Needs the optional `keyring` package, or pass any object with
    get_password(service, username) / set_password(service, username, password).
    """

    provider_id = "keyring"

    def __init__(self, service: str = "qshield", keyring_module=None):
        if keyring_module is None:
            try:
                import keyring as keyring_module   # optional dependency
            except ImportError:
                raise KeyStorageError("The 'keyring' package is not installed.") from None
        self.service, self._kr = service, keyring_module

    def new_key(self, context: bytes):
        account = "qshield-" + os.urandom(8).hex()
        key = os.urandom(AEAD_KEY_SIZE)
        self._kr.set_password(self.service, account,
                              base64.b64encode(key).decode("ascii"))
        return key, {"service": self.service, "account": account}

    def recover_key(self, params: dict, context: bytes) -> bytes:
        service, account = params.get("service"), params.get("account")
        if not isinstance(service, str) or not isinstance(account, str):
            raise KeyStorageError("Key file has invalid keychain parameters.")
        stored = self._kr.get_password(service, account)
        if stored is None:
            raise KeyStorageError("The keychain entry for this key file was not found.")
        try:
            key = base64.b64decode(stored, validate=True)
        except Exception:
            raise KeyStorageError("The keychain entry is damaged.") from None
        if len(key) != AEAD_KEY_SIZE:
            raise KeyStorageError("The keychain entry is damaged.")
        return key


# ---- Provider 3: envelope encryption (KMS / HSM hook) --------------------------
class KeyWrapper(Protocol):
    """Implement this for AWS KMS, GCP KMS, Azure Key Vault, a PKCS#11 HSM, etc.

    wrap() must encrypt `data_key` (32 bytes) under a key that never leaves the
    service, and return an opaque blob. Bind `context` as the service's
    encryption context / AAD if it supports one. unwrap() reverses it.
    """

    wrapper_id: str   # short label, e.g. "aws-kms:arn..." (stored in the header)

    def wrap(self, data_key: bytes, context: bytes) -> bytes: ...
    def unwrap(self, blob: bytes, context: bytes) -> bytes: ...


class EnvelopeProvider:
    """A fresh random data key protects the seed locally; the KeyWrapper protects
    only the data key. The wrapped data key is stored in the file header."""

    provider_id = "envelope"

    def __init__(self, wrapper: KeyWrapper):
        self.wrapper = wrapper

    def new_key(self, context: bytes):
        dek = os.urandom(AEAD_KEY_SIZE)
        blob = self.wrapper.wrap(dek, context)
        return dek, {"wrapper": self.wrapper.wrapper_id,
                     "wrapped": base64.b64encode(blob).decode("ascii")}

    def recover_key(self, params: dict, context: bytes) -> bytes:
        if params.get("wrapper") != self.wrapper.wrapper_id:
            raise KeyStorageError("This key file was wrapped by a different key service.")
        try:
            blob = base64.b64decode(params["wrapped"], validate=True)
        except Exception:
            raise KeyStorageError("Key file has a damaged wrapped key.") from None
        dek = self.wrapper.unwrap(blob, context)
        if len(dek) != AEAD_KEY_SIZE:
            raise KeyStorageError("The key service returned an unexpected key size.")
        return dek


# ---- Serialisation ------------------------------------------------------------
def _fingerprint(public_key: MLKEM768PublicKey) -> bytes:
    # Same definition as pq_transfer._fingerprint_bytes
    return hashlib.sha256(public_key.public_bytes_raw()).digest()


def _context(fp: bytes) -> bytes:
    return b"QShield key file v1|" + KEY_TYPE.encode() + b"|" + fp


def dumps_private_key(private_key: MLKEM768PrivateKey, provider: KeyProvider) -> bytes:
    """Return the protected private-key file as bytes."""
    if not isinstance(private_key, MLKEM768PrivateKey):
        raise TypeError("private_key must be an ML-KEM-768 private key.")
    seed = private_key.private_bytes_raw()
    if len(seed) != SEED_SIZE:
        raise KeyStorageError("Unexpected private key size. Stopping.")
    fp = _fingerprint(private_key.public_key())
    aead_key, pparams = provider.new_key(_context(fp))
    header = json.dumps(
        {"kty": KEY_TYPE, "fp": fp.hex(), "prov": provider.provider_id, "pp": pparams},
        sort_keys=True, separators=(",", ":")).encode()
    if len(header) > _MAX_HEADER:
        raise KeyStorageError("Key file header too large.")
    prefix = _PREFIX.pack(MAGIC, FILE_VERSION, len(header))
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(aead_key).encrypt(nonce, seed, prefix + header)
    return prefix + header + nonce + ct


def loads_private_key(data: bytes, provider: KeyProvider) -> MLKEM768PrivateKey:
    """Open a file made by dumps_private_key()."""
    generic = KeyStorageError("Could not open the key file: wrong password or key, or the file is damaged.")
    data = bytes(data)
    if len(data) < _PREFIX.size:
        raise KeyStorageError("This is not a QShield key file.")
    magic, version, hlen = _PREFIX.unpack_from(data, 0)
    if magic != MAGIC:
        raise KeyStorageError("This is not a QShield key file.")
    if version != FILE_VERSION:
        raise KeyStorageError(f"Unsupported key file version: {version}.")
    if hlen > _MAX_HEADER or len(data) < _PREFIX.size + hlen + NONCE_SIZE + SEED_SIZE + 16:
        raise KeyStorageError("The key file is damaged.")
    prefix = data[:_PREFIX.size]
    header_bytes = data[_PREFIX.size:_PREFIX.size + hlen]
    try:
        header = json.loads(header_bytes)
        kty, fp, prov, pparams = header["kty"], bytes.fromhex(header["fp"]), header["prov"], header["pp"]
    except Exception:
        raise KeyStorageError("The key file is damaged.") from None
    if kty != KEY_TYPE:
        raise KeyStorageError(f"This key file holds a {kty!r} key, not {KEY_TYPE}.")
    if prov != provider.provider_id:
        raise KeyStorageError(f"This key file needs the {prov!r} provider, not {provider.provider_id!r}.")
    if len(fp) != 32 or not isinstance(pparams, dict):
        raise KeyStorageError("The key file is damaged.")

    body = data[_PREFIX.size + hlen:]
    nonce, ct = body[:NONCE_SIZE], body[NONCE_SIZE:]
    try:
        aead_key = provider.recover_key(pparams, _context(fp))
        seed = AESGCM(aead_key).decrypt(nonce, ct, prefix + header_bytes)
    except InvalidTag:
        raise generic from None
    key = MLKEM768PrivateKey.from_seed_bytes(seed)
    if not hmac.compare_digest(_fingerprint(key.public_key()), fp):
        raise KeyStorageError("The key file does not match its stored fingerprint.")
    return key


# ---- Files on disk -------------------------------------------------------------
def save_private_key_file(private_key: MLKEM768PrivateKey, path, provider: KeyProvider,
                          overwrite: bool = False) -> Path:
    """Write the protected key to `path` (owner-only permissions on Linux/macOS).

    An existing file is never replaced unless overwrite=True. Overwrites are
    written to a temp file and then renamed, so a crash cannot leave a
    half-written key file.
    """
    blob = dumps_private_key(private_key, provider)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    binary = getattr(os, "O_BINARY", 0)
    if not overwrite:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        return path
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".qskf-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load_private_key_file(path, provider: KeyProvider) -> MLKEM768PrivateKey:
    return loads_private_key(Path(path).read_bytes(), provider)


# ---- Migration from the old BestAvailableEncryption PEM -------------------------
def is_legacy_pem(data: bytes) -> bool:
    return bytes(data).lstrip().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def migrate_legacy_pem(pem: bytes, old_password, provider: KeyProvider) -> bytes:
    """Open an old encrypted-PEM key (pq_transfer.private_key_to_protected_pem)
    and return it re-protected in the new format under `provider`."""
    from core.pq_transfer import load_private_key_from_bytes
    key = load_private_key_from_bytes(pem, old_password)
    return dumps_private_key(key, provider)
