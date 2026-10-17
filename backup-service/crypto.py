"""Demo-only AES-GCM envelope. Both Render services hold the same secret key."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from logic import b64, unb64


class StandbyCipher:
    def __init__(self, key_b64=None):
        encoded = key_b64 if key_b64 is not None else os.environ["BACKUP_AES_KEY_B64"]
        if isinstance(encoded, str):
            encoded = encoded.strip()
        try:
            key = unb64(encoded)
        except (ValueError, TypeError) as exc:
            raise ValueError("BACKUP_AES_KEY_B64 must be valid base64.") from exc
        if len(key) != 32:
            raise ValueError("BACKUP_AES_KEY_B64 must encode exactly 32 bytes.")
        self.aes = AESGCM(key)

    def encrypt(self, request_id, payload):
        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, payload, request_id.encode("ascii"))
        return {"version": 1, "request_id": request_id,
                "nonce": b64(nonce), "ciphertext": b64(ciphertext)}

    def decrypt(self, envelope):
        if envelope.get("version") != 1 or not isinstance(envelope.get("request_id"), str):
            raise ValueError("Unsupported backup envelope.")
        try:
            nonce = unb64(envelope["nonce"])
            ciphertext = unb64(envelope["ciphertext"])
            if len(nonce) != 12:
                raise ValueError("Invalid nonce.")
            return self.aes.decrypt(nonce, ciphertext, envelope["request_id"].encode("ascii"))
        except (InvalidTag, TypeError, UnicodeEncodeError) as exc:
            raise ValueError("Backup encryption verification failed.") from exc
