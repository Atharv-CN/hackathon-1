"""Remembers which receiver keys QShield has accepted for each identity.

Why it exists (the signature check alone is not enough)
  A relay can replay an OLD but still valid bundle. The store remembers the
  highest bundle number (`seq`) and the key ID seen for each identity, so:
    - an older bundle is rejected (rollback),
    - two different keys at the same number are rejected (equivocation),
    - a key the identity revoked is never accepted again,
    - a legitimate rotation (higher number, signed by the same identity) is
      accepted but reported, never silent.

What it is NOT
  It does not decide who to trust. Trust comes from the QShield ID the user
  supplies out of band. Forgetting a contact is an explicit, logged action.
  Without a file path the store lives only in memory (export/import it as JSON
  to keep it between sessions).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core.identity import KeyAuthError, _fail, security_log, _short

_STORE_VERSION = 1
_MAX_HISTORY = 50
_MAX_STORE_BYTES = 1024 * 1024
_RECORD_FIELDS = {"label", "source", "first_seen", "seq", "key_id", "revoked", "history"}


class TrustStoreError(Exception):
    """The trust store file is damaged or not valid. QShield refuses to guess."""


class TrustStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.records: dict[str, dict] = {}
        if self.path is not None and self.path.exists():
            self.records = self._parse(self.path.read_bytes())

    # -- persistence -------------------------------------------------------------
    @staticmethod
    def _parse(raw: bytes) -> dict:
        if len(raw) > _MAX_STORE_BYTES:
            raise TrustStoreError("The trust store file is too large.")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise TrustStoreError("The trust store file is damaged. Restore it from a backup.") from None
        if not isinstance(data, dict) or data.get("version") != _STORE_VERSION or not isinstance(data.get("contacts"), dict):
            raise TrustStoreError("The trust store file has an unsupported format.")
        for identity, rec in data["contacts"].items():
            if (
                not isinstance(identity, str)
                or not isinstance(rec, dict)
                or set(rec) != _RECORD_FIELDS
                or not isinstance(rec["seq"], int) or isinstance(rec["seq"], bool)
                or not (rec["key_id"] is None or isinstance(rec["key_id"], str))
                or not isinstance(rec["revoked"], list)
                or not all(isinstance(k, str) for k in rec["revoked"])
                or not isinstance(rec["history"], list)
            ):
                raise TrustStoreError("The trust store file has an invalid entry.")
        return data["contacts"]

    @classmethod
    def from_json(cls, raw: bytes) -> "TrustStore":
        store = cls()
        store.records = cls._parse(raw)
        return store

    def to_json(self) -> bytes:
        return json.dumps(
            {"version": _STORE_VERSION, "contacts": self.records}, indent=2, sort_keys=True
        ).encode("utf-8")

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".trust-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(self.to_json())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)  # atomic: never leaves a half-written store
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- contacts ----------------------------------------------------------------
    def get(self, identity: str) -> dict | None:
        return self.records.get(identity)

    def pin_identity(self, identity: str, label: str = "", source: str = "out_of_band") -> None:
        """Record that the user chose to trust this identity. `source` is kept for audit
        ("out_of_band" = ID received over a separate channel, "tofu" = first use)."""
        if identity not in self.records:
            self.records[identity] = {
                "label": label, "source": source, "first_seen": None,
                "seq": 0, "key_id": None, "revoked": [], "history": [],
            }
            security_log.info("identity pinned: identity=%s source=%s", _short(identity), source)
            self._save()

    def forget(self, identity: str) -> None:
        """Explicitly remove a contact. This also drops rollback and revocation memory,
        so it is logged and should only follow a deliberate re-verification."""
        if self.records.pop(identity, None) is not None:
            security_log.warning("contact forgotten: identity=%s", _short(identity))
            self._save()

    # -- the checks --------------------------------------------------------------
    def accept_bundle(self, identity: str, *, seq: int, key_id: str, revoked_key_ids, expires_at: int, now: int):
        """Check a bundle (already signature-verified) against what we remember, then record it.

        Returns (rotated, previous_key_id). Raises KeyAuthError and records nothing on failure."""
        rec = self.records.get(identity)
        known_revoked = set(rec["revoked"]) if rec else set()
        if key_id in known_revoked:
            raise _fail("revoked", "This key was revoked by its owner. Do not use it.", identity)
        if rec is not None and rec["key_id"] is not None:
            if seq < rec["seq"]:
                raise _fail(
                    "rollback",
                    "This key bundle is older than one QShield has already seen for this "
                    "identity. A relay may be replaying an old key. Do not send the file.",
                    identity,
                )
            if seq == rec["seq"] and key_id != rec["key_id"]:
                raise _fail(
                    "equivocation",
                    "Two different keys were presented with the same bundle number for this "
                    "identity. Do not send the file; contact the receiver.",
                    identity,
                )

        previous = rec["key_id"] if rec else None
        rotated = previous is not None and previous != key_id
        if rec is None:
            self.pin_identity(identity)
            rec = self.records[identity]
        rec["seq"] = max(rec["seq"], seq)
        rec["key_id"] = key_id
        rec["first_seen"] = rec["first_seen"] or now
        rec["revoked"] = sorted(known_revoked | set(revoked_key_ids))
        rec["history"] = (rec["history"] + [{"seq": seq, "key_id": key_id, "seen_at": now}])[-_MAX_HISTORY:]
        self._save()
        return rotated, previous if rotated else None
