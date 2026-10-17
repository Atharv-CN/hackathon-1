"""Payment tokens and their status (created -> sent -> approved / rejected).

A token (`ptok_...`) is a RANDOM reference for one successful payment. It is not
derived from the card and cannot be turned back into one. This module never sees
a card number: it only gets a PaymentResult (brand, last 4, amount, reference).

Two backends with the same methods:
  - SupabaseTokenStore : real Postgres (table `payment_tokens`, see SQL below)
  - MemoryTokenStore   : lives in the server process only; lost on restart.
                         The UI says so; it is never presented as persistent.

If Supabase is configured but fails, we raise an error. We never quietly fall
back to memory, because that would hide that nothing was saved.

SQL (run once in Supabase -> SQL Editor):

    create table payment_tokens (
      token        text primary key,
      payment_ref  text unique not null,
      brand        text,
      last4        text check (last4 ~ '^[0-9]{4}$'),
      amount_paise bigint not null,
      currency     text not null,
      status       text not null check (status in ('created','sent','approved','rejected')),
      created_at   timestamptz not null default now(),
      updated_at   timestamptz not null default now()
    );
    alter table payment_tokens enable row level security;  -- no policies: only the secret key can use it
"""

from __future__ import annotations

import re
import secrets
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone

TOKEN_RE = re.compile(r"^ptok_[A-Za-z0-9_-]{32}$")

# status -> statuses it may move to. approved/rejected are final.
ALLOWED_TRANSITIONS = {
    "created": {"sent"},
    "sent": {"approved", "rejected"},
    "approved": set(),
    "rejected": set(),
}


class TokenError(Exception):
    """Plain-English problem with a token or its storage."""


@dataclass(frozen=True)
class TokenRecord:
    token: str
    payment_ref: str
    brand: str
    last4: str
    amount_paise: int
    currency: str
    status: str
    created_at: str
    updated_at: str


def new_token() -> str:
    return "ptok_" + secrets.token_urlsafe(24)  # 24 random bytes -> 32 chars


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _check_token(token: str) -> str:
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        raise TokenError("That is not a valid token.")
    return token


def _check_transition(old: str, new: str) -> None:
    if new not in ALLOWED_TRANSITIONS.get(old, set()):
        raise TokenError(f"A token cannot go from '{old}' to '{new}'.")


def _require_succeeded(result) -> None:
    if getattr(result, "status", None) != "succeeded":
        raise TokenError("Tokens are only created for successful payments.")


class MemoryTokenStore:
    name = "In-memory (NOT persistent: lost when the server restarts)"
    persistent = False

    def __init__(self) -> None:
        self._by_token: dict[str, TokenRecord] = {}
        self._by_ref: dict[str, str] = {}
        self._lock = threading.Lock()

    def issue(self, result) -> TokenRecord:
        """Create the token for a successful payment. Same payment -> same token."""
        _require_succeeded(result)
        with self._lock:
            existing = self._by_ref.get(result.provider_ref)
            if existing:
                return self._by_token[existing]
            now = _now()
            rec = TokenRecord(new_token(), result.provider_ref, result.brand, result.last4,
                              result.amount_paise, result.currency, "created", now, now)
            self._by_token[rec.token] = rec
            self._by_ref[rec.payment_ref] = rec.token
            return rec

    def get(self, token: str) -> TokenRecord | None:
        return self._by_token.get(_check_token(token))

    def advance(self, token: str, new_status: str) -> TokenRecord:
        _check_token(token)
        with self._lock:
            rec = self._by_token.get(token)
            if rec is None:
                raise TokenError("Token not found.")
            _check_transition(rec.status, new_status)
            rec = replace(rec, status=new_status, updated_at=_now())
            self._by_token[token] = rec
            return rec


class SupabaseTokenStore:
    name = "Supabase Postgres"
    persistent = True

    def __init__(self, client) -> None:
        self._sb = client

    def _table(self):
        return self._sb.table("payment_tokens")

    @staticmethod
    def _rec(row: dict) -> TokenRecord:
        return TokenRecord(
            token=row["token"], payment_ref=row["payment_ref"], brand=row.get("brand") or "",
            last4=row.get("last4") or "", amount_paise=int(row["amount_paise"]),
            currency=row["currency"], status=row["status"],
            created_at=str(row.get("created_at", "")), updated_at=str(row.get("updated_at", "")),
        )

    def _find_by_ref(self, ref: str) -> TokenRecord | None:
        rows = self._table().select("*").eq("payment_ref", ref).execute().data
        return self._rec(rows[0]) if rows else None

    def issue(self, result) -> TokenRecord:
        _require_succeeded(result)
        try:
            existing = self._find_by_ref(result.provider_ref)
            if existing:
                return existing
            row = {
                "token": new_token(), "payment_ref": result.provider_ref,
                "brand": result.brand, "last4": result.last4,
                "amount_paise": result.amount_paise, "currency": result.currency,
                "status": "created",
            }
            try:
                inserted = self._table().insert(row).execute().data
            except Exception:
                # Another request may have inserted the same payment a moment ago.
                existing = self._find_by_ref(result.provider_ref)
                if existing:
                    return existing
                raise
            return self._rec(inserted[0] if inserted else row)
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError(f"Could not save the token to Supabase: {exc}") from exc

    def get(self, token: str) -> TokenRecord | None:
        _check_token(token)
        try:
            rows = self._table().select("*").eq("token", token).execute().data
        except Exception as exc:
            raise TokenError(f"Could not read the token from Supabase: {exc}") from exc
        return self._rec(rows[0]) if rows else None

    def advance(self, token: str, new_status: str) -> TokenRecord:
        rec = self.get(token)
        if rec is None:
            raise TokenError("Token not found.")
        _check_transition(rec.status, new_status)
        try:
            # Only update if the status is still what we just read (no lost updates).
            rows = (self._table().update({"status": new_status, "updated_at": _now()})
                    .eq("token", token).eq("status", rec.status).execute().data)
        except Exception as exc:
            raise TokenError(f"Could not update the token in Supabase: {exc}") from exc
        if not rows:
            raise TokenError("The token changed while you were updating it. Reload and try again.")
        return self._rec(rows[0])


_MEMORY = MemoryTokenStore()


def get_store():
    """Supabase when configured, otherwise the (clearly labelled) memory store."""
    import relay

    if relay.is_configured():
        try:
            return SupabaseTokenStore(relay._sb())
        except Exception as exc:
            raise TokenError(f"Supabase is configured but not usable: {exc}") from exc
    return _MEMORY


def as_dict(rec: TokenRecord) -> dict:
    return asdict(rec)
