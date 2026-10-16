"""Tiny Supabase relay so two devices can exchange QShield data.

Only two kinds of data ever go through here:
  - "pubkey":  a receiver's PUBLIC key (safe to share)
  - "package": an already-encrypted .qshield package (unreadable without the
               receiver's private key)

Private keys and original files never touch this module.

Setup: see README "Two-device demo". Needs SUPABASE_URL and
SUPABASE_SERVICE_KEY (environment variables, or Streamlit secrets).
"""

from __future__ import annotations  # lets "str | None" work on Python 3.9 too

import base64
import os
import secrets

MAX_BYTES = 5 * 1024 * 1024  # keep demo transfers small
_client = None


class RelayError(Exception):
    """Raised with a plain-English message when the relay can't be used."""


def _setting(name: str):
    value = os.environ.get(name)
    if value:
        return value
    try:
        import streamlit as st

        return st.secrets.get(name)
    except Exception:
        return None


def is_configured() -> bool:
    return bool(_setting("SUPABASE_URL") and _setting("SUPABASE_SERVICE_KEY"))


def _sb():
    global _client
    if _client is None:
        url, key = _setting("SUPABASE_URL"), _setting("SUPABASE_SERVICE_KEY")
        if not (url and key):
            raise RelayError(
                "Relay is not configured: set SUPABASE_URL and SUPABASE_SERVICE_KEY."
            )
        from supabase import create_client

        _client = create_client(url, key)
    return _client


def put(kind: str, data: bytes, filename: str | None = None) -> str:
    """Store bytes and return a short code the other device can use."""
    if kind not in ("pubkey", "package"):
        raise ValueError("kind must be 'pubkey' or 'package'")
    if len(data) > MAX_BYTES:
        raise RelayError("That is too large for the relay (limit 5 MB). Use a smaller test file.")
    code = secrets.token_urlsafe(6)
    try:
        _sb().table("transfers").insert(
            {
                "id": code,
                "kind": kind,
                "payload": base64.b64encode(data).decode(),
                "filename": filename,
            }
        ).execute()
    except RelayError:
        raise
    except Exception as exc:
        raise RelayError(f"Could not reach the relay: {exc}") from exc
    return code


def get(code: str, kind: str):
    """Return (bytes, filename), or (None, None) if the code is not found."""
    code = (code or "").strip()
    if not code:
        return None, None
    try:
        result = (
            _sb().table("transfers").select("*").eq("id", code).eq("kind", kind).execute()
        )
    except RelayError:
        raise
    except Exception as exc:
        raise RelayError(f"Could not reach the relay: {exc}") from exc
    if not result.data:
        return None, None
    row = result.data[0]
    return base64.b64decode(row["payload"]), row["filename"]


def delete(code: str) -> None:
    """Remove a stored item (best effort)."""
    try:
        _sb().table("transfers").delete().eq("id", (code or "").strip()).execute()
    except Exception:
        pass
