"""Token store: random tokens, one per payment, strict status flow, no card data.

SupabaseTokenStore is tested against a small FAKE client that mimics the few
supabase-py calls we use. That checks our logic, NOT a real Supabase project.
"""
import dataclasses
from datetime import datetime, timezone

import pytest

from core.mock_provider import charge
from core.token_store import (
    MemoryTokenStore, SupabaseTokenStore, TokenError, new_token, TOKEN_RE,
)

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


def payment(card="4111111111111111", key="k"):
    return charge(card_number=card, expiry="12/30", cvv="123", amount_paise=49900,
                  idempotency_key=key, ledger={}, now=NOW)


class FakeQuery:
    def __init__(self, rows, op, payload=None):
        self.rows, self.op, self.payload, self.filters = rows, op, payload, []

    def select(self, _cols="*"):
        return self

    def eq(self, col, val):
        self.filters.append((col, val))
        return self

    def execute(self):
        match = [r for r in self.rows if all(r.get(c) == v for c, v in self.filters)]
        if self.op == "insert":
            if any(r["token"] == self.payload["token"] or r["payment_ref"] == self.payload["payment_ref"]
                   for r in self.rows):
                raise RuntimeError("duplicate key value violates unique constraint")
            row = dict(self.payload, created_at="t0", updated_at="t0")
            self.rows.append(row)
            return type("R", (), {"data": [row]})
        if self.op == "update":
            for r in match:
                r.update(self.payload)
            return type("R", (), {"data": match})
        return type("R", (), {"data": match})


class FakeSupabase:
    def __init__(self):
        self.rows = []

    def table(self, name):
        assert name == "payment_tokens"
        outer = self

        class T:
            def select(self, cols="*"):
                return FakeQuery(outer.rows, "select").select(cols)

            def insert(self, row):
                return FakeQuery(outer.rows, "insert", row)

            def update(self, values):
                return FakeQuery(outer.rows, "update", values)
        return T()


@pytest.fixture(params=["memory", "supabase"])
def store(request):
    return MemoryTokenStore() if request.param == "memory" else SupabaseTokenStore(FakeSupabase())


def test_token_is_random_and_well_formed():
    a, b = new_token(), new_token()
    assert a != b and TOKEN_RE.match(a)


def test_issue_for_successful_payment(store):
    rec = store.issue(payment())
    assert TOKEN_RE.match(rec.token) and rec.status == "created"
    assert rec.last4 == "1111" and rec.amount_paise == 49900


def test_token_and_record_contain_no_card_number(store):
    rec = store.issue(payment())
    assert "4111111111111111" not in repr(dataclasses.asdict(rec))
    assert "4111111111111111" not in rec.token


def test_same_payment_gives_same_token_different_payment_new_token(store):
    p1 = payment(key="a")
    assert store.issue(p1).token == store.issue(p1).token
    assert store.issue(payment(key="b")).token != store.issue(p1).token


def test_declined_payment_gets_no_token(store):
    with pytest.raises(TokenError, match="successful"):
        store.issue(payment(card="4000000000000002"))


def test_status_flow(store):
    rec = store.issue(payment())
    assert store.advance(rec.token, "sent").status == "sent"
    assert store.advance(rec.token, "approved").status == "approved"
    assert store.get(rec.token).status == "approved"


@pytest.mark.parametrize("path", [["approved"], ["sent", "created"], ["sent", "approved", "sent"],
                                  ["sent", "rejected", "approved"]])
def test_illegal_transitions_rejected(store, path):
    rec = store.issue(payment())
    with pytest.raises(TokenError):
        for status in path:
            store.advance(rec.token, status)


def test_bad_or_unknown_token(store):
    for bad in ["", "ptok_short", "abc", "ptok_" + "!" * 32, None]:
        with pytest.raises(TokenError):
            store.get(bad)
    assert store.get(new_token()) is None
    with pytest.raises(TokenError, match="not found"):
        store.advance(new_token(), "sent")


def test_supabase_concurrent_change_is_not_silently_overwritten():
    fake = FakeSupabase()
    s = SupabaseTokenStore(fake)
    rec = s.issue(payment())
    original_get = s.get

    def stale_get(token):  # someone else moves it to 'sent' right after we read 'created'
        r = original_get(token)
        fake.rows[0]["status"] = "sent"
        return r
    s.get = stale_get
    with pytest.raises(TokenError, match="changed"):
        s.advance(rec.token, "sent")


def test_supabase_failure_is_an_error_not_a_silent_fallback():
    class Broken:
        def table(self, _):
            raise RuntimeError("network down")
    with pytest.raises(TokenError, match="Supabase"):
        SupabaseTokenStore(Broken()).issue(payment())
