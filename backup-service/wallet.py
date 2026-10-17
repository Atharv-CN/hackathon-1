"""Separate Wallet API: verify the encrypted handoff before accepting its token."""

import json
import logging
import os
import re
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from crypto import StandbyCipher
from logic import TEST_ID, authenticate, request_digest, validate_handoff
from storage import NeonStore

app = FastAPI(title="QShield standby Wallet verifier")
REVIEWER = re.compile(r"^[A-Za-z0-9_.@-]{1,80}$")
logger = logging.getLogger("uvicorn.error")


@app.get("/health")
def health():
    return {"status": "up"}


@app.post("/v1/wallet/accept")
async def accept(request: Request, x_timestamp: str = Header(default=""),
                 x_signature: str = Header(default="")):
    body = await request.body()
    if not authenticate(os.environ.get("WALLET_TO_BACKUP_SECRET"), x_timestamp, x_signature,
                        request.url.path, body):
        raise HTTPException(401, "Invalid or expired Wallet signature.")
    try:
        command = json.loads(body)
        if (not isinstance(command, dict) or set(command) != {"request_id", "reviewer_id"}
                or not isinstance(command["request_id"], str)
                or not TEST_ID.fullmatch(command["request_id"])
                or not isinstance(command["reviewer_id"], str)
                or not REVIEWER.fullmatch(command["reviewer_id"])):
            raise ValueError("Expected request_id and reviewer_id.")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc

    store = NeonStore()
    record = store.get(command["request_id"])
    if record is None:
        raise HTTPException(404, "Unknown handoff.")
    if record.get("wallet_status") not in ("pending", "accepted"):
        raise HTTPException(409, "Handoff is not pending.")
    try:
        envelope = {key: record[key] for key in ("version", "request_id", "nonce", "ciphertext")}
        if envelope["version"] != 1 or envelope["request_id"] != command["request_id"]:
            raise ValueError("Unsupported or mismatched backup envelope.")
        payload = validate_handoff(json.loads(StandbyCipher().decrypt(envelope)))
        if (payload["request_id"] != command["request_id"] or
                payload["token_id"] != record["token_id"] or
                request_digest(payload) != record["request_digest"]):
            raise ValueError("Handoff contents do not match the record.")
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    if record["wallet_status"] == "accepted":
        return {"request_id": command["request_id"], "wallet_status": "accepted", "created": False}
    changed = store.accept(command["request_id"], command["reviewer_id"],
                           datetime.now(timezone.utc).isoformat())
    if not changed:
        latest = store.get(command["request_id"])
        if latest is not None and latest.get("wallet_status") == "accepted":
            return {"request_id": command["request_id"], "wallet_status": "accepted", "created": False}
        raise HTTPException(409, "Handoff changed during Wallet acceptance.")
    logger.info("Backup handoff accepted request_id=%s reviewer_id=%s",
                command["request_id"], command["reviewer_id"])
    return {"request_id": command["request_id"], "wallet_status": "accepted", "created": True}
