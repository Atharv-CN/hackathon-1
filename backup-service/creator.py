"""Render standby API called by QShield's synthetic demo or a future backend."""

import json
import logging
import os

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from crypto import StandbyCipher
from logic import TEST_ID, authenticate, canonical, request_digest, validate_handoff
from storage import ConflictError, NeonStore

app = FastAPI(title="QShield standby creator")
logger = logging.getLogger("uvicorn.error")


def database_failure(exc):
    """Report a useful setup category without returning Neon credentials to clients."""
    logger.error("Backup database operation failed", exc_info=exc)
    if isinstance(exc, KeyError):
        detail = "BACKUP_DATABASE_URL is missing on the creator service."
    elif isinstance(exc, psycopg.errors.UndefinedTable):
        detail = "Neon table backup_handoffs is missing in this database."
    elif isinstance(exc, psycopg.OperationalError):
        detail = "Could not connect to Neon. Check BACKUP_DATABASE_URL on the creator service."
    else:
        detail = "Neon database operation failed. Check the creator runtime logs."
    raise HTTPException(503, detail) from exc


@app.get("/health")
def health():
    return {"status": "up"}


@app.get("/v1/handoffs/{request_id}")
def get_handoff(request_id: str, request: Request, x_timestamp: str = Header(default=""),
                x_signature: str = Header(default="")):
    if not authenticate(os.environ.get("PRIMARY_TO_BACKUP_SECRET"), x_timestamp, x_signature,
                        request.url.path, b""):
        raise HTTPException(401, "Invalid or expired backend signature.")
    if not TEST_ID.fullmatch(request_id):
        raise HTTPException(400, "Invalid test request ID.")
    try:
        data = NeonStore().get(request_id)
    except Exception as exc:
        database_failure(exc)
    if data is None:
        raise HTTPException(404, "Unknown handoff.")
    return {"request_id": request_id, "route": "neon_standby",
            "token_id": data["token_id"], "wallet_status": data["wallet_status"]}


@app.post("/v1/handoffs")
async def create_handoff(request: Request, x_timestamp: str = Header(default=""),
                         x_signature: str = Header(default="")):
    body = await request.body()
    if not authenticate(os.environ.get("PRIMARY_TO_BACKUP_SECRET"), x_timestamp, x_signature,
                        request.url.path, body):
        raise HTTPException(401, "Invalid or expired backend signature.")
    try:
        payload = validate_handoff(json.loads(body))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc

    digest = request_digest(payload)
    try:
        store = NeonStore()
        prior = store.get(payload["request_id"])
    except Exception as exc:
        database_failure(exc)
    if prior is not None:
        if prior.get("request_digest") != digest:
            raise HTTPException(409, "Request ID already belongs to a different payment.")
        return {"request_id": payload["request_id"], "route": "neon_standby",
                "wallet_status": prior["wallet_status"], "created": False}

    try:
        cipher = StandbyCipher()
    except KeyError as exc:
        logger.error("Backup encryption key is missing", exc_info=exc)
        raise HTTPException(503, "BACKUP_AES_KEY_B64 is missing on the creator service.") from exc
    except ValueError as exc:
        logger.error("Backup encryption configuration failed", exc_info=exc)
        raise HTTPException(503, str(exc)) from exc
    envelope = cipher.encrypt(payload["request_id"], canonical(payload))
    record = {
        **envelope,
        "request_digest": digest,
        "token_id": payload["token_id"],
        "wallet_status": "pending",
        "route": "neon_standby",
    }
    try:
        store.create(record)
    except ConflictError:
        # A concurrent identical retry may have won the unique request ID.
        try:
            prior = store.get(payload["request_id"])
        except Exception as exc:
            database_failure(exc)
        if prior is None or prior.get("request_digest") != digest:
            raise HTTPException(409, "Request ID already belongs to a different payment.")
        return {"request_id": payload["request_id"], "route": "neon_standby",
                "wallet_status": prior["wallet_status"], "created": False}
    except Exception as exc:
        database_failure(exc)
    logger.info("Backup handoff created request_id=%s", payload["request_id"])
    return {"request_id": payload["request_id"], "route": "neon_standby",
            "wallet_status": "pending", "created": True}
