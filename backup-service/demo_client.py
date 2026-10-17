"""Exercise a deployed standby service with synthetic data only."""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from logic import canonical


def send(url, secret, payload):
    body = canonical(payload)
    timestamp = str(int(time.time()))
    path = urlsplit(url).path.encode("ascii")
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + path + b"." + body,
                         hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Timestamp": timestamp,
                 "X-Signature": signature},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            print(response.read().decode())
    except urllib.error.HTTPError as exc:
        print(exc.code, exc.read().decode())
        raise SystemExit(1) from exc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["create", "accept"])
    parser.add_argument("--request-id", default="TEST-REQUEST-" + secrets.token_hex(5))
    parser.add_argument("--token-id", default="ptok_" + secrets.token_urlsafe(24))
    args = parser.parse_args()
    if args.mode == "create":
        send(os.environ["CREATOR_URL"].rstrip("/") + "/v1/handoffs",
             os.environ["PRIMARY_TO_BACKUP_SECRET"], {
                 "request_id": args.request_id,
                 "token_id": args.token_id,
                 "provider_reference": "mockpay_" + secrets.token_urlsafe(12),
                 "amount_minor": 49900,
                 "currency": "INR",
                 "payment_status": "succeeded",
             })
    else:
        send(os.environ["WALLET_URL"].rstrip("/") + "/v1/wallet/accept",
             os.environ["WALLET_TO_BACKUP_SECRET"], {
                 "request_id": args.request_id, "reviewer_id": "wallet-demo-operator",
             })


if __name__ == "__main__":
    main()
