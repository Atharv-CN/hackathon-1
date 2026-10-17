"""Interactively verify both deployed backup APIs using synthetic data only."""

import argparse
import getpass
import secrets

from demo_client import send
from logic import TEST_ID


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--accept", metavar="REQUEST_ID",
                        help="Accept an existing QShield backup request with the Wallet API")
    args = parser.parse_args()
    if args.accept:
        if not TEST_ID.fullmatch(args.accept):
            raise SystemExit("Expected a TEST- request ID from the QShield Pay page.")
        wallet_url = input("Wallet URL: ").strip().rstrip("/")
        if not wallet_url.startswith("https://"):
            raise SystemExit("Wallet URL must start with https://")
        wallet_secret = getpass.getpass("Wallet secret (hidden): ").strip()
        if not wallet_secret:
            raise SystemExit("Wallet secret is required.")
        send(wallet_url + "/v1/wallet/accept", wallet_secret, {
            "request_id": args.accept,
            "reviewer_id": "wallet-demo-operator",
        })
        print("Done. Wallet accepted the existing fake handoff.")
        return

    print("This sends one fake payment to Render and accepts it with the demo Wallet API.")
    creator_url = input("Creator URL: ").strip().rstrip("/")
    wallet_url = input("Wallet URL: ").strip().rstrip("/")
    if not creator_url.startswith("https://") or not wallet_url.startswith("https://"):
        raise SystemExit("Both URLs must start with https://")
    creator_secret = getpass.getpass("Creator secret (hidden): ").strip()
    wallet_secret = getpass.getpass("Wallet secret (hidden): ").strip()
    if not creator_secret or not wallet_secret:
        raise SystemExit("Both secrets are required.")

    request_id = "TEST-REQUEST-" + secrets.token_hex(8)
    print("\nCreating synthetic handoff", request_id)
    send(creator_url + "/v1/handoffs", creator_secret, {
        "request_id": request_id,
        "token_id": "ptok_" + secrets.token_urlsafe(24),
        "provider_reference": "mockpay_" + secrets.token_urlsafe(12),
        "amount_minor": 49900,
        "currency": "INR",
        "payment_status": "succeeded",
    })
    print("Accepting it with the Wallet API")
    send(wallet_url + "/v1/wallet/accept", wallet_secret, {
        "request_id": request_id,
        "reviewer_id": "wallet-demo-operator",
    })
    print("Done. Creator wrote to Neon and Wallet accepted the fake handoff.")


if __name__ == "__main__":
    main()
