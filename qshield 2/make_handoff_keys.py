"""One-time setup for the Payments -> Wallet handoff. Run on YOUR computer, not on the server.

    python make_handoff_keys.py

It makes two things:
  1. The WALLET key pair. The PRIVATE key is saved to a password-protected file
     (wallet_private_key.pem) that stays with the Wallet person. It is NOT given to the server.
  2. The PAYMENTS signing identity. The server needs it to sign handoffs.

Then it prints the settings to paste into your host's environment variables (Render ->
Environment). Never commit this output or the .pem file to git.
"""

import base64
import getpass
import os
import sys

from core import transfer_flow

KEY_FILE = "wallet_private_key.pem"


def ask_password(label: str) -> str:
    while True:
        first = getpass.getpass(f"{label} (12+ characters): ")
        if len(first) < 12:
            print("  Too short. Use at least 12 characters.")
            continue
        if getpass.getpass("  Type it again: ") != first:
            print("  They did not match. Try again.")
            continue
        return first


def main() -> int:
    if os.path.exists(KEY_FILE):
        print(f"{KEY_FILE} already exists. Move or delete it first; this script never overwrites a key.")
        return 1

    print("\n1) WALLET key. This password protects the Wallet private key file.")
    wallet_pw = ask_password("Wallet key password")
    wallet = transfer_flow.create_recipient_key_bundle(wallet_pw, suite=1)  # signed handoffs use ML-KEM-768

    print("\n2) PAYMENTS signing identity. The server will use this password to sign handoffs.")
    pay_pw = ask_password("Payments signing password")
    payments = transfer_flow.create_sender_identity_bundle(pay_pw)

    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(wallet.protected_pem)

    print(f"\nSaved {KEY_FILE} (give it ONLY to the Wallet person; do NOT upload it to the server or git).")
    print("\n=== Paste these into your host's environment variables ===")
    print(f"WALLET_PUBLIC_KEY={wallet.public_text}")
    print(f"PAYMENTS_SIGNING_IDENTITY_B64={base64.b64encode(payments.protected_file).decode()}")
    print(f"PAYMENTS_SIGNING_PASSWORD={pay_pw}")
    print(f"PAYMENTS_PUBLIC_IDENTITY={payments.public_text}")
    print("\n=== Read this out loud on a phone call, so the Wallet person can check it ===")
    print(f"Payments fingerprint: {payments.fingerprint_pretty}")
    print(f"(Wallet key fingerprint, for your records: {wallet.fingerprint_pretty})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
