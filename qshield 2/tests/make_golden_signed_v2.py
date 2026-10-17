"""Create tests/data/golden_signed_package_v2.json (run ONCE, then commit the file).

    python tests/make_golden_signed_v2.py

It builds one signed package from FIXED, PUBLIC test keys. The saved file is what
keeps "package format version 2" frozen: a later change that stops it from opening
is caught by test_version_2_golden_package_still_opens.

Run it with the REAL cryptography library (the one in requirements.txt).
The keys in the JSON are public test keys. Never use them for real data.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey  # noqa: E402

from core import signatures, signed_transfer  # noqa: E402

OUT = Path(__file__).parent / "data" / "golden_signed_package_v2.json"

RECIPIENT_SEED = bytes(range(64))                                   # same public seed idea as the v1 vector
SENDER_ED_SEED = bytes(range(100, 132))
SENDER_MLDSA_SEED = bytes(range(200, 232))
FILENAME = "golden-signed.txt"
PLAINTEXT = "QShield golden test vector, package format version 2 (hybrid-signed).\n"
CREATED_AT = 1_800_000_000


def main(force: bool = False) -> None:
    if OUT.exists() and not force:
        sys.exit(f"{OUT} already exists. The golden file must never change; pass --force only if you mean it.")
    recipient = MLKEM768PrivateKey.from_seed_bytes(RECIPIENT_SEED)
    sender = signatures._identity_from_secret_blob(SENDER_ED_SEED + SENDER_MLDSA_SEED)
    package = signed_transfer.sign_and_encrypt(
        PLAINTEXT.encode(), recipient.public_key(), sender, filename=FILENAME, created_at=CREATED_AT)
    # Prove it opens before saving it.
    result = signed_transfer.decrypt_and_verify(package, recipient, sender.public)
    assert result.data == PLAINTEXT.encode()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "WARNING": "TEST VECTOR ONLY. These private seeds are public. Never use them for real data.",
        "format": "QShield transfer package, version 2 (signed), KEM suite 1, signature suite 1 "
                  "(ML-KEM-768 + HKDF-SHA256 + AES-256-GCM, Ed25519 + ML-DSA-65)",
        "recipient_private_key_seed_hex": RECIPIENT_SEED.hex(),
        "sender_public_identity_hex": sender.public.to_bytes().hex(),
        "sender_fingerprint": sender.public.fingerprint(),
        "filename": FILENAME,
        "plaintext_utf8": PLAINTEXT,
        "created_at": CREATED_AT,
        "package_hex": package.hex(),
    }, indent=2) + "\n")
    print(f"Wrote {OUT}. Commit it.")


if __name__ == "__main__":
    main(force="--force" in sys.argv)
