"""Looking up a receiver's key through the untrusted relay, safely.

Kept separate from core/transfer_flow.py so it does not depend on ML-KEM.
"""

import relay
from core import identity
from core.trust_store import TrustStore


def fetch_authenticated_receiver_key(code: str, expected_identity: str, store: TrustStore,
                                     *, relay_get=None, now: int | None = None) -> identity.VerifiedKey:
    """Look up a bundle by short code and authenticate it against the identity the user expects.

    The relay and the code are untrusted: the result is trusted only if the bundle is
    signed by `expected_identity`. A code alone can never produce a key."""
    relay_get = relay_get or relay.get
    expected = identity.normalize_identity_id(expected_identity)  # raises KeyAuthError
    data, _ = relay_get(code, "keybundle")
    if data is None:
        legacy, _ = relay_get(code, "pubkey")
        if legacy is not None:
            raise identity._fail(
                "legacy_unsigned",
                "That code points to an old, unsigned public key. QShield will not use it. "
                "Ask the receiver to publish a signed key bundle.",
                expected,
            )
        raise identity._fail("not_found", "No key bundle was found for that code. Check it and try again.", expected)
    return identity.verify_key_bundle(data, expected, store, now=now)
