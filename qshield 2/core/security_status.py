"""The honest list of what QShield can and cannot do right now.

IMPORTANT RULE FOR THE TEAM:
Only change a feature to "working" after the real code exists AND you have
tested it AND the app really uses it. Never show a green tick for something
that is only pretend.
"""

WORKING = "✅ Working"
BUILT_NOT_CONNECTED = "🧩 Built and tested, not connected to the app yet"
NOT_BUILT = "⏳ Not built yet"
NOT_CLAIMED = "🚫 Not claimed"


def get_feature_list() -> list[dict]:
    """Return one row per security feature, with its real status."""
    return [
        {
            "Feature": "File integrity check (SHA-256)",
            "Status": WORKING,
            "Details": "Real hash from Python's hashlib. Optional extra check after decryption.",
        },
        {
            "Feature": "File encryption (AES-256-GCM)",
            "Status": WORKING,
            "Details": (
                "Implemented in core/file_crypto.py and used by the Sender Encrypt File "
                "and Receiver Decrypt buttons. File contents are secret; the file name "
                "is visible."
            ),
        },
        {
            "Feature": "Key establishment (ML-KEM-768 + HKDF-SHA256)",
            "Status": WORKING,
            "Details": (
                "Implemented in core/pq_transfer.py and used by the app. The receiver "
                "generates an ML-KEM-768 pair; the sender encrypts with the public key "
                "only. The private key is downloaded password-protected and is never "
                "shown to the sender. No independent security audit has been done."
            ),
        },
        {
            "Feature": "Encrypted file integrity verification",
            "Status": WORKING,
            "Details": (
                "AES-256-GCM authenticates the encrypted file and header. If the "
                ".qshield package is changed, or the wrong private key is used, "
                "decryption fails and no file contents are released."
            ),
        },
        {
            "Feature": "Relay public-key authentication (signed key bundles)",
            "Status": WORKING,
            "Details": (
                "Keys fetched through the relay are accepted only if signed by the "
                "QShield ID the sender got from the receiver by another channel. "
                "Substituted, expired, rolled-back or unsigned keys are rejected. "
                "Assumes the QShield ID itself was shared over a channel the relay does not control."
            ),
        },
        {
            "Feature": "Claim that the whole system is 'quantum-resistant'",
            "Status": NOT_CLAIMED,
            "Details": (
                "Only the key-establishment step uses a post-quantum algorithm "
                "(ML-KEM-768). There are no digital signatures and no audit."
            ),
        },
        {
            "Feature": "Sender identity verification",
            "Status": NOT_BUILT,
            "Details": (
                "Encryption does not prove who sent a file. Anyone who has the "
                "receiver's public key can make a valid package. Digital signatures "
                "are not built."
            ),
        },
        {
            "Feature": "Network file transfer",
            "Status": NOT_BUILT,
            "Details": (
                "Public keys and .qshield files are copied by hand (or handed over "
                "inside this one browser session). There is no network send yet."
            ),
        },
    ]
