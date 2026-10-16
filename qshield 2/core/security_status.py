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
            "Feature": "Key establishment, suite 1 (ML-KEM-768 + HKDF-SHA256)",
            "Status": WORKING,
            "Details": (
                "Implemented in core/pq_transfer.py and used by the app. The receiver "
                "generates an ML-KEM-768 pair; the sender encrypts with the public key "
                "only. The private key is downloaded password-protected and is never "
                "shown to the sender. ML-KEM only, no hybrid. No independent security "
                "audit has been done."
            ),
        },
        {
            "Feature": "Hybrid key establishment, suite 2 (X25519 + ML-KEM-768 + HKDF-SHA256)",
            "Status": WORKING,
            "Details": (
                "Both secrets go into the HKDF input, so an attacker must break both. "
                "If a flaw were found in ML-KEM, X25519 still protects against attackers "
                "using ordinary computers. A quantum computer breaks X25519, so against "
                "a quantum attacker only the ML-KEM half protects. Same tests and "
                "limits as suite 1."
            ),
        },
        {
            "Feature": "Higher security level, suite 3 (ML-KEM-1024 + HKDF-SHA256)",
            "Status": WORKING,
            "Details": (
                "ML-KEM-1024 only. It adds safety margin with larger keys, but it is "
                "the same algorithm family as suite 1, so it is not a hedge against a "
                "flaw in ML-KEM itself."
            ),
        },
        {
            "Feature": "Forward-secret live sessions (ephemeral-KEM handshake)",
            "Status": BUILT_NOT_CONNECTED,
            "Details": (
                "Implemented and tested in core/session.py (all three suites): a "
                "separate session protocol, not used for .qshield files, and not "
                "connected to the Streamlit app. If the server's long-term key leaks "
                "after a session ended, the recorded session stays closed. The client "
                "is not authenticated, and .qshield packages themselves still have no "
                "forward secrecy."
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
            "Feature": "Claim that the whole system is 'quantum-resistant'",
            "Status": NOT_CLAIMED,
            "Details": (
                "Only the key-establishment step uses a post-quantum algorithm "
                "(ML-KEM; suite 2 adds X25519, which is not post-quantum). There are "
                "no digital signatures and no audit."
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
