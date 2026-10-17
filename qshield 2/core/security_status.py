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
                "and Receiver Decrypt buttons. File contents, file name, exact size and "
                "time are all inside the encryption. The package length is still "
                "visible unless optional padding is used."
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
            "Feature": "Recommended suite 4 (X25519 + ML-KEM-1024 + HKDF-SHA256)",
            "Status": WORKING,
            "Details": (
                "The UI and local CLI default to this hybrid key. ML-KEM-1024 supplies "
                "post-quantum key establishment; X25519 adds a classical hedge. Both "
                "secrets and the whole package header go into HKDF. The combination "
                "has interoperability, tamper and round-trip tests but no independent audit."
            ),
        },
        {
            "Feature": "Forward-secret live sessions (ephemeral-KEM handshake)",
            "Status": BUILT_NOT_CONNECTED,
            "Details": (
                "Implemented and tested in core/session.py (original three suites): a "
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
            "Feature": "Legacy relay public-key authentication (Ed25519 signed key bundles)",
            "Status": BUILT_NOT_CONNECTED,
            "Details": (
                "Built in core, but not exposed in the recommended UI: its Ed25519 "
                "identity does not resist a sufficiently capable quantum computer. "
                "The UI requires direct public-key fingerprint confirmation instead."
            ),
        },
        {
            "Feature": "Quantum-resistant local file encryption (suite 4, verified recipient fingerprint)",
            "Status": WORKING,
            "Details": (
                "The local CLI processes files and keys on device and requires a full "
                "fingerprint match before encryption. ML-KEM-1024 is believed quantum "
                "resistant; the protocol itself is unaudited. It does not authenticate "
                "the sender or provide forward secrecy for stored files."
            ),
        },
        {
            "Feature": "Device-local Python developer API",
            "Status": WORKING,
            "Details": (
                "qshield_sdk.py exposes create_keys, get_fingerprint, encrypt_file and "
                "decrypt_file. It defaults to suite 4, requires the receiver's complete "
                "fingerprint, keeps old suites behind an explicit compatibility flag, "
                "and never overwrites existing key, package, or recovered files. "
                "examples/integration_demo.py exercises this API in a separate process "
                "without Streamlit or Supabase. pyproject.toml builds an installable "
                "qshield-sdk wheel and qshield-local command."
            ),
        },
        {
            "Feature": "Claim that the whole system is 'quantum-resistant'",
            "Status": NOT_CLAIMED,
            "Details": (
                "The hosted Streamlit server sees plaintext, passwords and private keys. "
                "The old Ed25519 relay identity is not quantum-resistant and is no "
                "longer in the recommended UI. Sender signatures are not connected; "
                "packages lack forward secrecy and there is no independent audit. "
                "Only the qualified claim of local file encryption is appropriate."
            ),
        },
        {
            "Feature": "Digital signatures (Ed25519 + ML-DSA-65, hybrid)",
            "Status": BUILT_NOT_CONNECTED,
            "Details": (
                "Implemented in core/signatures.py. Both signatures must verify, so a "
                "forger would have to break Ed25519 and ML-DSA-65 (NIST FIPS 204). "
                "There is no fallback to a single algorithm. Not connected to the app "
                "yet, no key revocation, no independent audit."
            ),
        },
        {
            "Feature": "Sender identity verification",
            "Status": BUILT_NOT_CONNECTED,
            "Details": (
                "Built and tested in core/signed_transfer.py but NOT used by the "
                "Sender and Receiver tabs yet. Packages made by this app are still "
                "unsigned: anyone who has the receiver's public key can make one. "
                "Signed (version 2) packages prove which trusted sender made them. "
                "Trust is only as good as the fingerprint check between people."
            ),
        },
        {
            "Feature": "Encrypted package network relay",
            "Status": WORKING,
            "Details": (
                "If Supabase is configured, the app can send and fetch already-encrypted "
                "packages. Key authentication still requires direct fingerprint verification."
            ),
        },
    ]
