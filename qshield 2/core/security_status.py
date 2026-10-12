"""Accurate security capabilities after UI integration."""

def get_feature_list() -> list[dict]:
    return [
        {'Feature': 'AES-256-GCM file encryption', 'Status': '✅ Connected', 'Details': 'Used by encrypted QShield packages.'},
        {'Feature': 'ML-KEM-768 key establishment', 'Status': '✅ Connected', 'Details': 'Receiver public key encrypts; private key decrypts.'},
        {'Feature': 'Package integrity verification', 'Status': '✅ Connected', 'Details': 'AES-GCM rejects modified packages during decryption.'},
        {'Feature': 'SHA-256 file fingerprint', 'Status': '✅ Working', 'Details': 'Shown for the original file in Sender.'},
        {'Feature': 'Sender identity authentication', 'Status': '⏳ Not built', 'Details': 'No sender signatures or trusted sender directory.'},
        {'Feature': 'Network delivery', 'Status': '⏳ Not built', 'Details': 'Encrypted package is downloaded and shared manually.'},
        {'Feature': 'Independent security audit', 'Status': '⏳ Not done', 'Details': 'Hackathon prototype only.'},
    ]
