"""Small helper functions for working with files.

Everything here is REAL, not simulated:
- sha256_of_bytes uses Python's built-in hashlib (a standard, trusted library).
"""

import hashlib


def sha256_of_bytes(data: bytes) -> str:
    """Return the SHA-256 fingerprint of some bytes as a 64-character hex string.

    If even one bit of the file changes, this fingerprint changes completely.
    That is how we can tell if a file was modified.
    """
    return hashlib.sha256(data).hexdigest()


def human_size(num_bytes: int) -> str:
    """Turn a number of bytes into text people can read, e.g. 2048 -> '2.0 KB'."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def clean_hash_text(text: str) -> str:
    """Tidy up a hash that someone pasted: remove spaces/newlines, make lowercase."""
    return "".join(text.split()).lower()
