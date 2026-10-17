"""Small device-local API for adding QShield file encryption to a Python app.

The caller is responsible for obtaining the receiver's full fingerprint through
an independent trusted channel. No network, Streamlit, or relay is used here.
"""

import hmac
import re
from dataclasses import dataclass
from pathlib import Path

from core import pq_transfer as pq

MAX_FILE_BYTES = 25 * 1024 * 1024  # version-1 packages are assembled in memory
RECOMMENDED_SUITE = 4


@dataclass(frozen=True)
class KeyInfo:
    """Safe-to-share details returned after saving the receiver's keys."""

    public_key_text: str
    fingerprint: str
    suite: int
    private_key_path: Path
    public_key_path: Path


def create_keys(private_key_path, public_key_path, password: str, *,
                suite: int = RECOMMENDED_SUITE, allow_legacy: bool = False) -> KeyInfo:
    """Save a protected private key and shareable public key; never replace files.

    Suite 4 is the default. Existing suites 1–3 require allow_legacy=True.
    The private key file is owner-readable only where the OS supports it.
    """
    if suite != RECOMMENDED_SUITE and not allow_legacy:
        raise ValueError("Older key suites require allow_legacy=True.")
    private_path, public_path = Path(private_key_path), Path(public_key_path)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("The private and public keys need different file paths.")
    if (private_path.exists() or private_path.is_symlink()
            or public_path.exists() or public_path.is_symlink()):
        raise FileExistsError("A key file already exists. Choose new paths.")

    private = pq.generate_recipient_keypair(suite)
    public = private.public_key()
    text = pq.public_key_to_text(public)
    fingerprint = pq.public_key_fingerprint(public)
    pq.save_private_key(private, private_path, password)
    try:
        public_path.parent.mkdir(parents=True, exist_ok=True)
        with public_path.open("x", encoding="ascii") as output:
            output.write(text + "\n")
    except BaseException:
        private_path.unlink()
        raise
    return KeyInfo(text, fingerprint, suite, private_path, public_path)


def get_fingerprint(public_key_text: str, *, pretty: bool = False) -> str:
    """Return the full SHA-256 fingerprint of a pasted public key."""
    return pq.public_key_fingerprint(pq.public_key_from_text(public_key_text), pretty=pretty)


def encrypt_file(source_path, package_path, public_key_text: str, *,
                 expected_fingerprint: str, allow_legacy: bool = False) -> Path:
    """Verify the receiver's fingerprint, then create a padded .qshield package.

    The expected fingerprint must be obtained from the receiver independently.
    A mismatch creates no package. Output files are never overwritten.
    """
    public = pq.public_key_from_text(public_key_text)
    if pq.suite_of(public) != RECOMMENDED_SUITE and not allow_legacy:
        raise ValueError("This recipient uses an older suite. Pass allow_legacy=True explicitly.")
    if not isinstance(expected_fingerprint, str):
        raise ValueError("Provide the receiver's full 64-digit fingerprint.")
    expected = "".join(expected_fingerprint.split()).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Provide the receiver's full 64-digit fingerprint.")
    if not hmac.compare_digest(expected, pq.public_key_fingerprint(public)):
        raise ValueError("Receiver fingerprint mismatch. Nothing was encrypted.")

    source = Path(source_path)
    if not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Choose a regular file no larger than 25 MiB.")
    return pq.encrypt_file_for_recipient(
        source, package_path, public, padding="padme", streaming=False,
    )


def decrypt_file(package_path, private_key_path, password: str, output_dir) -> Path:
    """Authenticate a package and publish the recovered file only on success.

    The private key stays on this device. Existing output files are preserved.
    """
    private = pq.load_private_key(private_key_path, password)
    return pq.decrypt_package_file(package_path, output_dir, private)
