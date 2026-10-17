"""Device-local QShield commands. No server or relay is contacted.

Usage: python qshield_local.py --help
"""

import argparse
import getpass
import hmac
import re
import secrets
from pathlib import Path

from core import pq_transfer as pq

MAX_FILE_SIZE = 25 * 1024 * 1024  # the version-1 package holds the file in memory


def _keygen(args):
    private_path, public_path = Path(args.private_key), Path(args.public_key)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("The private and public key files must have different names.")
    if private_path.exists() or private_path.is_symlink() or public_path.exists() or public_path.is_symlink():
        raise FileExistsError("A key output already exists; choose fresh file names.")
    password = getpass.getpass("Private-key password: ")
    if not password:
        raise ValueError("A private-key password is required.")
    if password != getpass.getpass("Repeat password: "):
        raise ValueError("Passwords did not match.")
    private = pq.generate_recipient_keypair(args.suite)
    public = private.public_key()
    pq.save_private_key(private, private_path, password)
    try:
        with public_path.open("x", encoding="utf-8") as target:
            target.write(pq.public_key_to_text(public) + "\n")
    except BaseException:
        private_path.unlink()
        raise
    print(f"Private key: {private_path}\nPublic key: {public_path}")
    print("Fingerprint (verify over a separate channel):")
    print(pq.public_key_fingerprint(public, pretty=True))


def _encrypt(args):
    source = Path(args.file)
    if not source.is_file() or source.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("Choose a regular file smaller than 25 MiB.")
    public = pq.public_key_from_text(Path(args.public_key).read_text(encoding="utf-8"))
    expected = re.sub(r"\s+", "", args.fingerprint).lower()
    actual = pq.public_key_fingerprint(public)
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not hmac.compare_digest(expected, actual):
        raise ValueError("Recipient fingerprint did not match; nothing was encrypted. Check it with the receiver directly.")
    output = Path(args.output) if args.output else Path(f"qshield-{secrets.token_hex(8)}.qshield")
    pq.encrypt_file_for_recipient(source, output, public, padding="padme", streaming=False)
    print(f"Encrypted package: {output}")


def _decrypt(args):
    password = getpass.getpass("Private-key password: ")
    private = pq.load_private_key(args.private_key, password)
    recovered = pq.decrypt_package_file(args.package, args.output_dir, private)
    print(f"Verified and recovered: {recovered}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local QShield file encryption. Keys and files stay on this device.")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="Generate a password-protected receiver key pair")
    keygen.add_argument("--private-key", required=True, help="Path to save the secret key")
    keygen.add_argument("--public-key", required=True, help="Path to save the public key")
    keygen.add_argument("--suite", type=int, choices=(1, 2, 3, 4), default=4,
                        help="4 = ML-KEM-1024 + X25519 (default); 1–3 are older formats")
    keygen.set_defaults(run=_keygen)
    encrypt = commands.add_parser("encrypt", help="Encrypt only after checking the receiver fingerprint")
    encrypt.add_argument("file", help="File to encrypt (maximum 25 MiB)")
    encrypt.add_argument("--public-key", required=True, help="Receiver's public-key text file")
    encrypt.add_argument("--fingerprint", required=True, help="64 hex characters confirmed with the receiver")
    encrypt.add_argument("--output", help="Package path (defaults to a random name)")
    encrypt.set_defaults(run=_encrypt)
    decrypt = commands.add_parser("decrypt", help="Verify and recover a package")
    decrypt.add_argument("package", help="Encrypted .qshield package")
    decrypt.add_argument("--private-key", required=True, help="Receiver's password-protected key")
    decrypt.add_argument("--output-dir", required=True, help="Directory for the recovered file")
    decrypt.set_defaults(run=_decrypt)
    args = parser.parse_args(argv)
    try:
        args.run(args)
    except (OSError, ValueError, TypeError, pq.TransferError, pq.PostQuantumUnavailableError) as exc:
        parser.exit(1, f"QShield stopped: {exc}\n")


if __name__ == "__main__":
    main()
