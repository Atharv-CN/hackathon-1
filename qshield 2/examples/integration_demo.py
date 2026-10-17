"""A separate app using only QShield's public SDK, with disposable test data.

From the qshield project folder: python -m examples.integration_demo
"""

from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

from qshield_sdk import create_keys, decrypt_file, encrypt_file, get_fingerprint


def main() -> None:
    # This is a local simulation of two apps. Real users must confirm the full
    # fingerprint over an independent trusted channel before sending a file.
    with TemporaryDirectory(prefix="qshield-integration-demo-") as temporary:
        root = Path(temporary)
        receiver, sender = root / "receiver", root / "sender"
        receiver.mkdir()
        sender.mkdir()

        keys = create_keys(
            receiver / "private.pem", receiver / "public.txt", "demo-only-password",
        )
        print(f"Receiver created suite {keys.suite} keys.")
        print(f"Receiver fingerprint: {keys.fingerprint}")

        # Transfer only the public key and the independently confirmed fingerprint.
        copyfile(keys.public_key_path, sender / "receiver-public.txt")
        trusted_fingerprint = keys.fingerprint  # simulates confirmation by phone
        public_text = (sender / "receiver-public.txt").read_text(encoding="ascii")
        assert get_fingerprint(public_text) == trusted_fingerprint

        original = sender / "harmless-demo.txt"
        original.write_text("QShield SDK integration test: hello, receiver!\n", encoding="utf-8")
        package = encrypt_file(
            original, sender / "delivery.qshield", public_text,
            expected_fingerprint=trusted_fingerprint,
        )
        print("Sender created a verified .qshield package.")

        copyfile(package, receiver / "delivery.qshield")
        recovered = decrypt_file(
            receiver / "delivery.qshield", keys.private_key_path,
            "demo-only-password", receiver / "recovered",
        )
        if recovered.read_bytes() != original.read_bytes():
            raise RuntimeError("Recovered file did not match the original.")
        print(f"Receiver recovered and verified: {recovered.name}")
        print("SUCCESS: a separate Python app used QShield without the website or relay.")


if __name__ == "__main__":
    main()
