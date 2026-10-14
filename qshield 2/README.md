# 🛡️ QShield

A 24-hour hackathon prototype for secure file sharing, built with Python and Streamlit.

## Current status (please read)

QShield is at **stage 4**. Here is the honest list:

| Feature | Status |
|---|---|
| File upload (Sender and Receiver) | ✅ Working |
| File fingerprint (SHA-256, from Python's `hashlib`) | ✅ Working |
| Checking a file against a fingerprint | ✅ Working |
| AES-256-GCM encryption connected to the app | ✅ Working |
| ML-KEM-768 key establishment connected to the app | ✅ Working |
| Encrypted file integrity verification (AES-GCM) | ✅ Working |
| Claiming the whole system is "quantum-resistant" | 🚫 Not claimed (see the limits in the ML-KEM section) |
| Sender identity verification | ⏳ Not built yet (encryption does not prove who sent a file) |
| Sending over a real network | ⏳ Not built yet |

**Use test files only. Do not upload real secrets.** Encryption is connected, but this is an unaudited hackathon prototype. It does not prove who the sender is.

**Team rule:** never show something as "working" unless real code exists and you have tested it. When you build a feature, update `core/security_status.py` at the same time. Do not use pretend or home-made cryptography.

## How to run it

You need **Python 3.10 or newer**. Check with `python --version` (or `python3 --version`).

Open a terminal inside the `qshield` folder, then follow the steps.

**Step 1: Make a private Python environment (one time only)**

Mac / Linux:
```
python3 -m venv venv
source venv/bin/activate
```

Windows (Command Prompt or PowerShell):
```
python -m venv venv
venv\Scripts\activate
```

You will see `(venv)` at the start of your terminal line. That means it worked.

**Step 2: Install the packages (one time only)**
```
pip install -r requirements.txt
```

**Step 3: Start the app**
```
streamlit run app.py
```

Your browser opens by itself. If it does not, go to http://localhost:8501

**To stop the app:** click the terminal and press `Ctrl + C`.

**Next time:** you only need to activate the environment (Step 1, second command) and run Step 3.

## How to try it

Use a harmless test file (for example a short `.txt`), never real secrets.

1. Open the **Receiver** tab. Choose a password and click **Generate ML-KEM-768 key pair**.
2. Copy the public key. Download the password-protected private key and keep it on the receiver side.
3. Open the **Sender** tab. Upload a test file, paste the public key, click **Encrypt File**, and download the `.qshield` package.
4. Back on the **Receiver** tab, upload the `.qshield` file, unlock it with the private key and password, and download the recovered original.
5. Try decrypting with a different key, or flip one byte of the `.qshield` file: you should see a security warning and no download.
6. Open the **Security Status** tab to see what is working and what is not.

## The encryption module

`core/file_crypto.py` encrypts and decrypts files with **AES-256-GCM** using the well-known `cryptography` library. It contains no home-made algorithms.

```python
from core.file_crypto import generate_key, encrypt_bytes, decrypt_bytes, DecryptionError

key = generate_key()                                   # new random 256-bit key
container = encrypt_bytes(file_bytes, key, filename="plan.pdf")

try:
    result = decrypt_bytes(container, key)             # result.data, result.filename
except DecryptionError:
    print("Wrong key, or the file was changed")        # nothing is returned
```

What it does:
- Makes a fresh random nonce for every encryption.
- Checks the file contents **and** the header (the file name, size and format version) when decrypting. If even one bit was changed, decryption fails and returns nothing.
- Never has a built-in key. The key is always passed in, and `generate_key()` makes a new random one.
- Has `encrypt_file()` and `decrypt_file()` for files on disk. They never overwrite an existing file unless you ask.

What it does **not** do (read this before you trust it):
- The **file name is visible**. It is checked for changes, but it is not secret. Only the file contents are secret.
- The file size is not hidden.
- Anyone who has the key can make a valid file, so it does not prove who the sender is.
- It does not share keys. How the sender safely gives the key to the receiver is the next problem to solve.
- Use a **new key for each transfer**.
- It is not claimed to be quantum-resistant.

## Sending a file to a recipient (ML-KEM-768)

`core/pq_transfer.py` lets a sender encrypt a file for a receiver **without the sender ever seeing the receiver's private key**.

Think of a padlock. The receiver makes a key pair. The *public* key is an open padlock that anyone can have. The *private* key is the only key that opens it, and it stays on the receiver's computer. The sender snaps the padlock shut around a fresh secret, and now both sides share that secret.

It uses standard algorithms from the `cryptography` library. There is no home-made crypto:
1. **ML-KEM-768** (NIST FIPS 203, designed to resist quantum computers) makes a shared secret and a "locked box" that only the receiver can open.
2. **HKDF-SHA256** turns that secret into a 256-bit key.
3. **AES-256-GCM** encrypts the file with that key.

```python
from core.pq_transfer import (
    generate_recipient_keypair, save_private_key, public_key_to_text,
    public_key_from_text, public_key_fingerprint,
    encrypt_for_recipient, decrypt_package,
)

# RECEIVER, on the receiver's own computer
private_key = generate_recipient_keypair()
save_private_key(private_key, "my_private.key", "a strong password")   # stays here
public_text = public_key_to_text(private_key.public_key())             # safe to share
print(public_key_fingerprint(private_key.public_key(), pretty=True))   # read this out to the sender

# SENDER: only ever receives the public text
public_key = public_key_from_text(public_text)
package = encrypt_for_recipient(file_bytes, public_key, filename="plan.pdf")

# RECEIVER again
result = decrypt_package(package, private_key)    # result.data, result.filename
```

If something is wrong you get `WrongRecipientError` (made for a different key) or `TransferError` (changed or damaged). Both are also a `DecryptionError`. If the installed `cryptography` cannot do ML-KEM-768 you get `PostQuantumUnavailableError`. QShield **never** quietly switches to ordinary encryption.

The package (format version 1) is a small header followed by the encrypted file. The header holds a format marker, the version, the algorithm suite number, a fingerprint of the recipient's key, and the ML-KEM locked box. The whole header is mixed into the key, so changing any part of the package makes opening it fail. A new suite number is how a future version can change algorithms without confusing old packages.

Read these limits before you trust it:
- **No proof of who sent it.** Anyone with the public key can make a package. Digital signatures would be needed for that. They are not built.
- **Check the public key.** Compare fingerprints with the receiver by phone or in person. Otherwise someone could swap in their own public key.
- **No forward secrecy.** If the private key is stolen later, old packages can be opened.
- The file name and size are visible.
- There has been no independent security audit.
- The Streamlit app now uses this module. The tabs still run in one browser session, so treat that as a demo of the buttons, not as two separate computers. The sender tab never displays the private key.

## Run the tests

```
pip install -r requirements-dev.txt
pytest
```

Add `-v` to see every test name. You should see `98 passed`.

What the tests prove:
- **Encryption works:** files of many sizes are encrypted and recovered, with and without ML-KEM.
- **Corruption is rejected:** changing **any single bit** anywhere in a package is rejected. So are truncated packages, extra bytes, mixed-up parts, and unknown versions.
- **Wrong keys are rejected:** a package for a different recipient key cannot be opened, even if the fingerprint label is forged.
- **The private key stays private:** it is not in the package and not in the shared public key, and it is saved only password-protected.
- **ML-KEM-768 is the real thing:** a separate implementation (`kyber-py`, used only in the tests) agrees with the library, and can open a QShield package.
- **Format version 1 is frozen:** a saved version-1 package in `tests/data/` must keep opening. Its key is a public test key, so never use it for real data.
- **No silent fallback:** if ML-KEM is unavailable, QShield stops.

## What is in each file

```
qshield/
├── app.py                  Start here. Sets up the page and the three tabs.
├── requirements.txt        Packages the app needs.
├── requirements-dev.txt    Same, plus pytest for running the tests.
├── pytest.ini              Test settings.
├── .streamlit/config.toml  Settings (upload size limit).
├── core/                   The "brain": code with no screen layout.
│   ├── file_utils.py       SHA-256 fingerprint, file size text.
│   ├── file_crypto.py      AES-256-GCM encrypt / decrypt.
│   ├── pq_transfer.py      ML-KEM-768 + HKDF + AES-256-GCM transfer packages.
│   ├── transfer_flow.py    Glue used by the Sender and Receiver tabs.
│   ├── state.py            Shared memory between the tabs.
│   └── security_status.py  The honest list of working / not-built features.
├── views/                  The "screens": what the user sees.
│   ├── sender.py           Sender tab.
│   ├── receiver.py         Receiver tab.
│   └── security_panel.py   Security Status tab.
└── tests/
    ├── test_file_crypto.py    Tests for the AES-256-GCM module.
    ├── test_pq_transfer.py    Tests for ML-KEM transfer packages.
    ├── test_mlkem_interop.py  Checks the library's ML-KEM against a second implementation.
    ├── test_app_integration.py Website encrypt/decrypt flow (no browser).
    └── data/golden_package_v1.json  Saved version-1 package (public TEST key only).
```

**Tip for beginners:** to add a new feature, put the logic in `core/` and the buttons and text in `views/`. Keeping them apart makes teamwork easier, because two people can work on different files without clashing.

## Common problems

| Problem | Fix |
|---|---|
| `streamlit: command not found` | Activate the environment (Step 1), then try again. |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again. |
| Port 8501 is busy | Run `streamlit run app.py --server.port 8502` |
| File is rejected as too big | The limit is 25 MB. Change `maxUploadSize` in `.streamlit/config.toml`. |
