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
| Sender identity verification (hybrid Ed25519 + ML-DSA-65 signatures) | 🧩 Built and tested in `core/`, not connected to the app tabs yet. Packages made by the app are still unsigned |
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

## Proving who sent it (hybrid signatures, package version 2)

ML-KEM keeps a file secret, but **anyone with the receiver's public key can build a valid version 1 package**. Signed packages fix that.
`core/signatures.py` and `core/signed_transfer.py` add a sender identity made of **two** signing keys, Ed25519 and **ML-DSA-65 (NIST FIPS 204)**.
**Both** signatures must verify, so a forger has to break both algorithms. There is no "one is enough" mode and no silent fallback:
if ML-DSA is missing, QShield stops with `SignatureUnavailableError` and never checks Ed25519 alone.

```python
from core import signatures, signed_transfer
from core.pq_transfer import generate_recipient_keypair

# SENDER, once, on the sender's own computer
identity = signatures.generate_signing_identity()
signatures.save_signing_identity(identity, "alice.qsk", "a long passphrase")   # password protected (scrypt + AES-256-GCM)
print(identity.public.fingerprint(pretty=True))   # read this out to the receiver
share = identity.public.to_text()                 # safe to share

# RECEIVER (already has an ML-KEM key pair)
receiver_key = generate_recipient_keypair()
alice = signatures.PublicIdentity.from_text(share, expected_fingerprint="...the fingerprint Alice read out...")

# SENDER
package = signed_transfer.sign_and_encrypt(file_bytes, receiver_key.public_key(), identity, filename="plan.pdf")

# RECEIVER
result = signed_transfer.decrypt_and_verify(package, receiver_key, trusted_senders=[alice])
result.data, result.filename, result.sender_fingerprint, result.created_at, result.package_id
```

What it gives you, and how:
- **The signature covers everything:** the file, the file name, the creation time, the sender's key fingerprint, and a hash of the package header.
- **Bound to one recipient and one package.** Bob cannot pass Alice's signed file on to Carol as if Alice had sent it to Carol, and a signature cannot be moved into another package.
- **Hidden from outsiders.** The signature, sender identity, file name and size sit *inside* the encryption (the version 1 package left the file name readable).
- **No downgrade.** `decrypt_and_verify` refuses a version 1 (unsigned) package and `trusted_senders` is required. A key inside the package is never trusted.
- **Nothing is released early.** Contents come back only after the key, decryption, sender, both signatures, file name and (optional) age checks all pass.
- **Optional replay defence:** `max_age_seconds=...`, and every result has a unique `package_id` you can remember.

Read these limits before you trust it:
- **A signature only proves "made by the holder of this key".** You must confirm the sender's fingerprint over a second channel (phone, in person). `PublicIdentity.from_text(..., expected_fingerprint=...)` does the comparison.
- **No key revocation.** If a sender's key is stolen, every receiver must stop trusting it themselves.
- **No forward secrecy** for the receiver's long-term ML-KEM key (same as version 1).
- **No deniability.** The receiver can prove to others that the sender signed it.
- The Streamlit tabs do **not** use this yet. They still make unsigned version 1 packages. The status page says so.
- Python cannot reliably erase secrets from memory. No independent security audit has been done.

**One-time step:** create the frozen version 2 test vector with the real libraries and commit it:

```
python tests/make_golden_signed_v2.py
```

Until that file exists, `test_version_2_golden_package_still_opens` is skipped.

## Two-device demo (optional Supabase relay)

If `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` are set, the Sender and Receiver tabs get extra code boxes. Without them the app works exactly as before.

1. In Supabase → SQL Editor, create the table:
   ```sql
   create table transfers (
     id text primary key,
     kind text not null,
     payload text not null,
     filename text,
     created_at timestamptz default now()
   );
   alter table transfers enable row level security;
   ```
2. Add `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` (the **secret** key) as environment variables on your host. Never commit them.
3. Flow: **Receiver** generates keys → "Share public key" → gets a code. **Sender** enters that code, encrypts → "Send to receiver via relay" → gets a package code. **Receiver** enters the package code → "Fetch package" → decrypts.

The relay only ever stores a public key or an already-encrypted package. The private key stays in the receiver's session; download it and re-upload it if the app restarts. Always confirm the public-key fingerprint by voice, because the relay does not prove who uploaded a key.

## Run the tests

```
pip install -r requirements-dev.txt
pytest
```

Add `-v` to see every test name. Everything should pass. The one skip is the version 2 golden-vector test, until you create its file (see above).

What the tests prove:
- **Encryption works:** files of many sizes are encrypted and recovered, with and without ML-KEM.
- **Corruption is rejected:** changing **any single bit** anywhere in a package is rejected. So are truncated packages, extra bytes, mixed-up parts, and unknown versions.
- **Wrong keys are rejected:** a package for a different recipient key cannot be opened, even if the fingerprint label is forged.
- **The private key stays private:** it is not in the package and not in the shared public key, and it is saved only password-protected.
- **ML-KEM-768 is the real thing:** a separate implementation (`kyber-py`, used only in the tests) agrees with the library, and can open a QShield package.
- **Format version 1 is frozen:** a saved version-1 package in `tests/data/` must keep opening. Its key is a public test key, so never use it for real data.
- **No silent fallback:** if ML-KEM is unavailable, QShield stops.
- **Forgeries fail:** an untrusted sender, a stolen identity claim, a changed file, name or time, a re-addressed package, a package with only one valid signature half, and an unsigned version 1 package are all rejected.

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
│   ├── signatures.py       Hybrid Ed25519 + ML-DSA-65 signatures, sender identities, protected key files.
│   ├── signed_transfer.py  Signed + encrypted version 2 packages (sign_and_encrypt, decrypt_and_verify).
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
    ├── test_signatures.py     Tests for the hybrid signature module and identity files.
    ├── test_signed_transfer.py Tests for signed packages, including forgery and forwarding attacks.
    ├── make_golden_signed_v2.py  Run once to create the frozen version 2 test vector.
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
