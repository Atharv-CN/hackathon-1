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
| ML-KEM-768 key establishment connected to the app (suite 1) | ✅ Working |
| Hybrid X25519 + ML-KEM-768 key establishment (suite 2) | ✅ Working |
| ML-KEM-1024 key establishment (suite 3) | ✅ Working |
| Encrypted file integrity verification (AES-GCM) | ✅ Working |
| Claiming the whole system is "quantum-resistant" | 🚫 Not claimed (see the limits in the ML-KEM section) |
| Relay public-key authentication (signed key bundles + QShield ID) | ✅ Working (see `docs/KEY_AUTHENTICATION.md`) |
| Sender identity verification (hybrid Ed25519 + ML-DSA-65 signatures) | 🧩 Built and tested in `core/`, not connected to the app tabs yet. Packages made by the app are still unsigned |
| Sending over a real network | ⏳ Not built yet |

**Use test files only. Do not upload real secrets.** Encryption is connected, but this is an unaudited hackathon prototype. It does not prove who the sender is.

**Team rule:** never show something as "working" unless real code exists and you have tested it. When you build a feature, update `core/security_status.py` at the same time. Do not use pretend or home-made cryptography.

## How to run it

You need **Python 3.9 or newer**. Check with `python --version` (or `python3 --version`).

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

1. Open the **Receiver** tab. Choose an algorithm suite (see below), choose a password and click **Generate ... key pair**.
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
- Checks the file contents, the file name, size and time, **and** the format version when decrypting. If even one bit was changed, decryption fails and returns nothing.
- Never has a built-in key. The key is always passed in, and `generate_key()` makes a new random one.
- Has `encrypt_file()` and `decrypt_file()` for files on disk. They now use the **streaming format** (see "Large files" below), never overwrite an existing file unless you ask, and never leave a half-written file behind.
- `encrypt_bytes()` / `decrypt_bytes()` are the original **whole-file, in-memory** functions (version 1, about 2 GB at most).

What it does **not** do (read this before you trust it):
- The **file name, exact size and creation time are inside the encryption** (container version 2; the old version 1 kept them visible and still opens). Someone holding the container sees only a marker, the version, a random nonce and the total length.
- The total length still reveals the file size unless you turn on **padding**: `encrypt_bytes(data, key, padding="padme")` (at most ~12% bigger, hides most of the size information) or `padding=65536` (round up to a multiple of that many bytes; `1048576` makes every file under 1 MB look alike). Padding is zeros inside the encryption and is checked on opening.
- Whoever stores or forwards the container sees **when** they got it and **what name they gave it**. The app's download name is random by default, so the real name does not leak there or into the relay.
- Anyone who has the key can make a valid file, so it does not prove who the sender is.
- It does not share keys. How the sender safely gives the key to the receiver is the next problem to solve.
- Use a **new key for each transfer**.
- It is not claimed to be quantum-resistant.

## Algorithm suites (the receiver chooses)

| Suite | Key establishment | What it is for |
|---|---|---|
| 1 (default) | ML-KEM-768 only, **no hybrid** | The original QShield format. |
| 2 | **X25519 + ML-KEM-768 (hybrid)** | Both secrets are joined and fed into HKDF, so an attacker has to break both. If a flaw is found in the newer algorithm (ML-KEM), X25519 still protects against attackers using ordinary computers. |
| 3 | ML-KEM-1024 only | Higher security level (bigger keys). Same algorithm family as suite 1, so it adds safety margin but is **not** a hedge against a flaw in ML-KEM itself. |

Be precise about what suite 2 buys you: it hedges against a *classical* break of ML-KEM. A large quantum computer breaks X25519, so against a quantum attacker suite 2 is only as strong as its ML-KEM half. The suite is chosen by the receiver when making the key pair. The public key says which suite to use, so the sender needs no setting. A key only opens packages of its own suite, and the suite is mixed into the key derivation, so nobody can downgrade a package by editing its header.

```python
private_key = generate_recipient_keypair(2)     # 1 = ML-KEM-768, 2 = hybrid, 3 = ML-KEM-1024
public_text = public_key_to_text(private_key.public_key())   # suite 2 and 3 texts start with "QS2:" / "QS3:"
```

Suite 2 key files hold two password-protected PEM blocks (X25519, then ML-KEM-768). Download the file and keep it whole.

## Sending a file to a recipient (ML-KEM)

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

The package (format version 1) is a small header followed by the encrypted file. The header holds a format marker, the version, the algorithm suite number, a fingerprint of the recipient's key, and the KEM locked box (1088 bytes for suite 1, 1120 for suite 2, 1568 for suite 3). The whole header is mixed into the key, so changing any part of the package makes opening it fail. A new suite number is how a future version can change algorithms without confusing old packages.

Read these limits before you trust it:
- **No proof of who sent it.** Anyone with the public key can make a package. Digital signatures would be needed for that. They are not built.
- **Check the public key.** Compare fingerprints with the receiver by phone or in person. Otherwise someone could swap in their own public key.
- **No forward secrecy for stored packages.** If the private key is stolen later, old packages can be opened. That is expected for files kept on disk. For live channels, see "Live sessions with forward secrecy" below.
- Visible outside the encryption: the suite, the recipient key fingerprint, and the total package length (rounded if you use padding). The file name, exact size and time are hidden. The Supabase relay also sees when a package was uploaded.
- There has been no independent security audit.
- The Streamlit app now uses this module. The tabs still run in one browser session, so treat that as a demo of the buttons, not as two separate computers. The sender tab never displays the private key.

## Package formats at a glance

Every `.qshield` package starts with the marker `QSHK`, then a version byte and a suite byte. The reader looks at both and refuses anything it does not recognise.

| Version / suite bytes | What it is | Made by | Opened by | Hides name, size, time? |
|---|---|---|---|---|
| 1 / 1, 2 or 3 | Whole-file package: ML-KEM-768, X25519 + ML-KEM-768 hybrid, or ML-KEM-1024, optional padding | `encrypt_for_recipient` | `decrypt_package`, `decrypt_package_file` | Yes |
| 2 / 2 | **Streaming** package (large files, ML-KEM-768 keys only) | `encrypt_stream_for_recipient`, `encrypt_file_for_recipient` (default for suite 1 keys without padding) | `decrypt_package`, `decrypt_package_stream`, `decrypt_package_file` | **No** (visible, authenticated) |
| 2 / 1 | **Signed** package (proves who sent it, ML-KEM-768 keys only) | `signed_transfer.sign_and_encrypt` | `signed_transfer.decrypt_and_verify` | Yes |

The streaming and signed formats happen to share version byte 2. They differ in the suite byte and in their key-derivation labels, and each reader refuses the other's packages (tested in `tests/test_format_interop.py`). `encrypt_file_for_recipient` uses streaming only for ML-KEM-768 keys without padding; hybrid, ML-KEM-1024 and padded files use version 1.

## Large files (streaming encryption)

The whole-file functions (`encrypt_bytes` / `decrypt_bytes`, `encrypt_for_recipient` / `decrypt_package`) take and return `bytes`, so memory use equals the file size and the library caps one AES-GCM call at about 2 GB. QShield also has a **streaming format** built on the STREAM construction (the documented Google Tink AES-GCM-HKDF scheme, implemented with `cryptography`'s AES-GCM and HKDF): the file is split into 1 MiB segments, each authenticated separately, and the last segment is authenticated as "final" so a cut-off file is detected.

```python
from core.file_crypto import generate_key, encrypt_file, decrypt_file
from core.pq_transfer import encrypt_file_for_recipient, decrypt_package_file

encrypt_file("movie.mkv", "movie.mkv.qshield", key)             # bounded memory, any size
decrypt_file("movie.mkv.qshield", "out/", key)                  # published only if EVERYTHING verifies
encrypt_file_for_recipient("movie.mkv", "m.qshield", public_key)    # ML-KEM + streaming (package version 2)
decrypt_package_file("m.qshield", "out/", private_key)
```

- **Memory:** a few segments (about 3-4 MiB with the default size), whatever the file size. Measured: 2 GiB + 12 KB encrypted and decrypted with a process peak of about 40 MiB. The limit is now 2**32 segments (about 4 PiB).
- **Safe output:** decryption goes to a private temporary file and is published only after the final segment and end-of-file verify. A failure deletes the temporary file and leaves any existing destination alone.
- **Stream APIs:** `encrypt_stream` / `decrypt_stream` and `encrypt_stream_for_recipient` / `decrypt_package_stream` work on open binary files. Their output may contain already-verified chunks before a later failure, so they are for callers that handle that (the `*_file` functions do).
- **Not bounded-memory:** anything that takes or returns `bytes`. `decrypt_package` and `decrypt_bytes` can open the streaming formats, but they hold the result in memory.
- **Compatibility:** older containers and packages (including the golden vectors) still open. Streaming packages are `QSHK` **version 2**. The browser app and older QShield versions cannot open them; tick "Make a version 1 package" in the Sender tab for those. Details: [`docs/STREAMING_FORMAT.md`](docs/STREAMING_FORMAT.md).
- **Known gaps (streaming format only):**
  - The file name, exact size and creation time are **authenticated but not encrypted**, unlike container version 2 from `encrypt_bytes`.
  - Padding is not available.
  - Streaming packages currently work with ML-KEM-768 keys (suite 1) only, not the hybrid or ML-KEM-1024 suites.
- **Not verified:** interoperability with Google Tink's own library.

**The web app still buffers whole files.** Streamlit's uploader keeps the entire upload in the server's memory and `st.download_button` takes the finished bytes, so the Sender and Receiver tabs are **not** end-to-end streaming. `maxUploadSize` is 25 MB in `.streamlit/config.toml`, and relay uploads are capped at 5 MB. For big files use the Python functions above on disk. (This describes Streamlit's documented behaviour; it was not measured.)

## Live sessions with forward secrecy (separate protocol)

`.qshield` packages are encrypted to a long-term key, so a leaked private key opens every saved package. `core/session.py` is a **separate protocol for live channels** that fixes this with an ephemeral-KEM handshake. Think of the padlock again: for every session the client makes a brand-new one-time padlock, uses it once, then **throws the key away**. Whoever steals the server's long-term key later cannot rebuild the keys of a finished session.

1. The client makes a one-time key pair and sends its public half, plus a locked box for the server's long-term key (`ClientHello`).
2. The server opens that box, locks a second box for the one-time key, and answers with a confirmation tag (`ServerHello`).
3. Both secrets go into HKDF-SHA256 together with a hash of the whole handshake. The client then deletes the one-time private key.
4. Messages use AES-256-GCM, one key per direction, with a counter so replayed, re-ordered or dropped messages are refused.

It works with all three suites (the server's key decides which). It uses only ML-KEM / X25519, HKDF, HMAC and AES-256-GCM from the `cryptography` library.

```python
from core.session import ClientHandshake, ServerHandshake

# SERVER: its long-term key from generate_recipient_keypair(...)
server = ServerHandshake(server_private_key)

# CLIENT: knows the server's PUBLIC key (fingerprint checked by phone)
client = ClientHandshake(server_public_key)
client_hello = client.start()                      # send to the server
server_hello, server_session = server.respond(client_hello)   # send back
client_session = client.finish(server_hello)       # raises HandshakeError if anything is off

record = client_session.seal(b"hello")             # send to the server
server_session.open(record)                        # b"hello"
```

`client_connect(sock, public_key)` and `server_accept(sock, private_key)` run the same thing over a TCP socket.

Limits (please read):
- **Only protects PAST sessions.** If the server's key is stolen before or during a session, the thief can impersonate the server and read that live session.
- **The client is not authenticated.** Anyone can open a session. There are no client keys or signatures.
- **Check the server's public key** by fingerprint, or the client may talk to an attacker.
- Forward secrecy depends on the client really forgetting the one-time key. Python cannot guarantee memory is wiped, and a machine that is already hacked during the session is lost.
- One handshake is one session, with no re-keying. It is **not connected to the Streamlit app**, and there has been no independent security audit.

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

The frozen version 2 test vector (`tests/data/golden_signed_package_v2.json`) was created with `python tests/make_golden_signed_v2.py`; `test_version_2_golden_package_still_opens` keeps the format from changing.

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

The relay is **not trusted**. It only stores a *signed key bundle* or an already-encrypted package. Public keys are accepted only if signed by the receiver's **QShield ID**, which the sender gets from the receiver by another channel (chat, email, in person). A relay that swaps the key is detected and the file is not encrypted. Details, threat model, rotation and limits: [`docs/KEY_AUTHENTICATION.md`](docs/KEY_AUTHENTICATION.md).

Revised flow: **Receiver** generates keys → **Create QShield identity** → sends the QShield ID to the sender (not via the relay) → **Publish signed key bundle** → gets a code. **Sender** enters the QShield ID and the code, encrypts → "Send to receiver via relay" → package code. **Receiver** enters the package code → "Fetch package" → decrypts. The old unsigned `pubkey` codes are rejected. If you paste a public key by hand instead, confirm its fingerprint with the receiver; QShield cannot verify who owns it.

## Run the tests

```
pip install -r requirements-dev.txt
pytest
```

Add `-v` to see every test name. All tests should pass; the exact count grows as tests are added.

What the tests prove:
- **Encryption works:** files of many sizes are encrypted and recovered, with and without ML-KEM.
- **Metadata is private:** the file name, exact size and creation time cannot be found anywhere in a container or package, with or without padding. Old version-1 containers still open.
- **Padding works:** padded packages fall into the expected size groups, padding must be all zeros, and forged padding or metadata is rejected.
- **Corruption is rejected:** changing **any single bit** anywhere in a package is rejected. So are truncated packages, extra bytes, mixed-up parts, and unknown versions.
- **Wrong keys are rejected:** a package for a different recipient key cannot be opened, even if the fingerprint label is forged.
- **The private key stays private:** it is not in the package and not in the shared public key, and it is saved only password-protected.
- **ML-KEM is the real thing:** a separate implementation (`kyber-py`, used only in the tests) agrees with the library for ML-KEM-768 and ML-KEM-1024, and can open QShield packages.
- **The hybrid really is a hybrid:** the AES key is rebuilt by hand from both secrets, and no key can be derived from only one of them. Both private halves are needed.
- **Sessions have forward secrecy:** a test records a whole session, then gives the attacker the server's long-term private key. Every attempt to rebuild the keys fails, and a control in the same test shows the same steps succeed when the deleted one-time key is supplied.
- **Sessions refuse tampering:** every changed handshake byte, an impostor server, a wrong server key, and any changed, replayed, re-ordered or dropped message is rejected.
- **No downgrades:** changing the suite label, or opening a package with a key of another suite, is refused.
- **Relay keys are authenticated:** a relay that swaps, replays, rolls back or downgrades a public key is rejected, using signed key bundles checked against a QShield ID.
- **Streaming is correct and bounded:** every chunk boundary, truncation at every length, reordered / removed / duplicated / transplanted segments, wrong final flags, trailing data, bad headers, counter overflow, and failed writes are tested; a 2 GiB+ stream is processed through a bounded pipe (set `QSHIELD_SKIP_LARGE_TESTS=1` to skip it on a very slow machine).
- **Format version 1 is frozen:** saved version-1 packages for all three suites in `tests/data/` must keep opening. Its key is a public test key, so never use it for real data.
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
│   ├── pq_transfer.py      ML-KEM / hybrid / ML-KEM-1024 + HKDF + AES-256-GCM transfer packages.
│   ├── session.py          Forward-secret live sessions (ephemeral-KEM handshake).
│   ├── signatures.py       Hybrid Ed25519 + ML-DSA-65 signatures, sender identities, protected key files.
│   ├── signed_transfer.py  Signed + encrypted version 2 packages (sign_and_encrypt, decrypt_and_verify).
│   ├── transfer_flow.py    Glue used by the Sender and Receiver tabs.
│   ├── identity.py         QShield ID, Ed25519 identity, signed key bundles + verification.
│   ├── key_directory.py    Safe relay lookup: code + expected QShield ID -> verified key.
│   ├── trust_store.py      Remembers seq / key / revocations per identity (anti-rollback).
│   ├── state.py            Shared memory between the tabs.
│   └── security_status.py  The honest list of working / not-built features.
├── views/                  The "screens": what the user sees.
│   ├── sender.py           Sender tab.
│   ├── receiver.py         Receiver tab.
│   └── security_panel.py   Security Status tab.
└── tests/
    ├── test_file_crypto.py    Tests for the AES-256-GCM module.
    ├── test_pq_transfer.py    Tests for ML-KEM-768 transfer packages (suite 1).
    ├── test_suites.py         Tests for suites 2 (hybrid) and 3, and suite mixing.
    ├── test_session.py        Tests for the forward-secret session protocol.
    ├── test_metadata_privacy.py Tests for hidden file name/size/time and padding.
    ├── test_mlkem_interop.py  Checks the library's ML-KEM against a second implementation.
    ├── test_signatures.py     Tests for the hybrid signature module and identity files.
    ├── test_signed_transfer.py Tests for signed packages, including forgery and forwarding attacks.
    ├── make_golden_signed_v2.py  Run once to create the frozen version 2 test vector.
    ├── test_app_integration.py Website encrypt/decrypt flow (no browser).
    ├── test_streaming.py        STREAM format: boundaries, tampering, truncation, memory, 2 GiB stream.
    ├── test_streaming_pq.py     Streaming ML-KEM packages (version 2) and the key hierarchy.
    ├── test_key_authentication.py      Adversarial tests: key substitution, rollback, revocation, legacy.
    ├── test_key_authentication_e2e.py  Original attack vs the fix, with real ML-KEM.
    └── data/golden_package_v1*.json  Saved version-1 packages (public TEST keys only).
```

**Tip for beginners:** to add a new feature, put the logic in `core/` and the buttons and text in `views/`. Keeping them apart makes teamwork easier, because two people can work on different files without clashing.

## Common problems

| Problem | Fix |
|---|---|
| `streamlit: command not found` | Activate the environment (Step 1), then try again. |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again. |
| Port 8501 is busy | Run `streamlit run app.py --server.port 8502` |
| File is rejected as too big | The web app's limit is 25 MB (Streamlit keeps uploads in memory). Change `maxUploadSize` in `.streamlit/config.toml`, or use `encrypt_file()` / `encrypt_file_for_recipient()` from Python for large files. |
