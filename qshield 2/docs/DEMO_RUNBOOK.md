# QShield hackathon demo runbook

## The one-minute story

QShield is a small Python API that developers can install in their own app. The
Streamlit site shows the same receive → send → open flow. A receiver creates a
password-protected private key and shares a public key. The sender checks the
full fingerprint through a separate trusted channel and encrypts a test file.
Only the receiver can open the package. The recommended key combines
ML-KEM-1024 with X25519; the encrypted file uses AES-256-GCM.

**Scope to say aloud:** local file encryption uses a post-quantum KEM, but the
combined protocol is unaudited. The hosted website handles plaintext and
passwords on its server. It does not authenticate the sender. Use test files.

## Prepare before presenting

1. From the `qshield` folder, use Python 3.10+ and install the demo:
   `python -m pip install '.[demo]'`.
2. Run `python -m pytest -q tests test_key_storage.py` after installing
   `requirements-dev.txt`. Confirm the final passing count on your machine.
3. Create a harmless `hello.txt` containing `Hello from QShield`.
4. Start `streamlit run app.py` (add `--server.fileWatcherType none` if macOS
   reports a file watcher error). Open two separate browser sessions: one regular
   window for Receive, one private/incognito window for Send. Separate sessions
   keep their session state apart. Keep a third window or a terminal ready for
   the independent Python example.
5. If a relay is configured, use it only for packages below 5 MiB. The download
   and upload path works without it. Do not put a secret service key in slides
   or screen captures.

## Live flow (about three minutes)

| Time | Show | Say |
|---|---|---|
| 0:00 | Receive → Create keys. Enter and repeat a unique 12+ character test password. Click Create keys and save the private key. | The public key can be shared. The private key and password stay with the receiver. Back up both. |
| 0:45 | Copy the full public key into the other session's Send tab. Read the displayed 64-digit fingerprint and compare with Receive over a separate channel. Tick confirmation. | The comparison stops a swapped public key; a fingerprint generated from the pasted key alone cannot prove ownership. |
| 1:30 | Choose `hello.txt`, click Encrypt file and download the randomly named `.qshield` file. | This package uses suite 4, hides its original name and exact size, and adds padding. |
| 2:00 | In Receive → Open a file, upload that `.qshield` package, use the session key or saved `.pem`, enter the password, click Decrypt file. | The download appears only after integrity verification. |
| 2:30 | Show the recovered text. In a terminal, run `python -m examples.integration_demo`. | A separate Python application calls the four-function SDK without the website or relay. |

### One security failure to show

Use a different receiver key or a damaged copy of the package, and click
Decrypt file again. The screen must show a security warning, clear any previous
recovered result, and offer no recovered-file download. Do this only with a test
package. The preflight tests also cover a changed byte, wrong password, wrong
key, wrong suite and fingerprint mismatch.

### Transfer when devices are separate

Use normal file transfer to give the sender the receiver's **public** key and
give the receiver the encrypted `.qshield` package. Confirm the full fingerprint
on a separate trusted channel, such as a call. If Supabase relay is configured,
Sender → Package details & relay delivery → Send via relay gives a package code;
Receiver → Advanced → Fetch package from relay accepts that code. This relay
only transports the encrypted package. Use the direct download/upload flow if
the relay or network is unavailable. Never transfer a private key or password.

## SDK check from another folder

Install from source with `python -m pip install .` or install the included
`dist/qshield_sdk-0.1.0-py3-none-any.whl`. To rebuild it, run
`python -m build --wheel`. From a different directory, use the installed
package to run the disposable example:

```bash
cd /tmp
python /path/to/qshield/examples/integration_demo.py
```

That program creates sender and receiver folders, transfers the public key and
package, and verifies the recovered content. Its hard-coded test password and
files exist only in a temporary directory. The four functions are
`create_keys`, `get_fingerprint`, `encrypt_file`, and `decrypt_file`; see the
README for copyable application code.

## Backup for presentation day

Before the round, record a short local screen capture of the four live actions
(create, confirm, encrypt, open) using a harmless test file. Keep a copy of the
encrypted test package, its matching test private key, and the test password
off-screen. Screenshots of the key-creation success, downloaded package, and
verified recovered file are sufficient as a slide fallback. Never display an
actual password, private key text, service credential or real secret file.

If the live site fails, run `python -m examples.integration_demo` and show its
SUCCESS line. If Python dependencies are unavailable, use the recorded capture
and explain that the SDK is packaged but the live environment is unavailable.

## Evidence and limits

- An isolated installation can import `qshield_sdk` from `site-packages` and
  complete a round trip from outside the source folder.
- Streamlit session tests exercise two independent sessions, package transfer,
  wrong key rejection, and tamper rejection.
- The relay requires valid Supabase credentials. Without them, the UI supports
  package download/upload; a live hosted relay transfer is not claimed as
  verified by the local tests.
- The 25 MiB UI/SDK limit and 5 MiB relay limit are intentional. Legacy
  streaming packages for larger files leak name and size and are not the
  recommended demo path.
