# Streaming encryption format (STREAM)

## Why

Format version 1 encrypts a whole file with **one** AES-GCM call. That needs the complete file (and the complete
ciphertext) in memory at once, and the `cryptography` library caps one call at 2**31 - 1 bytes (~2 GB). Raising
that constant would not help: memory use would still equal the file size, and a late failure could only be noticed
after everything was read. The streaming format fixes the architecture instead: the file is encrypted in
independent, authenticated segments, so memory use is a few segments however large the file is.

## The construction

QShield uses the **AES-GCM-HKDF Streaming AEAD (STREAM)** construction as documented for Google Tink
(<https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming>), AES-256 profile, with HKDF-SHA256.
It is implemented with `cryptography`'s `AESGCM` and `HKDF` only (no hand-written AES, GCM, HKDF or randomness).

**Deviations and honesty notes**
- It is **not** the Tink library and interoperability with it has **not been verified** (no network or Tink here).
  The tests compare the output byte-for-byte with a second, independently written implementation of the documented
  construction, which checks the code against the specification as understood, not against Tink itself.
- The stream starts after QShield's own envelope (below). The 40-byte STREAM header is counted as the first
  segment's offset exactly as the construction says; the QShield envelope is application framing and is not.
- Tink's own Python library was considered. It was not adopted because it works through keyset handles (not raw
  keys derived from ML-KEM), would add a large dependency, and could not be installed or tested here.
  Recommendation: verify interoperability against Tink's published test vectors before claiming it.

### Layout

```
standalone file (magic QSHS)                 recipient package (magic QSHK, version 2)
---------------------------------------      ----------------------------------------------
magic "QSHS" (4)                             magic "QSHK" (4), version = 2 (1), suite = 2 (1)
version = 1 (1), suite = 1 (1)               recipient key fingerprint (32), ML-KEM ciphertext (1088)
ciphertext segment size (4, big-endian)      ciphertext segment size (4, big-endian)
metadata length (4), metadata JSON           metadata length (4), metadata JSON
STREAM header (40)                           STREAM header (40)
segments ...                                 segments ...

STREAM header = header length 40 (1) | salt (32, random per stream) | nonce prefix (7, random per stream)
```

Everything before the STREAM header is authenticated but **not encrypted** (the file name and size are visible).

### Segments

- Each segment is `AES-256-GCM(chunk)` plus a 16-byte tag. **No per-segment AAD** (the construction puts application
  context in the key derivation instead).
- The first segment is `segment size - 40` bytes on the wire (it is shortened by the header); every other
  non-final segment is exactly `segment size`; the final segment is 1..`segment size` bytes.
  An empty file is one segment holding only a tag. A file that ends exactly on a boundary has **no** extra empty segment.
- Default segment size 1 MiB; allowed range 256 bytes .. 16 MiB (the reader never buffers more than that).
- **Nonce** (12 bytes) = nonce prefix (7) | segment number (4, big-endian, from 0) | final flag (1: 0 = more follow, 1 = last).
- The final flag is **not stored**. The reader decides it from where the data really ends (one segment of look-ahead),
  so cutting a stream short, or appending to it, makes authentication fail.
- At most 2**32 segments. The writer and reader refuse to use number 2**32, so a nonce can never repeat.

### Keys (one level)

```
standalone:  aes_key = HKDF-SHA256(ikm = caller's 32-byte key,        salt = STREAM salt,
                                   info = "QShield stream v1: ... standalone\0" | envelope)
recipient:   aes_key = HKDF-SHA256(ikm = ML-KEM shared secret (32 B), salt = STREAM salt,
                                   info = "QShield v2 stream: ...\0" | outer header | envelope)
```

`envelope` = everything before the STREAM header (segment size, metadata, and for standalone files the magic, version
and suite). For recipient packages `outer header` = magic, version, suite, recipient fingerprint and the ML-KEM
ciphertext. Changing any of those bytes, the salt, the nonce prefix or the key changes the derived key or nonce, so
nothing decrypts. The ML-KEM shared secret is fresh per package; nothing else is derived and no key is stored.

## Safe file output

A stream can contain many valid segments and still fail later (truncation, a bad last tag). So file functions
never write to the destination while decrypting:

1. decrypt into a private temporary file in the destination folder (`mkstemp`, mode 0600);
2. after the **final** segment and the end of the file verify, flush and `fsync`;
3. publish with a hard link (never replaces an existing file or symlink) or `os.replace` if `overwrite=True`;
4. on **any** error the temporary file is deleted and an existing destination is untouched.

The same is done when encrypting, so an interrupted run leaves no partial `.qshield` file.

## Versions and compatibility

| Format | Magic / version | API | Memory | Size |
|---|---|---|---|---|
| Standalone v1 | `QSHD` / 1 | `encrypt_bytes`, `decrypt_bytes` | whole file | ~2 GB max |
| Standalone streaming | `QSHS` / 1 | `encrypt_stream`, `decrypt_stream`, `encrypt_file`, `decrypt_file` | a few segments | no practical limit (2**32 segments) |
| Package v1 | `QSHK` / 1, suite 1 | `encrypt_for_recipient`, `decrypt_package` | whole file | ~2 GB max |
| Package streaming | `QSHK` / **2**, suite 2 | `encrypt_stream_for_recipient`, `decrypt_package_stream`, `encrypt_file_for_recipient`, `decrypt_package_file` | a few segments | no practical limit |

- Readers dispatch on the **validated** magic/version/suite. Unknown versions or suites are refused. A streaming
  file is never handed to the version 1 code or vice versa, and the key derivation labels differ, so rewriting the
  version bytes cannot turn one format into the other (tested).
- Version 1 files and packages, including the golden vector in `tests/data/`, still open unchanged.
- `decrypt_bytes` and `decrypt_package` also open the streaming formats, but they **return `bytes`**, so they
  necessarily hold the whole result in memory. Only the `file`/`stream` functions are bounded-memory.
- Older QShield versions and the **browser app cannot open version 2 packages.** The Sender tab has a checkbox to make a
  version 1 package for them.
- `encrypt_file` / `encrypt_file_for_recipient` now write the streaming format by default.
