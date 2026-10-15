# Public-key authentication (relay key substitution fix)

## The vulnerability

The relay (`relay.py`, Supabase) stored a receiver's raw ML-KEM-768 public key under a 48-bit short code.
The sender typed the code and QShield encrypted to **whatever key the relay returned**.

**Attack:** anyone who controls or compromises the relay (or can write to the `transfers` table) replaces the
stored key with their own. The sender encrypts for the attacker, who decrypts with their own private key.
The only defence was reading a 64-hex-character fingerprint aloud. Nothing tied the key to an identity.
A short code, a username or a successful API response is not proof of ownership.

## The fix in one paragraph

Each receiver has a long-term **Ed25519 identity key**. Its public half is written as a **QShield ID** (`QSID1-...`).
The receiver publishes their ML-KEM key inside a **signed key bundle**. The sender gets the QShield ID **once, from the
receiver, by a channel the relay does not control**, and verifies every bundle against it. The verifying key is decoded from the
ID the sender typed, never from anything the relay sent, so a relay that replaces both the bundle and any "verifying key" still
fails. The ID is short and reusable: no fingerprint reading per key, and ML-KEM key rotation needs no new verification.

## Threat model

| Attacker | Attack | Mitigation | Residual risk |
|---|---|---|---|
| Malicious / compromised relay | Swap the stored key for its own | Bundle must verify under the QShield ID the sender holds; attacker cannot sign as the receiver | None for the relay path, **if the QShield ID was obtained safely** |
| Relay | Present a bundle signed by the attacker's own identity | Rejected: identity must equal the expected ID | Same |
| Relay | Serve an old valid bundle (replay / rollback) | Per-identity `seq` is remembered in the trust store; lower `seq` rejected | A sender who has never seen a newer bundle can be replayed an old one **until it expires** (default 14 days) |
| Relay | Same `seq`, different key (equivocation) | Rejected | None |
| Relay / attacker with a leaked old key | Re-present a revoked key | Revoked key IDs (listed in a later signed bundle) are remembered and never accepted | Sender must have seen the revoking bundle; a relay can withhold it (denial of service, bounded by expiry) |
| Relay | Downgrade to old unsigned keys (`kind=pubkey`) or smuggle a raw key into a bundle | Sender never reads `pubkey`; non-JSON or unsigned data is rejected (`legacy_unsigned`); relay refuses to publish unsigned keys | Manual paste path (below) is unauthenticated by design |
| Relay | Reuse a signature in another context | Signature covers a domain string plus `typ`, `purpose`, `v`, `kem_alg` | None known |
| Anyone | Malformed / oversized / duplicate-key / wrong-type bundles | Strict parser, fail closed | Parser bugs |
| Attacker on the QShield ID channel | Give the sender the attacker's ID | **Not prevented** | **Bootstrap risk**, see below |
| Anyone who steals the identity key file | Sign bundles as the receiver | File is password-protected PKCS#8 | Weak password / endpoint compromise; recovery = new identity + new ID |

## What is signed

`signature = Ed25519(DOMAIN || payload_bytes)`, `DOMAIN = "QShield key bundle v1\0"`. The payload bytes travel verbatim next to the
signature (no re-serialization). Payload fields (exactly these): `typ, v, purpose, identity, kem_alg, kem_public_key, key_id, seq,
issued_at, expires_at, revoked_key_ids`. Unknown or missing fields are rejected. Validity is capped at 90 days.

Verification order (`core/identity.py::verify_key_bundle`): size/format, expected ID checksum, **signature under the expected ID**, field
checks, identity match, key size and `key_id == SHA-256(key)`, time window, then trust-store checks (revoked, rollback, equivocation).
Only then is a `VerifiedKey` returned and the store updated. `encrypt_for_verified_key` accepts nothing else.

## How to use it

**Receiver (Receiver tab, relay configured):**
1. Generate the ML-KEM key pair (existing button).
2. Click **Create QShield identity** (uses the same password box). Download the identity `.pem`; keep it safe.
3. Send your **QShield ID** to the sender by chat, email or in person. Do **not** rely on the relay for this.
4. Click **Publish signed key bundle to relay** and give the sender the receiver code.

**Sender:** enter the receiver's QShield ID **and** code. The UI shows "Key verified" or a red "Key NOT trusted" with the reason.
Optional: paste a raw public key instead; this requires ticking "I confirmed the fingerprint with the receiver" and is labelled unauthenticated.

**Rotation:** generate a new ML-KEM key and publish again. The `seq` rises automatically (time-based and strictly increasing).
The sender accepts it silently as far as verification goes but is shown a "key rotated" notice. **Compromise:** publish a new bundle whose
`revoked_key_ids` lists the old key ID (`sign_key_bundle(..., revoked_key_ids=[...])`); if the *identity* key leaked, create a new identity and
tell senders the new QShield ID out of band.

## Trust store

`core/trust_store.py` keeps, per QShield ID: latest `seq`, current `key_id`, revoked IDs, short history. It never decides trust by itself.
- Set `QSHIELD_TRUST_STORE=/path/trust.json` for a single-user install (atomic writes, mode 0600). A corrupt file stops the app (fail closed).
- Otherwise it is per browser session with **Download/Restore trust store** in the Sender tab. It is never shared between visitors.
- `TrustStore.forget(id)` removes a contact and its rollback/revocation memory. It is explicit and logged.

Security events are logged to the `qshield.security` logger (rejections, rotations, pins). Keys, bundles and passwords are never logged.

## Migration from old clients and keys

- Old relay rows of `kind=pubkey` are **not** used. The sender shows "legacy unsigned key". The receiver creates an identity, publishes a signed bundle, and shares the new code and ID.
- The `.qshield` package format is unchanged; old packages still decrypt (the golden-vector test is untouched).
- Old clients that paste keys keep working through the manual path. There is no compatibility mode that accepts unsigned relay keys.
- `relay.put("pubkey", ...)` now raises. No database migration is needed (`kind` is free text).

## Limits you should know

1. **Bootstrap:** the QShield ID is the trust anchor. If an attacker substitutes the ID on the channel you used, they win. Use a channel you already trust (an authenticated chat, in person, a signed repository file). A compact ID is easy to compare once if you want extra assurance.
2. **No first-use (TOFU) fallback for identities:** the relay is never allowed to introduce an identity. TOFU would let a malicious relay win the first contact, so there is no code path that pins an ID learned from the relay. The store's `source` field exists so a deployment that adds TOFU can mark such pins.
3. **Freshness:** timestamps and `seq` do not stop a relay replaying an old unexpired bundle to a sender with no newer state. Shorten `validity_seconds` for high-risk use.
4. **The sender is still not authenticated** (separate, pre-existing limit: encryption does not prove who sent a file).
5. Identity keys use Ed25519, which is **not** post-quantum. Confidentiality still uses ML-KEM-768, but a future quantum attacker could forge identity signatures and substitute keys. The README's "not claimed quantum-resistant" still applies.
6. The Streamlit session holds the password-protected identity PEM, not the raw key; signing needs the password each time.
7. This is a prototype and has had no independent audit. Passing tests does not prove the system secure.
8. The root `README.md` describes a Vite web app that is not part of this repository snapshot; it has no relay and is not changed here.

## Run the tests

```
cd "qshield 2"
pip install -r requirements-dev.txt
pytest tests/test_key_authentication.py tests/test_key_authentication_e2e.py -v
pytest            # everything
```
`test_key_authentication_e2e.py` needs a `cryptography` build with ML-KEM and is skipped otherwise.
