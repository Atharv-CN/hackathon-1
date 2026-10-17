# Independent no-Google fallback: Render + Neon

The normal QShield flow and the team's existing Supabase backend are the **primary path**. This separate path is for a demo where either or both are unavailable:

```text
Fake payment reference → Render creator → encrypted pending row in Neon Postgres
                                        → Render Wallet verifier → accepted
```

The backup APIs never call Supabase or QShield. Neon is a separate Postgres provider whose [Free plan says no credit card is required](https://neon.com/blog/making-pricing-more-predictable). Render [advertises free web services without payment](https://render.com/docs/your-first-deploy), but [may ask some users for a card to verify their account](https://community.render.com/t/the-deployement-of-a-web-service-fails/36005). If Render asks, you can run these same APIs on a team laptop for a hackathon demo, or later port them to Neon Functions. Do not claim a hosted failover until it has been deployed and tested.

## Set up

1. Create a free Neon project and run [`neon.sql`](neon.sql) in its SQL Editor. This creates a **separate** `backup_handoffs` table, outside Supabase.
2. Copy Neon's Postgres connection string into `BACKUP_DATABASE_URL` for both APIs. Keep it in secret environment variables, never in a webpage or Git. The code requires TLS.
3. Generate one AES key: `python3 -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'`. Put the same output in `BACKUP_AES_KEY_B64` on both APIs. Changing it makes old backup records unreadable.
4. Generate two different random request secrets. Put `PRIMARY_TO_BACKUP_SECRET` on the creator API and on the QShield demo caller. Put `WALLET_TO_BACKUP_SECRET` on the Wallet API and its trusted test caller. Never expose either to browser code.
5. If Render accepts your free account without a card, deploy both APIs from [`render.yaml`](../render.yaml) and enter the secret values. Check each `/health`. Free web services sleep after 15 idle minutes and may take about a minute to wake, so open them before presenting.
6. Use `demo_client.py` to create and accept a synthetic handoff first. Its INR amount (in paise) and `mockpay_` reference match the team's test payment provider.

For an easier deployed check, run `python3 backup-service/verify_deployment.py` from the repository root. It asks for both Render URLs and the creator and Wallet request secrets without displaying the secrets as you type. Successful `pending` and `accepted` responses prove both services can reach Neon. It does not require the Neon connection string on your laptop.

## Connect the QShield test checkout

The draft branch adds a server-side caller to the Streamlit payment page. Set `BACKUP_CREATOR_URL` to the HTTPS URL of `qshield-backup-creator` and set `PRIMARY_TO_BACKUP_SECRET` to the same creator request secret already on Render. Put both values in the QShield server environment or Streamlit secrets, never in browser JavaScript or Git. Run the QShield app from this branch to use the new code.

In the Pay form, tick **Simulate QShield + Supabase outage** to send a successful mock payment directly to Neon. If Supabase token creation actually fails, the page also tries the backup automatically. The request includes only the mock provider reference, INR amount, random token, and test status; it excludes the card number, expiry, CVV, and cardholder name. The page shows the backup request ID while Wallet verification is pending. The separate Wallet API is exercised by `verify_deployment.py`; the QShield Wallet tab does not accept Neon handoffs.

For a no-card local demo, install `requirements.txt`, put those same variables in the two terminal environments, then run `uvicorn creator:app --host 127.0.0.1 --port 8001` and `uvicorn wallet:app --host 127.0.0.1 --port 8002` from this folder. Set `CREATOR_URL=http://127.0.0.1:8001` and `WALLET_URL=http://127.0.0.1:8002` for the test client.

## What the demo proves

The creator accepts a synthetic payload such as:

```json
{"request_id":"TEST-REQUEST-1042","token_id":"ptok_abcdefghijklmnopqrstuvwxyzABCDEF","provider_reference":"mockpay_abcdefghijklmnop","amount_minor":49900,"currency":"INR","payment_status":"succeeded"}
```

It requires `X-Timestamp` and `X-Signature`, an HMAC-SHA256 over `timestamp + "." + URL_path + "." + exact_request_body` using `PRIMARY_TO_BACKUP_SECRET`. Requests expire after five minutes. A repeated request ID with the same body returns the original row; changing its body returns 409. The response route is `neon_standby`.

The separate Wallet API accepts `POST /v1/wallet/accept`, signed with `WALLET_TO_BACKUP_SECRET`:

```json
{"request_id":"TEST-REQUEST-1042","reviewer_id":"wallet-demo-operator"}
```

It decrypts the row, checks the AES-GCM authentication tag and payment fields, and atomically changes `pending` to `accepted`. A real Wallet caller must authenticate its operator; this demo service has no human login. To try a deployed setup, set `CREATOR_URL`, `WALLET_URL`, and both request secrets, then run `python demo_client.py create --request-id TEST-REQUEST-12345` followed by `python demo_client.py accept --request-id TEST-REQUEST-12345`.

## Limits

- This is a **QShield/Supabase outage simulation**, not a real payment system. The Streamlit integration requires the QShield app server to be running. If that app is truly down, a separate payment page or provider webhook must call Render directly.
- Neon backup data is independent of Supabase, but the two Render APIs and Neon must be reachable. The two services share an AES key and database credentials, so this is demo-level key custody.
- No real card number, CVV, bank detail, or customer data belongs here.
