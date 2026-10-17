-- Run in the separate Neon project's SQL Editor. Synthetic demo records only.
CREATE TABLE IF NOT EXISTS backup_handoffs (
    request_id text PRIMARY KEY,
    token_id text NOT NULL,
    request_digest text NOT NULL,
    version integer NOT NULL CHECK (version = 1),
    nonce text NOT NULL,
    ciphertext text NOT NULL,
    wallet_status text NOT NULL CHECK (wallet_status IN ('pending', 'accepted')),
    route text NOT NULL CHECK (route = 'neon_standby'),
    reviewer_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz
);
