"""Independent standby ledger in Neon Postgres, separate from Supabase."""

import os


class ConflictError(Exception):
    pass


class NeonStore:
    def __init__(self, connect=None):
        if connect is None:
            import psycopg
            connect = psycopg.connect
        self.connect = connect
        self.database_url = os.environ["BACKUP_DATABASE_URL"]

    def _db(self):
        # Neon requires TLS. Render and Neon credentials stay server-side.
        return self.connect(self.database_url, sslmode="require", connect_timeout=10)

    def get(self, request_id):
        with self._db() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT request_id, token_id, request_digest, version, nonce, ciphertext, "
                    "wallet_status, route FROM backup_handoffs WHERE request_id = %s",
                    (request_id,),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        fields = ("request_id", "token_id", "request_digest", "version", "nonce",
                  "ciphertext", "wallet_status", "route")
        return dict(zip(fields, row))

    def create(self, record):
        with self._db() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO backup_handoffs "
                    "(request_id, token_id, request_digest, version, nonce, ciphertext, "
                    "wallet_status, route) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (request_id) DO NOTHING RETURNING request_id",
                    tuple(record[key] for key in ("request_id", "token_id", "request_digest",
                                                   "version", "nonce", "ciphertext",
                                                   "wallet_status", "route")),
                )
                if cursor.fetchone() is None:
                    raise ConflictError("Request ID already exists.")

    def accept(self, request_id, reviewer_id, accepted_at):
        with self._db() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE backup_handoffs SET wallet_status = 'accepted', reviewer_id = %s, "
                    "accepted_at = %s WHERE request_id = %s AND wallet_status = 'pending' "
                    "RETURNING request_id",
                    (reviewer_id, accepted_at, request_id),
                )
                return cursor.fetchone() is not None
