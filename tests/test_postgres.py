import os
import unittest
import uuid

from app.auth import create_signup_account
from app.config import get_settings
from app.database import connect, init_db


@unittest.skipUnless(
    os.getenv("TARAQQUB_TEST_POSTGRES_URL"),
    "PostgreSQL integration URL is not configured.",
)
class PostgresCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["TARAQQUB_DATABASE_URL"] = os.environ[
            "TARAQQUB_TEST_POSTGRES_URL"
        ]
        os.environ["TARAQQUB_ALLOW_SIGNUP"] = "true"
        get_settings.cache_clear()
        init_db()

    def test_signup_creates_isolated_postgres_workspaces(self) -> None:
        suffix = uuid.uuid4().hex[:10]
        alice = create_signup_account(
            f"alice_{suffix}",
            "A-secure-test-password-2026",
            f"Alice {suffix}",
            "127.0.0.1",
        )
        bob = create_signup_account(
            f"bob_{suffix}",
            "B-secure-test-password-2026",
            f"Bob {suffix}",
            "127.0.0.2",
        )

        self.assertNotEqual(alice["workspace_id"], bob["workspace_id"])
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT username, workspace_id FROM users
                WHERE username IN (?, ?)
                ORDER BY username
                """,
                (alice["username"], bob["username"]),
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["workspace_id"], rows[1]["workspace_id"])
