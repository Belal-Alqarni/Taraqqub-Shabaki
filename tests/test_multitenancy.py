import os
import tempfile
import unittest

from fastapi import HTTPException
from starlette.requests import Request

from app.agents import (
    authenticate_agent,
    create_agent,
    ingest_report,
    revoke_agent,
)
from app.auth import create_signup_account
from app.config import get_settings
from app.database import connect, init_db
from app.schemas import AgentDeviceReport
from app.services import list_devices


class WorkspaceIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["TARAQQUB_DB_PATH"] = os.path.join(
            self.temp_dir.name, "test.db"
        )
        os.environ["TARAQQUB_ALLOW_SIGNUP"] = "true"
        os.environ["TARAQQUB_ENV"] = "development"
        get_settings.cache_clear()
        init_db()

    def tearDown(self) -> None:
        get_settings.cache_clear()
        self.temp_dir.cleanup()

    def signup(self, username: str) -> dict:
        return create_signup_account(
            username,
            f"{username}-Strong-Password-2026",
            f"{username} Workspace",
            f"test-{username}",
        )

    def test_agent_data_is_isolated_by_workspace(self) -> None:
        alice = self.signup("alice")
        bob = self.signup("bob")
        agent = create_agent(alice["workspace_id"], "Alice Agent")

        ingest_report(
            {"id": agent["id"], "workspace_id": alice["workspace_id"]},
            [
                AgentDeviceReport(
                    name="Alice Router",
                    ip_address="192.168.10.1",
                    role="router",
                    latency_ms=4.2,
                )
            ],
        )

        self.assertEqual(len(list_devices(alice)), 1)
        self.assertEqual(list_devices(bob), [])
        self.assertEqual(list_devices(alice)[0]["source"], "agent")

    def test_token_is_hashed_and_revocation_is_enforced(self) -> None:
        user = self.signup("carol")
        agent = create_agent(user["workspace_id"], "Carol Agent")
        with connect() as conn:
            stored = conn.execute(
                "SELECT token_hash FROM agents WHERE id = ?", (agent["id"],)
            ).fetchone()["token_hash"]
        self.assertNotEqual(stored, agent["token"])

        request = Request(
            {
                "type": "http",
                "headers": [
                    (
                        b"authorization",
                        f"Bearer {agent['token']}".encode("ascii"),
                    )
                ],
            }
        )
        self.assertEqual(authenticate_agent(request)["id"], agent["id"])
        revoke_agent(user["workspace_id"], agent["id"])
        with self.assertRaises(HTTPException) as raised:
            authenticate_agent(request)
        self.assertEqual(raised.exception.status_code, 401)

    def test_public_ip_reports_are_rejected(self) -> None:
        user = self.signup("dana")
        agent = create_agent(user["workspace_id"], "Dana Agent")
        with self.assertRaises(HTTPException) as raised:
            ingest_report(
                {"id": agent["id"], "workspace_id": user["workspace_id"]},
                [
                    AgentDeviceReport(
                        name="Public resolver",
                        ip_address="8.8.8.8",
                    )
                ],
            )
        self.assertEqual(raised.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
