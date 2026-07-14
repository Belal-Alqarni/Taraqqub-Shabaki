import ipaddress
import secrets
from collections import defaultdict
from time import monotonic

from fastapi import HTTPException, Request, status

from app.auth import token_hash, utc_now
from app.database import connect, insert_and_get_id, rows_to_dicts


REPORT_WINDOW_SECONDS = 300
REPORT_LIMIT = 30
_report_attempts: dict[int, list[float]] = defaultdict(list)


def create_agent(workspace_id: int, name: str) -> dict:
    raw_token = f"tqs_{secrets.token_urlsafe(32)}"
    now = utc_now().isoformat()
    with connect() as conn:
        agent_id = insert_and_get_id(
            conn,
            """
            INSERT INTO agents (workspace_id, name, token_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (workspace_id, name.strip(), token_hash(raw_token), now),
        )
    return {
        "id": agent_id,
        "name": name.strip(),
        "token": raw_token,
        "created_at": now,
    }


def list_agents(workspace_id: int) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, name, is_active, last_seen, created_at
            FROM agents
            WHERE workspace_id = ?
            ORDER BY id DESC
            """,
            (workspace_id,),
        ).fetchall()
    return rows_to_dicts(rows)


def revoke_agent(workspace_id: int, agent_id: int) -> dict:
    with connect() as conn:
        conn.execute(
            "UPDATE agents SET is_active = 0 WHERE id = ? AND workspace_id = ?",
            (agent_id, workspace_id),
        )
        row = conn.execute(
            """
            SELECT id, name, is_active, last_seen, created_at
            FROM agents WHERE id = ? AND workspace_id = ?
            """,
            (agent_id, workspace_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return dict(row)


def authenticate_agent(request: Request) -> dict:
    authorization = request.headers.get("Authorization", "")
    scheme, _, raw_token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not raw_token.startswith("tqs_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid agent token required.",
        )
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, workspace_id, name
            FROM agents
            WHERE token_hash = ? AND is_active = 1
            """,
            (token_hash(raw_token),),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked agent token.",
        )
    return dict(row)


def _validate_private_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid device IP address: {value}",
        ) from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Agents may report private IPv4 addresses only.",
        )
    return str(address)


def ingest_report(agent: dict, devices: list) -> dict:
    now_monotonic = monotonic()
    recent = [
        timestamp
        for timestamp in _report_attempts[agent["id"]]
        if now_monotonic - timestamp < REPORT_WINDOW_SECONDS
    ]
    if len(recent) >= REPORT_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Agent report rate limit exceeded.",
        )
    recent.append(now_monotonic)
    _report_attempts[agent["id"]] = recent

    now = utc_now().isoformat()
    workspace_id = agent["workspace_id"]
    with connect() as conn:
        for report in devices:
            ip_address = _validate_private_ip(report.ip_address)
            conn.execute(
                """
                INSERT INTO managed_devices (
                    workspace_id, agent_id, name, ip_address, role, vendor,
                    status, location, source, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Local Network', 'agent', ?)
                ON CONFLICT(workspace_id, ip_address) DO UPDATE SET
                    agent_id = excluded.agent_id,
                    name = excluded.name,
                    role = excluded.role,
                    vendor = excluded.vendor,
                    status = excluded.status,
                    last_seen = excluded.last_seen
                """,
                (
                    workspace_id,
                    agent["id"],
                    report.name,
                    ip_address,
                    report.role,
                    report.vendor,
                    report.status,
                    now,
                ),
            )
            device = conn.execute(
                """
                SELECT id, name FROM managed_devices
                WHERE workspace_id = ? AND ip_address = ?
                """,
                (workspace_id, ip_address),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO managed_metrics (
                    device_id, timestamp, latency_ms, packet_loss, cpu_usage,
                    memory_usage, traffic_in_mbps, traffic_out_mbps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device["id"],
                    now,
                    report.latency_ms,
                    report.packet_loss,
                    report.cpu_usage,
                    report.memory_usage,
                    report.traffic_in_mbps,
                    report.traffic_out_mbps,
                ),
            )
            _create_alert_if_needed(conn, device, report, now)
        conn.execute(
            "UPDATE agents SET last_seen = ? WHERE id = ?",
            (now, agent["id"]),
        )
    return {"status": "accepted", "count": len(devices), "received_at": now}


def _create_alert_if_needed(conn, device, report, now: str) -> None:
    if report.status == "online":
        return
    existing = conn.execute(
        """
        SELECT id FROM managed_alerts
        WHERE device_id = ? AND status = 'open'
        ORDER BY id DESC LIMIT 1
        """,
        (device["id"],),
    ).fetchone()
    if existing:
        return
    severity = "critical" if report.status == "down" else "warning"
    conn.execute(
        """
        INSERT INTO managed_alerts (
            device_id, severity, title, description, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            device["id"],
            severity,
            f"{device['name']} is {report.status}",
            (
                f"Latency {report.latency_ms} ms, packet loss "
                f"{report.packet_loss}%, CPU {report.cpu_usage}%, "
                f"memory {report.memory_usage}%."
            ),
            now,
        ),
    )
