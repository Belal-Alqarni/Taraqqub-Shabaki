from datetime import datetime, timezone

from app.database import connect, rows_to_dicts


def list_devices(user: dict) -> list[dict]:
    with connect() as conn:
        if user["username"] != "demo":
            rows = conn.execute(
                """
                SELECT d.*,
                       m.timestamp,
                       m.latency_ms,
                       m.packet_loss,
                       m.cpu_usage,
                       m.memory_usage,
                       m.traffic_in_mbps,
                       m.traffic_out_mbps
                FROM managed_devices d
                LEFT JOIN managed_metrics m ON m.id = (
                    SELECT id FROM managed_metrics
                    WHERE device_id = d.id ORDER BY id DESC LIMIT 1
                )
                WHERE d.workspace_id = ?
                ORDER BY d.id
                """,
                (user["workspace_id"],),
            ).fetchall()
            return rows_to_dicts(rows)
        rows = conn.execute(
            """
            SELECT d.*,
                   m.timestamp,
                   m.latency_ms,
                   m.packet_loss,
                   m.cpu_usage,
                   m.memory_usage,
                   m.traffic_in_mbps,
                   m.traffic_out_mbps
            FROM devices d
            LEFT JOIN metrics m ON m.id = (
                SELECT id FROM metrics WHERE device_id = d.id ORDER BY id DESC LIMIT 1
            )
            ORDER BY d.id
            """
        ).fetchall()
        return rows_to_dicts(rows)


def add_device(payload, user: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO managed_devices (
                workspace_id, name, ip_address, role, vendor, location,
                status, source, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, 'unknown', 'manual', ?)
            """,
            (
                user["workspace_id"],
                payload.name,
                payload.ip_address,
                payload.role,
                payload.vendor,
                payload.location,
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM managed_devices WHERE id = ? AND workspace_id = ?",
            (cursor.lastrowid, user["workspace_id"]),
        ).fetchone()
        return dict(row)


def recent_metrics(
    user: dict, device_id: int | None = None, limit: int = 120
) -> list[dict]:
    with connect() as conn:
        if user["username"] != "demo":
            parameters: list = [user["workspace_id"]]
            device_clause = ""
            if device_id:
                device_clause = "AND m.device_id = ?"
                parameters.append(device_id)
            parameters.append(limit)
            rows = conn.execute(
                f"""
                SELECT m.*
                FROM managed_metrics m
                JOIN managed_devices d ON d.id = m.device_id
                WHERE d.workspace_id = ? {device_clause}
                ORDER BY m.id DESC LIMIT ?
                """,
                tuple(parameters),
            ).fetchall()
            return rows_to_dicts(rows)
        if device_id:
            rows = conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return rows_to_dicts(rows)


def list_alerts(user: dict) -> list[dict]:
    with connect() as conn:
        if user["username"] != "demo":
            rows = conn.execute(
                """
                SELECT a.*, d.name AS device_name, d.ip_address
                FROM managed_alerts a
                JOIN managed_devices d ON d.id = a.device_id
                WHERE d.workspace_id = ?
                ORDER BY a.id DESC LIMIT 50
                """,
                (user["workspace_id"],),
            ).fetchall()
            return rows_to_dicts(rows)
        rows = conn.execute(
            """
            SELECT a.*, d.name AS device_name, d.ip_address
            FROM alerts a
            LEFT JOIN devices d ON d.id = a.device_id
            ORDER BY a.id DESC
            LIMIT 50
            """
        ).fetchall()
        return rows_to_dicts(rows)


def acknowledge_alert(alert_id: int, user: dict) -> dict:
    with connect() as conn:
        table = "alerts" if user["username"] == "demo" else "managed_alerts"
        if table == "managed_alerts":
            conn.execute(
                """
                UPDATE managed_alerts SET status = 'acknowledged'
                WHERE id = ? AND device_id IN (
                    SELECT id FROM managed_devices WHERE workspace_id = ?
                )
                """,
                (alert_id, user["workspace_id"]),
            )
            row = conn.execute(
                """
                SELECT a.* FROM managed_alerts a
                JOIN managed_devices d ON d.id = a.device_id
                WHERE a.id = ? AND d.workspace_id = ?
                """,
                (alert_id, user["workspace_id"]),
            ).fetchone()
        else:
            conn.execute(
                "UPDATE alerts SET status = 'acknowledged' WHERE id = ?",
                (alert_id,),
            )
            row = conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        if not row:
            raise ValueError("Alert not found.")
        return dict(row)


def topology(user: dict) -> dict:
    with connect() as conn:
        if user["username"] != "demo":
            devices = rows_to_dicts(
                conn.execute(
                    "SELECT * FROM managed_devices WHERE workspace_id = ? ORDER BY id",
                    (user["workspace_id"],),
                ).fetchall()
            )
            return {"nodes": devices, "links": []}
        devices = rows_to_dicts(conn.execute("SELECT * FROM devices ORDER BY id").fetchall())
        links = rows_to_dicts(conn.execute("SELECT * FROM links ORDER BY id").fetchall())
        return {"nodes": devices, "links": links}


def discovery_preview() -> dict:
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mode": "preview",
        "message": "Nmap discovery hook is ready. Replace preview data with authorized subnet scans.",
        "discovered": [
            {"ip_address": "192.0.2.10", "hostname": "helpdesk-pc", "open_ports": [22, 3389]},
            {"ip_address": "192.0.2.40", "hostname": "backup-nas", "open_ports": [22, 445, 8080]},
        ],
    }
