from datetime import datetime, timezone

from app.database import connect, rows_to_dicts


def list_devices() -> list[dict]:
    with connect() as conn:
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


def add_device(payload) -> dict:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO devices (name, ip_address, role, vendor, location)
            VALUES (?, ?, ?, ?, ?)
            """,
            (payload.name, payload.ip_address, payload.role, payload.vendor, payload.location),
        )
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return dict(row)


def recent_metrics(device_id: int | None = None, limit: int = 120) -> list[dict]:
    with connect() as conn:
        if device_id:
            rows = conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return rows_to_dicts(rows)


def list_alerts() -> list[dict]:
    with connect() as conn:
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


def acknowledge_alert(alert_id: int) -> dict:
    with connect() as conn:
        conn.execute("UPDATE alerts SET status = 'acknowledged' WHERE id = ?", (alert_id,))
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row)


def topology() -> dict:
    with connect() as conn:
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
