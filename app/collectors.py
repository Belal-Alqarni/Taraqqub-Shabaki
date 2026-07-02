import asyncio
import os
import random
import re
import subprocess
from datetime import datetime, timezone

from app.config import get_settings
from app.database import connect


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def status_from_metrics(latency_ms: float, packet_loss: float, cpu_usage: float, memory_usage: float) -> str:
    if packet_loss >= 40 or latency_ms >= 600:
        return "down"
    if packet_loss >= 10 or latency_ms >= 180 or cpu_usage >= 90 or memory_usage >= 92:
        return "degraded"
    return "online"


def generate_metrics(device: dict) -> dict:
    role_bias = {
        "router": (22, 0.5, 45, 52, 70, 64),
        "switch": (8, 0.2, 28, 36, 120, 118),
        "firewall": (18, 0.4, 58, 62, 95, 88),
        "server": (14, 0.3, 50, 66, 42, 39),
    }
    latency, loss, cpu, memory, traffic_in, traffic_out = role_bias.get(device["role"], role_bias["server"])
    jitter = random.random()

    if jitter > 0.94:
        latency *= random.uniform(6, 14)
        loss += random.uniform(8, 35)
        cpu += random.uniform(15, 35)
    elif jitter > 0.86:
        latency *= random.uniform(2, 5)
        loss += random.uniform(2, 9)
        memory += random.uniform(10, 22)

    return {
        "latency_ms": round(max(1, random.gauss(latency, latency * 0.25)), 2),
        "packet_loss": round(min(100, max(0, random.gauss(loss, 1.2))), 2),
        "cpu_usage": round(min(100, max(1, random.gauss(cpu, 9))), 2),
        "memory_usage": round(min(100, max(1, random.gauss(memory, 8))), 2),
        "traffic_in_mbps": round(max(0.1, random.gauss(traffic_in, traffic_in * 0.22)), 2),
        "traffic_out_mbps": round(max(0.1, random.gauss(traffic_out, traffic_out * 0.22)), 2),
    }


def ping_device(ip_address: str, attempts: int = 2) -> dict:
    command = (
        ["ping", "-n", str(attempts), "-w", "700", ip_address]
        if os.name == "nt"
        else ["ping", "-c", str(attempts), "-W", "1", ip_address]
    )
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(5, attempts * 2),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "latency_ms": 0.0,
            "packet_loss": 100.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "traffic_in_mbps": 0.0,
            "traffic_out_mbps": 0.0,
        }

    replies = re.findall(r"TTL=\d+", result.stdout, flags=re.IGNORECASE)
    times = [
        float(value)
        for value in re.findall(
            r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms",
            result.stdout,
            flags=re.IGNORECASE,
        )
    ]
    packet_loss = round((attempts - len(replies)) / attempts * 100, 2)
    latency = round(sum(times) / len(times), 2) if times else 0.0
    return {
        "latency_ms": latency,
        "packet_loss": packet_loss,
        "cpu_usage": 0.0,
        "memory_usage": 0.0,
        "traffic_in_mbps": 0.0,
        "traffic_out_mbps": 0.0,
    }


def collect_once() -> None:
    with connect() as conn:
        devices = [dict(row) for row in conn.execute("SELECT * FROM devices ORDER BY id").fetchall()]

    samples = []
    for device in devices:
        metrics = (
            ping_device(device["ip_address"])
            if device.get("source") == "discovered"
            else generate_metrics(device)
        )
        status = status_from_metrics(
            metrics["latency_ms"],
            metrics["packet_loss"],
            metrics["cpu_usage"],
            metrics["memory_usage"],
        )
        samples.append((device, metrics, status))

    with connect() as conn:
        for device, metrics, status in samples:
            conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device["id"]))
            conn.execute(
                """
                INSERT INTO metrics (
                    device_id, timestamp, latency_ms, packet_loss, cpu_usage, memory_usage,
                    traffic_in_mbps, traffic_out_mbps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device["id"],
                    utc_now(),
                    metrics["latency_ms"],
                    metrics["packet_loss"],
                    metrics["cpu_usage"],
                    metrics["memory_usage"],
                    metrics["traffic_in_mbps"],
                    metrics["traffic_out_mbps"],
                ),
            )
            maybe_create_alert(conn, device, status, metrics)


def maybe_create_alert(conn, device: dict, status: str, metrics: dict) -> None:
    if status == "online":
        return

    open_alert = conn.execute(
        "SELECT id FROM alerts WHERE device_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
        (device["id"],),
    ).fetchone()
    if open_alert:
        return

    severity = "critical" if status == "down" else "warning"
    title = f"{device['name']} is {status}"
    description = (
        f"Latency {metrics['latency_ms']} ms, packet loss {metrics['packet_loss']}%, "
        f"CPU {metrics['cpu_usage']}%, memory {metrics['memory_usage']}%."
    )
    conn.execute(
        """
        INSERT INTO alerts (device_id, severity, title, description, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (device["id"], severity, title, description, utc_now()),
    )


async def monitor_loop() -> None:
    interval = get_settings().monitor_interval
    while True:
        collect_once()
        await asyncio.sleep(interval)
