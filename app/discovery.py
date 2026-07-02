import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

from app.collectors import ping_device, utc_now
from app.config import get_settings
from app.database import connect


IPV4_RE = re.compile(r"IPv4 Address[^:]*:\s*([0-9.]+)")
MASK_RE = re.compile(r"Subnet Mask[^:]*:\s*([0-9.]+)")
GATEWAY_RE = re.compile(r"Default Gateway[^:]*:\s*([0-9.]+)")


def local_network() -> tuple[ipaddress.IPv4Network, str, str | None]:
    settings = get_settings()
    if settings.scan_network:
        network = ipaddress.ip_network(settings.scan_network, strict=False)
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or not network.is_private
            or network.num_addresses > 256
        ):
            raise RuntimeError(
                "TARAQQUB_SCAN_NETWORK must be a private IPv4 network with at most 256 addresses."
            )
        return network, _preferred_local_ip() or "container", settings.scan_gateway

    if not shutil.which("ipconfig"):
        raise RuntimeError(
            "Local network detection is unavailable. Set TARAQQUB_SCAN_NETWORK explicitly."
        )

    result = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=10,
        check=True,
    )

    preferred_ip = _preferred_local_ip()
    candidates = []
    for block in re.split(r"\r?\n\r?\n", result.stdout):
        ip_match = IPV4_RE.search(block)
        mask_match = MASK_RE.search(block)
        if not ip_match or not mask_match:
            continue

        address = ipaddress.ip_address(ip_match.group(1))
        if not address.is_private or address.is_loopback:
            continue

        gateway_match = GATEWAY_RE.search(block)
        gateway = gateway_match.group(1) if gateway_match else None
        if not gateway:
            mask = mask_match.group(1)
            block_addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", block)
            gateway = next(
                (
                    value
                    for value in reversed(block_addresses)
                    if value not in {str(address), mask}
                    and ipaddress.ip_address(value).is_private
                ),
                None,
            )
        network = ipaddress.ip_network(f"{address}/{mask_match.group(1)}", strict=False)
        candidates.append((network, str(address), gateway))

    if not candidates:
        raise RuntimeError("No active private IPv4 network was found.")

    selected = next(
        (item for item in candidates if item[1] == preferred_ip),
        next((item for item in candidates if item[2]), candidates[0]),
    )
    network, address, gateway = selected
    if network.num_addresses > 256:
        network = ipaddress.ip_network(f"{address}/24", strict=False)
    return network, address, gateway


def _preferred_local_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def scan_local_network() -> dict:
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("Nmap is not installed or is not available in PATH.")

    network, local_ip, gateway = local_network()
    if not network.is_private or network.num_addresses > 256:
        raise RuntimeError("Discovery is limited to private networks with at most 256 addresses.")

    result = subprocess.run(
        [nmap, "-sn", "-n", "-oX", "-", str(network)],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=90,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Nmap discovery failed.")

    root = ET.fromstring(result.stdout)
    discovered = []
    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address[@addrtype='ipv4']")
        if status is None or status.get("state") != "up" or address is None:
            continue

        ip_address = address.get("addr")
        parsed_address = ipaddress.ip_address(ip_address)
        if parsed_address in {network.network_address, network.broadcast_address}:
            continue
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None
        role = "router" if ip_address == gateway else "endpoint"
        name = hostname or ("Local Gateway" if role == "router" else f"Device {ip_address}")
        metrics = ping_device(ip_address)
        discovered.append(
            {
                "name": name,
                "ip_address": ip_address,
                "role": role,
                "status": "online",
                "latency_ms": metrics["latency_ms"],
                "packet_loss": metrics["packet_loss"],
            }
        )

    with connect() as conn:
        for item in discovered:
            conn.execute(
                """
                INSERT INTO devices (name, ip_address, role, vendor, location, status, source)
                VALUES (?, ?, ?, ?, ?, ?, 'discovered')
                ON CONFLICT(ip_address) DO UPDATE SET
                    name = excluded.name,
                    role = excluded.role,
                    status = excluded.status,
                    source = 'discovered'
                """,
                (
                    item["name"],
                    item["ip_address"],
                    item["role"],
                    "Unknown",
                    "Local Network",
                    item["status"],
                ),
            )
            device = conn.execute(
                "SELECT id FROM devices WHERE ip_address = ?", (item["ip_address"],)
            ).fetchone()
            conn.execute(
                """
                INSERT INTO metrics (
                    device_id, timestamp, latency_ms, packet_loss, cpu_usage, memory_usage,
                    traffic_in_mbps, traffic_out_mbps
                ) VALUES (?, ?, ?, ?, 0, 0, 0, 0)
                """,
                (
                    device["id"],
                    utc_now(),
                    item["latency_ms"],
                    item["packet_loss"],
                ),
            )

    return {
        "started_at": utc_now(),
        "mode": "live",
        "network": str(network),
        "local_ip": local_ip,
        "gateway": gateway,
        "count": len(discovered),
        "discovered": discovered,
    }
