import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


def settings() -> tuple[str, str, ipaddress.IPv4Network, int]:
    server = os.environ.get("TARAQQUB_SERVER_URL", "").strip().rstrip("/")
    token = os.environ.get("TARAQQUB_AGENT_TOKEN", "").strip()
    network_value = os.environ.get("TARAQQUB_AGENT_NETWORK", "").strip()
    interval = int(os.environ.get("TARAQQUB_AGENT_INTERVAL", "60"))

    parsed = urlparse(server)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("TARAQQUB_SERVER_URL must use HTTPS.")
    if not token.startswith("tqs_"):
        raise RuntimeError("TARAQQUB_AGENT_TOKEN is missing or invalid.")
    network = ipaddress.ip_network(network_value, strict=False)
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not network.is_private
        or network.num_addresses > 256
    ):
        raise RuntimeError(
            "TARAQQUB_AGENT_NETWORK must be a private IPv4 subnet no larger than /24."
        )
    if interval < 30:
        raise RuntimeError("TARAQQUB_AGENT_INTERVAL must be at least 30 seconds.")
    return server, token, network, interval


def ping(ip_address: str) -> tuple[float, float]:
    command = (
        ["ping", "-n", "2", "-w", "700", ip_address]
        if os.name == "nt"
        else ["ping", "-c", "2", "-W", "1", ip_address]
    )
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=6,
        check=False,
    )
    replies = re.findall(r"TTL=\d+", result.stdout, flags=re.IGNORECASE)
    times = [
        float(value)
        for value in re.findall(
            r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms",
            result.stdout,
            flags=re.IGNORECASE,
        )
    ]
    loss = round((2 - len(replies)) / 2 * 100, 2)
    latency = round(sum(times) / len(times), 2) if times else 0.0
    return latency, loss


def discover(network: ipaddress.IPv4Network) -> list[dict]:
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("Nmap is required by the network agent.")
    result = subprocess.run(
        [nmap, "-sn", "-n", "-oX", "-", str(network)],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Nmap discovery failed.")

    devices = []
    root = ET.fromstring(result.stdout)
    for host in root.findall("host"):
        state = host.find("status")
        address = host.find("address[@addrtype='ipv4']")
        if state is None or state.get("state") != "up" or address is None:
            continue
        ip_address = str(ipaddress.ip_address(address.get("addr", "")))
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None
        latency, packet_loss = ping(ip_address)
        devices.append(
            {
                "name": hostname or f"Device {ip_address}",
                "ip_address": ip_address,
                "role": "endpoint",
                "vendor": "Unknown",
                "status": "online" if packet_loss < 100 else "down",
                "latency_ms": latency,
                "packet_loss": packet_loss,
                "cpu_usage": 0,
                "memory_usage": 0,
                "traffic_in_mbps": 0,
                "traffic_out_mbps": 0,
            }
        )
    return devices


def send_report(server: str, token: str, devices: list[dict]) -> None:
    if not devices:
        print("No active devices found; no report sent.", flush=True)
        return
    request = urllib.request.Request(
        f"{server}/api/agent/v1/report",
        data=json.dumps({"devices": devices}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Taraqqub-Shabaki-Agent/0.1",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    print(f"Report accepted: {result['count']} devices.", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Taraqqub Shabaki network agent")
    parser.add_argument("--once", action="store_true", help="Send one report and exit")
    args = parser.parse_args()
    server, token, network, interval = settings()

    while True:
        try:
            devices = discover(network)
            send_report(server, token, devices)
        except (RuntimeError, OSError, urllib.error.URLError, ValueError) as exc:
            print(f"Agent cycle failed: {exc}", flush=True)
            if args.once:
                raise SystemExit(1) from exc
        if args.once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
