from app.services import list_devices, recent_metrics


def analyze_incident(user: dict, device_id: int | None, symptom: str) -> dict:
    devices = list_devices(user)
    device = next((item for item in devices if item["id"] == device_id), None) if device_id else None
    metrics = recent_metrics(user, device_id=device_id, limit=1)
    latest = metrics[0] if metrics else {}

    findings: list[str] = []
    recommendations: list[str] = []

    if latest.get("packet_loss", 0) >= 10:
        findings.append("High packet loss suggests link congestion, bad cabling, wireless interference, or an upstream outage.")
        recommendations.append("Check interface errors, duplex mismatch, uplink utilization, and recent topology changes.")

    if latest.get("latency_ms", 0) >= 180:
        findings.append("Latency is above the healthy threshold for normal LAN operations.")
        recommendations.append("Trace the path, compare latency between hops, and inspect firewall or router CPU.")

    if latest.get("cpu_usage", 0) >= 85:
        findings.append("High CPU can cause slow forwarding, delayed control-plane responses, and SNMP timeouts.")
        recommendations.append("Review top processes, routing churn, broadcast storms, and logging volume.")

    if latest.get("memory_usage", 0) >= 90:
        findings.append("Memory pressure may indicate leaks, overloaded services, or undersized hardware.")
        recommendations.append("Check service memory usage and schedule a controlled restart if the service is non-critical.")

    lowered = symptom.lower()
    if "port" in lowered or "service" in lowered:
        recommendations.append("Run an authorized service scan and compare open ports against the approved baseline.")
    if "down" in lowered or "offline" in lowered:
        recommendations.append("Validate power, physical link, gateway reachability, and management VLAN access.")

    if not findings:
        findings.append("No severe metric threshold is currently triggered. The symptom may be intermittent or service-specific.")
        recommendations.append("Increase polling frequency temporarily and collect logs from the affected device or service.")

    return {
        "device": device,
        "symptom": symptom,
        "likely_causes": findings,
        "recommended_actions": recommendations,
        "self_healing_candidate": bool(device and device.get("role") in {"server", "switch"}),
    }
