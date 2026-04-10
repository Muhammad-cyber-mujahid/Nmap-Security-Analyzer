RISKY_SERVICES = {
    "3389": {"name": "RDP", "risk": "Critical", "weight": 30},
    "445": {"name": "SMB", "risk": "High", "weight": 25},
    "23": {"name": "Telnet", "risk": "Critical", "weight": 35},
    "21": {"name": "FTP", "risk": "High", "weight": 20},
    "1433": {"name": "MSSQL", "risk": "High", "weight": 22},
    "3306": {"name": "MySQL", "risk": "High", "weight": 22},
    "5900": {"name": "VNC", "risk": "High", "weight": 18},
    "22": {"name": "SSH", "risk": "Medium", "weight": 12},
}


def get_risk_level(port: str, service: str = "", version: str = "") -> dict:
    info = RISKY_SERVICES.get(port, {"name": service or "Unknown", "risk": "Low", "weight": 5})

    # Version-based bonus risk
    if "OpenSSH" in version and any(v in version for v in ["6.", "7.0", "7.1", "7.2", "7.3", "7.4"]):
        info["risk"] = "High"
        info["weight"] = 25
        info["reason"] = "Outdated OpenSSH - vulnerable"

    return info


def calculate_host_risk_score(ports: list) -> int:
    """Calculate overall risk score 0-100"""
    if not ports:
        return 0

    total_score = 0
    max_possible = 0

    risk_multiplier = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    for port in ports:
        risk_info = get_risk_level(port["port"], port["service"], port.get("version", ""))
        weight = risk_info.get("weight", 5)
        multiplier = risk_multiplier.get(risk_info["risk"], 1)

        total_score += weight * multiplier
        max_possible += 40  # Max per port

    score = min(int((total_score / max_possible) * 100), 100)
    return max(score, 0)