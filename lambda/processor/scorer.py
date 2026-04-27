from datetime import datetime, timezone, timedelta

RISK_LEVELS = [
    (9.0, "CRITICAL", timedelta(hours=24)),
    (7.0, "HIGH",     timedelta(days=7)),
    (4.0, "MEDIUM",   timedelta(days=30)),
    (0.0, "LOW",      timedelta(days=90)),
]


def score_finding(cvss_score: float, asset_criticality: float, exposure_score: float) -> float:
    raw = (cvss_score * 0.5) + (asset_criticality * 0.3) + (exposure_score * 0.2)
    return round(min(raw, 10.0), 2)


def get_risk_level(risk_score: float) -> str:
    for threshold, level, _ in RISK_LEVELS:
        if risk_score >= threshold:
            return level
    return "LOW"


def get_sla_due_date(risk_score: float) -> str:
    now = datetime.now(timezone.utc)
    for threshold, _, sla_delta in RISK_LEVELS:
        if risk_score >= threshold:
            return (now + sla_delta).isoformat()
    return (now + timedelta(days=90)).isoformat()
