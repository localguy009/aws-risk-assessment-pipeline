import os
import boto3
from datetime import datetime, timezone

from scorer import score_finding, get_risk_level, get_sla_due_date
from enricher import get_asset_criticality, get_exposure_score, get_resource_tags

dynamodb = boto3.resource("dynamodb")
sns_client = boto3.client("sns")

TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
CRITICAL_THRESHOLD = float(os.environ.get("CRITICAL_SCORE_THRESHOLD", "9.0"))

table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    print(f"FULL EVENT: {event}")
    detail = event.get("detail", {})

    findings_list = detail.get("findings", [])
    if findings_list:
        finding = findings_list[0]
    else:
        finding = detail

    finding_id = finding.get("Id", finding.get("id", ""))
    if not finding_id:
        print(f"No finding ID found in event: {event}")
        return {"statusCode": 400, "body": "No finding ID in event"}

    resource = _extract_resource(finding)
    cvss_score = _extract_cvss(finding)
    network_reachability = _extract_network_reachability(finding)

    resource_tags = {}
    if resource.get("type") in ["AWS_EC2_INSTANCE", "AwsEc2Instance"]:
        instance_id = resource.get("id", "").split("/")[-1].split(":")[-1]
        resource_tags = get_resource_tags(instance_id)

    asset_criticality = get_asset_criticality(resource_tags)
    exposure_score = get_exposure_score(network_reachability)
    risk_score = score_finding(cvss_score, asset_criticality, exposure_score)
    risk_level = get_risk_level(risk_score)
    sla_due_date = get_sla_due_date(risk_score)

    now = datetime.now(timezone.utc).isoformat()
    existing = table.get_item(Key={"finding_id": finding_id}).get("Item")

    if existing:
        table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="SET risk_score = :rs, risk_level = :rl, last_updated = :lu, title = :t, exploit_available = :ea, fix_available = :fa",
            ExpressionAttributeValues={
                ":rs": str(risk_score),
                ":rl": risk_level,
                ":lu": now,
                ":t":  finding.get("Title", ""),
                ":ea": _extract_exploit(finding),
                ":fa": _extract_fix(finding),
            },
        )
    else:
        table.put_item(Item={
            "finding_id":        finding_id,
            "title":             finding.get("Title", ""),
            "description":       finding.get("Description", "")[:500] if finding.get("Description") else "",
            "exploit_available": _extract_exploit(finding),
            "fix_available":     _extract_fix(finding),
            "cve_id":            _extract_cve(finding),
            "resource_arn":      resource.get("arn", ""),
            "resource_type":     resource.get("type", ""),
            "resource_tags":     resource_tags,
            "package_name":      _extract_package(finding),
            "installed_version": _extract_installed_version(finding),
            "fixed_version":     _extract_fixed_version(finding),
            "cvss_score":        str(cvss_score),
            "asset_criticality": str(asset_criticality),
            "exposure_score":    str(exposure_score),
            "risk_score":        str(risk_score),
            "risk_level":        risk_level,
            "status":            "OPEN",
            "first_seen":        now,
            "last_updated":      now,
            "remediated_at":     None,
            "sla_due_date":      sla_due_date,
            "alert_sent":        False,
        })

    if risk_score >= CRITICAL_THRESHOLD and not (existing and existing.get("alert_sent")):
        _send_alert(finding_id, risk_score, risk_level, resource.get("arn", ""))
        table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="SET alert_sent = :true",
            ExpressionAttributeValues={":true": True},
        )

    print(f"Processed {finding_id} — risk score {risk_score} ({risk_level})")
    return {"statusCode": 200, "body": f"Processed finding {finding_id} - risk score {risk_score}"}


def _send_alert(finding_id, risk_score, risk_level, resource_arn):
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[CRITICAL] Risk Assessment Pipeline Alert",
        Message=(
            f"CRITICAL FINDING ALERT\n\n"
            f"Finding ID: {finding_id}\n"
            f"Risk Score: {risk_score}\n"
            f"Risk Level: {risk_level}\n"
            f"Resource: {resource_arn}\n"
            f"Action required within 24 hours per SLA."
        ),
    )


def _extract_resource(finding):
    resources = finding.get("Resources", finding.get("resources", []))
    if not resources:
        return {}
    r = resources[0]
    resource_id = r.get("Id", r.get("id", ""))
    resource_type = r.get("Type", r.get("type", ""))
    return {"arn": resource_id, "type": resource_type, "id": resource_id}


def _extract_cvss(finding):
    product_fields = finding.get("ProductFields", {})
    score = product_fields.get("aws/inspector/inspectorScore")
    if score:
        try:
            return float(score)
        except (TypeError, ValueError):
            pass
    score = (
        finding.get("FindingProviderFields", {}).get("Severity", {}).get("Normalized") or
        finding.get("Severity", {}).get("Normalized") or
        finding.get("inspectorScore", 0)
    )
    try:
        normalized = float(score)
        return round(normalized / 10, 1) if normalized > 10 else normalized
    except (TypeError, ValueError):
        return 0.0


def _extract_network_reachability(finding):
    types = finding.get("Types", finding.get("types", []))
    if types:
        finding_type = types[0] if isinstance(types, list) else types
        if "Network Reachability" in str(finding_type):
            return "NETWORK_REACHABLE"
    details = finding.get("networkReachabilityDetails", {})
    steps = details.get("networkPath", {}).get("steps", [{}])
    return steps[-1].get("componentType", "NOT_APPLICABLE")


def _extract_cve(finding):
    vuln_id = (
        finding.get("Vulnerabilities", [{}])[0].get("Id", "") if finding.get("Vulnerabilities") else
        finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId", "")
    )
    if not vuln_id:
        title = finding.get("Title", "")
        if title.startswith("CVE-"):
            vuln_id = title.split(" ")[0]
    return vuln_id


def _extract_package(finding):
    vulns = finding.get("Vulnerabilities", [])
    if vulns and vulns[0].get("VulnerablePackages"):
        return vulns[0]["VulnerablePackages"][0].get("Name", "")
    pkgs = finding.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
    return pkgs[0].get("name", "") if pkgs else ""


def _extract_installed_version(finding):
    vulns = finding.get("Vulnerabilities", [])
    if vulns and vulns[0].get("VulnerablePackages"):
        return vulns[0]["VulnerablePackages"][0].get("Version", "")
    pkgs = finding.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
    return pkgs[0].get("version", "") if pkgs else ""


def _extract_fixed_version(finding):
    vulns = finding.get("Vulnerabilities", [])
    if vulns and vulns[0].get("VulnerablePackages"):
        return vulns[0]["VulnerablePackages"][0].get("FixedInVersion", "")
    pkgs = finding.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
    return pkgs[0].get("fixedInVersion", "") if pkgs else ""


def _extract_exploit(finding):
    vulns = finding.get("Vulnerabilities", [])
    if vulns:
        return vulns[0].get("ExploitAvailable", "NO")
    return "NO"


def _extract_fix(finding):
    vulns = finding.get("Vulnerabilities", [])
    if vulns:
        return vulns[0].get("FixAvailable", "NO")
    return "UNKNOWN"
