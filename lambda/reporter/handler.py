import os
import boto3
from datetime import datetime, timezone

dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")

TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]
S3_BUCKET = os.environ["S3_REPORT_BUCKET"]

table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    findings = _get_open_findings()
    report_html = _generate_report(findings)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"reports/{timestamp}/risk-report.html"

    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=report_html.encode("utf-8"),
        ContentType="text/html",
    )

    return {"statusCode": 200, "body": f"Report uploaded to s3://{S3_BUCKET}/{key}"}


def _get_open_findings():
    response = table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr("status").eq("OPEN")
    )
    return response.get("Items", [])


def _generate_report(findings):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    sla_breaches = []

    for f in findings:
        level = f.get("risk_level", "LOW")
        if level in counts:
            counts[level] += 1
        sla = f.get("sla_due_date", "")
        if sla and sla < datetime.now(timezone.utc).isoformat():
            sla_breaches.append(f)

    findings_sorted = sorted(findings, key=lambda x: float(x.get("risk_score", 0)), reverse=True)

    severity_colors = {
        "CRITICAL": "#ff4444",
        "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",
        "LOW": "#44bb44"
    }

    finding_cards = ""
    for f in findings_sorted:
        score = float(f.get("risk_score", 0))
        level = f.get("risk_level", "")
        color = severity_colors.get(level, "#999")
        resource_short = f.get("resource_arn", "").split(":")[-1]
        sla_short = f.get("sla_due_date", "")[:10]
        title = f.get("title", f.get("cve_id", "Unknown"))
        description = f.get("description", "No description available.")
        exploit = f.get("exploit_available", "NO")
        fix = f.get("fix_available", "UNKNOWN")
        package = f.get("package_name", "")
        installed = f.get("installed_version", "")
        fixed_in = f.get("fixed_version", "")
        cvss = f.get("cvss_score", "N/A")

        exploit_badge = "<span style='background:#ff4444;color:white;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:bold'>EXPLOIT AVAILABLE</span>" if exploit == "YES" else "<span style='background:#888;color:white;padding:2px 8px;border-radius:4px;font-size:0.75em'>No exploit</span>"
        fix_badge = "<span style='background:#44bb44;color:white;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:bold'>FIX AVAILABLE</span>" if fix == "YES" else "<span style='background:#ff8800;color:white;padding:2px 8px;border-radius:4px;font-size:0.75em'>No fix yet</span>"

        finding_cards += (
            "<div style='background:white;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,0.1);border-left:5px solid " + color + "'>"
            "<div style='display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px'>"
            "<div>"
            "<span style='font-size:0.8em;color:#888;font-weight:bold;text-transform:uppercase'>Finding</span><br>"
            "<strong style='font-size:1em;color:#1a1a2e'>" + title + "</strong>"
            "</div>"
            "<div style='text-align:right'>"
            "<span style='font-size:2em;font-weight:bold;color:" + color + "'>" + str(score) + "</span><br>"
            "<span style='background:" + color + ";color:white;padding:2px 10px;border-radius:4px;font-size:0.8em;font-weight:bold'>" + level + "</span>"
            "</div>"
            "</div>"
            "<p style='color:#444;font-size:0.85em;margin:8px 0;line-height:1.5'>" + description + "</p>"
            "<div style='display:flex;gap:8px;margin:10px 0'>" + exploit_badge + fix_badge + "</div>"
            "<table style='width:100%;border-collapse:collapse;margin-top:12px;font-size:0.82em'>"
            "<tr style='background:#f5f5f5'>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555;width:140px'>Resource</td>"
            "<td style='padding:6px 10px;color:#222'>" + resource_short + "</td>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555;width:140px'>CVSS Score</td>"
            "<td style='padding:6px 10px;color:#222'>" + str(cvss) + "</td>"
            "</tr>"
            "<tr>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555'>Package</td>"
            "<td style='padding:6px 10px;color:#222'>" + (package or "N/A") + "</td>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555'>Installed</td>"
            "<td style='padding:6px 10px;color:#222'>" + (installed or "N/A") + "</td>"
            "</tr>"
            "<tr style='background:#f5f5f5'>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555'>Fix Version</td>"
            "<td style='padding:6px 10px;color:#222'>" + (fixed_in or "N/A") + "</td>"
            "<td style='padding:6px 10px;font-weight:bold;color:#555'>SLA Due</td>"
            "<td style='padding:6px 10px;color:#222'>" + sla_short + "</td>"
            "</tr>"
            "</table>"
            "</div>"
        )

    if sla_breaches:
        breach_section = (
            "<table><thead><tr>"
            "<th>Finding</th><th>Risk Level</th><th>Score</th><th>Due Date</th><th>Resource</th>"
            "</tr></thead><tbody>"
        )
        for f in sla_breaches:
            breach_section += (
                "<tr style='background:#fff3f3'>"
                "<td>" + f.get("title", f.get("cve_id", "")) + "</td>"
                "<td>" + f.get("risk_level", "") + "</td>"
                "<td>" + str(f.get("risk_score", "")) + "</td>"
                "<td>" + f.get("sla_due_date", "")[:10] + "</td>"
                "<td>" + f.get("resource_arn", "").split(":")[-1] + "</td>"
                "</tr>"
            )
        breach_section += "</tbody></table>"
    else:
        breach_section = "<p class='no-breach'>No SLA breaches detected.</p>"

    if not findings:
        findings_section = "<p style='color:#666;font-style:italic'>No open findings.</p>"
    else:
        findings_section = "<p style='color:#555;margin-bottom:16px'>" + str(len(findings)) + " open finding(s) — sorted by risk score</p>" + finding_cards

    html = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
    html += "<title>Risk Assessment Report - " + now + "</title>"
    html += "<style>"
    html += "body{font-family:Arial,sans-serif;margin:40px;background:#f0f2f5;color:#222}"
    html += "h1{color:#1a1a2e}h2{color:#16213e;border-bottom:2px solid #e0e0e0;padding-bottom:6px;margin-top:30px}"
    html += ".summary{display:flex;gap:20px;margin:20px 0}"
    html += ".card{padding:20px 30px;border-radius:8px;color:white;text-align:center;min-width:100px}"
    html += ".card h3{margin:0;font-size:2em}.card p{margin:4px 0 0;font-size:0.9em}"
    html += ".critical{background:#ff4444}.high{background:#ff8800}.medium{background:#ffcc00;color:#333}.low{background:#44bb44}"
    html += "table{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.1)}"
    html += "th{background:#1a1a2e;color:white;padding:10px 14px;text-align:left;font-size:0.85em}"
    html += "td{padding:9px 14px;border-bottom:1px solid #eee;font-size:0.85em}"
    html += "tr:last-child td{border-bottom:none}"
    html += ".meta{color:#666;font-size:0.85em;margin-bottom:30px}"
    html += ".no-breach{color:#44bb44;font-style:italic}"
    html += "</style></head><body>"
    html += "<h1>AWS Risk Assessment Report</h1>"
    html += "<p class='meta'>Generated: " + now + " &nbsp;|&nbsp; NIST SP 800-53: RA-3, RA-5 &nbsp;|&nbsp; Status: Open Findings Only</p>"
    html += "<h2>Executive Summary</h2>"
    html += "<div class='summary'>"
    html += "<div class='card critical'><h3>" + str(counts["CRITICAL"]) + "</h3><p>Critical</p></div>"
    html += "<div class='card high'><h3>" + str(counts["HIGH"]) + "</h3><p>High</p></div>"
    html += "<div class='card medium'><h3>" + str(counts["MEDIUM"]) + "</h3><p>Medium</p></div>"
    html += "<div class='card low'><h3>" + str(counts["LOW"]) + "</h3><p>Low</p></div>"
    html += "</div>"
    html += "<h2>SLA Breach Tracker</h2>"
    html += breach_section
    html += "<h2>All Open Findings</h2>"
    html += findings_section
    html += "<p class='meta' style='margin-top:40px'>Report source: DynamoDB table <code>" + TABLE_NAME + "</code> &nbsp;|&nbsp; Pipeline: aws-risk-assessment-pipeline &nbsp;|&nbsp; Controls: NIST 800-53 RA-3, RA-5</p>"
    html += "</body></html>"

    return html
