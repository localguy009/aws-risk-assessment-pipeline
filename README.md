# AWS Automated Risk Assessment Pipeline
### NIST SP 800-53 | Controls: RA-3, RA-5

A fully automated vulnerability management pipeline built on AWS. Inspector scans EC2 instances and container images for known CVEs → findings flow into Security Hub → Lambda deduplicates, enriches, and scores each finding → results are written to a structured risk register in DynamoDB → a static HTML report is generated and stored in S3.

This is not just a vulnerability scanner. It is a complete risk prioritization and evidence collection workflow

---

## Table of Contents
- [Pipeline Flow](#pipeline-flow)
- [NIST 800-53 Control Mapping](#nist-800-53-control-mapping)
- [AWS Services Used](#aws-services-used)
- [Risk Scoring Model](#risk-scoring-model)
- [Risk Register Schema](#risk-register-schema)
- [Report Output](#report-output)
- [Project Structure](#project-structure)
- [Deployment](#deployment)
- [Evidence and Audit Value](#evidence-and-audit-value)
- [Portfolio Context](#portfolio-context)

---

## Pipeline Flow

### Step 1 — Scan
AWS Inspector continuously monitors EC2 instances and ECR container images for software vulnerabilities. It compares installed packages against the National Vulnerability Database (NVD) and CVE sources. Each finding includes the CVE ID, affected package, installed version, fixed version, and a CVSS score.

### Step 2 — Aggregate
Inspector pushes all findings into AWS Security Hub using the Amazon Security Finding Format (ASFF). Security Hub acts as the normalized, centralized view of all findings across the environment. This is where a security analyst would triage and suppress false positives.

### Step 3 — Trigger
An EventBridge rule watches for Security Hub findings from Inspector. When a new finding arrives, EventBridge fires and invokes the processor Lambda function in near real-time with no polling required.

### Step 4 — Process
Lambda performs three operations:

- **Deduplication** — checks DynamoDB for an existing record matching the same CVE ID and resource ARN. If it already exists, the record is updated rather than duplicated.
- **Enrichment** — pulls resource tags (environment, owner, tier) to determine asset criticality.
- **Scoring** — applies the risk scoring model to produce a final numeric risk score from 0–10.

### Step 5 — Store
Lambda writes the enriched, scored finding to DynamoDB. Each record represents one entry in the risk register. Records are never deleted — when a vulnerability is remediated, the status field is updated and a remediation timestamp is added. This preserves full audit history.

### Step 6 — Report
A second Lambda function runs on a scheduled EventBridge rule daily at 06:00 UTC. It queries DynamoDB for all open findings, generates a static HTML report, and uploads it to S3. The report is downloaded directly from S3 and opened locally.

### Step 7 — Alert
If a finding scores above 9.0, Lambda publishes a message to an SNS topic which delivers an email notification to the configured recipient.

---

## NIST 800-53 Control Mapping

| Control | Title | How This Pipeline Satisfies It |
|---------|-------|-------------------------------|
| RA-3 | Risk Assessment | DynamoDB risk register provides documented, timestamped risk findings. Scoring model applies organizational risk criteria. Scheduled report produces a reviewable output on a defined cadence. |
| RA-3(1) | Supply Chain Risk Assessment | Container image scanning in Inspector covers third-party package vulnerabilities introduced through the software supply chain. |
| RA-5 | Vulnerability Monitoring and Scanning | Inspector provides continuous automated scanning of EC2 and container workloads. EventBridge + Lambda ensure findings are processed without manual intervention. |
| RA-5(2) | Update Vulnerabilities Scanned | Inspector automatically updates its CVE database. No manual intervention required to stay current. |
| RA-5(4) | Discoverable Information | Findings include affected resource ARN, installed version, and fixed version — enabling direct remediation action. |
| RA-5(5) | Privileged Access | IAM roles scoped with least privilege control what Inspector, Lambda, and DynamoDB can access. |

---

## AWS Services Used

| Service | Role in Pipeline |
|---------|-----------------|
| **AWS Inspector** | Continuous CVE scanning for EC2 and ECR container images |
| **AWS Security Hub** | Finding aggregation and normalization into ASFF format |
| **Amazon EventBridge** | Event-driven trigger on new findings and daily report schedule |
| **AWS Lambda** | Deduplication, enrichment, scoring, and report generation |
| **Amazon DynamoDB** | Persistent risk register with full finding history |
| **Amazon S3** | HTML report storage (downloaded and viewed locally) |
| **Amazon SNS** | Critical finding email alert delivery |
| **AWS IAM** | Least-privilege roles for each service |
| **Amazon CloudWatch** | Lambda execution logs and error monitoring |

---

## Risk Scoring Model

The pipeline does not pass CVSS scores through unchanged. It applies a three-factor scoring model to produce a risk score that reflects organizational context, not just technical severity.

```
Risk Score = (CVSS Base Score × 0.5) + (Asset Criticality × 0.3) + (Exposure Score × 0.2)
```

### CVSS Base Score (0–10)
Sourced directly from the Inspector finding. Represents the inherent technical severity of the vulnerability.

### Asset Criticality (0–10)
Derived from EC2 resource tags:

| Tag Value | Score |
|-----------|-------|
| `environment: production` | 10 |
| `environment: staging` | 6 |
| `environment: development` | 3 |
| `tier: web` (internet-facing) | +1 bonus |
| No tags present | 5 (default) |

### Exposure Score (0–10)
Derived from network reachability data in the Inspector finding:

| Condition | Score |
|-----------|-------|
| Internet-reachable, port open | 10 |
| Internal network only | 5 |
| No network path found | 1 |

### Final Score Thresholds

| Score Range | Risk Level | SLA |
|-------------|------------|-----|
| 9.0 – 10.0 | Critical | 24 hours |
| 7.0 – 8.9 | High | 7 days |
| 4.0 – 6.9 | Medium | 30 days |
| 0.0 – 3.9 | Low | 90 days |

---

## Risk Register Schema

Each DynamoDB record represents one vulnerability finding on one resource.

```json
{
  "finding_id": "inspector2/us-east-1/123456789012/finding/abc123",
  "cve_id": "CVE-2024-12345",
  "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
  "resource_type": "EC2",
  "resource_tags": {
    "environment": "production",
    "tier": "web",
    "owner": "platform-team"
  },
  "package_name": "openssl",
  "installed_version": "1.1.1k",
  "fixed_version": "1.1.1n",
  "cvss_score": 9.1,
  "asset_criticality": 10,
  "exposure_score": 10,
  "risk_score": 9.37,
  "risk_level": "CRITICAL",
  "status": "OPEN",
  "first_seen": "2026-04-27T08:14:00Z",
  "last_updated": "2026-04-27T08:14:00Z",
  "remediated_at": null,
  "sla_due_date": "2026-04-28T08:14:00Z",
  "alert_sent": true
}
```

---

## Report Output

The HTML report generated by the reporter Lambda includes:

- **Executive summary** — total open findings by risk level (Critical / High / Medium / Low)
- **SLA breach tracker** — findings past their remediation due date
- **Full findings table** — all open findings sorted by risk score, with CVE ID, resource, package, score, and SLA date

The report is regenerated daily and uploaded to S3 with versioning enabled. Each report is preserved as a dated snapshot, creating a historical archive of the environment's risk posture over time.

---

## Project Structure

```
aws-risk-assessment-pipeline/
│
├── lambda/
│   ├── processor/
│   │   ├── handler.py           # Main finding processor
│   │   ├── scorer.py            # Risk scoring model
│   │   ├── enricher.py          # Resource tag enrichment
│   │   └── requirements.txt
│   │
│   └── reporter/
│       ├── handler.py           # Report generator
│       └── requirements.txt
│
├── tests/
│   └── sample_finding.json      # Sample ASFF finding for local testing
│
├── docs/
│   └── architecture.png         # Architecture diagram
│
└── README.md
```

---

## Deployment

All AWS infrastructure is configured manually via the AWS Management Console. No Infrastructure as Code tooling is required to deploy this project.

### Prerequisites
- AWS account with Inspector v2 and Security Hub enabled
- Python 3.11 for Lambda function code
- AWS CLI configured (optional, for testing Lambda invocations locally)

### Build Order

| Step | Service | What You Configure |
|------|---------|-------------------|
| 1 | DynamoDB | Create `risk-register` table with `finding_id` partition key |
| 2 | S3 | Create report bucket with versioning and encryption enabled |
| 3 | IAM | Create processor and reporter roles with least-privilege policies |
| 4 | SNS | Create critical alerts topic, add email subscription |
| 5 | Lambda | Deploy processor function with DynamoDB + SNS permissions |
| 6 | Lambda | Deploy reporter function with DynamoDB + S3 permissions |
| 7 | EventBridge | Create finding rule — triggers processor on new Inspector findings |
| 8 | EventBridge | Create daily schedule — triggers reporter at 06:00 UTC |

---

## Evidence and Audit Value

This pipeline produces the following auditable artifacts:

| Artifact | Location | Audit Purpose |
|----------|----------|---------------|
| Raw findings (ASFF) | Security Hub | Source of truth for all vulnerability data |
| Scored risk register | DynamoDB | Documents risk assessment decisions and scores |
| Remediation history | DynamoDB (`remediated_at` field) | Proves vulnerabilities were addressed |
| HTML risk report | S3 (versioned, downloaded locally) | Point-in-time snapshot of risk posture |
| Lambda execution logs | CloudWatch Logs | Proves automation ran and when |
| SLA breach records | DynamoDB | Documents overdue remediation |
| Alert history | SNS / CloudWatch | Proves critical findings triggered notification |

An auditor asking *"how do you know what your vulnerabilities are and what you did about them?"* can be answered entirely from the outputs of this pipeline.

---

## Portfolio Context

### What This Demonstrates

- Ability to translate NIST 800-53 controls into working technical cloud workflows
- Hands-on knowledge of AWS security services and how they integrate
- Event-driven architecture design
- Risk quantification beyond raw CVSS scores
- Audit-ready evidence collection and retention
- Practical GRC engineering — not just documentation





