# AWS Automated Risk Assessment Pipeline
### NIST SP 800-53 | Controls: RA-3, RA-5

Automated vulnerability management pipeline on AWS. Inspector scans EC2 and container workloads → Security Hub aggregates findings → Lambda scores and enriches each finding → DynamoDB stores the risk register → HTML report uploads to S3 daily.

An auditor asking *"how do you know what your vulnerabilities are and what you did about them?"* can be answered entirely from the outputs of this pipeline.

---

## Pipeline Flow

```
Inspector → Security Hub → EventBridge → Lambda Processor → DynamoDB (risk register)
                                                           → SNS (critical alerts, score ≥ 9.0)

EventBridge (daily 06:00 UTC) → Lambda Reporter → S3 (HTML report)
```

Lambda performs three operations per finding: **deduplication** (no duplicate records), **enrichment** (EC2 tags → asset criticality), **scoring** (custom risk model).

---

## Risk Scoring Model

```
Risk Score = (CVSS × 0.5) + (Asset Criticality × 0.3) + (Exposure × 0.2)
```

| Factor | Source | Range |
|--------|--------|-------|
| CVSS | Inspector finding | 0–10 |
| Asset Criticality | EC2 tags (production=10, staging=6, dev=3) | 0–10 |
| Exposure | Inspector network reachability | 0–10 |

| Score | Risk Level | Remediation SLA |
|-------|------------|-----------------|
| 9.0–10.0 | Critical | 24 hours |
| 7.0–8.9 | High | 7 days |
| 4.0–6.9 | Medium | 30 days |
| 0.0–3.9 | Low | 90 days |

---

## NIST 800-53 Control Mapping

| Control | How This Pipeline Satisfies It |
|---------|-------------------------------|
| RA-3 | DynamoDB risk register with scored, timestamped findings. Scheduled report on defined cadence. |
| RA-3(1) | Container image scanning covers third-party supply chain vulnerabilities. |
| RA-5 | Continuous automated scanning via Inspector. EventBridge + Lambda process findings without manual steps. |
| RA-5(2) | Inspector CVE database updates automatically. |
| RA-5(4) | Findings include resource ARN, installed version, and fixed version for direct remediation. |
| RA-5(5) | Least-privilege IAM roles for each service. No direct human access to scan results. |

---

## AWS Services

| Service | Role |
|---------|------|
| AWS Inspector | Continuous CVE scanning — EC2 and ECR |
| AWS Security Hub | Finding aggregation in ASFF format |
| Amazon EventBridge | Event-driven trigger + daily report schedule |
| AWS Lambda | Deduplication, enrichment, scoring, reporting |
| Amazon DynamoDB | Persistent risk register |
| Amazon S3 | Versioned HTML report storage |
| Amazon SNS | Critical finding email alerts |
| AWS IAM | Least-privilege execution roles |
| Amazon CloudWatch | Lambda execution logs |

---

## Report Output

Daily HTML report includes: executive summary (counts by severity), SLA breach tracker, and full findings table sorted by risk score. Uploaded to the same S3 bucket at `reports/YYYY-MM-DD/risk-report.html` — S3 versioning is enabled so overwritten reports are preserved as version history.

---

## Project Structure

```
aws-risk-assessment-pipeline/
├── lambda/
│   ├── processor/
│   │   ├── handler.py       # Finding processor
│   │   ├── scorer.py        # Risk scoring model
│   │   └── enricher.py      # Asset enrichment
│   └── reporter/
│       └── handler.py       # Report generator
└── step-by-step-guide.md    # Full console build guide
```

---

## Deployment

Manual deployment via AWS Management Console. See [step-by-step-guide.md](step-by-step-guide.md) for full instructions.

| Step | Service | What You Configure |
|------|---------|-------------------|
| 1 | DynamoDB | `risk-register` table |
| 2 | S3 | Report bucket with versioning |
| 3 | IAM | Processor and reporter roles |
| 4 | SNS | Critical alerts topic + email subscription |
| 5 | Lambda | Processor function |
| 6 | Lambda | Reporter function |
| 7 | EventBridge | Inspector finding rule |
| 8 | EventBridge | Daily report schedule (06:00 UTC) |

---

## Audit Evidence

| Artifact | Location |
|----------|----------|
| Raw findings (ASFF) | Security Hub |
| Scored risk register | DynamoDB |
| Remediation history | DynamoDB (`remediated_at`) |
| Daily HTML report | S3 (versioned) |
| Lambda execution logs | CloudWatch |
| SLA breach records | DynamoDB |
| Alert history | SNS / CloudWatch |


