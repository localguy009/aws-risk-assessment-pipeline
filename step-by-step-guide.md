# AWS Risk Assessment Pipeline — Console Build Guide
### Step-by-Step Manual Deployment via AWS Management Console

Use this guide to build the full pipeline manually without any Infrastructure as Code tooling.

---

## Step 1 — DynamoDB

**Console:** DynamoDB → Create table

| Setting | Value |
|---------|-------|
| Table name | `risk-register` |
| Partition key | `finding_id` (String) |
| Sort key | None |
| Table class | DynamoDB Standard |
| Capacity mode | On-demand |
| Encryption | AWS owned key |

**Indexes** (created after table is Active):

Go to the table → Indexes tab → Create index

| Index | Partition Key | Type |
|-------|--------------|------|
| `status-index` | `status` (String) | GSI |
| `risk-level-index` | `risk_level` (String) | GSI |

Wait for both indexes to show **Active** before moving on.

---

## Step 2 — S3 Bucket

**Console:** S3 → Create bucket

| Setting | Value |
|---------|-------|
| Bucket name | `risk-assessment-reports-YOUR_ACCOUNT_ID` |
| Region | `us-east-1` |
| Object Ownership | ACLs disabled |
| Block Public Access | All four checkboxes checked |
| Versioning | Enabled |
| Encryption | SSE-S3 (default) |

---

## Step 3 — IAM Roles

### Processor Role

**Console:** IAM → Roles → Create role

| Setting | Value |
|---------|-------|
| Trusted entity | AWS service — Lambda |
| Managed policy | `AWSLambdaBasicExecutionRole` |
| Role name | `risk-pipeline-processor-role` |
| Description | Execution role for the risk assessment processor Lambda. Grants write access to DynamoDB, publish access to SNS, and EC2 describe permissions for tag-based asset enrichment. |

**Inline policy** — after role is created:
Add permissions → Create inline policy → JSON tab

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBWrite",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:YOUR_ACCOUNT_ID:table/risk-register"
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:risk-pipeline-critical-alerts"
    },
    {
      "Sid": "EC2DescribeTags",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeTags",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

Policy name: `risk-pipeline-processor-policy`

---

### Reporter Role

**Console:** IAM → Roles → Create role

| Setting | Value |
|---------|-------|
| Trusted entity | AWS service — Lambda |
| Managed policy | `AWSLambdaBasicExecutionRole` |
| Role name | `risk-pipeline-reporter-role` |
| Description | Execution role for the risk assessment reporter Lambda. Grants read access to the DynamoDB risk register and write access to the S3 report bucket. Used to generate and upload daily HTML vulnerability reports. |

**Inline policy** — after role is created:
Add permissions → Create inline policy → JSON tab

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBRead",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Scan",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:YOUR_ACCOUNT_ID:table/risk-register",
        "arn:aws:dynamodb:us-east-1:YOUR_ACCOUNT_ID:table/risk-register/index/*"
      ]
    },
    {
      "Sid": "S3Write",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::risk-assessment-reports-YOUR_ACCOUNT_ID",
        "arn:aws:s3:::risk-assessment-reports-YOUR_ACCOUNT_ID/*"
      ]
    }
  ]
}
```

Policy name: `risk-pipeline-reporter-policy`

---

## Step 4 — SNS Topic

**Console:** SNS → Topics → Create topic

| Setting | Value |
|---------|-------|
| Type | Standard |
| Name | `risk-pipeline-critical-alerts` |
| Display name | `Risk Pipeline Alerts` |

**Subscription** — after topic is created:
Create subscription → Protocol: Email → Endpoint: `YOUR_EMAIL`

Confirm the subscription by clicking the link in the confirmation email.

---

## Step 5 — Processor Lambda

**Console:** Lambda → Create function → Author from scratch

| Setting | Value |
|---------|-------|
| Function name | `risk-pipeline-processor` |
| Runtime | Python 3.11 |
| Architecture | x86_64 |
| Execution role | Use existing — `risk-pipeline-processor-role` |

**After creation — Environment variables:**
Configuration tab → Environment variables → Edit → Add:

| Key | Value |
|-----|-------|
| `DYNAMODB_TABLE_NAME` | `risk-register` |
| `SNS_TOPIC_ARN` | `arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:risk-pipeline-critical-alerts` |
| `CRITICAL_SCORE_THRESHOLD` | `9.0` |

**After creation — Timeout:**
Configuration tab → General configuration → Edit → Timeout: **30 seconds**

**After creation — Handler:**
Code tab → scroll to Runtime settings → Edit → set Handler to `handler.lambda_handler`

**Code — create 3 files in the Lambda inline editor:**

Rename `lambda_function.py` to `handler.py`, then create `scorer.py` and `enricher.py` using the + button.

Copy the code from the repository:
- [`lambda/processor/scorer.py`](lambda/processor/scorer.py)
- [`lambda/processor/enricher.py`](lambda/processor/enricher.py)
- [`lambda/processor/handler.py`](lambda/processor/handler.py)

---

## Step 6 — Reporter Lambda

**Console:** Lambda → Create function → Author from scratch

| Setting | Value |
|---------|-------|
| Function name | `risk-pipeline-reporter` |
| Runtime | Python 3.11 |
| Architecture | x86_64 |
| Execution role | Use existing — `risk-pipeline-reporter-role` |

**After creation — Environment variables:**
Configuration tab → Environment variables → Edit → Add:

| Key | Value |
|-----|-------|
| `DYNAMODB_TABLE_NAME` | `risk-register` |
| `S3_REPORT_BUCKET` | `risk-assessment-reports-YOUR_ACCOUNT_ID` |

**After creation — Timeout:**
Configuration tab → General configuration → Edit → Timeout: **60 seconds**

**After creation — Handler:**
Code tab → scroll to Runtime settings → Edit → set Handler to `handler.lambda_handler`

**Code — rename `lambda_function.py` to `handler.py` and paste:**

See [`lambda/reporter/handler.py`](lambda/reporter/handler.py)

---

## Step 7 — EventBridge Finding Rule

**Console:** EventBridge → Rules → Create rule

| Setting | Value |
|---------|-------|
| Name | `risk-pipeline-inspector-findings` |
| Description | Triggers processor Lambda when Inspector sends findings to Security Hub |
| Event bus | default |
| Rule type | Rule with an event pattern |

**Event pattern** — select Custom pattern (JSON editor) and paste:

```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "ProductName": ["Inspector"]
    }
  }
}
```

**Note:** The `WorkflowState: NEW` filter was removed so the rule catches all Inspector findings including updates and re-imports.

**Target:**
- Target type: AWS service
- Select a target: Lambda function
- Function: `risk-pipeline-processor`
- Execution role: Create a new role for this specific resource (default)

---

## Step 8 — EventBridge Daily Schedule

**Console:** EventBridge → Rules → Create rule

| Setting | Value |
|---------|-------|
| Name | `risk-pipeline-daily-report` |
| Description | Triggers reporter Lambda daily at 06:00 UTC to generate the HTML risk report |
| Rule type | Schedule |

**Schedule pattern:**
- Select **Cron-based schedule**
- Cron expression: `0 6 * * ? *`

**Note:** AWS cron requires 6 fields. The `?` in day-of-week is required when day-of-month is `*`.

**Target:**
- Target type: AWS service
- Select a target: Lambda function
- Function: `risk-pipeline-reporter`
- Execution role: Create a new role for this specific resource (default)

---

## Step 9 — End-to-End Test

**Test the processor manually:**

Lambda → risk-pipeline-processor → Test tab → create event named `sample-finding`:

```json
{
  "version": "0",
  "id": "test-event-001",
  "source": "aws.securityhub",
  "detail-type": "Security Hub Findings - Imported",
  "detail": {
    "id": "inspector2/us-east-1/YOUR_ACCOUNT_ID/finding/test-cve-2024-12345",
    "inspectorScore": 9.1,
    "resources": [
      {
        "type": "AWS_EC2_INSTANCE",
        "id": "arn:aws:ec2:us-east-1:YOUR_ACCOUNT_ID:instance/i-0test1234567890ab"
      }
    ],
    "packageVulnerabilityDetails": {
      "vulnerabilityId": "CVE-2024-12345",
      "vulnerablePackages": [
        {
          "name": "openssl",
          "version": "1.1.1k",
          "fixedInVersion": "1.1.1n"
        }
      ]
    },
    "networkReachabilityDetails": {
      "networkPath": {
        "steps": [
          {
            "componentType": "NETWORK_REACHABLE"
          }
        ]
      }
    }
  }
}
```

**Test the real automation:**

Go to Security Hub → CSPM → Findings → Add filter: Product name = Inspector → click any finding → change Workflow status to Notified then back to New. This re-sends the finding through EventBridge and triggers the processor Lambda. Watch CloudWatch → `/aws/lambda/risk-pipeline-processor` for log entries.

**Generate the report manually:**

Lambda → risk-pipeline-reporter → Test tab → event body `{}` → click Test.
Download from S3 → risk-assessment-reports-YOUR_ACCOUNT_ID → reports/YYYY-MM-DD/risk-report.html

**Troubleshooting tips:**
- If Lambda fires but DynamoDB is empty: check CloudWatch logs for the FULL EVENT print line to inspect the raw event format
- If Lambda does not fire: check EventBridge rule is enabled and target is correct
- CVSS score is extracted from `ProductFields['aws/inspector/inspectorScore']` in real Security Hub events

---

## Resource Summary

| Resource | Name |
|----------|------|
| DynamoDB table | `risk-register` |
| S3 bucket | `risk-assessment-reports-YOUR_ACCOUNT_ID` |
| IAM role | `risk-pipeline-processor-role` |
| IAM role | `risk-pipeline-reporter-role` |
| SNS topic | `risk-pipeline-critical-alerts` |
| Lambda | `risk-pipeline-processor` |
| Lambda | `risk-pipeline-reporter` |
| EventBridge rule | `risk-pipeline-inspector-findings` |
| EventBridge rule | `risk-pipeline-daily-report` |

---

*AWS region: us-east-1 | Account: YOUR_ACCOUNT_ID | NIST SP 800-53 Rev 5 — RA-3, RA-5*
