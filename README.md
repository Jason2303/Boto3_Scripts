# AWS Cloud Security CLI

## What it does
On my journey to learn Boto3, I built 5 Python scripts to detect security issues within my AWS account.

## Prerequisites
- Python 3.7+
- boto3
- AWS credentials configured via AWS CLI
- GuardDuty enabled
- Running EC2 instances tagged appropriately
- S3 bucket
- Security Hub enabled

## Usage

### S3 Audit
Checks if the buckets within your account are encrypted and whether public ACL access is enabled.
command: python cli.py s3-audit

### IAM Audit
Audits IAM users within your account to check if MFA devices are enabled and how old their access keys are, to support regular key rotation and a strong security posture.
command: python cli.py iam-audit

### GuardDuty
Uses detectors to pull HIGH severity findings from GuardDuty and saves them to a local JSON file.
command: python cli.py guardduty

### EC2
Programmatically starts or stops EC2 instances based on their tags.
command: python cli.py ec2 --tag-key Environment --tag-value Production --action stop
command: python cli.py ec2 --tag-key Environment --tag-value Production --action start

### Security Hub
Escalates HIGH and CRITICAL findings via SNS email notification and suppresses MEDIUM and LOW findings.
command: python cli.py securityhub

## Notes
- The GuardDuty script has a 50-finding limit per run due to an API constraint on `get_findings`.
- Update the `sns_arn` variable in `cli.py` with your own SNS topic ARN before running the `securityhub` command.