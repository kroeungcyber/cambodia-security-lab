# AWS Security Benchmark (Cambodia Edition)

## Cambodian Compliance Requirements
- Data residency within ASEAN region
- Khmer-language IAM policies for local teams
- Special considerations for:
  - Banking sector (highly regulated)
  - E-commerce (PCI DSS compliance)
  - Government workloads (restricted data)

## Core Security Controls
1. **Identity & Access Management**
   - MFA enforcement for all root accounts
   - Cambodian business hour restrictions for privileged access
   - Khmer-language policy documents

2. **Logging & Monitoring**
   - CloudTrail enabled across all regions
   - Alerts for Cambodian IP space anomalies
   - Integration with Cambodia CERT feeds

3. **Data Protection**
   - KMS with ASEAN-region keys
   - S3 bucket policies restricting cross-border transfers
   - RDS encryption meeting Cambodian standards

## Implementation Steps
```bash
# Sample AWS CLI commands for Cambodian compliance
aws iam create-policy --policy-name Khmer-Compliance-Baseline \
    --policy-document file://khmer_policy.json \
    --description "Baseline security policy for Cambodian operations"