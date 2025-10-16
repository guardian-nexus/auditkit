# Security Policy

## Overview

AuditKit is designed with security-first principles. This document outlines the permissions required, security considerations, and how to safely use AuditKit in your environment.

## Permissions Required

### AWS Permissions (Read-Only)

AuditKit requires **READ-ONLY** AWS permissions. No write, modify, or delete permissions are needed.

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetAccountPasswordPolicy",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccountSummary",
        "s3:ListBuckets",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "kms:ListKeys",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**What these permissions do:**
- `List*` / `Describe*` / `Get*` - Read configuration data only
- **NO** `Create*` / `Update*` / `Delete*` / `Put*` permissions
- **NO** ability to modify your infrastructure

### Azure Permissions (Read-Only)

AuditKit requires **READ-ONLY** Azure permissions via the built-in Reader role or equivalent.

**Required Azure Role:**
- Built-in **"Reader"** role at Subscription scope

**OR Custom Role with these permissions:**
```json
{
  "permissions": [
    {
      "actions": [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
        "Microsoft.Insights/activitylogs/read",
        "Microsoft.Security/assessments/read"
      ],
      "notActions": [],
      "dataActions": [],
      "notDataActions": []
    }
  ]
}
```

**What these permissions do:**
- `*/read` - Read configuration data only
- **NO** `*/write` / `*/delete` / `*/action` permissions
- **NO** ability to modify your infrastructure

## Running Safely

### 1. Test in Sandbox First

Always test AuditKit in a non-production environment first:

**AWS:**
```bash
# Configure sandbox account credentials
aws configure --profile sandbox
export AWS_PROFILE=sandbox

# Run scan
./auditkit scan -provider aws -profile sandbox -verbose
```

**Azure:**
```bash
# Login to sandbox subscription
az login
az account set --subscription "sandbox-subscription-id"

# Run scan
./auditkit scan -provider azure -verbose
```

### 2. Create Dedicated Read-Only User

**AWS - Create Read-Only IAM User:**
```bash
# Create dedicated user
aws iam create-user --user-name auditkit-scanner

# Attach read-only policy (use policy from above)
aws iam put-user-policy --user-name auditkit-scanner \
  --policy-name AuditKitReadOnly \
  --policy-document file://auditkit-policy.json

# Create access keys
aws iam create-access-key --user-name auditkit-scanner
```

**Azure - Create Read-Only Service Principal:**
```bash
# Create service principal with Reader role
az ad sp create-for-rbac --name "auditkit-scanner" \
  --role Reader \
  --scopes /subscriptions/{subscription-id}

# Output will show credentials to use
```

### 3. Audit CloudTrail / Activity Logs After Running

**AWS - Check CloudTrail:**
```bash
# Filter for recent read-only events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ReadOnly,AttributeValue=true \
  --max-results 50
```

**Azure - Check Activity Log:**
```bash
# View recent read operations
az monitor activity-log list \
  --caller auditkit-scanner \
  --status Succeeded
```

### 4. Use AWS IAM Policy Simulator

Test the policy before using it:

```bash
# Simulate read operations (should succeed)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:user/auditkit-scanner \
  --action-names iam:ListUsers s3:ListBuckets \
  --resource-arns "*"

# Simulate write operations (should fail)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:user/auditkit-scanner \
  --action-names s3:DeleteBucket ec2:TerminateInstances \
  --resource-arns "*"
```

## Data Privacy

### What Data Does AuditKit Access?

**AuditKit reads:**
- Configuration metadata (bucket names, instance IDs, user names)
- Security settings (encryption status, MFA status, firewall rules)
- Compliance-relevant configuration (logging, monitoring, access controls)

**AuditKit does NOT read:**
- Actual data stored in S3 buckets
- Database contents
- Application logs content
- Secrets or credentials
- File contents

### Where Does Data Go?

**AuditKit:**
- **Stores all results locally** on your machine
- **No data leaves your environment**
- **No telemetry or phone-home**
- **All network traffic goes directly to AWS/Azure APIs**
- **NO third-party services contacted**
- **NO external data transmission**

**You can verify this by:**
1. Monitoring network traffic during scans
2. Checking source code (it's open source)
3. Running in air-gapped environments

## Authentication Methods

### AWS Authentication

AuditKit uses standard AWS SDK authentication:

1. **AWS Profile** (recommended for testing):
   ```bash
   aws configure --profile myprofile
   ./auditkit scan -provider aws -profile myprofile
   ```

2. **Environment Variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="..."
   export AWS_SECRET_ACCESS_KEY="..."
   export AWS_SESSION_TOKEN="..."  # if using temporary credentials
   ./auditkit scan -provider aws
   ```

3. **IAM Role** (when running on EC2):
   ```bash
   # Automatically uses instance profile
   ./auditkit scan -provider aws
   ```

### Azure Authentication

AuditKit uses standard Azure SDK authentication:

1. **Azure CLI** (recommended for testing):
   ```bash
   az login
   ./auditkit scan -provider azure
   ```

2. **Service Principal**:
   ```bash
   export AZURE_CLIENT_ID="..."
   export AZURE_CLIENT_SECRET="..."
   export AZURE_TENANT_ID="..."
   export AZURE_SUBSCRIPTION_ID="..."
   ./auditkit scan -provider azure
   ```

3. **Managed Identity** (when running on Azure VM):
   ```bash
   # Automatically uses managed identity
   ./auditkit scan -provider azure
   ```

## Security Best Practices

### 1. Principle of Least Privilege

Only grant the specific permissions listed above. Do not use:
- `AdministratorAccess` policy (AWS)
- `Owner` or `Contributor` role (Azure)
- `*:*` wildcard permissions

### 2. Use Temporary Credentials

When possible, use temporary credentials:

**AWS:**
```bash
# Use AWS STS to get temporary credentials
aws sts get-session-token --duration-seconds 3600
```

**Azure:**
```bash
# Service principal credentials are inherently temporary
# Rotate secrets regularly
az ad sp credential reset --name auditkit-scanner
```

### 3. Rotate Credentials Regularly

- **AWS:** Rotate access keys every 90 days
- **Azure:** Rotate service principal secrets every 90 days
- Use AWS Secrets Manager / Azure Key Vault for credential management

### 4. Monitor Scanner Activity

Set up alerts for:
- Unusual number of API calls
- API calls from unexpected locations
- Failed authentication attempts

**AWS CloudWatch Example:**
```bash
# Create alarm for excessive API calls
aws cloudwatch put-metric-alarm \
  --alarm-name "AuditKit-Excessive-Calls" \
  --metric-name CallCount \
  --threshold 10000
```

### 5. Scope Permissions When Possible

**AWS - Limit to specific resources:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetBucketEncryption"],
    "Resource": "arn:aws:s3:::my-specific-bucket"
  }]
}
```

**Azure - Limit to resource group:**
```bash
# Create role assignment at resource group scope
az role assignment create \
  --assignee {sp-id} \
  --role Reader \
  --scope /subscriptions/{sub-id}/resourceGroups/{rg-name}
```

## Reporting Security Issues

If you discover a security vulnerability in AuditKit:

**DO:**
- Email: security@auditkit.io
- Include detailed steps to reproduce
- Allow reasonable time for fix before public disclosure

**DON'T:**
- Open public GitHub issues for vulnerabilities
- Post on social media
- Exploit the vulnerability

**Response Time:**
- Initial acknowledgment: 24-48 hours
- Fix timeline: Based on severity (critical <7 days)

## Compliance Certifications

AuditKit is designed to help you achieve compliance, but the tool itself:

- **Open Source**: Fully auditable code
- **No Data Collection**: Privacy-focused design
- **Read-Only**: Cannot modify your infrastructure
- **Local Execution**: All processing happens on your machine

## Additional Security Resources

- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [NIST 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CMMC Model Documentation](https://www.acq.osd.mil/cmmc/)

## Questions?

- **General Security Questions**: security@auditkit.io
- **Documentation**: https://github.com/guardian-nexus/auditkit
- **Community**: GitHub Discussions

---

**Last Updated:** October 16, 2025  
**Version:** 1.0
