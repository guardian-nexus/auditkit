# AuditKit - Open Source SOC2 Compliance Scanner

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.20-blue)
![Stars](https://img.shields.io/github/stars/guardian-nexus/auditkit?style=social)

**A startup asked me to help with their SOC2 audit prep. Consultants wanted $50k just to tell them what to fix. I built this to automate the technical discovery part.**

## ⚠️ Important: What This Tool Actually Does

**AuditKit scans AWS infrastructure for SOC2 technical controls - roughly 30% of SOC2 compliance.** 

### ✅ What We Check
- S3 bucket public access and encryption
- IAM MFA, password policies, access key rotation
- Security group configurations
- CloudTrail logging
- RDS encryption

### ❌ What We DON'T Check (The Other 70% of SOC2)
- Organizational policies and procedures
- Employee training and background checks
- Vendor risk management
- Physical security controls
- Change management processes
- Incident response procedures

**This is NOT a complete SOC2 solution.** It's the technical scanner that consultants use on Day 1.

## 💥 See It In Action

```bash
$ ./auditkit scan

🔍 Starting aws compliance scan...

AWS Account: 123456789012
─────────────────────────────
❌ [CRITICAL] CC6.2 - Network Security
  Issue: 2 S3 buckets allow public access: customer-data, logs-backup
  Fix: aws s3api put-public-access-block --bucket customer-data --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

❌ [CRITICAL] CC6.6 - Multi-Factor Authentication
  Issue: Root account lacks MFA protection
  Fix: Enable MFA: https://console.aws.amazon.com/iam/home#/security_credentials

✅ CC6.1 - Logical Access Controls: No security groups expose sensitive ports to 0.0.0.0/0
✅ CC7.1 - Security Monitoring: CloudTrail logging enabled (2 active trails)

─────────────────────────────
Score: 50.0% (2 passed, 2 failed)

📋 Top Recommendations:
  1. 🚨 CRITICAL: Enable MFA for root account immediately
  2. 🚨 CRITICAL: Review and restrict public S3 bucket access
  3. Enable AWS Config for continuous compliance monitoring
```

## 🚀 Quick Start

### Prerequisites
```bash
# 1. Install Go 1.20+
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 2. Configure AWS credentials
aws configure
# OR manually create:
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
EOF
```

### Installation
```bash
# Clone the repo
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner

# Build the binary
go build -o auditkit cmd/auditkit/main.go

# Run your first scan
./auditkit scan
```

### Docker Alternative
```bash
docker build -t auditkit .
docker run -v ~/.aws:/root/.aws auditkit scan
```

## 📖 Usage Examples

### Basic Scanning
```bash
# Scan with default AWS profile
./auditkit scan

# Use specific AWS profile
./auditkit scan -profile production

# Scan specific services only
./auditkit scan -services s3,iam

# Output formats
./auditkit scan -format json
./auditkit scan -format html -output report.html
```

### AWS IAM Permissions Required
Create a read-only IAM user with this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "cloudtrail:ListTrails",
        "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

### Continuous Monitoring
```bash
# Add to crontab for daily scans
0 9 * * * /usr/local/bin/auditkit scan -format json -output /var/log/auditkit/$(date +\%Y\%m\%d).json

# CI/CD Integration (GitHub Actions)
- name: SOC2 Compliance Check
  run: |
    ./auditkit scan -format json
    if [ $? -ne 0 ]; then
      echo "Compliance issues found"
      exit 1
    fi
```

## 📊 SOC2 Controls Mapped

| Control | Description | What We Check |
|---------|-------------|---------------|
| **CC6.1** | Logical & Physical Access | Security groups, network ACLs |
| **CC6.2** | Network Security | S3 public access, VPC configuration |
| **CC6.3** | Encryption at Rest | S3 & RDS encryption settings |
| **CC6.6** | Multi-Factor Authentication | Root & IAM user MFA status |
| **CC6.7** | User Access Reviews | Password policies, user permissions |
| **CC6.8** | Access Key Management | Key rotation, unused credentials |
| **CC7.1** | Security Monitoring | CloudTrail, GuardDuty status |

## 💰 Cost Comparison

| Solution | Year 1 Cost | What You Get |
|----------|-------------|--------------|
| Big 4 Consultant | $50,000+ | One-time assessment + report |
| Vanta/Drata | $20,000+/year | Full compliance platform |
| Security Auditor | $15,000 | Technical infrastructure review |
| **AuditKit** | **Free** | Technical controls scanning |

## 🤝 Contributing

We need help! This is an MVP that covers basic AWS scanning. 

**High Priority Contributions:**
- **More AWS checks**: EBS encryption, Lambda permissions, Secrets Manager
- **Azure support**: Equivalent checks for Azure resources
- **GCP support**: Google Cloud Platform scanning
- **Better reporting**: PDF generation, Excel exports
- **Auto-remediation**: Safe fixes that can be automated

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🛡️ Security

- **Read-only**: Never modifies your infrastructure
- **No data storage**: Results only in memory/output files
- **No telemetry**: Completely offline, no phone-home
- **Open source**: Audit the code yourself

Found a security issue? Email admin@auditkit.io (not a GitHub issue).

## 🗺️ Roadmap

### Currently Working (v0.1.0)
- ✅ AWS S3 scanning
- ✅ IAM configuration checks
- ✅ Security group analysis
- ✅ CloudTrail verification
- ✅ Basic HTML/JSON reporting

### Next Release (v0.2.0)
- 🔄 EBS volume encryption checks
- 🔄 Lambda function permissions
- 🔄 RDS detailed configuration
- 🔄 Secrets Manager rotation
- 🔄 PDF report generation

### Future (v1.0.0)
- 🔮 Azure support
- 🔮 GCP support
- 🔮 Kubernetes scanning
- 🔮 Auto-remediation for safe fixes
- 🔮 Web dashboard

## ❓ FAQ

**Q: Is this enough for SOC2?**  
A: No. This covers technical infrastructure (~30%). You need policies, procedures, and evidence of implementation for the other 70%.

**Q: Can I use this for my audit?**  
A: Yes, for the technical controls portion. Your auditor will still need evidence of policies, training, vendor management, etc.

**Q: Why is this free?**  
A: Because $50k for what amounts to API calls is ridiculous. If you want a managed version later, we'll charge for that.

**Q: Does it work with AWS Organizations?**  
A: Currently scans one account at a time. Multi-account support coming.

## 📜 License

Apache 2.0 - See [LICENSE](LICENSE)

## 🙏 Acknowledgments

Built with frustration at enterprise software pricing. 

If this saves you money:
- ⭐ Star the repo
- 🐛 Report bugs
- 📢 Tell others
- 🍺 Buy me a coffee...or beer (optional) - https://buymeacoffee.com/auditkit

---

**Remember:** This is a tool, not a complete solution. SOC2 requires documented policies, procedures, and evidence of implementation. This scanner helps with the technical part, but you still need the rest.
