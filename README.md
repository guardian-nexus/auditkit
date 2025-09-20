# AuditKit - Open Source SOC2 Compliance Scanner

Pass SOC2 without paying consultants $50K. AuditKit scans your AWS infrastructure and tells you exactly what to fix.

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)
![Version](https://img.shields.io/badge/version-v0.3.0-green)

## 🎯 The Problem

- SOC2 consultants charge $50,000+ for compliance prep
- Vanta/Drata cost $20,000+/year and are overkill for small companies  
- Prowler has 400+ checks but doesn't tell you what SOC2 actually needs
- You just need to know: **Will I pass? What do I fix first?**

## ✨ The Solution

AuditKit is a free, open-source tool that:
- ✅ Scans your AWS account for the 25+ controls auditors actually check
- 🎯 Shows exactly what will fail your audit (with prioritization)
- 📸 Tells you what screenshots to collect for evidence
- 🔧 Generates fix scripts for critical issues
- 📊 Tracks your progress over time

## 🚀 Quick Start

```bash
# Install
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest

# Or download binary
wget https://github.com/guardian-nexus/auditkit/releases/latest/download/auditkit-linux-amd64
chmod +x auditkit-linux-amd64
sudo mv auditkit-linux-amd64 /usr/local/bin/auditkit

# Run your first scan
auditkit scan

# Generate PDF report for auditor
auditkit scan -format pdf -output soc2-report.pdf

# Generate fix script
auditkit fix -output fixes.sh
```

## 📋 What AuditKit Checks (25+ SOC2 Controls)

### 🔥 Critical Controls (Fail These = Fail Audit)
- [x] Root account MFA enabled
- [x] No public S3 buckets  
- [x] No open security groups (SSH/RDP/databases)
- [x] CloudTrail logging active
- [x] Access keys rotated < 90 days

### ⚠️ High Priority Controls
- [x] Password policy (14+ chars, complexity)
- [x] EBS/RDS encryption enabled
- [x] VPC Flow Logs enabled
- [x] GuardDuty threat detection active
- [x] Inactive users removed (>90 days)
- [x] AWS Config recording changes

### 📋 Additional Controls
- [x] S3 versioning for backup/recovery
- [x] Multi-region CloudTrail
- [x] CloudWatch security alarms
- [x] SNS topics for alerts
- [x] Systems Manager patch compliance
- [x] Auto-scaling for availability
- [x] Service account security
- [x] Excessive admin permissions

## 🎯 Why AuditKit vs Others?

| Tool | Price | What It Does | What It Doesn't |
|------|-------|--------------|-----------------|
| **Prowler** | Free | 400+ generic checks | No SOC2 mapping, no evidence guides |
| **Vanta/Drata** | $20K+/year | Full compliance platform | Expensive, complex, overkill for SMBs |
| **Consultants** | $50K+ | Human expertise | One-time snapshot, no automation |
| **AuditKit** | **Free** | SOC2-specific + screenshot guides | Just what you need to pass |

## 📸 Evidence Collection

AuditKit doesn't just find issues - it tells you EXACTLY what screenshots auditors want:

```
🔥 CRITICAL: Root Account MFA
Status: FAIL
Evidence: Root account has NO MFA protection
Fix: aws iam enable-mfa-device --device root
Screenshot Guide:
  1. Sign in to AWS as root user
  2. Click account name → 'Security credentials'  
  3. Screenshot 'Multi-factor authentication (MFA)' section
  4. Must show at least one MFA device assigned
Console URL: https://console.aws.amazon.com/iam/home#/security_credentials
```

## 🎯 Commands

```bash
# Basic scan
auditkit scan

# Scan with specific profile
auditkit scan -profile production

# Generate PDF report
auditkit scan -format pdf -output report.pdf

# Generate HTML dashboard
auditkit scan -format html -output dashboard.html

# Track progress over time
auditkit progress

# Compare last two scans
auditkit compare

# Generate fix script
auditkit fix -output remediation.sh

# Check for updates
auditkit update
```

## 📊 Progress Tracking

See your compliance improve over time:

```
$ auditkit progress

📊 Your SOC2 Journey Progress
==============================
Account: 123456789012
First scan: Jan 2, 2025
Total scans: 5
Issues fixed: 12
Score improvement: +35.2% (54.8% → 90.0%)

Score Trend:
Jan 02: ██████████ 54.8%
Jan 09: ████████████ 62.3%
Jan 16: ██████████████ 71.5%
Jan 23: ████████████████ 85.2%
Jan 30: ██████████████████ 90.0%
```

## 🔧 Auto-Fix Generation

AuditKit generates safe remediation scripts:

```bash
$ auditkit fix
✅ Fix script generated: auditkit-fixes.sh

$ cat auditkit-fixes.sh
#!/bin/bash
# 🔥 CRITICAL FIXES (Do these first!)
echo '[1/3] Enabling root MFA...'
# Manual step required - see documentation

echo '[2/3] Blocking public S3 access...'
aws s3api put-public-access-block --bucket my-public-bucket \
  --public-access-block-configuration BlockPublicAcls=true...

echo '[3/3] Closing open security groups...'
aws ec2 revoke-security-group-ingress --group-id sg-123456 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
```

## 🏗️ Architecture

```
AuditKit/
├── scanner/           # Core scanning engine
│   ├── pkg/aws/      # AWS service checks
│   │   ├── checks/   # Modular SOC2 controls
│   │   │   ├── s3.go
│   │   │   ├── iam.go
│   │   │   ├── ec2.go
│   │   │   └── ...
│   ├── pkg/report/   # PDF/HTML generation
│   └── pkg/tracker/  # Progress tracking
└── docs/             # Evidence guides
```

## 🤝 Contributing

We need help! Especially with:
- [ ] Azure/GCP support
- [ ] More SOC2 controls
- [ ] Better remediation scripts
- [ ] Evidence collection automation

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📊 Anonymous Telemetry

AuditKit collects anonymous usage data to improve the tool:
- Version, OS, compliance score
- Failed control types (no details)
- No AWS account info, resource names, or IPs

Opt out: `export AUDITKIT_NO_TELEMETRY=1`

## 🚨 Limitations

- **Technical controls only** (~30% of SOC2)
- Doesn't cover policies, procedures, or employee training
- Can't review your disaster recovery documentation
- Won't interview your employees about security practices

**You still need:**
- Written security policies
- Employee security training records
- Vendor management documentation
- Incident response procedures

## 📈 Roadmap

- [x] AWS scanning (v0.1.0)
- [x] PDF reports (v0.2.0)
- [x] Progress tracking (v0.3.0)
- [ ] Auto-remediation (v0.4.0)
- [ ] Azure support (v0.5.0)
- [ ] GCP support (v0.6.0)
- [ ] CMMC compliance (v1.0.0)

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/guardian-nexus/auditkit/discussions)
- **Updates**: Watch this repo for updates

## 📜 License

Apache 2.0 - We chose Apache over MIT to give you patent protection. Use it, modify it, sell it - just help others pass SOC2 without going broke.

## 🙏 Credits

Built by engineers who were quoted $50K for SOC2 prep and decided to build a free tool instead.

---

**If AuditKit helps you pass SOC2, please:**
- ⭐ Star this repo
- 📣 Share your success on X/LinkedIn
- 🤝 Contribute improvements back

☕ **If AuditKit saved you money, consider [buying me a coffee](https://www.buymeacoffee.com/auditkit)**

*Remember: A scanner is not a replacement for proper security practices. This tool helps with technical controls (~30% of SOC2). You still need policies, procedures, and documentation for the other 70%.*

---
whatever i like emojis...
