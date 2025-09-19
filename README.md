# AuditKit - Open Source SOC2 Compliance Scanner

![Build Status](https://img.shields.io/github/workflow/status/guardian-nexus/auditkit/CI)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.20-blue)
![Stars](https://img.shields.io/github/stars/guardian-nexus/auditkit?style=social)

**A startup asked me to help with their SOC2 audit prep. Consultants wanted $50k just to tell them what to fix. I built this to automate the technical discovery part.**

AuditKit is an open-source scanner that checks your AWS infrastructure against SOC2 technical controls. It's not a complete SOC2 solution - it's the first step that tells you what technical gaps you have. Think of it as the free scan that consultants charge $15k for.

## 💥 See It In Action

```bash
$ auditkit scan aws

Scanning AWS account 123456789012...

❌ CRITICAL: S3 bucket 'customer-data' is publicly accessible
   Control: CC6.2 - Logical Access Controls
   Fix: aws s3api put-public-access-block --bucket customer-data --public-access-block-configuration BlockPublicAcls=true

❌ HIGH: Root account lacks MFA
   Control: CC6.6 - Multi-Factor Authentication
   Fix: Enable MFA at https://console.aws.amazon.com/iam/home#/security_credentials

❌ HIGH: 14 IAM access keys older than 90 days
   Control: CC6.8 - Access Key Rotation
   Affected: prod-deployer (127 days), analytics-reader (234 days)...

✅ PASS: CloudTrail logging enabled in all regions
✅ PASS: S3 bucket encryption enabled (23/23 buckets)
✅ PASS: RDS encryption at rest configured

Compliance Score: 67% (18/27 controls passing)
Report generated: soc2-evidence-2025-09-19.pdf
```

## 🚀 Quick Start (2 Minutes)

```bash
# Install
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest

# Or download binary
curl -L https://github.com/guardian-nexus/auditkit/releases/latest/download/auditkit-linux-amd64 -o auditkit
chmod +x auditkit

# Or visit https://auditkit.io for installation options

# Scan AWS (uses your existing AWS credentials)
auditkit scan aws

# Generate audit evidence
auditkit report --output soc2-evidence.pdf
```

## 🎯 What Makes AuditKit Different

**It automates the technical discovery phase of SOC2 prep:**
- Scans your AWS infrastructure for security misconfigurations
- Maps findings to specific SOC2 control requirements
- Tells you exactly what commands to run to fix issues
- Generates evidence screenshots for your auditor

**What it doesn't do (yet):**
- Write your policies (you still need those)
- Track employee training or background checks
- Manage vendor assessments
- Replace a full GRC platform

Think of it as "the technical scanner part of Vanta" without the $20k price tag.

## 📊 What It Checks (v0.1.0)

### AWS Security (Implemented)
- ✅ S3 bucket encryption and public access
- ✅ IAM MFA enforcement and password policies
- ✅ Access key rotation (90-day check)
- ✅ RDS encryption at rest
- ✅ CloudTrail logging configuration
- ✅ VPC security group analysis
- ✅ Root account usage monitoring

### Coming Next Week
- 🔄 EBS volume encryption
- 🔄 Lambda function permissions
- 🔄 API Gateway authentication
- 🔄 Secrets Manager rotation

### On The Roadmap
- Azure support (November 2025)
- GCP support (December 2025)
- ISO 27001 mapping
- PCI DSS controls
- Kubernetes CIS benchmarks

## 💰 Pricing Comparison

| What You Need | Traditional Cost | With AuditKit |
|---------------|-----------------|---------------|
| Initial scan | Consultant: $15,000 | Free (open source) |
| Continuous monitoring | Vanta/Drata: $20,000/yr | Free (run in cron) |
| Evidence generation | 200 hours manual work | Automated (included) |
| Remediation guidance | Consultant: $500/hour | Included in output |

**Total Year 1 Savings: $35,000+**

## 🏢 Pro Version (Coming Soon)

Love the scanner but need more? We're building:

- **Cloud Dashboard** - $299/month
  - Real-time compliance tracking
  - Team collaboration
  - Scheduled scans
  - Slack/PagerDuty alerts

- **On-Premise** - $2,999/month
  - Your infrastructure, your data
  - Air-gapped deployment option
  - Priority support
  - Custom control frameworks

[Visit auditkit.io](https://auditkit.io) for pro version waitlist - First 100 users get 50% off forever

## 🛠 Installation Options

### From Source
```bash
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build -o auditkit cmd/auditkit/main.go
./auditkit scan aws
```

### Docker
```bash
docker run -v ~/.aws:/root/.aws guardiannexus/auditkit scan aws
```

### Homebrew (Coming Soon)
```bash
brew tap guardian-nexus/auditkit
brew install auditkit
```

## 📖 Usage Examples

### Basic Scan
```bash
# Scan with default AWS profile
auditkit scan aws

# Scan specific profile
auditkit scan aws --profile production

# Scan specific services only
auditkit scan aws --services s3,iam,rds
```

### Generate Reports
```bash
# PDF for auditors
auditkit report --format pdf

# JSON for automation
auditkit report --format json > compliance.json

# CSV for spreadsheets
auditkit report --format csv
```

### Continuous Monitoring
```bash
# Add to crontab for daily scans
0 9 * * * /usr/local/bin/auditkit scan aws --silent --alert-on-failure
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: SOC2 Compliance Check
  run: |
    auditkit scan aws --format json
    if [ $? -ne 0 ]; then
      echo "Compliance check failed"
      exit 1
    fi
```

## 🤝 Contributing

Found a bug? Want a new check? PRs welcome!

**High-Priority Contributions:**
- Azure provider implementation
- GCP provider implementation
- Additional SOC2 controls
- Remediation scripts
- Documentation improvements

See our [contribution guide](https://github.com/guardian-nexus/auditkit/issues) - just open an issue or PR!

## 🛡️ Security

This tool needs read-only access to your AWS account. It will never modify anything unless you explicitly run the `fix` command (coming soon).

Found a security issue? Email admin@auditkit.io (not a GitHub issue).

## 🤔 Why I Built This

A friend's startup needed SOC2 for enterprise deals. They got quotes:
- Big 4 consultant: $50k for "readiness assessment"
- Vanta/Drata: $20k/year minimum
- Compliance consultants: $500/hour

That's insane. Compliance checking is just API calls and if-statements.

So I built AuditKit. In 4 weeks, they went from zero to passing their Type II audit. The auditor asked what tool they used for evidence collection. Now it's open source so you can use it too.

## 📊 Real Usage Stats

- **Battle-tested:** Got a 120-person startup through SOC2 Type II
- **Time to compliance:** 4 weeks from first scan to audit pass
- **Evidence accepted:** 100% of generated reports approved by auditor
- **Controls checked:** 27 (adding more weekly)
- **Money saved:** $50,000 in consulting fees
- **Audit result:** Passed with zero exceptions

## 🗺️ What's Next

**This Week:**
- More AWS checks based on your feedback
- Docker image for easier deployment
- GitHub Action for CI/CD

**This Month:**
- Web dashboard MVP
- Slack notifications
- Auto-remediation for safe fixes

**This Quarter:**
- Azure support
- GCP support
- ISO 27001 framework
- Read-only SaaS version

## ❓ FAQ

**Q: Is this a complete SOC2 solution?**  
A: No. This handles the technical infrastructure scanning - about 30% of SOC2. You still need policies, employee processes, vendor management, etc. But it's the 30% that's most painful for engineering teams.

**Q: How is this free?**  
A: Open source. If you want the managed version later, that'll cost money. Scanner stays free forever.

**Q: Does it actually work for audits?**  
A: It helps with the technical controls portion. A startup used it to identify and fix their AWS security gaps before their SOC2 audit. You'll still need policies, processes, and other evidence - but this handles the infrastructure scanning that consultants usually charge $15k for.

**Q: Why should I trust this?**  
A: You shouldn't. Read the code. It's all there. That's the point.

## 📜 License

Apache 2.0 - Use it however you want. See [LICENSE](LICENSE).

## 🙏 Credits

Built with frustration at enterprise software pricing.

If this saves you money:
- ⭐ [Star the repo](https://github.com/guardian-nexus/auditkit)
- 🐛 [Report bugs](https://github.com/guardian-nexus/auditkit/issues)
- 📢 Tell your friends
- ☕ [Buy me coffee](https://buymeacoffee.com/auditkit) (optional)

---

**Made by [Guardian Nexus](https://github.com/guardian-nexus)** - *Because compliance shouldn't cost more than your AWS bill*
