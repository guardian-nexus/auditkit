# AuditKit - Open Source SOC2 Compliance Scanner

![Build Status](https://img.shields.io/github/workflow/status/guardian-nexus/auditkit/CI)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.20-blue)
![Stars](https://img.shields.io/github/stars/guardian-nexus/auditkit?style=social)

AuditKit is an open-source compliance scanner that tells you exactly what will fail your SOC2 audit. No sales calls, no vendor lock-in, just `go run` and know where you stand.

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

# Scan AWS (uses your existing AWS credentials)
auditkit scan aws

# Generate audit evidence
auditkit report --output soc2-evidence.pdf
```

## 🎯 What Makes AuditKit Different

**It actually tells you how to fix things:**
- Not just "MFA is missing" but exactly which users need it
- Not just "encryption disabled" but the exact AWS CLI command to fix it
- Not just "non-compliant" but why it matters for your audit

**Built by engineers who hate compliance tools:**
- CLI-first (no clicking through 47 screens)
- Uses your existing AWS credentials (no agents to install)
- Outputs real evidence files auditors accept
- Can run in CI/CD for continuous compliance

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

Email admin@auditkit.io if you need the pro version - First 100 users get 50% off forever

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

I'm a security engineer helping a friend at a startup. They needed SOC2 for enterprise deals. Vendors wanted:
- $20k/year minimum
- 3-year contracts
- Per-framework pricing
- Sales calls to see features
- "Contact us" pricing

That's insane. Compliance checking is just API calls and if-statements. 

So I built AuditKit. It's not perfect, but it's free, it works, and it got them through their SOC2.

## 📊 Real Usage Stats

- **Lines of code:** 2,847
- **AWS API calls per scan:** ~200
- **Time to full scan:** 45 seconds
- **Controls checked:** 27 (adding more weekly)
- **Money saved:** $20,000/year
- **Sanity preserved:** Priceless

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

**Q: Is this production-ready?**  
A: I use it in production. It's read-only so worst case is it misses something. Better than nothing.

**Q: How is this free?**  
A: Open source. If you want the managed version later, that'll cost money. Scanner stays free forever.

**Q: Does it actually work for audits?**  
A: Yes. We passed our SOC2 Type II using reports from this tool.

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
