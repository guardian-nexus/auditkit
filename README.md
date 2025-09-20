# AuditKit - SOC2 Evidence Collection & Compliance Prep

**Turn AWS Config findings into auditor-ready evidence. Be 80% ready BEFORE calling expensive consultants.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)
![Version](https://img.shields.io/badge/version-v0.3.0-green)

## ⚠️ Important Disclaimer

**AuditKit is a PREPARATION tool, not a replacement for professional audit services:**
- SOC2 audits require certified CPAs
- This tool identifies common issues but doesn't guarantee compliance
- Always engage qualified professionals for actual certification
- We help you be prepared, not certified

**Think of us as the practice test, not the actual exam.**

## 📸 What Makes AuditKit Different: Evidence Collection

**Every other tool:** "Your S3 bucket is public" ❌

**AuditKit:** "Your S3 bucket is public. Here's how to prove you fixed it:" ✅
```
1. Open S3 Console
2. Click bucket 'my-public-bucket'  
3. Go to Permissions tab
4. Screenshot showing all 4 "Block public access" = ON
5. Save as: SOC2_Evidence_S3_Public_Access.png
Console URL: https://s3.console.aws.amazon.com/s3/buckets/...
```

**This is what auditors actually want.** Not your tool's report. AWS Console screenshots.

*Thanks to u/amw3000 on Reddit for this insight that changed everything in v0.3.0.*

## 🤝 Works With Your Existing Tools

**Not a replacement, a complement:**

| Tool | What It Does | What AuditKit Adds |
|------|--------------|-------------------|
| **AWS Config** | Continuous compliance monitoring | Evidence collection guides |
| **Prowler** | 400+ security checks | SOC2-specific remediation |
| **Security Hub** | Centralized findings | Screenshot requirements |
| **GuardDuty** | Threat detection | Audit trail evidence |
| **ElectricEye** | Multi-cloud scanning | Evidence documentation |

**Better together:** Use Config/Prowler to find issues, AuditKit to prove you fixed them.

## 🎯 What AuditKit Actually Does

Most companies pay consultants $50K+ for SOC2 prep. Here's the dirty secret: **$40K of that is finding obvious issues** like:
- No MFA on root account
- Public S3 buckets
- Unencrypted databases
- No audit logging
- 90+ day old access keys

AuditKit finds these issues in 15 minutes, not 200 billable hours. But more importantly, it tells you EXACTLY how to document the fixes for your auditor.

**The Result:** Your $50K audit becomes a $10K audit. Consultants handle actual compliance expertise, not basic AWS hygiene and evidence collection.

## 🚀 Quick Start

```bash
# Install
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest

# Run scan with evidence collection
auditkit scan

# Generate PDF with screenshot guides
auditkit scan -format pdf -output soc2-evidence.pdf

# Track your progress
auditkit progress

# Generate evidence checklist
auditkit evidence
```

## 📊 The Math That Matters

| Without AuditKit | With AuditKit |
|------------------|---------------|
| Consultant finds 50 issues | You fix 40 obvious issues yourself |
| 200 hours @ $300/hour = $60K | 50 hours @ $300/hour = $15K |
| 3-month timeline | 1-month timeline |
| Consultants collect evidence | You arrive with evidence ready |
| **Total: $60,000** | **Total: $15,000** |

**You save: $45,000** (and consultants actually like you because you're prepared)

## 🔍 What We Check (The 25 Controls That Matter)

### 🔥 CRITICAL - Fix These or Fail Audit
- Root account MFA (with screenshot guide)
- Public S3 buckets (with remediation steps)
- Open SSH/RDP to internet (with console URLs)
- No CloudTrail logging (with exact settings needed)
- 180+ day old access keys (with rotation guide)

### ⚠️ HIGH - Major Findings Auditors Flag
- Weak password policy
- Unencrypted EBS/RDS
- No VPC Flow Logs
- GuardDuty disabled
- Inactive IAM users

### 📋 MEDIUM - Best Practices
- S3 versioning
- Multi-region CloudTrail
- CloudWatch alarms
- AWS Config recording
- Systems Manager patch compliance

## 📸 Evidence Collection - The Secret Sauce

v0.3.0's killer feature - for EVERY control, we tell you:

```yaml
Control: Root Account MFA
Status: FAIL
Fix Command: aws iam enable-mfa-device --device arn:aws:iam::...
Evidence Required:
  Step 1: Sign in to AWS Console as root user
  Step 2: Navigate to IAM → Security Credentials
  Step 3: Screenshot showing:
    - MFA section header visible
    - At least one virtual MFA device
    - Status showing "Activated"
    - Account ID visible in top right
  Step 4: Save as "SOC2_Evidence_CC6.6_Root_MFA.png"
  Console URL: https://console.aws.amazon.com/iam/home#/security_credentials
```

No more "what evidence do you need?" emails. No more audit delays.

## 🎯 Commands That Matter

```bash
# Basic scan - find issues
auditkit scan

# Generate PDF evidence guide - for auditors
auditkit scan -format pdf -output evidence-guide.pdf

# Track evidence collection progress
auditkit evidence

# Show compliance improvement
auditkit progress

# Compare scans over time
auditkit compare

# Generate fix scripts
auditkit fix -output remediation.sh
```

## 📈 What's New in v0.3.0

Based on Reddit feedback from 217+ security professionals:
- ✅ **Evidence Collection Guides** - Step-by-step screenshot instructions
- ✅ **PDF Generation** - Requested by u/Glittering-Duck-634
- ✅ **Progress Tracking** - Show improvement over time
- ✅ **Fix Script Generation** - One-click remediation
- ✅ **Modular Code Structure** - Better for contributors

## 🤝 Who This Is Really For

### ✅ Perfect For:
- Startups preparing for first SOC2
- Companies wanting to reduce consultant costs
- Engineers who hate evidence collection
- Teams using AWS Config who need evidence guides
- MSPs helping multiple clients with compliance

### ❌ Not For:
- Replacing certified auditors
- Getting actual SOC2 certification
- Companies needing 400+ security checks (use Prowler)
- If you need continuous monitoring (use AWS Config)

## 🏗️ Technical Architecture

```
auditkit/
├── scanner/              # Core engine (Go)
│   ├── pkg/aws/         # AWS SDK integration
│   │   └── checks/      # Individual SOC2 controls
│   ├── pkg/report/      # PDF/HTML generation
│   ├── pkg/tracker/     # Progress tracking
│   └── pkg/evidence/    # Screenshot guides
├── docs/                
│   └── evidence-examples/ # Real screenshot examples
└── integrations/        # Config/Prowler integration guides
```

Built in Go because:
- Single binary deployment
- No dependencies hell
- Runs anywhere (even air-gapped)
- Fast as hell
- Your paranoid security team will actually run it

## 📈 Roadmap

- [x] v0.1: AWS scanning (Jan 2025)
- [x] v0.2: PDF reports (Jan 2025)
- [x] v0.3: Evidence collection guides (Jan 2025) ← **Based on Reddit feedback!**
- [ ] v0.4: AWS Config integration (Feb 2025)
- [ ] v0.5: Azure support (Mar 2025)
- [ ] v0.6: GCP support (Apr 2025)
- [ ] v1.0: Multi-framework (SOC2/ISO/CMMC) (May 2025)

## 🤔 FAQ (The Honest Answers)

**Q: Why not just use AWS Config + SOC2 Conformance Pack?**
A: Great if you have AWS expertise. Most startups don't. Plus, Config doesn't tell you how to collect evidence for auditors. AuditKit bridges that gap.

**Q: How is this different from Prowler/ElectricEye/Steampipe?**
A: They're better scanners (400+ checks). We focus on evidence collection - the screenshot guides auditors actually want. Use them together.

**Q: Will this replace my $50K consultant?**
A: No. But it'll reduce their bill to $10K. They handle actual compliance, not finding obvious issues or collecting basic evidence.

**Q: Is this legally sufficient for SOC2?**
A: Hell no. You need a CPA for certification. This is prep work.

**Q: Can I trust a free tool with my AWS credentials?**
A: It's open source. Audit the code. Runs locally. Never phones home. Your credentials never leave your machine.

**Q: Who maintains this?**
A: Engineers who were quoted $50K for SOC2 prep and decided to build the evidence collection tool consultants don't want you to have.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Questions**: [GitHub Discussions](https://github.com/guardian-nexus/auditkit/discussions)
- **Updates**: [Newsletter](https://auditkit.substack.com) (Weekly updates, no spam)

## ☕ Support Development

If AuditKit saved you money:

<a href="https://www.buymeacoffee.com/auditkit"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=auditkit&button_colour=5F7FFF&font_colour=ffffff&font_family=Inter&outline_colour=000000&coffee_colour=FFDD00" /></a>

Seriously, if this saved you even $10K, throw us $50. We'll build that Azure support everyone's asking for.

## 📜 License

Apache 2.0 - Use it, modify it, sell it. Just help others avoid the $50K consultant trap.

## 🙏 Contributing

Want to help? Based on Reddit feedback, we need:
- AWS Config import functionality
- Azure/GCP support
- More screenshot examples
- Integration guides for other tools
- Evidence automation scripts

See [CONTRIBUTING.md](CONTRIBUTING.md)

## ⚡ The One-Liner That Matters

**"It's spell-check for compliance. You still need an editor, but at least you're not paying them to fix typos."**

---

*Built by engineers who believe compliance evidence shouldn't cost more than your AWS bill.*

*Special thanks to r/cybersecurity for the honest feedback that shaped v0.3.0*
