# AuditKit - Multi-Framework Compliance Scanner & Evidence Collection

**SOC2, PCI-DSS, HIPAA, ISO 27001 - One scan, all frameworks. Turn compliance chaos into auditor-ready evidence.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)
![Version](https://img.shields.io/badge/version-v0.4.0-green)

> 🚀 **v0.4.0 MAJOR UPDATE**: Multi-framework support is HERE! Scan for SOC2, PCI-DSS, and HIPAA in one run. First open-source tool to do this. 

## 🎯 The Problem We Actually Solve

**Every compliance framework wants the same shit:**
- Is your S3 public? (SOC2: CC6.2, PCI: 2.1, HIPAA: §164.312(a)(1))
- Got MFA enabled? (SOC2: CC6.6, PCI: 8.3, HIPAA: §164.312(a)(2)(i))
- Encryption at rest? (SOC2: CC6.3, PCI: 3.4, HIPAA: §164.312(a)(2)(iv))

**But every framework calls it something different.**

AuditKit v0.4.0 maps your AWS controls to ALL frameworks simultaneously. One scan, multiple compliance reports. Plus evidence collection guides that auditors actually accept.

## ⚠️ Important Disclaimer

**AuditKit is a PREPARATION tool, not a replacement for professional audit services:**
- SOC2 requires certified CPAs
- PCI-DSS requires QSAs (Qualified Security Assessors)
- HIPAA requires experienced compliance professionals
- This tool identifies common issues but doesn't guarantee compliance
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

## 🚀 Quick Start

```bash
# Install
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest

# Scan for ALL frameworks (NEW in v0.4.0!)
auditkit scan -framework all

# Scan for specific framework
auditkit scan -framework pci      # PCI-DSS only
auditkit scan -framework soc2     # SOC2 only
auditkit scan -framework hipaa    # HIPAA only

# Generate multi-framework PDF report
auditkit scan -framework all -format pdf -output compliance-evidence.pdf

# Track your progress per framework
auditkit progress -framework pci

# Generate framework-specific evidence checklist
auditkit evidence -framework hipaa
```

## 🎯 What's New in v0.4.0

**BREAKING: First open-source tool with true multi-framework support**

### One Scan, Multiple Frameworks
```bash
$ auditkit scan -framework all

Scanning for: SOC2, PCI-DSS, HIPAA, ISO 27001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL ISSUES ACROSS FRAMEWORKS:
🔥 Root MFA Missing
   - SOC2: CC6.6 (CRITICAL)
   - PCI: Requirement 8.3.1 (FAIL)
   - HIPAA: §164.312(a)(2)(i) (REQUIRED)
   - ISO: A.9.4.2 (MANDATORY)

📊 Compliance Scores:
   SOC2:  67% (20/30 controls)
   PCI:   45% (14/31 requirements)
   HIPAA: 72% (18/25 safeguards)
   ISO:   69% (22/32 controls)
```

### Framework-Specific Requirements
- **PCI-DSS**: 90-day key rotation (stricter than SOC2's 180)
- **HIPAA**: Encryption mandatory (not just recommended)
- **ISO 27001**: Documented ISMS requirements
- **SOC2**: Trust Services Criteria mapping

### Smart Priority Adjustment
```
Same issue, different severity:
- Old access keys (120 days):
  - SOC2: MEDIUM (180-day requirement)
  - PCI: CRITICAL (90-day requirement)
  - HIPAA: HIGH (access control required)
```

## 📊 The Math That Matters (Updated for Multi-Framework)

| Without AuditKit | With AuditKit |
|------------------|---------------|
| SOC2 Consultant: $50K | |
| PCI-DSS QSA: $40K | One scan finds issues for ALL |
| HIPAA Consultant: $30K | Fix once, comply with multiple |
| ISO 27001 Auditor: $45K | Evidence works for all frameworks |
| **Total: $165,000** | **Total: $40,000** |

**You save: $125,000** (and auditors love that you understand cross-framework requirements)

## 🔍 What We Check (By Framework)

### SOC2 Trust Services Criteria
- **CC6.x**: Logical & Physical Access Controls
- **CC7.x**: System Operations
- **A1.x**: Availability
- **C1.x**: Confidentiality
- **PI1.x**: Privacy

### PCI-DSS Requirements
- **Req 1-2**: Network Security
- **Req 3-4**: Cardholder Data Protection
- **Req 7-8**: Access Control
- **Req 10**: Logging and Monitoring
- **Req 11**: Security Testing

### HIPAA Safeguards
- **§164.308**: Administrative (18 controls)
- **§164.310**: Physical (9 controls)
- **§164.312**: Technical (15 controls)

### ISO 27001 Controls
- **A.5**: Information Security Policies
- **A.9**: Access Control
- **A.10**: Cryptography
- **A.12**: Operations Security
- **A.16**: Incident Management

## 🤝 Works With Your Existing Tools

**Not a replacement, a complement:**

| Tool | What It Does | What AuditKit Adds |
|------|--------------|-------------------|
| **AWS Config** | Continuous compliance monitoring | Multi-framework mapping |
| **Prowler** | 400+ security checks | Framework-specific priorities |
| **Security Hub** | Centralized findings | Evidence requirements per framework |
| **GuardDuty** | Threat detection | Compliance control mapping |

**Better together:** Use Config/Prowler to find issues, AuditKit to map them to frameworks and collect evidence.

## 📸 Evidence Collection - Now Framework-Aware

v0.4.0's enhancement - evidence guides now specify framework requirements:

```yaml
Control: Access Key Rotation
Frameworks Affected:
  SOC2: CC6.8 (180-day requirement) - MEDIUM
  PCI: 8.2.4 (90-day requirement) - CRITICAL
  HIPAA: §164.308(a)(5)(ii)(D) - HIGH
  
Fix Command: aws iam create-access-key --user-name USERNAME
Evidence Required:
  For PCI: Screenshot must show ALL keys < 90 days
  For SOC2: Screenshot must show keys < 180 days
  For HIPAA: Document key rotation procedure
  
Console URL: https://console.aws.amazon.com/iam/home#/users
Save As: 
  - PCI_DSS_Req_8.2.4_Key_Rotation.png
  - SOC2_CC6.8_Access_Management.png
  - HIPAA_164.308_a_5_Access_Controls.png
```

## 🎯 Commands That Matter

```bash
# Scan for everything
auditkit scan -framework all

# Generate framework-specific report
auditkit scan -framework pci -format pdf -output pci-compliance.pdf

# Compare framework requirements
auditkit compare-frameworks

# Show what's different between frameworks
auditkit diff -framework1 soc2 -framework2 pci

# Track evidence collection per framework
auditkit evidence -framework hipaa

# Generate fix scripts with framework priorities
auditkit fix -framework pci -output pci-remediation.sh
```

## 📈 Framework Comparison Dashboard

```
$ auditkit compare-frameworks

CONTROL COMPARISON ACROSS FRAMEWORKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MFA Requirement:
├── SOC2:  Required for privileged accounts
├── PCI:   Required for ALL network access
├── HIPAA: Required for ePHI access
└── ISO:   Required per risk assessment

Encryption at Rest:
├── SOC2:  Recommended (CC6.3)
├── PCI:   MANDATORY (Req 3.4)
├── HIPAA: REQUIRED (§164.312(a)(2)(iv))
└── ISO:   Required for classified data

Key Rotation:
├── SOC2:  180 days
├── PCI:   90 days (STRICTER!)
├── HIPAA: "Reasonable" timeframe
└── ISO:   Based on key usage
```

## 🏗️ Technical Architecture

```
auditkit/
├── scanner/              
│   ├── pkg/aws/         
│   │   └── checks/      # Framework-aware control checks
│   ├── pkg/frameworks/  # NEW: Framework mappings
│   │   ├── soc2.go     # SOC2 TSC mappings
│   │   ├── pci.go      # PCI-DSS requirement mappings
│   │   ├── hipaa.go    # HIPAA safeguard mappings
│   │   └── iso27001.go # ISO control mappings
│   ├── pkg/report/      # Multi-framework reports
│   └── pkg/evidence/    # Framework-specific evidence guides
├── docs/                
│   ├── framework-mappings/  # Control cross-references
│   └── evidence-examples/   # Per-framework examples
└── integrations/        
```

## 📈 Roadmap

- [x] v0.1: AWS scanning (Sep 2025)
- [x] v0.2: PDF reports (Sep 2025)
- [x] v0.3: Evidence collection guides (Sep 2025)
- [x] v0.4: Multi-framework support (Sep 2025) ← **We're here!**
- [ ] v0.5: Azure support (Late Sep, Early Oct 2025)
- [ ] v0.6: GCP support (Oct 2025)
- [ ] v0.7: NIST 800-53 & FedRAMP (Nov 2025)
- [ ] v0.8: CIS Controls & CMMC (Nov 2025)
- [ ] v1.0: Full automation suite (Dec 2025)

## 🤔 FAQ (The Really Honest Answers)

**Q: How do you map controls between frameworks?**
A: Years of pain. We've mapped every control to its equivalent across frameworks. Sometimes it's 1:1, sometimes one PCI requirement covers 3 SOC2 controls.

**Q: Which framework should I scan for?**
A: All of them. Seriously. Fix the strictest requirement and you'll pass the others.

**Q: Is PCI-DSS really that much stricter?**
A: Yes. 90-day key rotation vs 180. Password length minimums. Network segmentation requirements. PCI doesn't fuck around.

**Q: Can this do CMMC?**
A: Coming in v0.8. CMMC is... special. Like PCI had a baby with FedRAMP.

**Q: Why is the HIPAA score usually highest?**
A: HIPAA is surprisingly vague. "Reasonable safeguards" can mean a lot of things. PCI gives you exact numbers.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/guardian-nexus/auditkit/discussions)
- **Updates**: [Newsletter](https://auditkit.substack.com) (Major releases only, no spam)
- **Questions**: Open a discussion, not an issue

## ☕ Support Development

If AuditKit saved you from hiring separate consultants for each framework:

<a href="https://www.buymeacoffee.com/auditkit"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=☕&slug=auditkit&button_colour=5F7FFF&font_colour=ffffff&font_family=Inter&outline_colour=000000&coffee_colour=FFDD00" /></a>

Seriously, if this saved you even $50K across frameworks, throw us $100. We'll add that CMMC support everyone in defense is begging for.

## 📜 License

Apache 2.0 - Use it, modify it, sell it. Just help others navigate the compliance hellscape.

## 🙏 Contributing

Want to help? Priority based on user requests:
1. **Azure/GCP support** (everyone's multi-cloud now)
2. **CMMC mappings** (defense contractors need this)
3. **Kubernetes controls** (CIS Benchmarks)
4. **Terraform compliance** (infrastructure as code)
5. **Evidence automation** (screenshot via Selenium?)

See [CONTRIBUTING.md](CONTRIBUTING.md)

## ⚡ The One-Liner That Matters

**"It's Rosetta Stone for compliance frameworks. Same controls, different languages."**

---

*Built by engineers who realized every framework asks for the same 30 things with different names.*

*Special thanks to r/cybersecurity for the feedback that shaped this multi-framework approach*

## 📊 Stats That Matter

- **221+ upvotes** on r/cybersecurity (that never happens for compliance tools)
- **50K+ views** from security professionals
- **36 stars** in first weekend
- **5 forks**
- **First open-source tool** to do multi-framework mapping properly

---

*v0.4.0 - Because compliance frameworks are just different ways to ask "is your shit encrypted?"*
