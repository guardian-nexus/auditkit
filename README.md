# AuditKit - Multi-Cloud Compliance Scanner & Evidence Collection

**Open-source compliance scanner for AWS, Azure, and M365 with auditor-ready evidence collection guides.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Version](https://img.shields.io/badge/version-v0.6.2-green)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

## What AuditKit Does

AuditKit scans your cloud infrastructure against SOC2, PCI-DSS, and CMMC controls and provides:

1. **Multi-Cloud Support** - AWS, Azure, M365 (via ScubaGear integration)
2. **Clear Pass/Fail Status** - 64 SOC2 controls, 30 PCI-DSS controls, 17 CMMC Level 1 controls
3. **Exact Fix Commands** - Cloud-specific CLI commands for remediation
4. **Evidence Collection Guides** - Step-by-step screenshots auditors accept
5. **Priority-Based Fixes** - Critical issues that will fail your audit vs. nice-to-haves
6. **Unified Reporting** - Combine AWS, Azure, and M365 findings in one report

## Quick Start

### AWS
```bash
# Configure AWS credentials
aws configure

# Run SOC2 scan
auditkit scan -provider aws -framework soc2

# Run CMMC Level 1 scan (DoD contractors)
auditkit scan -provider aws -framework cmmc

# Generate PDF report
auditkit scan -provider aws -framework soc2 -format pdf -output aws-soc2.pdf
```

### Azure
```bash
# Configure Azure credentials
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Run SOC2 scan
auditkit scan -provider azure -framework soc2

# Run CMMC Level 1 scan
auditkit scan -provider azure -framework cmmc

# Generate PCI-DSS report
auditkit scan -provider azure -framework pci -format pdf -output azure-pci.pdf
```

### M365
```bash
# Import ScubaGear M365 security results
auditkit integrate -source scubagear -file ScubaResults.json -format text

# Generate M365 compliance report
auditkit integrate -source scubagear -file ScubaResults.json -format pdf -output m365-report.pdf

# Combine with AWS/Azure for complete coverage
auditkit scan -provider aws -framework soc2 -output aws-report.pdf
auditkit integrate -source scubagear -file ScubaResults.json -output m365-report.pdf
```

## Recent Updates

**v0.6.2 (Oct 2025)** - Hotfix: Framework scanning improvements  
**v0.6.1 (Oct 2025)** - M365/Entra ID integration via ScubaGear + Community-contributed mappings  
**v0.6.0 (Sept 2025)** - CMMC Level 1 support with November 10, 2025 deadline tracking  
**v0.5.0 (Sept 2025)** - Azure provider support with full SOC2/PCI-DSS implementation  

## What's New in v0.6.2

### Fixes
- **Framework scanning improvements** - All frameworks (CMMC, SOC2, PCI) now return proper control counts
- **Import path optimizations** - Improved scanner reliability
- **Enhanced stability** - Better error handling for multi-cloud environments

### M365/Entra ID Integration (v0.6.1)
- **ScubaGear support** - Import CISA's M365 security assessment results
- **29 Entra ID rules** - Community-contributed mappings for authentication, MFA, and access controls
- **Unified reporting** - Combine AWS, Azure, and M365 findings in one compliance report
- **Framework mappings** - M365 findings mapped to SOC2, PCI-DSS, HIPAA, and CMMC

## Current Implementation Status

### Cloud Providers
| Provider | Files | Checks | Status | Authentication |
|----------|-------|--------|--------|----------------|
| **AWS** | 17 check files | ~150 checks | ✅ Production | AWS CLI, IAM roles |
| **Azure** | 12 check files | ~110 checks | ✅ Production | CLI, Service Principal, Managed Identity |
| **M365/Entra** | Integration | 29 rules | ✅ Via ScubaGear | ScubaGear output |
| **GCP** | Not started | 0 | 🚧 Planned v0.7.0 | - |

### Framework Coverage
| Framework | AWS Controls | Azure Controls | M365 Controls | Status |
|-----------|--------------|----------------|---------------|--------|
| **SOC2** | 64 (CC1-CC9) | 64 (CC1-CC9) | 29 Entra rules | ✅ Production Ready |
| **PCI-DSS v4.0** | 30 technical | 30 technical | 29 Entra rules | ✅ Production Ready |
| **CMMC Level 1** | 17 practices | 17 practices | - | ✅ Production Ready |
| **CMMC Level 2** | 110 practices | 110 practices | - | 🔥 [Pro Feature](https://auditkit.io/pro/) |
| **HIPAA** | ~10 mapped | ~10 mapped | 29 Entra rules | 🧪 Experimental |
| **ISO 27001** | ~5 mapped | ~5 mapped | - | 🧪 Experimental |

### CMMC Compliance
- **CMMC Level 1**: 17 foundational practices for Federal Contract Information (FCI)
- **Deadline**: November 10, 2025 - All DoD contracts will require CMMC compliance
- **Coverage**: Both AWS and Azure providers support complete Level 1 assessment
- **Evidence**: Screenshot guides for all 17 practices with exact Azure Portal/AWS Console URLs

## What Makes AuditKit Different

### 1. Unified Multi-Cloud Compliance

First open-source tool to unify AWS + Azure + M365 compliance scanning with framework-specific controls and evidence collection guidance.

### 2. Evidence Collection That Auditors Accept

Every control includes:
- Screenshot navigation paths (exact console URLs)
- Step-by-step remediation instructions
- Framework-specific requirements
- Evidence collection checklist

### 3. Framework-Specific Requirements

```yaml
CMMC Level 1:
- 17 foundational practices for FCI protection
- Required for all DoD contractors by November 10, 2025

PCI-DSS Specific:
- 90-day password rotation (not 180 like SOC2)
- MFA for ALL users (not just privileged)
- 12-month log retention (not 90 days)
- Quarterly vulnerability scans required

SOC2 Specific:
- Risk-based approach allowed
- 180-day rotation acceptable
- MFA for privileged users only
```

## Requirements

- **Go**: 1.19+
- **Cloud Access**: 
  - AWS: Configured AWS CLI (`aws configure`)
  - Azure: Azure CLI (`az login`) or Service Principal
  - M365: ScubaGear results file (see [CISA ScubaGear](https://github.com/cisagov/ScubaGear))
- **Permissions**: Read-only access to cloud resources

## Installation

### From Source
```bash
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit
./auditkit scan
```

### Using Go Install
```bash
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@v0.6.2
```

### Download Binary
See [Releases](https://github.com/guardian-nexus/auditkit/releases) for pre-built binaries.

## Command Reference

```bash
# Scanning
auditkit scan                          # Default SOC2 scan for AWS
auditkit scan -provider azure          # Azure SOC2 scan
auditkit scan -framework pci           # PCI-DSS scan
auditkit scan -framework cmmc          # CMMC Level 1 scan (DoD contractors)
auditkit scan -framework all           # All frameworks
auditkit scan -verbose                 # Detailed output

# M365 Integration
auditkit integrate -source scubagear -file ScubaResults.json
auditkit integrate -source scubagear -file ScubaResults.json -format pdf
auditkit integrate -source scubagear -file ScubaResults.json -verbose

# Reporting
auditkit scan -format pdf -output report.pdf    # PDF with evidence checklist
auditkit scan -format json                       # JSON output
auditkit scan -format html -output report.html   # HTML report

# Remediation
auditkit fix                           # Generate fix script
auditkit fix -output fixes.sh          # Save to file

# Progress Tracking
auditkit progress                      # Show improvement over time
auditkit compare                       # Compare last two scans

# Evidence Collection
auditkit evidence                      # Generate evidence tracker
auditkit evidence -output tracker.html  # Save tracker
```

## M365 Integration Workflow

### Step 1: Run ScubaGear Assessment
```powershell
# Install CISA ScubaGear (Windows PowerShell)
Install-Module -Name ScubaGear

# Run M365 security assessment
Invoke-SCuBA -ProductNames aad -OutPath ./ScubaResults
```

### Step 2: Import into AuditKit
```bash
# Import M365 findings
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -format text

# Generate M365 compliance report
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -format pdf -output m365-compliance.pdf
```

### Step 3: Unified Reporting
```bash
# Complete multi-cloud compliance coverage
auditkit scan -provider aws -framework soc2 -output aws-soc2.pdf
auditkit scan -provider azure -framework soc2 -output azure-soc2.pdf
auditkit integrate -source scubagear -file ScubaResults.json -output m365-soc2.pdf
```

## Azure Authentication Options

```bash
# Option 1: Azure CLI (easiest)
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Option 2: Service Principal
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-secret"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Option 3: Managed Identity (for Azure VMs)
# Automatically detected, no configuration needed
```

## Roadmap

- [x] v0.3.0 - Evidence collection (Sept 2025)
- [x] v0.4.0 - Multi-framework support (Sept 2025)
- [x] v0.4.1 - Full SOC2 implementation (Sept 2025)
- [x] v0.5.0 - Azure support (Sept 2025)
- [x] v0.6.0 - CMMC Level 1 support (Sept 2025)
- [x] v0.6.1 - M365 integration via ScubaGear (Oct 2025)
- [x] v0.6.2 - Framework scanning improvements (Oct 2025)
- [ ] v0.7.0 - GCP support (Dec 2025)
- [ ] v0.7.1 - Prowler integration (Dec 2025)
- [ ] v0.8.0 - Kubernetes compliance (Jan 2026)
- [ ] v0.9.0 - Terraform/IaC scanning (Feb 2026)
- [ ] v1.0.0 - Automated evidence collection (Mar 2026)

## Important Disclaimers

1. **This is a preparation tool** - You still need a CPA firm for actual SOC2 certification
2. **Not a security scanner** - Focused on compliance evidence, not vulnerability detection
3. **Framework limitations**:
   - SOC2, PCI-DSS & CMMC Level 1: Production ready
   - HIPAA & ISO 27001: Experimental mappings only
4. **CMMC Level 2**: Contact us for Level 2+ requirements (110 practices for CUI handling)
5. **Manual verification required** - Some controls need human review
6. **M365 Integration**: Requires CISA ScubaGear for M365 assessment

## Contributing

We need help with:
1. **Additional M365 domains** - SharePoint, Teams, Exchange mappings
2. **GCP provider** - Mirror AWS/Azure structure
3. **Prowler integration** - Import Prowler AWS/Azure/GCP results
4. **HIPAA controls** - Complete the 45 administrative safeguards
5. **ISO 27001** - Map all 114 controls
6. **Evidence automation** - Selenium/Playwright for screenshots
7. **Container scanning** - Kubernetes, Docker compliance

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Newsletter**: [auditkit.substack.com](https://auditkit.substack.com)
- **Support Development**: [Buy Me a Coffee](https://www.buymeacoffee.com/auditkit)

## FAQ

**Q: How does M365 integration work?**  
A: Run CISA's ScubaGear tool to assess your M365 environment, then use `auditkit integrate` to import the results and map them to compliance frameworks.

**Q: Is CMMC Level 1 implementation complete?**  
A: Yes, v0.6.0 includes full CMMC Level 1 implementation with all 17 practices for both AWS and Azure.

**Q: When is the CMMC deadline?**  
A: November 10, 2025. All new DoD contracts will require CMMC compliance starting this date.

**Q: What about CMMC Level 2?**  
A: CMMC Level 2 (110 practices for CUI handling) is available as a Pro feature. Check out [AuditKit Pro](https://auditkit.io/pro/).

**Q: Why is my compliance score low?**  
A: Enable security services first (AWS: GuardDuty, Config, CloudTrail | Azure: Defender, Policy, Activity Logs | M365: Conditional Access, Identity Protection)

**Q: Can I scan multiple AWS accounts or Azure subscriptions?**  
A: Currently one at a time. Use different profiles: `auditkit scan -profile production`

**Q: Does this replace Prowler/ScoutSuite?**  
A: No, those are security scanners. AuditKit focuses on compliance evidence collection for auditors with framework-specific mappings.

## License

Apache 2.0 - Use freely, even commercially.

---

**Built by engineers who've been through too many compliance audits.**

**Special thanks to our community contributors for comprehensive Entra ID mappings that enable unified multi-cloud compliance reporting.**
