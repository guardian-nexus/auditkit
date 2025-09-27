# AuditKit - Multi-Cloud Compliance Scanner & Evidence Collection

**Open-source compliance scanner for AWS and Azure with auditor-ready evidence collection guides.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Version](https://img.shields.io/badge/version-v0.6.0-green)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

## What AuditKit Does

AuditKit scans your cloud infrastructure against SOC2, PCI-DSS, and CMMC controls and provides:

1. **Multi-Cloud Support** - AWS (production), Azure (v0.5.0) 
2. **Clear Pass/Fail Status** - 64 SOC2 controls, 30 PCI-DSS controls, 17 CMMC Level 1 controls
3. **Exact Fix Commands** - Cloud-specific CLI commands for remediation
4. **Evidence Collection Guides** - Step-by-step screenshots auditors accept
5. **Priority-Based Fixes** - Critical issues that will fail your audit vs. nice-to-haves

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

### Azure (v0.5.0)
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

## Recent Updates

**v0.6.0 (Sept 2025)** - CMMC Level 1 support with November 10, 2025 deadline tracking + CMMC Level 2 Pro available  
**v0.5.0 (Sept 2025)** - Azure provider support with full SOC2/PCI-DSS implementation  
**v0.4.1 (Sept 2025)** - Complete SOC2 implementation (all 64 Common Criteria)  
**v0.4.0 (Sept 2025)** - Multi-framework support with PCI-DSS v4.0  
**v0.3.0 (Sept 2025)** - Evidence collection guides based on Reddit feedback

## Current Implementation Status

### Cloud Providers
| Provider | Files | Checks | Status | Authentication |
|----------|-------|--------|--------|----------------|
| **AWS** | 17 check files | ~150 checks | ✅ Production | AWS CLI, IAM roles |
| **Azure** | 12 check files | ~110 checks | ✅ Production | CLI, Service Principal, Managed Identity |
| **GCP** | Not started | 0 | 🚧 Planned v0.7.0 | - |

### Framework Coverage
| Framework | AWS Controls | Azure Controls | Status |
|-----------|--------------|----------------|--------|
| **SOC2** | 64 (CC1-CC9) | 64 (CC1-CC9) | ✅ Production Ready |
| **PCI-DSS v4.0** | 30 technical | 30 technical | ✅ Production Ready |
| **CMMC Level 1** | 17 practices | 17 practices | ✅ Production Ready |
| **CMMC Level 2** | 110 practices (Pro) | 110 practices (Pro) | 🔥 Pro Feature - Contact hello@auditkit.io |
| **HIPAA** | ~10 mapped | ~10 mapped | 🧪 Experimental Only |
| **ISO 27001** | ~5 mapped | ~5 mapped | 🧪 Experimental Only |

### CMMC Compliance (NEW in v0.6.0)
- **CMMC Level 1**: 17 foundational practices for Federal Contract Information (FCI)
- **Deadline**: November 10, 2025 - All DoD contracts will require CMMC compliance
- **Coverage**: Both AWS and Azure providers support complete Level 1 assessment
- **Evidence**: Screenshot guides for all 17 practices with exact Azure Portal/AWS Console URLs

### Azure Services Covered (v0.5.0+)
- **Azure AD (Entra ID)**: MFA, privileged roles, guest access, password policies
- **Full SOC2 Implementation**: All 64 Common Criteria controls (CC1-CC9)
- **CMMC Implementation**: All 17 Level 1 practices with DoD deadline tracking
- **Storage Accounts**: Public access, encryption, secure transfer, access keys
- **Virtual Machines**: Disk encryption, managed disks, security extensions
- **Network Security Groups**: Open ports, dangerous rules, flow logs
- **Key Vault**: Soft delete, purge protection, access policies
- **Activity Logs**: Retention, log profiles, diagnostic settings
- **Azure SQL**: Transparent encryption, auditing, firewall rules
- **Managed Identities**: System vs user-assigned configuration

## What Makes AuditKit Different

### 1. Evidence Collection That Auditors Accept

```yaml
Control Failed: CC6.2 - Public S3 Bucket
Fix Command: aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

Evidence Required:
1. Navigate to: https://s3.console.aws.amazon.com/s3/buckets/my-bucket
2. Click "Permissions" tab
3. Screenshot showing all 4 "Block public access" settings = ON
4. Save as: SOC2_CC6.2_S3_Public_Access.png
```

## What's New in v0.6.0

### CMMC Level 1 Support
- **17 CMMC Level 1 practices** implementing foundational cybersecurity for DoD contractors
- **November 10, 2025 deadline tracking** - Shows days remaining until mandatory compliance
- **Both AWS and Azure support** - Complete CMMC Level 1 coverage across cloud providers
- **Federal Contract Information (FCI) protection** - Basic safeguarding requirements
- **Evidence collection guides** - Screenshot instructions for all 17 practices
- **Built-in upgrade messaging** - Clear path to Level 2 Pro for CUI handling

### CMMC Level 2 Pro Available
- **110 CMMC Level 2 practices** for organizations handling Controlled Unclassified Information (CUI)
- **Enterprise features** including advanced evidence automation and reporting
- **Priority support** for DoD contractors facing November 2025 deadline
- **Contact hello@auditkit.io** for CMMC Level 2 Pro licensing and access

### CMMC Practices Covered (Level 1 Open Source)
- **Access Control (AC)**: Limit system access and control information flow
- **Identification & Authentication (IA)**: User identity verification and authentication
- **Media Protection (MP)**: Control and sanitize CUI media
- **Personnel Security (PS)**: Screen personnel prior to system access
- **System Protection (SC)**: Cryptographic mechanisms and session management
- **System Integrity (SI)**: Flaw identification, malicious code protection, security monitoring

### Technical Improvements
- Enhanced deadline countdown for time-sensitive compliance requirements
- Improved framework-specific verbose output with control counts
- Better integration with existing SOC2 and PCI-DSS workflows
- Consistent evidence collection format across all frameworks

### 3. Framework-Specific Requirements

```yaml
CMMC Level 1 (NEW):
- 17 foundational practices for FCI protection
- Required for all DoD contractors by November 10, 2025
- Self-assessment certification process
- Focuses on basic cybersecurity hygiene

PCI-DSS Specific:
- 90-day password rotation (not 180 like SOC2)
- MFA for ALL users (not just privileged)
- 12-month log retention (not 90 days)
- Quarterly vulnerability scans required
- No 0.0.0.0/0 security rules (zero tolerance)

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
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@v0.6.0
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
auditkit scan -verbose                 # Detailed output with deadline tracking

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

## Project Structure

```
auditkit/
└── scanner/
    ├── cmd/auditkit/           # CLI entry point (main.go)
    ├── go.mod                  # Go dependencies
    └── pkg/
        ├── aws/                # AWS provider (19 files)
        │   ├── scanner.go      
        │   ├── priority.go     
        │   └── checks/         
        │       ├── cloudtrail.go
        │       ├── cmmc_level1.go       # CMMC Level 1 practices (NEW)
        │       ├── config.go
        │       ├── ec2.go
        │       ├── iam.go
        │       ├── iam_advanced.go
        │       ├── monitoring.go
        │       ├── pci_dss.go           # PCI-DSS v4.0 controls
        │       ├── rds.go
        │       ├── s3.go
        │       ├── soc2_cc1_cc2.go      # SOC2 Common Criteria 1-2
        │       ├── soc2_cc3_cc5.go      # SOC2 Common Criteria 3-5
        │       ├── soc2_cc6_cc9.go      # SOC2 Common Criteria 6-9
        │       ├── systems.go
        │       ├── types.go
        │       └── vpc.go
        ├── azure/              # Azure provider (15 files)
        │   ├── scanner.go      
        │   └── checks/         
        │       ├── aad.go               # Azure AD/Entra ID
        │       ├── cmmc_level1.go       # CMMC Level 1 practices (NEW)
        │       ├── compute.go           # VMs and disks
        │       ├── identity.go          # Managed identities
        │       ├── keyvault.go          # Key Vault checks
        │       ├── monitoring.go        # Activity logs
        │       ├── network.go           # NSGs and networking
        │       ├── pci_dss.go           # PCI-DSS v4.0 controls
        │       ├── soc2_cc1_cc2.go      # SOC2 Common Criteria 1-2
        │       ├── soc2_cc3_cc5.go      # SOC2 Common Criteria 3-5
        │       ├── soc2_cc6_cc9.go      # SOC2 Common Criteria 6-9
        │       ├── sql.go               # Azure SQL
        │       ├── storage.go           # Storage accounts
        │       └── types.go
        ├── cache/              # Scan result caching
        ├── evidence/           # Screenshot guidance
        ├── remediation/        # Fix script generation
        ├── report/             # PDF/HTML generation
        ├── telemetry/          # Anonymous usage stats
        ├── tracker/            # Progress tracking
        └── updater/            # Version checking
```

## Roadmap

- [x] v0.3.0 - Evidence collection (Sept 2025)
- [x] v0.4.0 - Multi-framework support (Sept 2025)
- [x] v0.4.1 - Full SOC2 implementation (Sept 2025)
- [x] v0.5.0 - Azure support (Sept 2025)
- [x] v0.6.0 - CMMC Level 1 support (Sept 2025)
- [ ] v0.7.0 - GCP support (Dec 2025)
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

## Contributing

We need help with:
1. **GCP provider** - Mirror AWS/Azure structure
2. **HIPAA controls** - Complete the 45 administrative safeguards
3. **ISO 27001** - Map all 114 controls
4. **CMMC Level 2** - 110 additional practices for CUI protection
5. **Evidence automation** - Selenium/Playwright for screenshots
6. **Container scanning** - Kubernetes, Docker compliance

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Newsletter**: [auditkit.substack.com](https://auditkit.substack.com)
- **Support Development**: [Buy Me a Coffee](https://www.buymeacoffee.com/auditkit)

## FAQ

**Q: Is CMMC Level 1 implementation complete?**  
A: Yes, v0.6.0 includes full CMMC Level 1 implementation with all 17 practices for both AWS and Azure. Production-ready for DoD contractor compliance.

**Q: When is the CMMC deadline?**  
A: November 10, 2025. All new DoD contracts will require CMMC compliance starting this date. AuditKit shows countdown and deadline tracking.

**Q: What about CMMC Level 2?**  
A: CMMC Level 2 (110 practices for CUI handling) is available as a Pro feature with enterprise support and advanced automation. Contact hello@auditkit.io for licensing information.

**Q: Why is my compliance score low?**  
A: Enable security services first (AWS: GuardDuty, Config, CloudTrail | Azure: Defender, Policy, Activity Logs)

**Q: Which cloud provider has better coverage?**  
A: Both AWS and Azure have identical control coverage across SOC2, PCI-DSS, and CMMC Level 1. AWS has slightly more mature checks due to being implemented first.

**Q: Can I scan multiple AWS accounts or Azure subscriptions?**  
A: Currently one at a time. Use different profiles: `auditkit scan -profile production`

**Q: Does this replace Prowler/ScoutSuite?**  
A: No, those are security scanners. AuditKit focuses on compliance evidence collection for auditors with framework-specific mappings.

## License

Apache 2.0 - Use freely, even commercially.

---

**Built by engineers who've been through too many compliance audits. Special thanks to the off-the-cuff contributions from Jordan**
