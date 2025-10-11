# AuditKit - Multi-Cloud Compliance Scanner & Evidence Collection

**Open-source compliance scanner for AWS, Azure, and M365. Automates technical controls and generates audit-ready reports for SOC2, PCI-DSS, HIPAA, and CMMC frameworks.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.6.5-green.svg)](https://github.com/guardian-nexus/auditkit/releases)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

## What AuditKit Does

AuditKit scans your cloud infrastructure against SOC2, PCI-DSS, and CMMC controls and provides:

1. **Multi-Cloud Support** - AWS, Azure, M365 (via ScubaGear integration)
2. **Clear Pass/Fail Status** - 64 SOC2 controls, 30 PCI-DSS controls, 17 CMMC Level 1 controls
3. **Exact Fix Commands** - Cloud-specific CLI commands for remediation
4. **Evidence Collection Guides** - Step-by-step screenshots auditors accept
5. **Priority-Based Fixes** - Critical issues that will fail your audit vs. nice-to-haves
6. **Unified Reporting** - Combine AWS, Azure, and M365 findings in one report
7. **Professional Reports** - Generate PDF and HTML reports with evidence checklists

**Important:** AuditKit scans technical controls only. Full compliance requires organizational documentation, policies, and formal assessment by qualified auditors.

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

# Generate interactive HTML report
auditkit scan -provider aws -framework soc2 -format html -output aws-soc2.html

# Show complete output (all controls, no truncation)
auditkit scan -provider aws -framework soc2 --full
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

# Generate PCI-DSS report with full output
auditkit scan -provider azure -framework pci -format pdf -output azure-pci.pdf --full
```

### M365 (Complete Coverage)
```bash
# Import comprehensive M365 security results
auditkit integrate -source scubagear -file ScubaResults.json -format text

# Available M365 domains:
# - Entra ID (AAD): Authentication, MFA, Conditional Access
# - Exchange Online: Email security, DLP, anti-phishing
# - SharePoint: Document security, sharing policies
# - Teams: Chat security, meeting policies
# - Power Platform: Data loss prevention, governance
# - Power BI: Data security, sharing controls
# - Defender: Threat protection, security policies

# Generate M365 compliance report
auditkit integrate -source scubagear -file ScubaResults.json -format pdf -output m365-report.pdf

# Combine with AWS/Azure for complete coverage
auditkit scan -provider aws -framework soc2 -output aws-report.pdf
auditkit integrate -source scubagear -file ScubaResults.json -output m365-report.pdf
```

## Recent Updates
**v0.6.5 (Oct 2025)** - Hotfix to address PCI-DSS Scanner crash. See CHANGELOG  
**v0.6.4 (Oct 2025)** - Enhanced output control with `--full` flag  
**v0.6.3 (Oct 2025)** - Enhanced reports + Complete M365 coverage  
**v0.6.2 (Oct 2025)** - Framework scanning improvements & Hotfix  
**v0.6.1 (Oct 2025)** - M365/Entra ID integration via ScubaGear  
**v0.6.0 (Sept 2025)** - CMMC Level 1 support with November 10, 2025 deadline tracking  

## What's New in v0.6.4

### Enhanced Output Control
- **`--full` flag** - Show ALL controls without truncation in text output
- **Complete PDF reports** - All controls now displayed (no truncation)
- **Complete HTML reports** - Already showing everything, now consistent across formats
- **Smart default behavior** - Terminal output remains concise by default for readability

```bash
# Default (concise output for terminal readability)
auditkit scan -provider aws -framework cmmc -verbose

# Full output (show all 127 controls in terminal)
auditkit scan -provider aws -framework cmmc -verbose --full

# PDF (always shows everything now)
auditkit scan -provider aws -framework cmmc -format pdf -output report.pdf

# HTML (already showed everything)
auditkit scan -provider aws -framework cmmc -format html -output report.html
```

### What Changed in v0.6.4

| Output Format | Before v0.6.4 | After v0.6.4 |
|---------------|---------------|--------------|
| **Console (default)** | Truncated to ~40 controls | Same (concise for readability) |
| **Console (--full)** | Not available | Shows all 127 controls |
| **PDF** | Truncated to ~25 controls | Shows all controls |
| **HTML** | Already showed all | No change (still complete) |

### Why This Matters

**For auditors:** PDF reports now include complete control lists without manual compilation  
**For engineers:** `--full` flag provides comprehensive output for debugging and analysis  
**For compliance teams:** Consistent reporting across all output formats

## Current Implementation Status

### Cloud Providers
| Provider | Files | Checks | Status | Authentication |
|----------|-------|--------|--------|----------------|
| **AWS** | 17 check files | ~150 checks | ✅ Production | AWS CLI, IAM roles |
| **Azure** | 12 check files | ~110 checks | ✅ Production | CLI, Service Principal, Managed Identity |
| **M365** | 7 domains | 100+ rules | ✅ Via ScubaGear | ScubaGear output |
| **GCP** | Not started | 0 | 🚧 Planned v0.7.0 | - |

### Framework Coverage
| Framework | AWS Controls | Azure Controls | M365 Controls | Status |
|-----------|--------------|----------------|---------------|--------|
| **SOC2** | 64 (CC1-CC9) | 64 (CC1-CC9) | 100+ rules | ✅ Production Ready |
| **PCI-DSS v4.0** | 30 technical | 30 technical | Security rules | ✅ Production Ready |
| **CMMC Level 1** | 17 practices | 17 practices | Mapped rules | ✅ Production Ready |
| **CMMC Level 2** | 110 practices | 110 practices | Advanced rules | [Pro Feature](https://auditkit.io/pro/) |
| **HIPAA** | ~10 mapped | ~10 mapped | Security rules | 🧪 Experimental |
| **ISO 27001** | ~5 mapped | ~5 mapped | - | 🧪 Experimental |

### CMMC Compliance
- **CMMC Level 1**: 17 foundational practices for Federal Contract Information (FCI)
- **Deadline**: November 10, 2025 - All DoD contracts will require CMMC compliance
- **Coverage**: Both AWS and Azure providers support complete Level 1 assessment
- **Evidence**: Screenshot guides for all 17 practices with exact Azure Portal/AWS Console URLs

## What Makes AuditKit Different

### 1. First True Multi-Cloud Compliance Tool

Only open-source tool to unify AWS + Azure + M365 (all 7 domains) compliance scanning with framework-specific controls and evidence collection guidance.

### 2. Professional Reports That Auditors Accept

**PDF Reports Include:**
- Cover page with compliance score visualization
- Executive summary in plain English
- Critical issues with remediation commands
- Evidence collection guides with step-by-step instructions
- Framework-specific checklists
- Footer on every page
- **NEW in v0.6.4:** Complete control lists (no truncation)

**HTML Reports Include:**
- Interactive tabs (Failed/Passed controls)
- Clickable AWS/Azure Console URLs
- Copy-paste ready remediation commands
- Modern responsive design
- Searchable and filterable

### 3. Complete M365 Security Coverage

```yaml
Entra ID (AAD):
- MFA enforcement
- Conditional Access policies
- Identity Protection
- Password policies

Exchange Online:
- Anti-phishing policies
- DLP rules
- Email encryption
- Malware protection

SharePoint:
- Sharing policies
- External sharing controls
- DLP policies
- Access controls

Teams:
- Meeting security
- Chat policies
- External access
- Recording policies

Power Platform:
- DLP policies
- Connector governance
- Environment controls
- Data classification

Power BI:
- Tenant settings
- Sharing policies
- External sharing
- Row-level security

Defender:
- Safe Links
- Safe Attachments
- Anti-phishing
- Security policies
```

### 4. Framework-Specific Requirements

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
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@v0.6.4
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
auditkit scan --full                   # Show ALL controls (no truncation)

# M365 Integration
auditkit integrate -source scubagear -file ScubaResults.json
auditkit integrate -source scubagear -file ScubaResults.json -format pdf
auditkit integrate -source scubagear -file ScubaResults.json -format html
auditkit integrate -source scubagear -file ScubaResults.json -verbose

# Reporting
auditkit scan -format pdf -output report.pdf    # Professional PDF report
auditkit scan -format html -output report.html  # Interactive HTML report
auditkit scan -format json                       # JSON output
auditkit scan -format text --full                # Complete text output

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

# Run comprehensive M365 security assessment (all domains)
Invoke-SCuBA -ProductNames aad,exo,defender,sharepoint,teams,powerbi,powerplatform -OutPath ./ScubaResults

# Or run individual domains
Invoke-SCuBA -ProductNames aad -OutPath ./ScubaResults  # Just Entra ID
Invoke-SCuBA -ProductNames exo -OutPath ./ScubaResults  # Just Exchange
```

### Step 2: Import into AuditKit
```bash
# Import M365 findings (all domains)
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -format text

# Generate M365 compliance report
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -format pdf -output m365-compliance.pdf

# Generate HTML report with interactive tabs
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -format html -output m365-compliance.html
```

### Step 3: Unified Reporting
```bash
# Complete multi-cloud compliance coverage
auditkit scan -provider aws -framework soc2 -format pdf -output aws-soc2.pdf
auditkit scan -provider azure -framework soc2 -format pdf -output azure-soc2.pdf
auditkit integrate -source scubagear -file ScubaResults.json -format pdf -output m365-soc2.pdf

# Or generate HTML reports for web viewing
auditkit scan -provider aws -framework soc2 -format html -output aws-soc2.html
auditkit scan -provider azure -framework soc2 -format html -output azure-soc2.html
auditkit integrate -source scubagear -file ScubaResults.json -format html -output m365-soc2.html
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

## Examples

### Sample Scan Output

```bash
$ auditkit scan -provider aws -framework soc2 -verbose

Scanning AWS account 123456789012...
Region: us-east-1

[CRITICAL] IAM.001 - Root Account MFA
Status: FAIL
Evidence: Root account does not have MFA enabled
Framework Mappings:
  → SOC2: CC6.6 (Logical Access Controls)
  → PCI-DSS: Requirement 8.3.1 (MFA for all users)
  → CMMC: IA.L1-3.5.2 (Multi-factor Authentication)
  → HIPAA: §164.312(a)(2)(i) (Unique User Identification)
Console URL: https://console.aws.amazon.com/iam/home#/security_credentials
Screenshot Guide: Navigate to Security credentials → MFA → Screenshot "Assigned MFA device"
Remediation: aws iam enable-mfa-device --user-name root --serial-number arn:aws:iam::123456789012:mfa/root

[CRITICAL] S3.002 - Public Bucket Access
Status: FAIL
Evidence: Bucket 'customer-data' allows public access
Framework Mappings:
  → SOC2: CC6.3 (Logical Access - Data Protection)
  → PCI-DSS: Requirement 1.3.1 (DMZ Configuration)
  → CMMC: SC.L1-3.13.16 (Boundary Protection)
  → HIPAA: §164.312(a)(1) (Access Control)
Console URL: https://s3.console.aws.amazon.com/s3/buckets/customer-data
Screenshot Guide: Permissions tab → Block public access → All 4 settings "On"
Remediation: aws s3api put-public-access-block --bucket customer-data --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

[PASS] IAM.003 - Password Policy
Status: PASS
Evidence: Password policy meets requirements (14 char minimum, complexity enabled, 90-day rotation)
Framework Mappings:
  → SOC2: CC6.1 (Logical Access)
  → PCI-DSS: Requirement 8.2.3 (Password Complexity)
  → CMMC: IA.L1-3.5.7 (Password Management)

Compliance Score: 67.2% (43/64 controls passed)
Critical Issues: 5
High Priority: 8
Medium Priority: 3
Passed Controls: 43

Report generated: aws-soc2-report.pdf
Evidence tracker: evidence-tracker.html

# Use --full to see ALL controls without truncation
$ auditkit scan -provider aws -framework soc2 --full
[Shows all 64 controls with complete details...]
```

### Multi-Framework Scan Results

Running a scan against all frameworks shows how a single control maps across different compliance requirements:

```bash
$ auditkit scan -provider aws -framework all

Control: CloudTrail Multi-Region Logging
Status: FAIL
Impact: HIGH

Framework Mappings:
  SOC2 CC7.2: System Operations - Logging and monitoring
  PCI-DSS 10.1: Audit trails to link access to users
  CMMC SI.L1-3.14.6: Monitor organizational systems
  HIPAA §164.312(b): Audit controls and logging
  ISO 27001 A.12.4.1: Event logging requirements

One fix resolves 5 compliance requirements.
```

### Before/After Comparison

**Before Fixes (Initial Scan):**
```
Compliance Score: 34.2%
Critical Issues: 12
Failed Controls: 42/64
Estimated Fix Time: ~40 hours
```

**After Fixes (Re-scan):**
```
Compliance Score: 96.8%
Critical Issues: 0
Failed Controls: 2/64 (manual review required)
Time to Fix: 6 hours actual
```

### Evidence Collection Example

```bash
$ auditkit evidence -output evidence-tracker.html

Evidence tracker generated with 64 requirements

Progress Summary:
✓ Collected: 18 screenshots
⏳ Remaining: 46 screenshots
🎯 Next Required: IAM_MFA_Evidence.png

Evidence Categories:
- Identity & Access: 12/24 collected
- Data Protection: 3/15 collected
- Monitoring & Logging: 3/10 collected
- Network Security: 0/15 collected

Open evidence-tracker.html in browser to see interactive checklist
```

### M365 Integration Example

```bash
# Step 1: Run ScubaGear assessment
PS> Invoke-SCuBA -ProductNames aad,exo,defender,sharepoint,teams -OutPath ./ScubaResults

# Step 2: Import into AuditKit
$ auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json -verbose

Importing M365 security findings...

Entra ID (AAD): 29 rules processed
  ✓ 18 passed
  ✗ 11 failed
  Critical: MFA not enforced for all users

Exchange Online: 23 rules processed
  ✓ 15 passed
  ✗ 8 failed
  Critical: Anti-phishing policy not configured

SharePoint: 18 rules processed
  ✓ 12 passed
  ✗ 6 failed

Teams: 15 rules processed
  ✓ 10 passed
  ✗ 5 failed

M365 Compliance Score: 61.2% (55/90 rules passed)

Framework Mappings:
  SOC2: 12 failed controls
  PCI-DSS: 8 failed controls
  HIPAA: 15 failed controls
  CMMC: 9 failed controls

Report: m365-compliance.pdf
```

### Unified Multi-Cloud Report

Combining AWS, Azure, and M365 scans:

```bash
# Scan all three environments
$ auditkit scan -provider aws -framework soc2 -output aws-report.pdf
$ auditkit scan -provider azure -framework soc2 -output azure-report.pdf
$ auditkit integrate -source scubagear -file ScubaResults.json -output m365-report.pdf

Combined Results:
- AWS: 67.2% compliant (43/64 controls)
- Azure: 71.8% compliant (46/64 controls)
- M365: 61.2% compliant (55/90 rules)

Overall Compliance: 66.4%
Total Critical Issues: 18 across all environments
Estimated Fix Time: ~60 hours

Priority Actions:
1. Enable MFA across all platforms (AWS root, Azure AD, M365)
2. Configure audit logging (CloudTrail, Activity Logs, M365 Audit)
3. Encrypt data at rest (S3, Azure Storage, SharePoint)
4. Block public access (S3 buckets, Azure Storage, SharePoint sites)
5. Implement network segmentation (VPCs, NSGs, Conditional Access)
```

### CMMC Level 1 Assessment Example

```bash
$ auditkit scan -provider aws -framework cmmc -verbose

CMMC Level 1 Assessment for Federal Contract Information (FCI)
17 Foundational Practices

Access Control (AC):
  [PASS] AC.L1-3.1.1: Limit system access to authorized users
  [PASS] AC.L1-3.1.2: Limit system access to authorized transactions
  [FAIL] AC.L1-3.1.20: External connections verified and monitored
  [PASS] AC.L1-3.1.22: Control public information on systems

Identification & Authentication (IA):
  [FAIL] IA.L1-3.5.1: Identify system users and processes
  [FAIL] IA.L1-3.5.2: Multi-factor authentication for network access

Media Protection (MP):
  [PASS] MP.L1-3.8.3: Sanitize or destroy media before disposal

Physical Protection (PE):
  [INFO] PE.L1-3.10.1: Limit physical access - MANUAL VERIFICATION REQUIRED
  [INFO] PE.L1-3.10.3: Escort visitors - MANUAL VERIFICATION REQUIRED
  [INFO] PE.L1-3.10.4: Physical access logs - MANUAL VERIFICATION REQUIRED
  [INFO] PE.L1-3.10.5: Manage physical access devices - MANUAL VERIFICATION REQUIRED

System & Communications (SC):
  [PASS] SC.L1-3.13.1: Boundary protection via firewalls
  [FAIL] SC.L1-3.13.5: Public access to organizational systems

System & Information Integrity (SI):
  [PASS] SI.L1-3.14.1: Flaw remediation via patching
  [FAIL] SI.L1-3.14.2: Malicious code protection
  [PASS] SI.L1-3.14.4: Update malicious code protection
  [FAIL] SI.L1-3.14.5: Periodic system scans

CMMC Level 1 Score: 47% (8/17 practices passed)
  Automated Checks: 8/12 passed
  Manual Verification Required: 5 practices (PE family)
  
Critical Gaps:
  - Multi-factor authentication not enforced
  - Malicious code protection not configured
  - Public system access not controlled
  - Periodic vulnerability scans not enabled

Deadline: November 10, 2025 (32 days remaining)
Status: NOT READY for CMMC Level 1 certification

Next Steps:
  1. Enable MFA on all accounts
  2. Configure AWS GuardDuty for malware protection
  3. Block public access on all S3 buckets
  4. Enable AWS Inspector for vulnerability scanning
  5. Document physical security controls

# Use --full to see ALL 127 CMMC Level 2 controls (Pro version)
$ auditkit scan -provider aws -framework cmmc --full
```

### Report Examples

**PDF Report Features:**
- Professional cover page with compliance score
- Executive summary in plain English
- Critical issues with remediation commands
- Evidence collection checklist with console URLs
- Framework-specific requirements (SOC2, PCI, CMMC)
- Before/after comparison tracking
- **NEW in v0.6.4:** Complete control lists (no truncation)

**HTML Report Features:**
- Interactive tabs for Failed/Passed controls
- Searchable and filterable
- Clickable AWS/Azure Console URLs
- Copy-paste ready remediation commands
- Responsive design (mobile/desktop)
- Real-time progress tracking

### Common Scenarios

**Scenario 1: Startup Preparing for SOC2**
```bash
# Initial assessment
$ auditkit scan -provider aws -framework soc2
Score: 34% - High priority: Enable GuardDuty, Config, CloudTrail

# After 1 week of fixes
$ auditkit scan -provider aws -framework soc2
Score: 78% - Improved 44% in 7 days

# Ready for audit
$ auditkit scan -provider aws -framework soc2 -format pdf --full
Score: 96% - 2 manual controls remaining, audit-ready
```

**Scenario 2: DoD Contractor CMMC Deadline**
```bash
# 45 days before deadline
$ auditkit scan -provider aws -framework cmmc
Level 1 Score: 41% (7/17) - NOT READY

# 30 days before deadline
$ auditkit scan -provider aws -framework cmmc
Level 1 Score: 76% (13/17) - ALMOST READY

# 15 days before deadline
$ auditkit scan -provider aws -framework cmmc -format pdf --full
Level 1 Score: 100% (17/17) - READY for C3PAO assessment
```

**Scenario 3: Multi-Cloud Enterprise**
```bash
# Scan all environments
$ ./scan-all-clouds.sh

AWS Production:     87% compliant (SOC2)
AWS Staging:        72% compliant (SOC2)
Azure Production:   91% compliant (SOC2)
M365 Tenant:        68% compliant (SOC2)

Overall:            79.5% compliant
Critical Issues:    3 (all in M365)
Fix Priority:       Enable M365 MFA, Configure DLP policies
```

### Quick Start Examples

**Most Common Use Case: SOC2 Preparation**
```bash
# 1. Initial scan
auditkit scan -provider aws -framework soc2

# 2. Generate audit report
auditkit scan -provider aws -framework soc2 -format pdf -output soc2-audit.pdf

# 3. Create evidence tracker
auditkit evidence -output evidence.html

# 4. Get fix commands
auditkit fix -output fixes.sh

# 5. Apply fixes and re-scan
bash fixes.sh
auditkit scan -provider aws -framework soc2
```

**CMMC Fast Track (30 Days to Compliant)**
```bash
# Day 1: Assess current state
auditkit scan -provider aws -framework cmmc -verbose --full

# Day 7: Re-scan after quick wins
auditkit scan -provider aws -framework cmmc
auditkit compare  # Shows improvement

# Day 14: Mid-point check
auditkit scan -provider aws -framework cmmc -format html

# Day 28: Final validation
auditkit scan -provider aws -framework cmmc -format pdf -output cmmc-assessment.pdf

# Day 30: Submit to C3PAO
# You now have complete evidence package ready
```

### Sample File Structure After Scans

```
audit-results/
├── aws-soc2-report.pdf           # Professional audit report
├── aws-soc2-report.html          # Interactive web version
├── evidence-tracker.html         # Screenshot checklist
├── fixes.sh                      # Auto-generated remediation
├── scan-history.json             # Progress tracking
├── screenshots/
│   ├── IAM_MFA_Evidence.png
│   ├── S3_Encryption_Evidence.png
│   └── CloudTrail_Logging.png
└── compliance-scores.txt         # Score history
```

## Roadmap

- [x] v0.3.0 - Evidence collection (Sept 2025)
- [x] v0.4.0 - Multi-framework support (Sept 2025)
- [x] v0.4.1 - Full SOC2 implementation (Sept 2025)
- [x] v0.5.0 - Azure support (Sept 2025)
- [x] v0.6.0 - CMMC Level 1 support (Sept 2025)
- [x] v0.6.1 - M365 Entra ID integration (Oct 2025)
- [x] v0.6.2 - Framework scanning improvements & Hotfix (Oct 2025)
- [x] v0.6.3 - Enhanced reports + Complete M365 coverage (Oct 2025)
- [x] v0.6.4 - Enhanced output control with --full flag (Oct 2025)
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
6. **M365 Integration**: Requires CISA ScubaGear for M365 assessment (free, open-source tool from CISA)

## Contributing

We need help with:
1. **Additional framework mappings** - NIST 800-53, FedRAMP, GDPR
2. **GCP provider** - Mirror AWS/Azure structure
3. **Prowler integration** - Import Prowler AWS/Azure/GCP results
4. **HIPAA controls** - Complete the 45 administrative safeguards
5. **ISO 27001** - Map all 114 controls
6. **Evidence automation** - Selenium/Playwright for screenshots
7. **Container scanning** - Kubernetes, Docker compliance

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**Special thanks to our community contributors** for comprehensive M365 domain mappings (Entra ID, Exchange, SharePoint, Teams, Power Platform, Power BI, Defender) that enable true multi-cloud compliance reporting!

## Support

- **Issues**: [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Newsletter**: [auditkit.substack.com](https://auditkit.substack.com)
- **Support Development**: [Buy Me a Coffee](https://www.buymeacoffee.com/auditkit)

## FAQ

**Q: How does M365 integration work?**  
A: Run CISA's ScubaGear tool to assess your M365 environment (all 7 domains supported), then use `auditkit integrate` to import the results and map them to compliance frameworks (SOC2, PCI-DSS, HIPAA, CMMC).

**Q: What M365 domains are supported?**  
A: All 7 major domains: Entra ID (AAD), Exchange Online, SharePoint, Teams, Power Platform, Power BI, and Defender for Office 365.

**Q: Is CMMC Level 1 implementation complete?**  
A: Yes, v0.6.0 includes full CMMC Level 1 implementation with all 17 practices for both AWS and Azure.

**Q: When is the CMMC deadline?**  
A: November 10, 2025. All new DoD contracts will require CMMC compliance starting this date.

**Q: What about CMMC Level 2?**  
A: CMMC Level 2 (110 practices for CUI handling) is available as a Pro feature. Check out [AuditKit Pro](https://auditkit.io/pro/).

**Q: What's the difference between PDF and HTML reports?**  
A: PDF reports are professional documents for auditors with evidence checklists. HTML reports are interactive with tabs, clickable links, and copy-paste commands - better for internal use. Both now show complete control lists in v0.6.4.

**Q: When should I use the --full flag?**  
A: Use `--full` when you need to see ALL controls in terminal output (e.g., for debugging, comprehensive analysis, or exporting to other tools). Default output is concise for readability. PDF and HTML always show everything.

**Q: Why is my compliance score low?**  
A: Enable security services first:
- **AWS**: GuardDuty, Config, CloudTrail, Security Hub
- **Azure**: Defender for Cloud, Azure Policy, Activity Logs, Sentinel
- **M365**: Conditional Access, Identity Protection, DLP policies, Defender for Office 365

**Q: Can I scan multiple AWS accounts or Azure subscriptions?**  
A: Currently one at a time. Use different profiles: `auditkit scan -profile production`

**Q: Does this replace Prowler/ScoutSuite?**  
A: No, those are security scanners. AuditKit focuses on compliance evidence collection for auditors with framework-specific mappings.

## License

Apache 2.0 - Use freely, even commercially.

---

**Built by engineers who've been through too many compliance audits.**

**Huge thanks to our community contributors for M365 domain mappings that make AuditKit the first truly unified multi-cloud compliance tool!**
