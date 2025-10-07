# Changelog

## [v0.6.1] - 2025-10-07

### Added
- **M365 Integration**: New `integrate` command for importing ScubaGear M365 security results
- **Community Contribution**: Comprehensive Entra ID mappings (29 rules) contributed by community member
- Unified compliance reporting across AWS, Azure, and M365
- Step-by-step remediation guidance for M365 controls
- Screenshot evidence collection instructions for Entra ID policies
- Direct Azure portal console URLs for each control
- Framework mappings: M365 findings now map to SOC2, PCI-DSS, HIPAA

### Changed
- Updated version to v0.6.1
- Improved error messages for integration failures
- Enhanced verbose mode for debugging integration parsing

### Removed
- Telemetry tracking completely removed (no analytics or usage tracking)

### Technical
- New integration framework at `pkg/integrations/`
- ScubaGear parser implementation
- Community-contributed mappings at `mappings/scubagear/entra.json`

### Credits
Special thanks to our community contributor for the comprehensive Entra ID security mappings that make AuditKit the first open-source tool providing unified AWS, Azure, and M365 compliance reporting.


## [v0.6.0] - 2025-09-27
Added

CMMC Level 1 Support: Complete implementation of all 17 CMMC Level 1 practices for both AWS and Azure
DoD Contractor Compliance: Support for Federal Contract Information (FCI) protection requirements
November 10, 2025 Deadline Tracking: Built-in countdown and deadline warnings for CMMC compliance
CMMC Evidence Collection: Screenshot guides and console URLs for all 17 Level 1 practices
Framework-Specific Help: Enhanced verbose output with control counts and deadline information
Upgrade Messaging: Clear path to CMMC Level 2 Pro for organizations handling CUI

Enhanced

Multi-Framework Support: CMMC now joins SOC2 and PCI-DSS as fully supported compliance frameworks
Deadline Awareness: Time-sensitive compliance requirements now show days remaining
Evidence Collection: Consistent screenshot guide format across all frameworks
Framework Validation: Improved error handling and help text for supported frameworks

Technical

Added cmmc_level1.go for AWS provider with all 17 practices
Added cmmc_level1.go for Azure provider with all 17 practices
Enhanced main.go with CMMC-specific verbose output and deadline calculations
Improved framework filtering logic to handle CMMC controls
Added CMMC control name mappings and categorization

Business

Open Source Strategy: CMMC Level 1 freely available to build credibility with DoD contractors
Clear Monetization Path: Level 2 Pro offering for organizations requiring CUI protection (110 practices)
Market Timing: Release aligns with growing urgency around November 2025 deadline

## [0.5.0] - 2025-10-22

### Added
- **Azure Support** - Complete Azure provider implementation
  - Full SOC2 Common Criteria coverage (all 64 controls across CC1-CC9)
  - Full PCI-DSS v4.0 implementation (30 technical controls)
  - Storage Account security (public access, encryption, secure transfer)
  - Azure AD/Entra ID validation (MFA, privileged roles, guest access)
  - Network Security Group analysis (open ports, dangerous rules)
  - VM and Disk encryption checks
  - Key Vault security (purge protection, soft delete)
  - Activity Log retention validation (12-month for PCI-DSS)
  - Azure SQL security assessment (TDE, auditing)
  - Dedicated SOC2 modules (soc2_cc1_cc2.go, soc2_cc3_cc5.go, soc2_cc6_cc9.go)

### Changed
- **Improved Error Messages** - Better guidance when credentials not configured
- **Framework Consistency** - Aligned control mappings between AWS and Azure
- **Updated Dependencies** - Added Azure SDK for Go

### Fixed
- Azure SDK compatibility issues (method names, field access)
- Compilation errors in Azure check files
- Missing package declarations in some files
- Types.go emoji field removed completely

### Technical
- Added `/pkg/azure/` provider structure
- Implemented 10+ Azure check files (storage, aad, network, compute, etc.)
- Updated main.go to support multi-cloud providers
- Added Azure authentication support (CLI, Service Principal, Managed Identity)

## [0.4.1] - 2025-09-21
### Added
- Complete SOC2 Common Criteria implementation (64 controls across CC1-CC9)
- AWS connectivity check before scanning (prevents false results)
- Defensive nil checks for all AWS API responses

### Fixed
- Critical: Nil pointer dereferences in SOC2 checks when AWS APIs fail
- AWS SDK v2 type mismatches (pointer vs value types)
- Scanner reporting fake pass/fail results when not connected to AWS
- Memory access violations in CC6.2, CC6.5, and CC3-CC5 checks

### Changed
- Help text clarifies Azure/GCP "coming soon" status
- Help text marks PCI/HIPAA as "EXPERIMENTAL - limited controls"
- Improved error messages when AWS credentials not configured

### Technical
- Fixed soc2_cc1_cc2.go, soc2_cc3_cc5.go, soc2_cc6_cc9.go
- Updated scanner.go to check AWS connectivity first
- Removed duplicate/conflicting SSM client initialization

## [0.4.0] - 2025-09-20
### Added
- 🚀 Multi-framework support (SOC2, PCI-DSS, HIPAA)
- Framework-specific priority mapping
- Cross-framework control comparison
- Framework-aware evidence collection
- 64 complete SOC2 controls

## [0.3.0] - 2024-09-20
### Added
- 📸 Evidence collection tracker (`auditkit evidence`)
- 📊 Progress tracking over time (`auditkit progress`)
- 🔧 Auto-generate remediation scripts (`auditkit fix`)
- 📈 Compare scans (`auditkit compare`)
- 25+ SOC2 controls (up from ~10)
- Enhanced PDF reports with screenshot guides
- Success celebration at 90%+ compliance
