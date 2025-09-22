# Changelog

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
