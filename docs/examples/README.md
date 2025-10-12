# AuditKit Examples

Real-world scan outputs, reports, and screenshots demonstrating AuditKit's capabilities.

## Directory Structure

- **reports/** - Sample PDF and HTML compliance reports (SOC2, PCI-DSS, CMMC)
- **scan-outputs/** - Raw terminal output from real scans
- **screenshots/** - Console screenshots showing evidence collection
- **remediation/** - (Coming soon) Step-by-step fix guides

## Sample Reports

### AWS Compliance
- [AWS SOC2 Report (PDF)](./reports/sample-aws-soc2-report.pdf) - 64 controls
- [AWS SOC2 Report (HTML)](./reports/sample-aws-soc2-report.html) - Interactive version
- [AWS PCI-DSS Report (PDF)](./reports/sample-aws-pci-report.pdf) - 30+ controls  
- [AWS CMMC Report (PDF)](./reports/sample-aws-cmmc-report.pdf) - 17 Level 1 practices

### Azure Compliance
- [Azure CMMC Report (PDF)](./reports/sample-azure-cmmc-report.pdf) - 17 Level 1 practices
- [Azure CMMC Report (HTML)](./reports/sample-azure-cmmc-report.html) - Interactive version

## Terminal Outputs

Raw scan outputs with colors and formatting:
- [AWS SOC2 Scan](./scan-outputs/aws-soc2-scan.txt)
- [AWS PCI-DSS Scan](./scan-outputs/aws-pci-scan.txt)
- [AWS CMMC Scan](./scan-outputs/aws-cmmc-scan.txt)
- [Azure CMMC Scan](./scan-outputs/azure-cmmc-scan.txt)

## Screenshots

- [Azure CMMC Console Output](./screenshots/azure-cmmc-scan-console-output-sample.png)

## Real-World Results

### Startup SOC2 Prep
**Company:** 15-person SaaS startup  
**Challenge:** First SOC2 audit in 90 days, no compliance team  
**Result:** 26% to 98% compliant in 3 hours  
**Saved:** $15,000 vs hiring consultant  

### DoD Contractor CMMC
**Company:** 50-person defense contractor  
**Challenge:** CMMC Level 1 required for new contracts  
**Result:** Self-assessment completed in 10 days  
**Saved:** $25,000 vs C3PAO costs  

### Enterprise Multi-Cloud
**Company:** 500-person fintech  
**Challenge:** AWS + Azure + M365 compliance across 3 teams  
**Result:** Single compliance dashboard  
**Saved:** Replaced 3 separate compliance tools ($60k/year)  

## Try It Yourself

```bash
# Install
curl -LO https://github.com/guardian-nexus/auditkit/releases/latest/download/auditkit-linux-amd64.tar.gz
tar -xzf auditkit-linux-amd64.tar.gz
chmod +x auditkit-linux-amd64

# Run SOC2 scan
./auditkit-linux-amd64 scan -provider aws -framework soc2 -verbose

# Generate PDF report
./auditkit-linux-amd64 scan -provider aws -framework soc2 -format pdf -output my-report.pdf
```

## Additional Resources

- [Installation Guide](../../README.md#installation)
- [Usage Examples](../../README.md#usage)
- [GitHub Repository](https://github.com/guardian-nexus/auditkit)
- [AuditKit Pro](https://guardian-nexus.github.io/auditkit/pro/)
