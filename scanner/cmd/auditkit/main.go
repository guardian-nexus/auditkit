// scanner/cmd/auditkit/main.go
package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
    "time"
    
    awsScanner "github.com/guardian-nexus/auditkit/scanner/pkg/aws"
)

type ComplianceResult struct {
    Timestamp       time.Time              `json:"timestamp"`
    Provider        string                 `json:"provider"`
    AccountID       string                 `json:"account_id,omitempty"`
    Score           float64                `json:"score"`
    TotalControls   int                    `json:"total_controls"`
    PassedControls  int                    `json:"passed_controls"`
    FailedControls  int                    `json:"failed_controls"`
    Controls        []ControlResult        `json:"controls"`
    Recommendations []string               `json:"recommendations"`
}

type ControlResult struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Category    string `json:"category"`
    Severity    string `json:"severity,omitempty"`
    Status      string `json:"status"` // PASS, FAIL, NOT_APPLICABLE
    Evidence    string `json:"evidence"`
    Remediation string `json:"remediation,omitempty"`
}

func main() {
    var (
        provider = flag.String("provider", "aws", "Cloud provider (aws, azure, gcp)")
        profile  = flag.String("profile", "default", "AWS profile to use")
        format   = flag.String("format", "text", "Output format (text, json, html)")
        output   = flag.String("output", "", "Output file (default: stdout)")
        verbose  = flag.Bool("verbose", false, "Verbose output")
        services = flag.String("services", "all", "Comma-separated services to scan (s3,iam,ec2,rds,cloudtrail)")
    )
    flag.Parse()

    if flag.NArg() < 1 {
        printUsage()
        os.Exit(1)
    }

    command := flag.Arg(0)

    switch command {
    case "scan":
        runScan(*provider, *profile, *format, *output, *verbose, *services)
    case "report":
        generateReport(*format, *output)
    case "fix":
        runRemediation(*provider, *profile)
    case "version":
        fmt.Println("AuditKit v0.2.0 - SOC2 compliance scanning that actually works")
    default:
        fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
        printUsage()
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println(`AuditKit - Open Source SOC2 Compliance Scanner

Usage:
  auditkit scan [options]     Scan infrastructure for compliance
  auditkit report [options]   Generate audit-ready report
  auditkit fix [options]      Apply automated remediations
  auditkit version           Show version

Options:
  -provider string   Cloud provider (aws, azure, gcp) (default "aws")
  -profile string    AWS profile to use (default "default")
  -format string     Output format (text, json, html) (default "text")
  -output string     Output file (default: stdout)
  -services string   Services to scan (default "all")
  -verbose          Verbose output

Examples:
  # Quick scan with text output
  auditkit scan

  # Scan specific AWS profile
  auditkit scan -profile production

  # Generate HTML report
  auditkit scan -format html -output report.html

  # Scan only specific services
  auditkit scan -services s3,iam

For more information: https://github.com/guardian-nexus/auditkit`)
}

func runScan(provider, profile, format, output string, verbose bool, services string) {
    if verbose {
        fmt.Fprintf(os.Stderr, "🔍 Starting %s compliance scan with profile %s...\n", provider, profile)
    }

    result := performScan(provider, profile, verbose, services)
    
    // Add a summary header for text format
    if format == "text" && output == "" {
        printTextSummary(result)
        return
    }
    
    outputResults(result, format, output)
}

func performScan(provider, profile string, verbose bool, services string) ComplianceResult {
    if provider != "aws" {
        return mockScan(provider)
    }
    
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Error initializing AWS scanner: %v\n", err)
        fmt.Fprintf(os.Stderr, "\nMake sure you have AWS credentials configured:\n")
        fmt.Fprintf(os.Stderr, "  aws configure --profile %s\n", profile)
        os.Exit(1)
    }
    
    // Get account ID
    accountID := scanner.GetAccountID(context.Background())
    
    if verbose {
        fmt.Fprintf(os.Stderr, "📊 Scanning AWS Account: %s\n", accountID)
    }
    
    ctx := context.Background()
    
    // Parse services to scan
    serviceList := strings.Split(services, ",")
    if services == "all" {
        serviceList = []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
    }
    
    scanResults, err := scanner.ScanServices(ctx, serviceList, verbose)
    if err != nil {
        fmt.Fprintf(os.Stderr, "⚠️  Warning during scan: %v\n", err)
    }
    
    // Convert to ComplianceResult format
    controls := []ControlResult{}
    passed := 0
    failed := 0
    
    for _, result := range scanResults {
        control := ControlResult{
            ID:          result.Control,
            Name:        getControlName(result.Control),
            Category:    getControlCategory(result.Control),
            Severity:    result.Severity,
            Status:      result.Status,
            Evidence:    result.Evidence,
            Remediation: result.Remediation,
        }
        controls = append(controls, control)
        
        if result.Status == "PASS" {
            passed++
        } else {
            failed++
        }
    }
    
    score := 0.0
    if len(controls) > 0 {
        score = float64(passed) / float64(len(controls)) * 100
    }
    
    return ComplianceResult{
        Timestamp:      time.Now(),
        Provider:       provider,
        AccountID:      accountID,
        Score:          score,
        TotalControls:  len(controls),
        PassedControls: passed,
        FailedControls: failed,
        Controls:       controls,
        Recommendations: generateRecommendations(controls),
    }
}

func printTextSummary(result ComplianceResult) {
    fmt.Printf("\n")
    fmt.Printf("AuditKit SOC2 Compliance Scan Results\n")
    fmt.Printf("=====================================\n")
    fmt.Printf("AWS Account: %s\n", result.AccountID)
    fmt.Printf("Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
    fmt.Printf("\n")
    
    // Score with color
    scoreColor := "\033[32m" // green
    if result.Score < 80 {
        scoreColor = "\033[33m" // yellow
    }
    if result.Score < 60 {
        scoreColor = "\033[31m" // red
    }
    fmt.Printf("Compliance Score: %s%.1f%%\033[0m\n", scoreColor, result.Score)
    fmt.Printf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls)
    fmt.Printf("\n")
    
    // Show failures first
    if result.FailedControls > 0 {
        fmt.Printf("\033[31m❌ Failed Controls:\033[0m\n")
        fmt.Printf("-------------------\n")
        for _, control := range result.Controls {
            if control.Status == "FAIL" {
                severityColor := "\033[33m" // yellow for HIGH
                if control.Severity == "CRITICAL" {
                    severityColor = "\033[31m" // red for CRITICAL
                }
                fmt.Printf("\n%s[%s]\033[0m %s - %s\n", severityColor, control.Severity, control.ID, control.Name)
                fmt.Printf("  Issue: %s\n", control.Evidence)
                if control.Remediation != "" {
                    fmt.Printf("  Fix: %s\n", control.Remediation)
                }
            }
        }
        fmt.Printf("\n")
    }
    
    // Show passes
    fmt.Printf("\033[32m✅ Passed Controls:\033[0m\n")
    fmt.Printf("-------------------\n")
    for _, control := range result.Controls {
        if control.Status == "PASS" {
            fmt.Printf("  • %s - %s: %s\n", control.ID, control.Name, control.Evidence)
        }
    }
    
    // Recommendations
    if len(result.Recommendations) > 0 {
        fmt.Printf("\n📋 Top Recommendations:\n")
        fmt.Printf("----------------------\n")
        for i, rec := range result.Recommendations {
            if i >= 5 { // Only show top 5
                break
            }
            fmt.Printf("  %d. %s\n", i+1, rec)
        }
    }
    
    fmt.Printf("\n")
    fmt.Printf("For detailed report, run: auditkit scan -format html -output report.html\n")
    fmt.Printf("\n")
}

func getControlName(controlID string) string {
    controlNames := map[string]string{
        "CC6.1": "Logical and Physical Access Controls",
        "CC6.2": "Network Security",
        "CC6.3": "Encryption at Rest",
        "CC6.6": "Multi-Factor Authentication",
        "CC6.7": "User Access Reviews",
        "CC6.8": "Access Key Rotation",
        "CC7.1": "Security Monitoring and Logging",
        "CC7.2": "Incident Detection and Response",
        "A1.1":  "Availability Monitoring",
        "A1.2":  "Backup and Recovery",
        "PI1.1": "Privacy Controls",
        "C1.1":  "Data Retention",
    }
    
    if name, ok := controlNames[controlID]; ok {
        return name
    }
    return "Security Control"
}

func getControlCategory(controlID string) string {
    if strings.HasPrefix(controlID, "CC") {
        return "Common Criteria"
    } else if strings.HasPrefix(controlID, "A") {
        return "Availability"
    } else if strings.HasPrefix(controlID, "PI") {
        return "Privacy"
    } else if strings.HasPrefix(controlID, "C") {
        return "Confidentiality"
    }
    return "Security"
}

func generateRecommendations(controls []ControlResult) []string {
    recs := []string{}
    
    // Analyze failures and generate specific recommendations
    hasPublicS3 := false
    hasOldKeys := false
    hasNoMFA := false
    hasOpenPorts := false
    hasNoLogging := false
    
    for _, control := range controls {
        if control.Status == "FAIL" {
            switch control.ID {
            case "CC6.2":
                if strings.Contains(control.Evidence, "public") || strings.Contains(control.Evidence, "0.0.0.0/0") {
                    hasPublicS3 = true
                    hasOpenPorts = true
                }
            case "CC6.8":
                hasOldKeys = true
            case "CC6.6":
                hasNoMFA = true
            case "CC7.1":
                hasNoLogging = true
            }
        }
    }
    
    // Priority recommendations based on failures
    if hasNoMFA {
        recs = append(recs, "🚨 CRITICAL: Enable MFA for root account immediately")
    }
    if hasPublicS3 {
        recs = append(recs, "🚨 CRITICAL: Review and restrict public S3 bucket access")
    }
    if hasOpenPorts {
        recs = append(recs, "⚠️  HIGH: Restrict security groups - no 0.0.0.0/0 on sensitive ports")
    }
    if hasOldKeys {
        recs = append(recs, "⚠️  HIGH: Implement 90-day access key rotation policy")
    }
    if hasNoLogging {
        recs = append(recs, "⚠️  HIGH: Enable CloudTrail in all regions for audit trail")
    }
    
    // General recommendations
    recs = append(recs, "Enable AWS Config for continuous compliance monitoring")
    recs = append(recs, "Implement least privilege IAM policies")
    recs = append(recs, "Enable GuardDuty for threat detection")
    recs = append(recs, "Configure automated backups for all databases")
    recs = append(recs, "Set up billing alerts to detect unusual activity")
    
    return recs
}

func mockScan(provider string) ComplianceResult {
    fmt.Fprintf(os.Stderr, "⚠️  %s provider not yet implemented, showing sample data\n", provider)
    
    controls := []ControlResult{
        {
            ID:       "CC6.1",
            Name:     "Logical Access Controls",
            Category: "Security",
            Status:   "PASS",
            Evidence: "Sample: MFA enabled, password policy configured",
        },
        {
            ID:          "CC6.2",
            Name:        "Network Security",
            Category:    "Security",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "Sample: Security group allows unrestricted access",
            Remediation: "Restrict security group rules",
        },
    }
    
    return ComplianceResult{
        Timestamp:       time.Now(),
        Provider:        provider,
        Score:           50.0,
        TotalControls:   2,
        PassedControls:  1,
        FailedControls:  1,
        Controls:        controls,
        Recommendations: []string{"This is sample data - configure provider to see real results"},
    }
}

func outputResults(result ComplianceResult, format, output string) {
    var data []byte
    var err error

    switch format {
    case "json":
        data, err = json.MarshalIndent(result, "", "  ")
    case "text":
        // Text format for file output
        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("AuditKit Compliance Report\n"))
        sb.WriteString(fmt.Sprintf("==========================\n"))
        sb.WriteString(fmt.Sprintf("Generated: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
        sb.WriteString(fmt.Sprintf("Provider: %s\n", result.Provider))
        sb.WriteString(fmt.Sprintf("Account: %s\n\n", result.AccountID))
        sb.WriteString(fmt.Sprintf("COMPLIANCE SCORE: %.1f%%\n", result.Score))
        sb.WriteString(fmt.Sprintf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls))
        sb.WriteString(fmt.Sprintf("Controls Failed: %d\n\n", result.FailedControls))
        
        sb.WriteString("FAILED CONTROLS:\n")
        sb.WriteString("----------------\n")
        for _, control := range result.Controls {
            if control.Status == "FAIL" {
                sb.WriteString(fmt.Sprintf("\n[%s] %s - %s\n", control.Severity, control.ID, control.Name))
                sb.WriteString(fmt.Sprintf("  Issue: %s\n", control.Evidence))
                if control.Remediation != "" {
                    sb.WriteString(fmt.Sprintf("  Fix: %s\n", control.Remediation))
                }
            }
        }
        
        sb.WriteString("\n\nRECOMMENDATIONS:\n")
        sb.WriteString("----------------\n")
        for i, rec := range result.Recommendations {
            sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
        }
        
        data = []byte(sb.String())
    case "html":
        data = []byte(generateHTML(result))
    default:
        fmt.Fprintf(os.Stderr, "Unsupported format: %s\n", format)
        os.Exit(1)
    }

    if err != nil {
        fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
        os.Exit(1)
    }

    if output != "" {
        err = os.WriteFile(output, data, 0644)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("✅ Report saved to %s\n", output)
    } else {
        fmt.Print(string(data))
    }
}

func formatRecommendations(recommendations []string) string {
    result := ""
    for i, rec := range recommendations {
        result += fmt.Sprintf("%d. %s\n", i+1, rec)
    }
    return result
}

func generateHTML(result ComplianceResult) string {
    // [Keep existing HTML generation code - it's already good]
    return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>AuditKit Compliance Report</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 40px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 2px solid #e1e4e8;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #0366d6;
        }
        .account-info {
            color: #586069;
            margin-top: 10px;
            font-size: 14px;
        }
        .score { 
            font-size: 72px; 
            font-weight: bold;
            color: %s; 
            margin: 20px 0;
        }
        .score-label {
            font-size: 14px;
            color: #586069;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stats {
            display: flex;
            gap: 40px;
            margin: 30px 0;
        }
        .stat {
            flex: 1;
        }
        .stat-value {
            font-size: 28px;
            font-weight: bold;
            color: #24292e;
        }
        .stat-label {
            font-size: 12px;
            color: #586069;
            text-transform: uppercase;
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        table { 
            width: 100%%; 
            border-collapse: collapse; 
            margin-top: 30px;
        }
        th { 
            text-align: left; 
            padding: 12px;
            background: #f6f8fa;
            border-bottom: 2px solid #e1e4e8;
            font-weight: 600;
            color: #24292e;
        }
        td { 
            padding: 12px; 
            border-bottom: 1px solid #e1e4e8; 
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-pass {
            background: #d4f4dd;
            color: #28a745;
        }
        .status-fail {
            background: #fdd;
            color: #dc3545;
        }
        .severity-critical {
            color: #dc3545;
            font-weight: bold;
        }
        .severity-high {
            color: #f0ad4e;
            font-weight: bold;
        }
        .recommendations {
            background: #f6f8fa;
            border-left: 4px solid #0366d6;
            padding: 20px;
            margin-top: 30px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e1e4e8;
            text-align: center;
            color: #586069;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">AuditKit</div>
            <div style="color: #586069; margin-top: 5px;">SOC2 Compliance Report</div>
            <div class="account-info">AWS Account: %s</div>
        </div>
        
        <div class="score-label">Compliance Score</div>
        <div class="score">%.1f%%</div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value pass">%d</div>
                <div class="stat-label">Controls Passed</div>
            </div>
            <div class="stat">
                <div class="stat-value fail">%d</div>
                <div class="stat-label">Controls Failed</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">Total Controls</div>
            </div>
        </div>
        
        <h2 style="margin-top: 40px;">Control Status</h2>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Name</th>
                <th>Category</th>
                <th>Status</th>
                <th>Evidence</th>
            </tr>
            %s
        </table>
        
        <div class="recommendations">
            <h3>Priority Recommendations</h3>
            <ol>
            %s
            </ol>
        </div>
        
        <div class="footer">
            <p>Generated by AuditKit on %s</p>
            <p>Open source SOC2 compliance scanning</p>
            <p><a href="https://auditkit.io" style="color: #0366d6;">auditkit.io</a> | <a href="https://github.com/guardian-nexus/auditkit" style="color: #0366d6;">GitHub</a></p>
        </div>
    </div>
</body>
</html>`,
        getScoreColor(result.Score),
        result.AccountID,
        result.Score,
        result.PassedControls,
        result.FailedControls,
        result.TotalControls,
        generateControlRows(result.Controls),
        generateRecommendationHTML(result.Recommendations),
        result.Timestamp.Format("January 2, 2006 at 3:04 PM"))
}

func generateRecommendationHTML(recommendations []string) string {
    html := ""
    for _, rec := range recommendations[:min(5, len(recommendations))] {
        html += fmt.Sprintf("<li>%s</li>", rec)
    }
    return html
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func getScoreColor(score float64) string {
    if score >= 80 {
        return "#28a745"
    } else if score >= 60 {
        return "#ffc107"
    }
    return "#dc3545"
}

func generateControlRows(controls []ControlResult) string {
    html := ""
    for _, control := range controls {
        statusClass := "status-pass"
        statusText := "PASS"
        if control.Status == "FAIL" {
            statusClass = "status-fail"
            statusText = "FAIL"
        }
        
        severityBadge := ""
        if control.Severity != "" && control.Status == "FAIL" {
            severityClass := "severity-high"
            if control.Severity == "CRITICAL" {
                severityClass = "severity-critical"
            }
            severityBadge = fmt.Sprintf(" <span class='%s'>[%s]</span>", severityClass, control.Severity)
        }
        
        html += fmt.Sprintf(`<tr>
            <td><strong>%s</strong>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td><span class="%s">%s</span></td>
            <td>%s</td>
        </tr>`,
            control.ID,
            severityBadge,
            control.Name, 
            control.Category,
            statusClass,
            statusText,
            control.Evidence)
    }
    return html
}

func generateReport(format, output string) {
    fmt.Println("Generating audit report from last scan...")
    fmt.Println("Note: This feature requires cached scan results (not yet implemented)")
}

func runRemediation(provider, profile string) {
    fmt.Printf("🔧 Running automated remediation for %s...\n", provider)
    fmt.Println("Note: Automated remediation coming in v0.2.0")
    fmt.Println("\nFor now, run the scan and follow the remediation commands provided")
}
