// /home/dijital/Documents/auditkit/scanner/cmd/auditkit/main.go
package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"
    
    awsScanner "github.com/guardian-nexus/auditkit/scanner/pkg/aws"
    "github.com/guardian-nexus/auditkit/scanner/pkg/report"
    "github.com/guardian-nexus/auditkit/scanner/pkg/tracker"
    "github.com/guardian-nexus/auditkit/scanner/pkg/telemetry"
    "github.com/guardian-nexus/auditkit/scanner/pkg/updater"
    "github.com/guardian-nexus/auditkit/scanner/pkg/remediation"
)

const CurrentVersion = "v0.3.0"

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
    ID              string `json:"id"`
    Name            string `json:"name"`
    Category        string `json:"category"`
    Severity        string `json:"severity,omitempty"`
    Status          string `json:"status"` // PASS, FAIL, NOT_APPLICABLE
    Evidence        string `json:"evidence"`
    Remediation     string `json:"remediation,omitempty"`
    RemediationDetail string `json:"remediation_detail,omitempty"`
    Priority        string `json:"priority,omitempty"`
    Impact          string `json:"impact,omitempty"`
    ScreenshotGuide string `json:"screenshot_guide,omitempty"`
    ConsoleURL      string `json:"console_url,omitempty"`
}

type ProgressData struct {
    AccountID    string            `json:"account_id"`
    LastScan     time.Time        `json:"last_scan"`
    FirstScan    time.Time        `json:"first_scan"`
    ScanCount    int              `json:"scan_count"`
    ScoreHistory []ScorePoint     `json:"score_history"`
    FixedIssues  map[string]bool  `json:"fixed_issues"`
}

type ScorePoint struct {
    Date  time.Time `json:"date"`
    Score float64   `json:"score"`
}

func main() {
    var (
        provider = flag.String("provider", "aws", "Cloud provider (aws, azure, gcp)")
        profile  = flag.String("profile", "default", "AWS profile to use")
        format   = flag.String("format", "text", "Output format (text, json, html, pdf)")
        output   = flag.String("output", "", "Output file (default: stdout)")
        verbose  = flag.Bool("verbose", false, "Verbose output")
        services = flag.String("services", "all", "Comma-separated services to scan (s3,iam,ec2,rds,cloudtrail)")
    )

    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    command := os.Args[1]

    flag.CommandLine.Parse(os.Args[2:])

    switch command {
    case "scan":
        runScan(*provider, *profile, *format, *output, *verbose, *services)
    case "report":
        generateReport(*format, *output)
    case "evidence":
        runEvidenceTracker(*provider, *profile, *output)
    case "fix":
        generateFixScript(*profile, *output)
    case "progress":
        showProgress(*profile)
    case "compare":
        compareScan(*profile)
    case "update":
        updater.CheckForUpdates()
    case "version":
        fmt.Printf("AuditKit %s - SOC2 compliance scanning with evidence collection\n", CurrentVersion)
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
  auditkit evidence [options] Track evidence collection progress
  auditkit fix [options]      Generate remediation script
  auditkit progress          Show compliance improvement over time
  auditkit compare           Compare last two scans
  auditkit update            Check for updates
  auditkit version           Show version

Options:
  -provider string   Cloud provider (aws, azure, gcp) (default "aws")
  -profile string    AWS profile to use (default "default")
  -format string     Output format (text, json, html, pdf) (default "text")
  -output string     Output file (default: stdout)
  -services string   Services to scan (default "all")
  -verbose          Verbose output

Examples:
  # Quick scan with text output
  auditkit scan

  # Generate PDF report with evidence checklist
  auditkit scan -format pdf -output soc2-report.pdf

  # Generate fix script
  auditkit fix -output fixes.sh

  # Show progress over time
  auditkit progress

  # Compare improvements
  auditkit compare

For more information: https://github.com/guardian-nexus/auditkit`)
}

func runScan(provider, profile, format, output string, verbose bool, services string) {
    startTime := time.Now()
    
    if verbose {
        fmt.Fprintf(os.Stderr, "🔍 Starting %s compliance scan with profile %s...\n", provider, profile)
    }

    result := performScan(provider, profile, verbose, services)
    
    // Track scan duration
    duration := time.Since(startTime)
    
    // Save progress for tracking
    saveProgress(result.AccountID, result.Score, result.Controls)
    
    // Send telemetry if opted in
    telemetry.SendTelemetry(result.AccountID, result.Score, convertToTelemetryControls(result.Controls), duration)
    
    // Success celebration for high scores
    if result.Score >= 90 {
        fmt.Printf("\n🎉 CONGRATULATIONS! %.1f%% compliance!\n", result.Score)
        fmt.Println("\nShare your success:")
        fmt.Printf("  Post on X: https://x.com/intent/tweet?text=Just%%20hit%%20%.0f%%%%20SOC2%%20compliance%%20using%%20AuditKit!%%20Free%%20tool:%%20github.com/guardian-nexus/auditkit\n", result.Score)
        fmt.Println("  Star us: https://github.com/guardian-nexus/auditkit")
    } else if result.Score >= 70 {
        fmt.Printf("\n👍 Getting there! %.1f%% compliance.\n", result.Score)
        fmt.Println("Run 'auditkit compare' to see your progress over time.")
    }
    
    switch format {
    case "text":
        if output == "" {
            printTextSummary(result)
        } else {
            outputTextToFile(result, output)
        }
    case "pdf":
        // Convert to report.ComplianceResult for PDF generation
        pdfResult := report.ComplianceResult{
            Timestamp:       result.Timestamp,
            Provider:        result.Provider,
            AccountID:       result.AccountID,
            Score:           result.Score,
            TotalControls:   result.TotalControls,
            PassedControls:  result.PassedControls,
            FailedControls:  result.FailedControls,
            Controls:        convertControlsForPDF(result.Controls),
            Recommendations: result.Recommendations,
        }
        
        if output == "" {
            output = fmt.Sprintf("auditkit-report-%s.pdf", time.Now().Format("2006-01-02-150405"))
        }
        
        err := report.GeneratePDF(pdfResult, output)
        if err != nil {
            fmt.Fprintf(os.Stderr, "❌ Error generating PDF: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("✅ PDF report saved to %s\n", output)
        fmt.Printf("📸 Review failed controls for screenshot requirements\n")
    case "json":
        outputJSON(result, output)
    case "html":
        outputHTML(result, output)
    default:
        fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
        os.Exit(1)
    }
}

func saveProgress(accountID string, score float64, controls []ControlResult) error {
    homeDir, _ := os.UserHomeDir()
    dataPath := filepath.Join(homeDir, ".auditkit", accountID + ".json")
    
    // Create directory
    os.MkdirAll(filepath.Dir(dataPath), 0755)
    
    // Load existing or create new
    var progress ProgressData
    if data, err := os.ReadFile(dataPath); err == nil {
        json.Unmarshal(data, &progress)
    } else {
        progress = ProgressData{
            AccountID:    accountID,
            FirstScan:    time.Now(),
            FixedIssues:  make(map[string]bool),
            ScoreHistory: []ScorePoint{},
        }
    }
    
    // Update progress
    progress.LastScan = time.Now()
    progress.ScanCount++
    progress.ScoreHistory = append(progress.ScoreHistory, ScorePoint{
        Date:  time.Now(),
        Score: score,
    })
    
    // Track what's been fixed
    for _, control := range controls {
        if control.Status == "PASS" {
            progress.FixedIssues[control.ID] = true
        }
    }
    
    // Save
    data, _ := json.MarshalIndent(progress, "", "  ")
    return os.WriteFile(dataPath, data, 0644)
}

func showProgress(profile string) {
    // Get account ID first
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        return
    }
    
    ctx := context.Background()
    accountID := scanner.GetAccountID(ctx)
    
    homeDir, _ := os.UserHomeDir()
    dataPath := filepath.Join(homeDir, ".auditkit", accountID + ".json")
    
    data, err := os.ReadFile(dataPath)
    if err != nil {
        fmt.Println("No previous scans found. Run 'auditkit scan' first!")
        return
    }
    
    var progress ProgressData
    json.Unmarshal(data, &progress)
    
    fmt.Println("\n📊 Your SOC2 Journey Progress")
    fmt.Println("==============================")
    fmt.Printf("Account: %s\n", progress.AccountID)
    fmt.Printf("First scan: %s\n", progress.FirstScan.Format("Jan 2, 2006"))
    fmt.Printf("Total scans: %d\n", progress.ScanCount)
    fmt.Printf("Issues fixed: %d\n", len(progress.FixedIssues))
    
    if len(progress.ScoreHistory) > 1 {
        first := progress.ScoreHistory[0].Score
        last := progress.ScoreHistory[len(progress.ScoreHistory)-1].Score
        improvement := last - first
        
        if improvement > 0 {
            fmt.Printf("Score improvement: +%.1f%% (%.1f%% → %.1f%%)\n", improvement, first, last)
        }
        
        // Show trend
        fmt.Println("\nScore Trend:")
        startIdx := 0
        if len(progress.ScoreHistory) > 5 {
            startIdx = len(progress.ScoreHistory) - 5
        }
        for _, point := range progress.ScoreHistory[startIdx:] {
            bars := int(point.Score / 5)
            barString := strings.Repeat("█", bars)
            fmt.Printf("%s: %s %.1f%%\n", 
                point.Date.Format("Jan 02"),
                barString,
                point.Score)
        }
    }
    
    fmt.Println("\n💡 Tip: Run 'auditkit scan -format pdf' to generate evidence for your auditor")
}

func compareScan(profile string) {
    // Get account ID first
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        return
    }
    
    ctx := context.Background()
    accountID := scanner.GetAccountID(ctx)
    
    homeDir, _ := os.UserHomeDir()
    dataPath := filepath.Join(homeDir, ".auditkit", accountID + ".json")
    
    // Load history
    data, err := os.ReadFile(dataPath)
    if err != nil {
        fmt.Println("Need at least 2 scans to compare. Run 'auditkit scan' first!")
        return
    }
    
    var progress ProgressData
    json.Unmarshal(data, &progress)
    
    if len(progress.ScoreHistory) < 2 {
        fmt.Println("Need at least 2 scans to compare.")
        return
    }
    
    // Compare last two scans
    prev := progress.ScoreHistory[len(progress.ScoreHistory)-2]
    curr := progress.ScoreHistory[len(progress.ScoreHistory)-1]
    
    fmt.Println("\n📊 Compliance Progress Report")
    fmt.Println("============================")
    fmt.Printf("Previous: %.1f%% (%s)\n", prev.Score, prev.Date.Format("Jan 2, 3:04 PM"))
    fmt.Printf("Current:  %.1f%% (%s)\n", curr.Score, curr.Date.Format("Jan 2, 3:04 PM"))
    
    improvement := curr.Score - prev.Score
    if improvement > 0 {
        fmt.Printf("\n✅ Improved by %.1f%%!\n", improvement)
    } else if improvement < 0 {
        fmt.Printf("\n⚠️  Declined by %.1f%%\n", -improvement)
    } else {
        fmt.Println("\n➡️  No change")
    }
    
    // Show what changed
    fmt.Println("\nTo see what changed, run:")
    fmt.Println("  auditkit scan -verbose")
}

func generateFixScript(profile, output string) {
    fmt.Println("🔧 Generating remediation script...")
    
    // Get account ID and run scan
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        return
    }
    
    ctx := context.Background()
    accountID := scanner.GetAccountID(ctx)
    
    fmt.Printf("Scanning AWS Account %s to identify fixes...\n", accountID)
    
    services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
    scanResults, _ := scanner.ScanServices(ctx, services, false)
    
    // Convert to ControlResult format
    var controls []remediation.ControlResult
    for _, result := range scanResults {
        controls = append(controls, remediation.ControlResult{
            Control:           result.Control,
            Status:            result.Status,
            Severity:          result.Severity,
            RemediationDetail: result.RemediationDetail,
        })
    }
    
    if output == "" {
        output = "auditkit-fixes.sh"
    }
    
    err = remediation.GenerateFixScript(controls, output)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating fix script: %v\n", err)
        return
    }
    
    fmt.Printf("✅ Fix script generated: %s\n", output)
    fmt.Println("⚠️  REVIEW CAREFULLY before running!")
    fmt.Printf("   chmod +x %s\n", output)
    fmt.Printf("   ./%s\n", output)
}

func convertToTelemetryControls(controls []ControlResult) []telemetry.ControlResult {
    var result []telemetry.ControlResult
    for _, c := range controls {
        result = append(result, telemetry.ControlResult{
            ID:       c.ID,
            Status:   c.Status,
            Severity: c.Severity,
        })
    }
    return result
}

func performScan(provider, profile string, verbose bool, services string) ComplianceResult {
    // Check for non-AWS providers FIRST, before trying AWS initialization
    if provider != "aws" {
        return mockScan(provider)
    }
    
    // Now safe to initialize AWS scanner since we know provider == "aws"
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Error initializing AWS scanner: %v\n", err)
        fmt.Fprintf(os.Stderr, "\nMake sure you have AWS credentials configured:\n")
        fmt.Fprintf(os.Stderr, "  aws configure --profile %s\n", profile)
        os.Exit(1)
    }
    
    // Get account ID
    ctx := context.Background()
    accountID := scanner.GetAccountID(ctx)
    
    if verbose {
        fmt.Fprintf(os.Stderr, "📊 Scanning AWS Account: %s\n", accountID)
    }
    
    // Parse services to scan
    serviceList := strings.Split(services, ",")
    if services == "all" {
        serviceList = []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
    }
    
    scanResults, err := scanner.ScanServices(ctx, serviceList, verbose)
    if err != nil {
        fmt.Fprintf(os.Stderr, "⚠️  Warning during scan: %v\n", err)
    }
    
    // Convert to ComplianceResult format with prioritization
    controls := []ControlResult{}
    passed := 0
    failed := 0
    critical := 0
    high := 0
    
    for _, result := range scanResults {
        priority, impact := getPriorityAndImpact(result.Control, result.Severity, result.Status)
        
        control := ControlResult{
            ID:              result.Control,
            Name:            getControlName(result.Control),
            Category:        getControlCategory(result.Control),
            Severity:        result.Severity,
            Status:          result.Status,
            Evidence:        result.Evidence,
            Remediation:     result.Remediation,
            RemediationDetail: result.RemediationDetail,
            Priority:        priority,
            Impact:          impact,
            ScreenshotGuide: result.ScreenshotGuide,
            ConsoleURL:      result.ConsoleURL,
        }
        controls = append(controls, control)
        
        if result.Status == "PASS" {
            passed++
        } else {
            failed++
            if result.Severity == "CRITICAL" {
                critical++
            } else if result.Severity == "HIGH" {
                high++
            }
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
        Recommendations: generatePrioritizedRecommendations(controls, critical, high),
    }
}

func runEvidenceTracker(provider, profile, output string) {
    fmt.Println("📸 Generating evidence collection tracker...")
    
    // Get account ID and run scan
    scanner, err := awsScanner.NewScanner(profile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        return
    }
    
    ctx := context.Background()
    accountID := scanner.GetAccountID(ctx)
    
    fmt.Printf("Scanning AWS Account %s...\n", accountID)
    
    services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
    scanResults, _ := scanner.ScanServices(ctx, services, false)
    
    // Convert to tracker.ControlResult format
    // Note: Using the actual field names from the tracker package
    var controls []tracker.ControlResult
    for _, result := range scanResults {
        controls = append(controls, tracker.ControlResult{
            Control: result.Control,
            Status:  result.Status,
        })
    }
    
    // Generate a simple HTML evidence tracker since GenerateEvidenceTracker doesn't exist
    if output == "" {
        output = "evidence-tracker.html"
    }
    
    // Create a simple HTML evidence tracker
    html := generateEvidenceTrackerHTML(controls, accountID)
    err = os.WriteFile(output, []byte(html), 0644)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating tracker: %v\n", err)
        return
    }
    
    fmt.Printf("✅ Evidence tracker saved to %s\n", output)
    fmt.Println("📋 Open this file in your browser and check off evidence as you collect it!")
}

func generateEvidenceTrackerHTML(controls []tracker.ControlResult, accountID string) string {
    html := `<!DOCTYPE html>
<html>
<head>
    <title>AuditKit Evidence Tracker</title>
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
            max-width: 800px;
            margin: 0 auto;
        }
        h1 { color: #0366d6; }
        .control {
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #e1e4e8;
            border-radius: 4px;
        }
        .pass { background: #d4f4dd; }
        .fail { background: #fdd; }
        input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.5);
        }
        label {
            display: flex;
            align-items: center;
            cursor: pointer;
        }
        .status {
            margin-left: auto;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-pass { background: #28a745; color: white; }
        .status-fail { background: #dc3545; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📸 Evidence Collection Tracker</h1>
        <p>AWS Account: ` + accountID + `</p>
        <p>Check off each control as you collect the screenshot evidence:</p>
        `
    
    for _, control := range controls {
        class := "pass"
        statusClass := "status-pass"
        statusText := "PASS"
        if control.Status == "FAIL" {
            class = "fail"
            statusClass = "status-fail"
            statusText = "FAIL"
        }
        
        html += fmt.Sprintf(`
        <div class="control %s">
            <label>
                <input type="checkbox" onclick="this.parentElement.style.textDecoration = this.checked ? 'line-through' : 'none'">
                %s - %s
                <span class="status %s">%s</span>
            </label>
        </div>`, class, control.Control, getControlName(control.Control), statusClass, statusText)
    }
    
    html += `
        <script>
            // Save checkbox states to localStorage
            const checkboxes = document.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach((cb, index) => {
                const key = 'evidence_' + index;
                if (localStorage.getItem(key) === 'true') {
                    cb.checked = true;
                    cb.parentElement.style.textDecoration = 'line-through';
                }
                cb.addEventListener('change', () => {
                    localStorage.setItem(key, cb.checked);
                });
            });
        </script>
    </div>
</body>
</html>`
    return html
}

func getPriorityAndImpact(controlID, severity, status string) (string, string) {
    if status == "PASS" {
        return "✅ PASSED", "Control is properly configured"
    }
    
    // Define critical controls that will fail audit
    criticalControls := map[string]bool{
        "CC6.6": true,  // Root MFA
        "CC6.2": true,  // Public S3 buckets
        "CC6.1": true,  // Open security groups
    }
    
    if criticalControls[controlID] && severity == "CRITICAL" {
        return "🔥 CRITICAL", "AUDIT BLOCKER - Fix immediately or fail SOC2"
    } else if severity == "HIGH" {
        return "⚠️ HIGH", "Major finding - Auditor will flag this"
    } else if severity == "MEDIUM" {
        return "📋 MEDIUM", "Should fix - Makes audit smoother"
    } else {
        return "💡 LOW", "Nice to have - Strengthens posture"
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
    
    // Count critical issues
    criticalCount := 0
    highCount := 0
    for _, control := range result.Controls {
        if control.Status == "FAIL" {
            if strings.Contains(control.Priority, "CRITICAL") {
                criticalCount++
            } else if strings.Contains(control.Priority, "HIGH") {
                highCount++
            }
        }
    }
    
    if criticalCount > 0 {
        fmt.Printf("\033[31m🔥 Critical Issues: %d (FIX IMMEDIATELY)\033[0m\n", criticalCount)
    }
    if highCount > 0 {
        fmt.Printf("\033[33m⚠️  High Priority: %d\033[0m\n", highCount)
    }
    fmt.Printf("\n")
    
    // Show failures first, grouped by priority
    if result.FailedControls > 0 {
        // Critical failures
        hasCritical := false
        for _, control := range result.Controls {
            if control.Status == "FAIL" && strings.Contains(control.Priority, "CRITICAL") {
                if !hasCritical {
                    fmt.Printf("\033[31m🔥 CRITICAL - Fix These NOW or Fail SOC2:\033[0m\n")
                    fmt.Printf("----------------------------------------\n")
                    hasCritical = true
                }
                fmt.Printf("\033[31m[%s]\033[0m %s - %s\n", control.Severity, control.ID, control.Name)
                fmt.Printf("  Issue: %s\n", control.Evidence)
                fmt.Printf("  Impact: %s\n", control.Impact)
                if control.Remediation != "" {
                    // Shorten long remediation commands for terminal
                    remediation := control.Remediation
                    if len(remediation) > 100 {
                        remediation = "See PDF report for full command"
                    }
                    fmt.Printf("  Fix: %s\n", remediation)
                }
                fmt.Printf("\n")
            }
        }
        
        // High priority failures
        hasHigh := false
        for _, control := range result.Controls {
            if control.Status == "FAIL" && strings.Contains(control.Priority, "HIGH") {
                if !hasHigh {
                    fmt.Printf("\033[33m⚠️ HIGH Priority Issues:\033[0m\n")
                    fmt.Printf("------------------------\n")
                    hasHigh = true
                }
                fmt.Printf("\033[33m[%s]\033[0m %s - %s\n", control.Severity, control.ID, control.Name)
                fmt.Printf("  Issue: %s\n", control.Evidence)
                if control.Remediation != "" {
                    remediation := control.Remediation
                    if len(remediation) > 100 {
                        remediation = "See PDF report for full command"
                    }
                    fmt.Printf("  Fix: %s\n", remediation)
                }
                fmt.Printf("\n")
            }
        }
        
        // Other failures
        hasOther := false
        for _, control := range result.Controls {
            if control.Status == "FAIL" && !strings.Contains(control.Priority, "CRITICAL") && !strings.Contains(control.Priority, "HIGH") {
                if !hasOther {
                    fmt.Printf("📋 Other Issues:\n")
                    fmt.Printf("----------------\n")
                    hasOther = true
                }
                fmt.Printf("[%s] %s - %s: %s\n", control.Severity, control.ID, control.Name, control.Evidence)
            }
        }
    }
    
    // Show passes (condensed)
    fmt.Printf("\n\033[32m✅ Passed Controls:\033[0m\n")
    fmt.Printf("-------------------\n")
    for _, control := range result.Controls {
        if control.Status == "PASS" {
            fmt.Printf("  • %s - %s: %s\n", control.ID, control.Name, control.Evidence)
        }
    }
    
    // Recommendations
    if len(result.Recommendations) > 0 {
        fmt.Printf("\n📋 Priority Action Items:\n")
        fmt.Printf("-------------------------\n")
        for i, rec := range result.Recommendations {
            if i >= 5 { // Only show top 5
                break
            }
            fmt.Printf("  %d. %s\n", i+1, rec)
        }
    }
    
    fmt.Printf("\n")
    fmt.Printf("📄 For detailed report with evidence checklist:\n")
    fmt.Printf("   auditkit scan -format pdf -output report.pdf\n")
    fmt.Printf("\n")
}

func getControlName(controlID string) string {
    controlNames := map[string]string{
        "CC6.1": "Logical and Physical Access Controls",
        "CC6.2": "Network Security - S3 Public Access",
        "CC6.3": "Encryption at Rest",
        "CC6.6": "Root Account MFA",
        "CC6.7": "Password Policy",
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

func generatePrioritizedRecommendations(controls []ControlResult, criticalCount, highCount int) []string {
    recs := []string{}
    
    // Start with impact summary
    if criticalCount > 0 {
        recs = append(recs, fmt.Sprintf("🔥 URGENT: Fix %d CRITICAL issues immediately - these WILL fail your audit", criticalCount))
    }
    
    // Analyze specific failures
    hasPublicS3 := false
    hasNoMFA := false
    hasOpenPorts := false
    hasOldKeys := false
    hasNoLogging := false
    hasNoEncryption := false
    
    for _, control := range controls {
        if control.Status == "FAIL" {
            switch control.ID {
            case "CC6.2":
                hasPublicS3 = true
            case "CC6.6":
                hasNoMFA = true
            case "CC6.1":
                hasOpenPorts = true
            case "CC6.8":
                hasOldKeys = true
            case "CC7.1":
                hasNoLogging = true
            case "CC6.3":
                hasNoEncryption = true
            }
        }
    }
    
    // Priority recommendations based on what will fail audit
    if hasNoMFA {
        recs = append(recs, "🔥 CRITICAL: Enable MFA for root account TODAY - auditors check this first")
    }
    if hasPublicS3 {
        recs = append(recs, "🔥 CRITICAL: Block public access on S3 buckets - data exposure = instant fail")
    }
    if hasOpenPorts {
        recs = append(recs, "⚠️ HIGH: Close ports 22/3389/3306 from 0.0.0.0/0 - major security finding")
    }
    if hasOldKeys {
        recs = append(recs, "⚠️ HIGH: Rotate access keys older than 90 days - compliance requirement")
    }
    if hasNoLogging {
        recs = append(recs, "⚠️ HIGH: Enable CloudTrail in all regions - audit trail required")
    }
    if hasNoEncryption {
        recs = append(recs, "📋 MEDIUM: Enable encryption on all S3 buckets - best practice")
    }
    
    // General recommendations
    recs = append(recs, "Enable AWS Config for continuous compliance monitoring")
    recs = append(recs, "Document your security policies and procedures")
    recs = append(recs, "Set up automated alerting for security events")
    recs = append(recs, "Schedule quarterly access reviews")
    
    return recs
}

func convertControlsForPDF(controls []ControlResult) []report.ControlResult {
    pdfControls := []report.ControlResult{}
    for _, c := range controls {
        pdfControls = append(pdfControls, report.ControlResult{
            ID:              c.ID,
            Name:            c.Name,
            Category:        c.Category,
            Severity:        c.Severity,
            Status:          c.Status,
            Evidence:        c.Evidence,
            Remediation:     c.Remediation,
            ScreenshotGuide: c.ScreenshotGuide,
            ConsoleURL:      c.ConsoleURL,
        })
    }
    return pdfControls
}

func outputTextToFile(result ComplianceResult, output string) {
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
            sb.WriteString(fmt.Sprintf("\n%s [%s] %s - %s\n", control.Priority, control.Severity, control.ID, control.Name))
            sb.WriteString(fmt.Sprintf("  Issue: %s\n", control.Evidence))
            sb.WriteString(fmt.Sprintf("  Impact: %s\n", control.Impact))
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
    
    err := os.WriteFile(output, []byte(sb.String()), 0644)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("✅ Report saved to %s\n", output)
}

func outputJSON(result ComplianceResult, output string) {
    data, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
        os.Exit(1)
    }
    
    if output != "" {
        err = os.WriteFile(output, data, 0644)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("✅ JSON report saved to %s\n", output)
    } else {
        fmt.Print(string(data))
    }
}

func outputHTML(result ComplianceResult, output string) {
    html := generateHTML(result)
    
    if output != "" {
        err := os.WriteFile(output, []byte(html), 0644)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("✅ HTML report saved to %s\n", output)
    } else {
        fmt.Print(html)
    }
}

func generateHTML(result ComplianceResult) string {
    scoreColor := getScoreColor(result.Score)
    
    return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>AuditKit SOC2 Compliance Report</title>
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
            max-width: 1200px;
            margin: 0 auto;
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
        .subtitle {
            color: #586069;
            margin-top: 5px;
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
            text-align: center;
        }
        .score-label {
            font-size: 14px;
            color: #586069;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-align: center;
        }
        .stats {
            display: flex;
            gap: 40px;
            margin: 30px 0;
            justify-content: center;
        }
        .stat {
            text-align: center;
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
            margin-top: 5px;
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .critical-alert {
            background: #fee;
            border: 2px solid #dc3545;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
        }
        .critical-alert h3 {
            color: #dc3545;
            margin: 0 0 10px 0;
        }
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
        .priority-critical {
            color: #dc3545;
            font-weight: bold;
        }
        .priority-high {
            color: #f0ad4e;
            font-weight: bold;
        }
        .priority-medium {
            color: #0366d6;
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
        .evidence-note {
            background: #fff9c4;
            border: 1px solid #fbc02d;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">AuditKit</div>
            <div class="subtitle">SOC2 Compliance Report</div>
            <div class="account-info">AWS Account: %s | Generated: %s</div>
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
        
        %s
        
        <div class="evidence-note">
            <strong>📸 Evidence Collection Required:</strong> For each failed control below, you need to collect screenshots after fixing the issue. 
            Generate a PDF report for a complete evidence checklist: <code>auditkit scan -format pdf</code>
        </div>
        
        <h2 style="margin-top: 40px;">Control Status Details</h2>
        <table>
            <tr>
                <th>Priority</th>
                <th>Control</th>
                <th>Name</th>
                <th>Status</th>
                <th>Evidence/Issue</th>
                <th>Impact</th>
            </tr>
            %s
        </table>
        
        <div class="recommendations">
            <h3>Priority Action Items</h3>
            <ol>
            %s
            </ol>
        </div>
        
        <div class="footer">
            <p>Generated by AuditKit on %s</p>
            <p>Open source SOC2 compliance scanning that actually works</p>
            <p><a href="https://auditkit.io" style="color: #0366d6;">auditkit.io</a> | <a href="https://github.com/guardian-nexus/auditkit" style="color: #0366d6;">GitHub</a></p>
        </div>
    </div>
</body>
</html>`,
        scoreColor,
        result.AccountID,
        result.Timestamp.Format("January 2, 2006 at 3:04 PM"),
        result.Score,
        result.PassedControls,
        result.FailedControls,
        result.TotalControls,
        generateCriticalAlert(result.Controls),
        generateControlRows(result.Controls),
        generateRecommendationHTML(result.Recommendations),
        result.Timestamp.Format("January 2, 2006 at 3:04 PM"))
}

func generateCriticalAlert(controls []ControlResult) string {
    criticalIssues := []string{}
    for _, control := range controls {
        if control.Status == "FAIL" && strings.Contains(control.Priority, "CRITICAL") {
            criticalIssues = append(criticalIssues, fmt.Sprintf("<li><strong>%s</strong>: %s</li>", control.Name, control.Evidence))
        }
    }
    
    if len(criticalIssues) > 0 {
        return fmt.Sprintf(`
        <div class="critical-alert">
            <h3>🔥 CRITICAL ISSUES - Fix These Immediately!</h3>
            <p>These issues WILL cause your SOC2 audit to fail:</p>
            <ul>%s</ul>
        </div>`, strings.Join(criticalIssues, ""))
    }
    return ""
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
        
        priorityClass := ""
        if strings.Contains(control.Priority, "CRITICAL") {
            priorityClass = "priority-critical"
        } else if strings.Contains(control.Priority, "HIGH") {
            priorityClass = "priority-high"
        } else if strings.Contains(control.Priority, "MEDIUM") {
            priorityClass = "priority-medium"
        }
        
        html += fmt.Sprintf(`<tr>
            <td><span class="%s">%s</span></td>
            <td><strong>%s</strong></td>
            <td>%s</td>
            <td><span class="%s">%s</span></td>
            <td>%s</td>
            <td style="font-size: 12px; color: #586069;">%s</td>
        </tr>`,
            priorityClass,
            control.Priority,
            control.ID,
            control.Name,
            statusClass,
            statusText,
            control.Evidence,
            control.Impact)
    }
    return html
}

func generateRecommendationHTML(recommendations []string) string {
    html := ""
    for _, rec := range recommendations[:min(7, len(recommendations))] {
        style := ""
        if strings.Contains(rec, "CRITICAL") || strings.Contains(rec, "🔥") {
            style = ` style="color: #dc3545; font-weight: bold;"`
        } else if strings.Contains(rec, "HIGH") || strings.Contains(rec, "⚠️") {
            style = ` style="color: #f0ad4e;"`
        }
        html += fmt.Sprintf("<li%s>%s</li>", style, rec)
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

func mockScan(provider string) ComplianceResult {
    fmt.Fprintf(os.Stderr, "⚠️  %s provider not yet implemented, showing sample data\n", provider)
    
    controls := []ControlResult{
        {
            ID:       "CC6.1",
            Name:     "Logical Access Controls",
            Category: "Security",
            Status:   "PASS",
            Evidence: "Sample: MFA enabled, password policy configured",
            Priority: "✅ PASSED",
            Impact:   "Control is properly configured",
        },
        {
            ID:          "CC6.2",
            Name:        "Network Security",
            Category:    "Security",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "Sample: Security group allows unrestricted access",
            Remediation: "Restrict security group rules",
            Priority:    "⚠️ HIGH",
            Impact:      "Major finding - Auditor will flag this",
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

func generateReport(format, output string) {
    fmt.Println("Generating audit report from last scan...")
    fmt.Println("Note: This feature requires cached scan results (not yet implemented)")
    fmt.Println("For now, run: auditkit scan -format pdf")
}
