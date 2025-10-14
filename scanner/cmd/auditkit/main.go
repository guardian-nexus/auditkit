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
	azureScanner "github.com/guardian-nexus/auditkit/scanner/pkg/azure"
	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations"
	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations/scubagear"
	"github.com/guardian-nexus/auditkit/scanner/pkg/remediation"
	"github.com/guardian-nexus/auditkit/scanner/pkg/report"
	"github.com/guardian-nexus/auditkit/scanner/pkg/tracker"
	"github.com/guardian-nexus/auditkit/scanner/pkg/updater"
	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
)

const CurrentVersion = "v0.6.8"

type ComplianceResult struct {
	Timestamp       time.Time       `json:"timestamp"`
	Provider        string          `json:"provider"`
	Framework       string          `json:"framework"`
	AccountID       string          `json:"account_id,omitempty"`
	Score           float64         `json:"score"`
	TotalControls   int             `json:"total_controls"`
	PassedControls  int             `json:"passed_controls"`
	FailedControls  int             `json:"failed_controls"`
	Controls        []ControlResult `json:"controls"`
	Recommendations []string        `json:"recommendations"`
}

type ControlResult struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Severity          string            `json:"severity,omitempty"`
	Status            string            `json:"status"`
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Priority          string            `json:"priority,omitempty"`
	Impact            string            `json:"impact,omitempty"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

type ProgressData struct {
	AccountID    string          `json:"account_id"`
	LastScan     time.Time       `json:"last_scan"`
	FirstScan    time.Time       `json:"first_scan"`
	ScanCount    int             `json:"scan_count"`
	ScoreHistory []ScorePoint    `json:"score_history"`
	FixedIssues  map[string]bool `json:"fixed_issues"`
}

type ScorePoint struct {
	Date      time.Time `json:"date"`
	Score     float64   `json:"score"`
	Framework string    `json:"framework"`
}

func main() {
	var (
		provider  = flag.String("provider", "aws", "Cloud provider: aws, azure (both with full SOC2/PCI support)")
		profile   = flag.String("profile", "default", "AWS profile or Azure subscription to use")
		framework = flag.String("framework", "all", "Compliance framework: soc2, pci, cmmc, hipaa (limited), all")
		format    = flag.String("format", "text", "Output format (text, json, html, pdf)")
		output    = flag.String("output", "", "Output file (default: stdout)")
		verbose   = flag.Bool("verbose", false, "Verbose output")
		full      = flag.Bool("full", false, "Show all controls in text output (default: truncated for readability)")
		services  = flag.String("services", "all", "Comma-separated services to scan")
		source    = flag.String("source", "", "Integration source: scubagear, prowler")
		file      = flag.String("file", "", "Integration file to parse")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	flag.CommandLine.Parse(os.Args[2:])

	switch command {
	case "scan":
		runScan(*provider, *profile, *framework, *format, *output, *verbose, *full, *services)
	case "integrate":
		runIntegration(*source, *file, *format, *output, *verbose)
	case "report":
		generateReport(*format, *output)
	case "evidence":
		runEvidenceTracker(*provider, *profile, *output)
	case "fix":
		generateFixScript(*provider, *profile, *output)
	case "progress":
		showProgress(*provider, *profile)
	case "compare":
		compareScan(*provider, *profile)
	case "update":
		updater.CheckForUpdates()
	case "version":
		fmt.Printf("AuditKit %s - Multi-cloud compliance scanning (AWS, Azure, M365)\n", CurrentVersion)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AuditKit - Multi-Cloud Compliance Scanner

Usage:
  auditkit scan [options]        Scan infrastructure for compliance
  auditkit integrate [options]   Import external tool results (ScubaGear, Prowler)
  auditkit report [options]      Generate audit-ready report
  auditkit evidence [options]    Track evidence collection progress
  auditkit fix [options]         Generate remediation script
  auditkit progress              Show compliance improvement over time
  auditkit compare               Compare last two scans
  auditkit update                Check for updates
  auditkit version               Show version

Options:
  -provider string   Cloud provider: aws, azure (default "aws")
  -profile string    AWS profile or Azure subscription (default "default")
  -framework string  Compliance framework: soc2, pci, cmmc, hipaa, 800-53, all (default "all")
  -format string     Output format (text, json, html, pdf) (default "text")
  -output string     Output file (default: stdout)
  -services string   Services to scan (default "all")
  -source string     Integration source: scubagear, prowler
  -file string       File to parse for integration
  -verbose          Verbose output
  -full             Show all controls in text output (default: truncated)

Frameworks:
  soc2    SOC2 Type II Common Criteria (full coverage)
  pci     PCI-DSS v4.0 (full coverage)
  cmmc    CMMC Level 1 (17 practices) & Level 2 (110 practices)
  hipaa   HIPAA Security Rule (experimental)
  800-53  NIST 800-53 Rev 5 (via framework crosswalk)
  all     Run all available frameworks

Integration Examples:
  # Import ScubaGear M365 results
  auditkit integrate -source scubagear -file ScubaResults.json

  # Generate unified PDF with M365 findings
  auditkit integrate -source scubagear -file ScubaResults.json -format pdf

Examples:
  # AWS SOC2 scan
  auditkit scan -provider aws -framework soc2

  # Azure PCI-DSS scan
  auditkit scan -provider azure -framework pci

  # NIST 800-53 scan
  auditkit scan -provider aws -framework 800-53

  # Generate PDF report
  auditkit scan -format pdf -output report.pdf
  
  # Show all controls (not truncated)
  auditkit scan -provider aws -framework cmmc --full

For more information: https://github.com/guardian-nexus/auditkit`)
}

func runIntegration(source, file, format, output string, verbose bool) {
	if source == "" || file == "" {
		fmt.Fprintf(os.Stderr, "Error: Both -source and -file are required for integration\n")
		fmt.Fprintf(os.Stderr, "Example: auditkit integrate -source scubagear -file ScubaResults.json\n")
		os.Exit(1)
	}

	ctx := context.Background()

	switch strings.ToLower(source) {
	case "scubagear":
		if verbose {
			fmt.Fprintf(os.Stderr, "Loading ScubaGear integration...\n")
		}

		mappingsDir := filepath.Join("mappings", "scubagear")
		
		if _, err := os.Stat(mappingsDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: ScubaGear mappings not found at %s\n", mappingsDir)
			fmt.Fprintf(os.Stderr, "Make sure entra.json exists in mappings/scubagear/\n")
			os.Exit(1)
		}

		integration := scubagear.NewScubaGearIntegration(mappingsDir)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Loading mappings from %s...\n", mappingsDir)
		}

		if err := integration.LoadMappings(); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading mappings: %v\n", err)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Parsing ScubaGear results from %s...\n", file)
		}

		results, err := integration.ParseFile(ctx, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ScubaGear file: %v\n", err)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Found %d M365 findings\n", len(results))
		}

		integrationResult := convertIntegrationResults(results, "M365")

		switch format {
		case "text":
			printIntegrationSummary(integrationResult)
		case "json":
			data, _ := json.MarshalIndent(integrationResult, "", "  ")
			if output != "" {
				os.WriteFile(output, data, 0644)
				fmt.Printf("Results saved to %s\n", output)
			} else {
				fmt.Println(string(data))
			}
		case "pdf":
			if output == "" {
				output = fmt.Sprintf("auditkit-m365-report-%s.pdf", time.Now().Format("2006-01-02-150405"))
			}
			pdfResult := report.ComplianceResult{
				Timestamp:       integrationResult.Timestamp,
				Provider:        integrationResult.Provider,
				AccountID:       integrationResult.AccountID,
				Score:           integrationResult.Score,
				TotalControls:   integrationResult.TotalControls,
				PassedControls:  integrationResult.PassedControls,
				FailedControls:  integrationResult.FailedControls,
				Controls:        convertControlsForPDF(integrationResult.Controls),
				Recommendations: integrationResult.Recommendations,
				Framework:       integrationResult.Framework,
			}
			err := report.GeneratePDF(pdfResult, output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("M365 compliance report saved to %s\n", output)
		default:
			fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
			os.Exit(1)
		}

	case "prowler":
		fmt.Fprintf(os.Stderr, "Prowler integration coming soon\n")
		fmt.Fprintf(os.Stderr, "For now, use native AWS/Azure scanning:\n")
		fmt.Fprintf(os.Stderr, "  auditkit scan -provider aws -framework soc2\n")
		os.Exit(1)

	default:
		fmt.Fprintf(os.Stderr, "Unknown integration source: %s\n", source)
		fmt.Fprintf(os.Stderr, "Supported sources: scubagear, prowler (coming soon)\n")
		os.Exit(1)
	}
}

func convertIntegrationResults(results []integrations.IntegrationResult, provider string) ComplianceResult {
	controls := []ControlResult{}
	passed := 0
	failed := 0

	for _, r := range results {
		control := ControlResult{
			ID:              r.RuleID,
			Name:            r.Title,
			Category:        r.Product,
			Severity:        getSeverityFromStatus(r.Status),
			Status:          r.Status,
			Evidence:        r.Evidence,
			Remediation:     r.Remediation,
			ScreenshotGuide: r.ScreenshotGuide,
			ConsoleURL:      r.ConsoleURL,
			Frameworks:      r.Frameworks,
		}

		controls = append(controls, control)

		if r.Status == "PASS" {
			passed++
		} else if r.Status == "FAIL" {
			failed++
		}
	}

	score := 0.0
	if len(controls) > 0 {
		score = float64(passed) / float64(len(controls)) * 100
	}

	return ComplianceResult{
		Timestamp:       time.Now(),
		Provider:        provider,
		Framework:       "soc2",
		AccountID:       "M365-tenant",
		Score:           score,
		TotalControls:   len(controls),
		PassedControls:  passed,
		FailedControls:  failed,
		Controls:        controls,
		Recommendations: generateIntegrationRecommendations(controls),
	}
}

func getSeverityFromStatus(status string) string {
	switch status {
	case "FAIL":
		return "HIGH"
	case "PASS":
		return "PASSED"
	default:
		return "MEDIUM"
	}
}

func generateIntegrationRecommendations(controls []ControlResult) []string {
	recs := []string{}
	failedCount := 0

	for _, c := range controls {
		if c.Status == "FAIL" {
			failedCount++
		}
	}

	if failedCount > 0 {
		recs = append(recs, fmt.Sprintf("Fix %d failed M365 security controls", failedCount))
	}

	recs = append(recs, "Review Microsoft Entra ID conditional access policies")
	recs = append(recs, "Ensure MFA is enforced for all users")
	recs = append(recs, "Configure identity protection policies")
	recs = append(recs, "Enable security defaults if not using conditional access")

	return recs
}

func printIntegrationSummary(result ComplianceResult) {
	fmt.Printf("\n")
	fmt.Printf("AuditKit M365 Integration Results\n")
	fmt.Printf("===================================\n")
	fmt.Printf("Provider: %s\n", result.Provider)
	fmt.Printf("Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")
	
	scoreColor := "\033[32m"
	if result.Score < 80 {
		scoreColor = "\033[33m"
	}
	if result.Score < 60 {
		scoreColor = "\033[31m"
	}
	fmt.Printf("Compliance Score: %s%.1f%%\033[0m\n", scoreColor, result.Score)
	fmt.Printf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls)
	fmt.Printf("\n")

	if result.FailedControls > 0 {
		fmt.Printf("\033[31mFailed M365 Controls:\033[0m\n")
		fmt.Printf("------------------------\n")
		for _, control := range result.Controls {
			if control.Status == "FAIL" {
				fmt.Printf("\033[31m[FAIL]\033[0m %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Issue: %s\n", control.Evidence)
				if control.Remediation != "" {
					fmt.Printf("  Fix: %s\n", control.Remediation)
				}
				if control.ConsoleURL != "" {
					fmt.Printf("  URL: %s\n", control.ConsoleURL)
				}
				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("\n\033[32mPassed Controls:\033[0m\n")
	fmt.Printf("-------------------\n")
	for _, control := range result.Controls {
		if control.Status == "PASS" {
			fmt.Printf("  - %s - %s\n", control.ID, control.Name)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Printf("\nRecommendations:\n")
		fmt.Printf("------------------\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}

	fmt.Printf("\nFor detailed report:\n")
	fmt.Printf("   auditkit integrate -source scubagear -file <file> -format pdf\n")
	fmt.Printf("\n")
}

func runScan(provider, profile, framework, format, output string, verbose bool, full bool, services string) {
	validFrameworks := map[string]bool{
		"soc2":       true,
		"pci":        true,
		"hipaa":      true,
		"cmmc":       true,
		"800-53":     true,
		"nist800-53": true,
		"all":        true,
	}

	if !validFrameworks[strings.ToLower(framework)] {
		fmt.Fprintf(os.Stderr, "Error: Invalid framework: %s\n", framework)
		fmt.Fprintf(os.Stderr, "Valid options: soc2, pci, cmmc (Level 1 only), hipaa, 800-53, all\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "CMMC Level 2 requires upgrade to Pro:\n")
		fmt.Fprintf(os.Stderr, "  Visit: https://auditkit.io/pro\n")
		fmt.Fprintf(os.Stderr, "  Email: sales@auditkit.io\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s compliance scan for %s...\n", 
			strings.ToUpper(framework), provider)
	}

	result := performScan(provider, profile, framework, verbose, services)

	saveProgress(result.AccountID, result.Score, result.Controls, framework)

	automatedChecks := result.PassedControls + result.FailedControls
	manualChecks := 0
	for _, control := range result.Controls {
		if control.Status == "INFO" {
			manualChecks++
		}
	}

	if result.Score >= 90 {
		fmt.Printf("\nCONGRATULATIONS! %.1f%% of automated checks passed!\n", result.Score)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  NOTE: %d additional manual controls require documentation.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to generate collection checklist.\n")
		}
		
		fmt.Println("\nShare your success:")
		fmt.Printf("  Post on X: https://x.com/intent/tweet?text=Just%%20hit%%20%.0f%%%%20automated%%20checks%%20using%%20AuditKit!%%20Free%%20tool:%%20github.com/guardian-nexus/auditkit\n", 
			result.Score)
		fmt.Println("  Star us: https://github.com/guardian-nexus/auditkit")
	} else if result.Score >= 70 {
		fmt.Printf("\nGetting there! %.1f%% of automated checks passed.\n", result.Score)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  NOTE: %d additional manual controls require documentation.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to generate collection checklist.\n")
		}
		
		fmt.Println("Run 'auditkit compare' to see your progress over time.")
	} else {
		fmt.Printf("\nAutomated Check Score: %.1f%% (%d/%d passed)\n", 
			result.Score, result.PassedControls, automatedChecks)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  IMPORTANT: Only %d of %d total controls are automated.\n", 
				automatedChecks, automatedChecks+manualChecks)
			fmt.Printf("   %d controls require manual documentation and evidence.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to track what you need to collect.\n")
		}
	}

	switch format {
	case "text":
		if output == "" {
			printTextSummary(result, full)
		} else {
			outputTextToFile(result, output)
		}
	case "pdf":
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
			Framework:       result.Framework,
		}

		if output == "" {
			output = fmt.Sprintf("auditkit-%s-%s-report-%s.pdf", 
				provider,
				strings.ToLower(framework), 
				time.Now().Format("2006-01-02-150405"))
		}

		err := report.GeneratePDF(pdfResult, output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PDF report saved to %s\n", output)
		fmt.Printf("Review failed controls for screenshot requirements\n")
	case "json":
		outputJSON(result, output)
	case "html":
		outputHTML(result, output)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
}

func performScan(provider, profile, framework string, verbose bool, services string) ComplianceResult {
	var scanResults []interface{}
	var accountID string
	
	ctx := context.Background()
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing AWS scanner: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nMake sure you have AWS credentials configured:\n")
			fmt.Fprintf(os.Stderr, "  aws configure --profile %s\n", profile)
			os.Exit(1)
		}
		
		accountID = scanner.GetAccountID(ctx)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning AWS Account: %s\n", accountID)
			fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
		}
		
		serviceList := strings.Split(services, ",")
		if services == "all" {
			serviceList = []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		}
		
		awsResults, err := scanner.ScanServices(ctx, serviceList, verbose, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during scan: %v\n", err)
		}
		
		for _, r := range awsResults {
			scanResults = append(scanResults, r)
		}
		
	case "azure":
		scanner, err := azureScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Azure scanner: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nMake sure you have Azure credentials configured:\n")
			fmt.Fprintf(os.Stderr, "  az login\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_SUBSCRIPTION_ID=<your-subscription-id>\n")
			fmt.Fprintf(os.Stderr, "\nOr use service principal:\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_CLIENT_ID=<client-id>\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_CLIENT_SECRET=<client-secret>\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_TENANT_ID=<tenant-id>\n")
			os.Exit(1)
		}
		
		accountID = scanner.GetAccountID(ctx)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning Azure Subscription: %s\n", accountID)
			fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
		}
		
		serviceList := strings.Split(services, ",")
		if services == "all" {
			serviceList = []string{"storage", "aad", "network", "compute", "sql"}
		}
		
		azureResults, err := scanner.ScanServices(ctx, serviceList, verbose, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during scan: %v\n", err)
		}
		
		for _, r := range azureResults {
			scanResults = append(scanResults, r)
		}
		
	case "gcp":
		fmt.Println("GCP support coming Q1 2026")
		fmt.Println("\nPlanned GCP checks:")
		fmt.Println("  - Cloud Storage bucket policies")
		fmt.Println("  - IAM & Service Account management")
		fmt.Println("  - VPC firewall rules")
		fmt.Println("  - Cloud KMS encryption")
		fmt.Println("\nGet notified: https://auditkit.substack.com")
		os.Exit(0)
		
	default:
		fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", provider)
		fmt.Fprintf(os.Stderr, "Supported providers: aws, azure\n")
		os.Exit(1)
	}
	
	// Convert scan results to ComplianceResult format
	controls := []ControlResult{}
	passed := 0
	failed := 0
	critical := 0
	high := 0
	
	// Load crosswalk once if needed for 800-53
	var crosswalk *mappings.Crosswalk
	var crosswalkErr error
	requestedUpper := strings.ToUpper(framework)
	if requestedUpper == "800-53" || requestedUpper == "NIST800-53" {
		crosswalk, crosswalkErr = mappings.GetCrosswalk()
		if crosswalkErr != nil && verbose {
			fmt.Fprintf(os.Stderr, "Warning: Could not load 800-53 crosswalk: %v\n", crosswalkErr)
		}
	}
	
	for _, result := range scanResults {
		var control ControlResult
		
		// Type assertion based on provider
		switch provider {
		case "aws":
			if awsResult, ok := result.(awsScanner.ScanResult); ok {
				priority, impact := getPriorityAndImpact(awsResult.Control, awsResult.Severity, awsResult.Status, framework)
				control = ControlResult{
					ID:                awsResult.Control,
					Name:              getControlName(awsResult.Control),
					Category:          getControlCategory(awsResult.Control),
					Severity:          awsResult.Severity,
					Status:            awsResult.Status,
					Evidence:          awsResult.Evidence,
					Remediation:       awsResult.Remediation,
					RemediationDetail: awsResult.RemediationDetail,
					Priority:          priority,
					Impact:            impact,
					ScreenshotGuide:   awsResult.ScreenshotGuide,
					ConsoleURL:        awsResult.ConsoleURL,
					Frameworks:        awsResult.Frameworks,
				}
			}
		case "azure":
			if azureResult, ok := result.(azureScanner.ScanResult); ok {
				priority, impact := getPriorityAndImpact(azureResult.Control, azureResult.Severity, azureResult.Status, framework)
				control = ControlResult{
					ID:                azureResult.Control,
					Name:              getControlName(azureResult.Control),
					Category:          getControlCategory(azureResult.Control),
					Severity:          azureResult.Severity,
					Status:            azureResult.Status,
					Evidence:          azureResult.Evidence,
					Remediation:       azureResult.Remediation,
					RemediationDetail: azureResult.RemediationDetail,
					Priority:          priority,
					Impact:            impact,
					ScreenshotGuide:   azureResult.ScreenshotGuide,
					ConsoleURL:        azureResult.ConsoleURL,
					Frameworks:        azureResult.Frameworks,
				}
			}
		}
		
		// Filter by framework if not "all"
		if framework != "all" {
			hasRequestedFramework := false

			// Special handling for 800-53 using crosswalk
			if (requestedUpper == "800-53" || requestedUpper == "NIST800-53") && crosswalk != nil {
				// Try to derive 800-53 IDs (works with OR without Frameworks map)
				nist80053IDs := crosswalk.Get800_53String(control.Frameworks, control.ID)
				
				if nist80053IDs != "" {
					hasRequestedFramework = true
					originalID := control.ID
					
					// Replace control ID with 800-53 IDs
					control.ID = nist80053IDs
					
					// Update control name to show source
					control.Name = fmt.Sprintf("%s (via %s)", control.Name, originalID)
					
					// Add to frameworks map
					if control.Frameworks == nil {
						control.Frameworks = make(map[string]string)
					}
					control.Frameworks["NIST800-53"] = nist80053IDs
					control.Frameworks["Source"] = originalID
					
					if verbose {
						fmt.Fprintf(os.Stderr, "✓ Mapped %s → %s\n", originalID, nist80053IDs)
					}
				}
			} else if control.Frameworks != nil && len(control.Frameworks) > 0 {
				// Standard framework matching for other frameworks (only if Frameworks exists)
				for fw := range control.Frameworks {
					fwUpper := strings.ToUpper(fw)
					if fwUpper == requestedUpper ||
						(requestedUpper == "PCI" && fwUpper == "PCI-DSS") ||
						(requestedUpper == "PCI-DSS" && fwUpper == "PCI") ||
						(requestedUpper == "SOC2" && fwUpper == "SOC2") ||
						(requestedUpper == "CMMC" && fwUpper == "CMMC") ||
						(requestedUpper == "HIPAA" && fwUpper == "HIPAA") {
						hasRequestedFramework = true
						break
					}
				}
			}

			if !hasRequestedFramework {
				continue
			}
		}

		controls = append(controls, control)
		
		if control.Status == "PASS" {
			passed++
		} else if control.Status == "FAIL" {
			failed++
			if control.Severity == "CRITICAL" {
				critical++
			} else if control.Severity == "HIGH" {
				high++
			}
		}
	}
	
	score := 0.0
	automatedChecks := passed + failed
	if automatedChecks > 0 {
		score = float64(passed) / float64(automatedChecks) * 100
	}
	
	return ComplianceResult{
		Timestamp:       time.Now(),
		Provider:        provider,
		Framework:       framework,
		AccountID:       accountID,
		Score:           score,
		TotalControls:   len(controls),
		PassedControls:  passed,
		FailedControls:  failed,
		Controls:        controls,
		Recommendations: generatePrioritizedRecommendations(controls, critical, high, framework),
	}
}

func saveProgress(accountID string, score float64, controls []ControlResult, framework string) error {
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
	os.MkdirAll(filepath.Dir(dataPath), 0755)
	
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
	
	progress.LastScan = time.Now()
	progress.ScanCount++
	progress.ScoreHistory = append(progress.ScoreHistory, ScorePoint{
		Date:      time.Now(),
		Score:     score,
		Framework: framework,
	})
	
	for _, control := range controls {
		if control.Status == "PASS" {
			progress.FixedIssues[control.ID] = true
		}
	}
	
	data, _ := json.MarshalIndent(progress, "", "  ")
	return os.WriteFile(dataPath, data, 0644)
}

func showProgress(provider, profile string) {
	var accountID string
	ctx := context.Background()
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "azure":
		scanner, err := azureScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	}
	
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
	data, err := os.ReadFile(dataPath)
	if err != nil {
		fmt.Println("No previous scans found. Run 'auditkit scan' first!")
		return
	}
	
	var progress ProgressData
	json.Unmarshal(data, &progress)
	
	fmt.Println("\nYour Compliance Journey Progress")
	fmt.Println("===================================")
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
		
		fmt.Println("\nScore Trend:")
		startIdx := 0
		if len(progress.ScoreHistory) > 5 {
			startIdx = len(progress.ScoreHistory) - 5
		}
		for _, point := range progress.ScoreHistory[startIdx:] {
			bars := int(point.Score / 5)
			barString := strings.Repeat("█", bars)
			framework := point.Framework
			if framework == "" {
				framework = "SOC2"
			}
			fmt.Printf("%s [%s]: %s %.1f%%\n",
				point.Date.Format("Jan 02"),
				framework,
				barString,
				point.Score)
		}
	}
	
	fmt.Println("\nTip: Run 'auditkit scan -framework 800-53' to check NIST 800-53 compliance")
}

func compareScan(provider, profile string) {
	var accountID string
	ctx := context.Background()
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "azure":
		scanner, err := azureScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	}
	
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
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
	
	prev := progress.ScoreHistory[len(progress.ScoreHistory)-2]
	curr := progress.ScoreHistory[len(progress.ScoreHistory)-1]
	
	fmt.Println("\nCompliance Progress Report")
	fmt.Println("============================")
	fmt.Printf("Previous: %.1f%% [%s] (%s)\n", prev.Score, prev.Framework, prev.Date.Format("Jan 2, 3:04 PM"))
	fmt.Printf("Current:  %.1f%% [%s] (%s)\n", curr.Score, curr.Framework, curr.Date.Format("Jan 2, 3:04 PM"))
	
	improvement := curr.Score - prev.Score
	if improvement > 0 {
		fmt.Printf("\nImproved by %.1f%%!\n", improvement)
	} else if improvement < 0 {
		fmt.Printf("\nDeclined by %.1f%%\n", -improvement)
	} else {
		fmt.Println("\nNo change")
	}
	
	fmt.Println("\nTo see what changed, run:")
	fmt.Println("  auditkit scan -verbose")
}

func generateFixScript(provider, profile, output string) {
	fmt.Println("Generating remediation script...")
	
	ctx := context.Background()
	var accountID string
	var controls []remediation.ControlResult
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning AWS Account %s to identify fixes...\n", accountID)
		
		services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, remediation.ControlResult{
				Control:           result.Control,
				Status:            result.Status,
				Severity:          result.Severity,
				RemediationDetail: result.RemediationDetail,
			})
		}
	case "azure":
		fmt.Println("Azure fix script generation coming soon")
		return
	}
	
	if output == "" {
		output = fmt.Sprintf("auditkit-%s-fixes.sh", provider)
	}
	
	err := remediation.GenerateFixScript(controls, output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating fix script: %v\n", err)
		return
	}
	
	fmt.Printf("Fix script generated: %s\n", output)
	fmt.Println("REVIEW CAREFULLY before running!")
	fmt.Printf("   chmod +x %s\n", output)
	fmt.Printf("   ./%s\n", output)
}

func runEvidenceTracker(provider, profile, output string) {
	fmt.Println("Generating evidence collection tracker...")
	
	ctx := context.Background()
	var accountID string
	var controls []tracker.ControlResult
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning AWS Account %s...\n", accountID)
		
		services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, tracker.ControlResult{
				Control: result.Control,
				Status:  result.Status,
			})
		}
	case "azure":
		scanner, err := azureScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning Azure Subscription %s...\n", accountID)
		
		services := []string{"storage", "aad", "network"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, tracker.ControlResult{
				Control: result.Control,
				Status:  result.Status,
			})
		}
	}
	
	if output == "" {
		output = "evidence-tracker.html"
	}
	
	html := generateEvidenceTrackerHTML(controls, accountID)
	err := os.WriteFile(output, []byte(html), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating tracker: %v\n", err)
		return
	}
	
	fmt.Printf("Evidence tracker saved to %s\n", output)
	fmt.Println("Open this file in your browser and check off evidence as you collect it!")
}

func getPriorityAndImpact(controlID, severity, status, framework string) (string, string) {
	if status == "PASS" {
		return "PASSED", "Control is properly configured"
	}
	
	criticalByFramework := map[string]map[string]bool{
		"pci": {
			"CC6.2": true,
			"CC6.3": true,
			"CC6.6": true,
			"CC7.1": true,
		},
		"hipaa": {
			"CC6.3": true,
			"CC7.1": true,
			"CC6.6": true,
		},
		"soc2": {
			"CC6.6": true,
			"CC6.2": true,
			"CC6.1": true,
		},
	}
	
	if framework != "all" && framework != "" {
		if frameworkCritical, exists := criticalByFramework[strings.ToLower(framework)]; exists {
			if frameworkCritical[controlID] && severity == "CRITICAL" {
				return fmt.Sprintf("%s CRITICAL", strings.ToUpper(framework)), 
					fmt.Sprintf("%s AUDIT BLOCKER - Fix immediately or fail %s", strings.ToUpper(framework), strings.ToUpper(framework))
			}
		}
	}
	
	if severity == "CRITICAL" {
		return "CRITICAL", "AUDIT BLOCKER - Fix immediately or fail compliance"
	} else if severity == "HIGH" {
		return "HIGH", "Major finding - Auditor will flag this"
	} else if severity == "MEDIUM" {
		return "MEDIUM", "Should fix - Makes audit smoother"
	} else {
		return "LOW", "Nice to have - Strengthens posture"
	}
}

func printTextSummary(result ComplianceResult, full bool) {
	fmt.Printf("\n")
	frameworkLabel := "Multi-Framework"
	if result.Framework != "" && result.Framework != "all" {
		frameworkLabel = strings.ToUpper(result.Framework)
	}
	
	fmt.Printf("AuditKit %s Compliance Scan Results\n", frameworkLabel)
	fmt.Printf("=====================================\n")
	fmt.Printf("%s Account: %s\n", strings.ToUpper(result.Provider), result.AccountID)
	fmt.Printf("Framework: %s\n", frameworkLabel)
	fmt.Printf("Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")
	
	scoreColor := "\033[32m"
	if result.Score < 80 {
		scoreColor = "\033[33m"
	}
	if result.Score < 60 {
		scoreColor = "\033[31m"
	}
	fmt.Printf("Compliance Score: %s%.1f%%\033[0m\n", scoreColor, result.Score)
	fmt.Printf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls)
	
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
		fmt.Printf("\033[31mCritical Issues: %d (FIX IMMEDIATELY)\033[0m\n", criticalCount)
	}
	if highCount > 0 {
		fmt.Printf("\033[33mHigh Priority: %d\033[0m\n", highCount)
	}
	fmt.Printf("\n")
	
	if result.FailedControls > 0 {
		hasCritical := false
		criticalShown := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && strings.Contains(control.Priority, "CRITICAL") {
				if !hasCritical {
					fmt.Printf("\033[31mCRITICAL - Fix These NOW:\033[0m\n")
					fmt.Printf("================================\n")
					hasCritical = true
				}
				
				if !full && criticalShown >= 10 {
					remaining := criticalCount - 10
					if remaining > 0 {
						fmt.Printf("  ... and %d more critical issues (use --full to see all)\n\n", remaining)
					}
					break
				}
				
				fmt.Printf("\n\033[31m[FAIL]\033[0m %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Issue: %s\n", control.Evidence)
				
				if control.Remediation != "" {
					fmt.Printf("  Fix: %s\n", control.Remediation)
				}
				
				if control.ScreenshotGuide != "" {
					fmt.Printf("  Evidence: %s\n", control.ScreenshotGuide)
				}
				
				if control.ConsoleURL != "" {
					fmt.Printf("  Console: %s\n", control.ConsoleURL)
				}
				fmt.Printf("\n")
				criticalShown++
			}
		}
		
		hasHigh := false
		highShown := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && strings.Contains(control.Priority, "HIGH") {
				if !hasHigh {
					fmt.Printf("\033[33mHIGH Priority Issues:\033[0m\n")
					fmt.Printf("========================\n")
					hasHigh = true
				}
				
				if !full && highShown >= 10 {
					remaining := highCount - highShown
					if remaining > 0 {
						fmt.Printf("  ... and %d more high priority issues (use --full to see all)\n\n", remaining)
					}
					break
				}
				
				fmt.Printf("\n\033[33m[FAIL]\033[0m %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Issue: %s\n", control.Evidence)
				
				if control.Remediation != "" {
					fmt.Printf("  Fix: %s\n", control.Remediation)
				}
				
				if control.ScreenshotGuide != "" {
					fmt.Printf("  Evidence: %s\n", control.ScreenshotGuide)
				}
				
				if control.ConsoleURL != "" {
					fmt.Printf("  Console: %s\n", control.ConsoleURL)
				}
				fmt.Printf("\n")
				highShown++
			}
		}
		
		hasOther := false
		otherShown := 0
		otherCount := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && !strings.Contains(control.Priority, "CRITICAL") && !strings.Contains(control.Priority, "HIGH") {
				otherCount++
			}
		}
		
		for _, control := range result.Controls {
			if control.Status == "FAIL" && !strings.Contains(control.Priority, "CRITICAL") && !strings.Contains(control.Priority, "HIGH") {
				if !hasOther {
					fmt.Printf("Other Issues:\n")
					fmt.Printf("================\n")
					hasOther = true
				}
				
				if !full && otherShown >= 10 {
					remaining := otherCount - 10
					if remaining > 0 {
						fmt.Printf("  ... and %d more issues (use --full to see all)\n\n", remaining)
					}
					break
				}
				
				fmt.Printf("[FAIL] %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Issue: %s\n", control.Evidence)
				if control.Remediation != "" {
					fmt.Printf("  Fix: %s\n", control.Remediation)
				}
				fmt.Printf("\n")
				otherShown++
			}
		}
		
		hasInfo := false
		infoShown := 0
		infoCount := 0
		for _, control := range result.Controls {
			if control.Status == "INFO" {
				infoCount++
			}
		}
		
		for _, control := range result.Controls {
			if control.Status == "INFO" {
				if !hasInfo {
					fmt.Printf("Manual Documentation Required:\n")
					fmt.Printf("=================================\n")
					hasInfo = true
				}
				
				if !full && infoShown >= 20 {
					remaining := infoCount - 20
					if remaining > 0 {
						fmt.Printf("  ... and %d more manual controls (use --full to see all)\n\n", remaining)
					}
					break
				}
				
				fmt.Printf("[INFO] %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Guidance: %s\n", control.Evidence)
				if control.ScreenshotGuide != "" {
					fmt.Printf("  Evidence: %s\n", control.ScreenshotGuide)
				}
				fmt.Printf("\n")
				infoShown++
			}
		}
	}
	
	fmt.Printf("\033[32mPassed Controls:\033[0m\n")
	fmt.Printf("===================\n")
	passCount := 0
	for _, control := range result.Controls {
		if control.Status == "PASS" {
			fmt.Printf("  - %s - %s\n", control.ID, control.Name)
			passCount++
			if !full && passCount >= 15 {
				remaining := result.PassedControls - 15
				if remaining > 0 {
					fmt.Printf("  ... and %d more passing controls (use --full to see all)\n", remaining)
				}
				break
			}
		}
	}
	
	if len(result.Recommendations) > 0 {
		fmt.Printf("\nPriority Action Items:\n")
		fmt.Printf("=========================\n")
		for i, rec := range result.Recommendations {
			if i >= 5 {
				break
			}
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}
	
	fmt.Printf("\n")
	if !full && result.TotalControls > 50 {
		fmt.Printf("💡 Tip: Use --full flag to see all %d controls without truncation\n", result.TotalControls)
		fmt.Printf("   auditkit scan -provider %s -framework %s --full\n\n", result.Provider, strings.ToLower(result.Framework))
	}
	fmt.Printf("For detailed %s report with full evidence checklist:\n", frameworkLabel)
	fmt.Printf("   auditkit scan -provider %s -framework %s -format pdf -output report.pdf\n", result.Provider, strings.ToLower(result.Framework))
	fmt.Printf("\nTo track evidence collection progress:\n")
	fmt.Printf("   auditkit evidence -provider %s\n", result.Provider)
	fmt.Printf("\n")
}

func generatePrioritizedRecommendations(controls []ControlResult, criticalCount, highCount int, framework string) []string {
	recs := []string{}
	
	if framework == "pci" {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("PCI-DSS URGENT: Fix %d CRITICAL issues - QSA will fail your assessment", criticalCount))
		}
		recs = append(recs, "Document cardholder data flow and network segmentation")
	} else if framework == "hipaa" {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("HIPAA URGENT: Fix %d CRITICAL issues - violates Security Rule", criticalCount))
		}
		recs = append(recs, "Ensure all Business Associate Agreements (BAAs) are in place")
	} else {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("URGENT: Fix %d CRITICAL issues immediately - these WILL fail your audit", criticalCount))
		}
	}
	
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
	
	if hasNoMFA {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 8.3.1: Enable MFA for all console access immediately")
		} else {
			recs = append(recs, "CRITICAL: Enable MFA for root/admin accounts TODAY - auditors check this first")
		}
	}
	if hasPublicS3 {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 1.2.1: No direct public access to cardholder data environment")
		} else {
			recs = append(recs, "CRITICAL: Block public access on storage - data exposure = instant fail")
		}
	}
	if hasNoEncryption {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 3.4: Encrypt all stored cardholder data")
		} else if framework == "hipaa" {
			recs = append(recs, "HIPAA 164.312(a)(2)(iv): Implement encryption for ePHI")
		} else {
			recs = append(recs, "MEDIUM: Enable encryption on all storage - best practice")
		}
	}
	if hasOpenPorts {
		recs = append(recs, "HIGH: Close management ports from internet - major security finding")
	}
	if hasOldKeys {
		recs = append(recs, "HIGH: Rotate access keys/credentials older than 90 days - compliance requirement")
	}
	if hasNoLogging {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 10.1: Implement audit trails to link access to individual users")
		} else {
			recs = append(recs, "HIGH: Enable audit logging - required for compliance")
		}
	}
	
	recs = append(recs, "Enable continuous compliance monitoring")
	recs = append(recs, "Document your security policies and procedures")
	recs = append(recs, "Set up automated alerting for security events")
	if framework == "pci" {
		recs = append(recs, "Schedule quarterly vulnerability scans (PCI-DSS 11.2)")
	}
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
			Frameworks:      c.Frameworks,
		})
	}
	return pdfControls
}

func getControlName(controlID string) string {
	controlNames := map[string]string{
		"CC1.1": "Organizational Governance",
		"CC1.2": "Board Oversight",
		"CC1.3": "Organizational Structure",
		"CC1.4": "Commitment to Competence",
		"CC1.5": "Accountability",
		"CC2.1": "Information and Communication",
		"CC2.2": "Internal Communication",
		"CC2.3": "External Communication",
		"CC3.1": "Risk Assessment Process",
		"CC3.2": "Risk Identification",
		"CC3.3": "Risk Analysis",
		"CC3.4": "Risk Management",
		"CC4.1": "Monitoring Activities",
		"CC4.2": "Evaluation of Deficiencies",
		"CC5.1": "Control Activities",
		"CC5.2": "Technology Controls",
		"CC5.3": "Policy Implementation",
		"CC6.1": "Logical and Physical Access Controls",
		"CC6.2": "Network Security",
		"CC6.3": "Encryption at Rest",
		"CC6.6": "Authentication Controls",
		"CC6.7": "Password Policy",
		"CC6.8": "Access Key Rotation",
		"CC7.1": "Security Monitoring and Logging",
		"CC7.2": "Incident Detection and Response",
		"CC7.3": "Security Event Analysis",
		"CC7.4": "Performance Monitoring",
		"CC7.5": "Vulnerability Management",
		"CC8.1": "Change Management Process",
		"CC9.1": "Risk Mitigation",
		"CC9.2": "Vendor Management",
		"A1.1":  "Availability Monitoring",
		"A1.2":  "Backup and Recovery",
		"A1.3":  "Disaster Recovery",
		"PI1.1": "Privacy Controls",
		"PI1.2": "Data Subject Rights",
		"PI1.3": "Data Retention",
		"PI1.4": "Data Disposal",
		"PI1.5": "Privacy Notice",
		"PI1.6": "Data Quality",
		"C1.1":  "Confidentiality Controls",
		"C1.2":  "Data Classification",
		"PCI-1.2.1": "Network Segmentation",
		"PCI-1.3.1": "No Direct Public Access",
		"PCI-2.2.2": "Default Configuration Changes",
		"PCI-3.4":   "Encryption at Rest",
		"PCI-3.5":   "Encryption Key Management",
		"PCI-4.1":   "Encryption in Transit",
		"PCI-7.1":   "Least Privilege Access",
		"PCI-8.1.4": "Remove Inactive Users",
		"PCI-8.1.8": "Session Timeout",
		"PCI-8.2.3": "Password Strength",
		"PCI-8.2.4": "Password Rotation",
		"PCI-8.3.1": "MFA for All Access",
		"PCI-10.1":  "Audit Trail Implementation",
		"PCI-10.5.3": "Log Retention",
		"PCI-11.2.2": "Quarterly Vulnerability Scans",
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
	} else if strings.HasPrefix(controlID, "PCI") {
		return "PCI-DSS"
	}
	return "Security"
}

func outputTextToFile(result ComplianceResult, output string) {
	var sb strings.Builder
	frameworkLabel := "Multi-Framework"
	if result.Framework != "" && result.Framework != "all" {
		frameworkLabel = strings.ToUpper(result.Framework)
	}
	
	sb.WriteString(fmt.Sprintf("AuditKit %s Compliance Report\n", frameworkLabel))
	sb.WriteString(fmt.Sprintf("==========================\n"))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Provider: %s\n", result.Provider))
	sb.WriteString(fmt.Sprintf("Framework: %s\n", frameworkLabel))
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
	fmt.Printf("Report saved to %s\n", output)
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
		fmt.Printf("JSON report saved to %s\n", output)
	} else {
		fmt.Print(string(data))
	}
}

func outputHTML(result ComplianceResult, output string) {
	htmlResult := report.ComplianceResult{
		Timestamp:       result.Timestamp,
		Provider:        result.Provider,
		AccountID:       result.AccountID,
		Score:           result.Score,
		TotalControls:   result.TotalControls,
		PassedControls:  result.PassedControls,
		FailedControls:  result.FailedControls,
		Controls:        convertControlsForPDF(result.Controls),
		Recommendations: result.Recommendations,
		Framework:       result.Framework,
	}
	
	html := report.GenerateHTML(htmlResult)

	if output == "" {
		output = fmt.Sprintf("auditkit-%s-%s-report-%s.html", 
			strings.ToLower(result.Provider),
			strings.ToLower(result.Framework), 
			time.Now().Format("2006-01-02-150405"))
	}

	err := os.WriteFile(output, []byte(html), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing HTML file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("HTML report saved to %s\n", output)
	fmt.Printf("Open in browser: file://%s/%s\n", getCurrentDir(), output)
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

func generateEvidenceTrackerHTML(controls []tracker.ControlResult, accountID string) string {
	return ""
}

func generateReport(format, output string) {
	fmt.Println("Generating audit report from last scan...")
	fmt.Println("Note: This feature requires cached scan results (not yet implemented)")
	fmt.Println("For now, run: auditkit scan -format pdf")
}
