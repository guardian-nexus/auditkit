package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

type ComplianceResult struct {
	Timestamp       time.Time
	Provider        string
	AccountID       string
	Framework       string // NEW: Which framework(s) being reported
	Score           float64
	TotalControls   int
	PassedControls  int
	FailedControls  int
	Controls        []ControlResult
	Recommendations []string
}

type ControlResult struct {
	ID              string
	Name            string
	Category        string
	Severity        string
	Status          string
	Evidence        string
	Remediation     string
	ScreenshotGuide string
	ConsoleURL      string
	Frameworks      map[string]string // NEW: Framework mappings
}

func GeneratePDF(result ComplianceResult, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// Determine framework label
	frameworkLabel := "Multi-Framework Compliance"
	if result.Framework != "" && result.Framework != "all" {
		frameworkLabel = strings.ToUpper(result.Framework) + " Compliance"
	}

	// Header
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 15, frameworkLabel+" Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, fmt.Sprintf("Generated: %s", result.Timestamp.Format("January 2, 2006 at 3:04 PM")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("AWS Account: %s", result.AccountID), "", 1, "C", false, 0, "")
	
	// Add framework coverage info
	if result.Framework == "all" {
		pdf.CellFormat(0, 5, "Coverage: SOC2, PCI-DSS, HIPAA", "", 1, "C", false, 0, "")
	}
	pdf.Ln(10)

	// Score Section
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Overall Compliance Score", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "B", 36)
	if result.Score < 60 {
		pdf.SetTextColor(220, 53, 69)
	} else if result.Score < 80 {
		pdf.SetTextColor(255, 193, 7)
	} else {
		pdf.SetTextColor(40, 167, 69)
	}
	pdf.CellFormat(0, 20, fmt.Sprintf("%.1f%%", result.Score), "", 1, "C", false, 0, "")

	// Stats
	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(60, 8, fmt.Sprintf("Total Controls: %d", result.TotalControls), "", 0, "L", false, 0, "")
	pdf.SetTextColor(40, 167, 69)
	pdf.CellFormat(60, 8, fmt.Sprintf("Passed: %d", result.PassedControls), "", 0, "L", false, 0, "")
	pdf.SetTextColor(220, 53, 69)
	pdf.CellFormat(60, 8, fmt.Sprintf("Failed: %d", result.FailedControls), "", 1, "L", false, 0, "")
	pdf.Ln(10)

	// Framework-specific critical issues
	pdf.SetTextColor(220, 53, 69)
	pdf.SetFont("Arial", "B", 14)
	
	criticalTitle := "CRITICAL - Fix These Immediately"
	if result.Framework == "pci" {
		criticalTitle = "PCI-DSS Critical Requirements - Fix for Compliance"
	} else if result.Framework == "hipaa" {
		criticalTitle = "HIPAA Security Rule Violations - Fix Immediately"
	}
	
	pdf.CellFormat(0, 10, criticalTitle, "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	criticalCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" && control.Severity == "CRITICAL" {
			criticalCount++
			pdf.SetTextColor(220, 53, 69)
			pdf.SetFont("Arial", "B", 11)
			
			// Show framework-specific requirement
			controlLabel := fmt.Sprintf("[CRITICAL] %s - %s", control.ID, control.Name)
			if control.Frameworks != nil && result.Framework != "all" && result.Framework != "" {
				if req, ok := control.Frameworks[strings.ToUpper(result.Framework)]; ok {
					controlLabel = fmt.Sprintf("[%s %s] %s", strings.ToUpper(result.Framework), req, control.Name)
				}
			}
			
			pdf.CellFormat(0, 7, controlLabel, "", 1, "L", false, 0, "")

			pdf.SetFont("Arial", "", 10)
			pdf.SetTextColor(0, 0, 0)
			pdf.MultiCell(0, 5, fmt.Sprintf("  Issue: %s", control.Evidence), "", "L", false)

			if control.Remediation != "" {
				pdf.SetFont("Arial", "I", 9)
				pdf.SetTextColor(64, 64, 64)
				remedy := control.Remediation
				if len(remedy) > 150 {
					remedy = remedy[:150] + "..."
				}
				pdf.MultiCell(0, 4, fmt.Sprintf("  Fix: %s", remedy), "", "L", false)
			}
			pdf.Ln(3)
		}
	}

	if criticalCount == 0 {
		pdf.SetTextColor(40, 167, 69)
		pdf.SetFont("Arial", "", 10)
		pdf.CellFormat(0, 8, "No critical issues found - good job!", "", 1, "L", false, 0, "")
	}

	// Framework Mapping Page (if showing all frameworks)
	if result.Framework == "all" || result.Framework == "" {
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 18)
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(0, 10, "Multi-Framework Control Mapping", "", 1, "L", false, 0, "")
		
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.MultiCell(0, 5, "Each control maps to multiple compliance frameworks:", "", "L", false)
		pdf.Ln(5)
		
		// Create a mapping table
		pdf.SetFont("Arial", "B", 9)
		pdf.CellFormat(40, 7, "Control", "1", 0, "L", false, 0, "")
		pdf.CellFormat(40, 7, "SOC2", "1", 0, "L", false, 0, "")
		pdf.CellFormat(40, 7, "PCI-DSS", "1", 0, "L", false, 0, "")
		pdf.CellFormat(40, 7, "HIPAA", "1", 1, "L", false, 0, "")
		
		pdf.SetFont("Arial", "", 8)
		for _, control := range result.Controls {
			if control.Frameworks != nil {
				pdf.CellFormat(40, 6, control.Name[:min(20, len(control.Name))], "1", 0, "L", false, 0, "")
				pdf.CellFormat(40, 6, control.Frameworks["SOC2"], "1", 0, "L", false, 0, "")
				pdf.CellFormat(40, 6, control.Frameworks["PCI-DSS"], "1", 0, "L", false, 0, "")
				pdf.CellFormat(40, 6, control.Frameworks["HIPAA"], "1", 1, "L", false, 0, "")
			}
		}
	}

	// Evidence Collection Guide
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 10, "Screenshot Evidence Collection Guide", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(100, 100, 100)
	
	evidenceNote := "Your auditor needs screenshots proving each control is fixed."
	if result.Framework == "pci" {
		evidenceNote = "QSA (Qualified Security Assessor) requires documented evidence for each control."
	} else if result.Framework == "hipaa" {
		evidenceNote = "HIPAA audit requires documentation showing technical safeguards are in place."
	}
	
	pdf.MultiCell(0, 5, evidenceNote+" Follow these EXACT steps:", "", "L", false)
	pdf.Ln(5)

	// Group controls by status for better organization
	failedControls := []ControlResult{}
	passedControls := []ControlResult{}

	for _, control := range result.Controls {
		if control.Status == "FAIL" {
			failedControls = append(failedControls, control)
		} else {
			passedControls = append(passedControls, control)
		}
	}

	// Failed controls - need evidence after fixing
	if len(failedControls) > 0 {
		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(220, 53, 69)
		pdf.CellFormat(0, 8, "Failed Controls - Fix Then Screenshot", "", 1, "L", false, 0, "")
		pdf.Ln(2)

		for i, control := range failedControls {
			// Box around each control
			pdf.SetDrawColor(220, 53, 69)
			pdf.SetLineWidth(0.5)
			startY := pdf.GetY()

			pdf.SetFont("Arial", "B", 11)
			pdf.SetTextColor(0, 0, 0)
			
			// Show framework requirements
			title := fmt.Sprintf("%d. %s - %s", i+1, control.ID, control.Name)
			if control.Frameworks != nil && len(control.Frameworks) > 0 {
				requirements := []string{}
				for fw, req := range control.Frameworks {
					requirements = append(requirements, fmt.Sprintf("%s %s", fw, req))
				}
				title += fmt.Sprintf(" [%s]", strings.Join(requirements, ", "))
			}
			
			pdf.CellFormat(0, 7, title, "", 1, "L", false, 0, "")

			// Add console URL if available
			if control.ConsoleURL != "" {
				pdf.SetFont("Arial", "U", 9)
				pdf.SetTextColor(3, 102, 214)
				pdf.CellFormat(0, 5, fmt.Sprintf("Console: %s", control.ConsoleURL), "", 1, "L", false, 0, "")
			}

			// Add screenshot instructions if available
			if control.ScreenshotGuide != "" {
				pdf.SetFont("Arial", "", 9)
				pdf.SetTextColor(64, 64, 64)

				// Split guide by newlines for better formatting
				steps := strings.Split(control.ScreenshotGuide, "\n")
				for _, step := range steps {
					if len(step) > 0 {
						pdf.CellFormat(0, 4, step, "", 1, "L", false, 0, "")
					}
				}
			}

			// Draw box around this control
			endY := pdf.GetY()
			pdf.Rect(10, startY-2, 190, endY-startY+4, "D")
			pdf.Ln(5)
		}
	}

	// Passed controls - need evidence for audit
	if len(passedControls) > 0 {
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(40, 167, 69)
		pdf.CellFormat(0, 8, "Passed Controls - Screenshot for Audit", "", 1, "L", false, 0, "")
		pdf.Ln(2)

		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(100, 100, 100)
		pdf.MultiCell(0, 4, "Even though these passed, you still need screenshots as evidence:", "", "L", false)
		pdf.Ln(3)

		for _, control := range passedControls {
			pdf.SetFont("Arial", "", 10)
			pdf.SetTextColor(40, 167, 69)
			pdf.CellFormat(5, 5, "[✓]", "", 0, "L", false, 0, "")
			pdf.SetTextColor(0, 0, 0)
			
			label := fmt.Sprintf("%s - %s", control.ID, control.Name)
			if control.Frameworks != nil && result.Framework != "all" && result.Framework != "" {
				if req, ok := control.Frameworks[strings.ToUpper(result.Framework)]; ok {
					label = fmt.Sprintf("[%s %s] %s", strings.ToUpper(result.Framework), req, control.Name)
				}
			}
			
			pdf.CellFormat(0, 5, label, "", 1, "L", false, 0, "")
		}
	}

	// Framework-specific evidence checklist
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	
	checklistTitle := "Evidence Collection Checklist"
	if result.Framework != "" && result.Framework != "all" {
		checklistTitle = strings.ToUpper(result.Framework) + " Evidence Checklist"
	}
	
	pdf.CellFormat(0, 10, checklistTitle, "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, "Check off each item as you collect evidence", "", 1, "L", false, 0, "")
	pdf.Ln(5)

	// Create framework-specific checklist
	pdf.SetFont("Arial", "", 10)
	checklistItems := getFrameworkChecklist(result.Framework)

	for _, item := range checklistItems {
		pdf.CellFormat(0, 6, item, "", 1, "L", false, 0, "")
	}

	// Footer
	pdf.SetY(-30)
	pdf.SetFont("Arial", "I", 9)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, "Generated by AuditKit - Multi-Framework Compliance Scanner", "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "SOC2 | PCI-DSS | HIPAA Compliance in One Scan", "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "https://github.com/guardian-nexus/auditkit", "", 1, "C", false, 0, "")

	return pdf.OutputFileAndClose(outputPath)
}

func getFrameworkChecklist(framework string) []string {
	switch strings.ToLower(framework) {
	case "pci":
		return []string{
			"[ ] Cardholder Data Environment (CDE) Network Diagram",
			"[ ] Firewall Configuration Screenshots (Requirement 1)",
			"[ ] User Access Control Matrix (Requirement 7)",
			"[ ] MFA Configuration for All Admin Access (Requirement 8.3)",
			"[ ] Password Policy Settings (Requirement 8.2)",
			"[ ] Access Key Rotation Report (< 90 days)",
			"[ ] Encryption Settings for Data at Rest (Requirement 3.4)",
			"[ ] Audit Log Configuration (Requirement 10)",
			"[ ] Log Retention Settings (90+ days minimum)",
			"[ ] Vulnerability Scan Results (Requirement 11)",
			"[ ] Security Patch Documentation (Requirement 6.2)",
			"[ ] Incident Response Plan (Requirement 12.10)",
		}
	case "hipaa":
		return []string{
			"[ ] Access Control Documentation (164.312(a)(1))",
			"[ ] Unique User Identification Settings (164.312(a)(2)(i))",
			"[ ] Automatic Logoff Configuration (164.312(a)(2)(iii))",
			"[ ] Encryption/Decryption Methods (164.312(a)(2)(iv))",
			"[ ] Audit Logs and Controls (164.312(b))",
			"[ ] Integrity Controls Documentation (164.312(c)(1))",
			"[ ] Transmission Security Settings (164.312(e)(1))",
			"[ ] Business Associate Agreements (BAAs)",
			"[ ] Risk Assessment Documentation",
			"[ ] Workforce Training Records",
			"[ ] Contingency Plan and Backup Procedures",
			"[ ] Physical Safeguards Documentation",
		}
	default: // SOC2 or all
		return []string{
			"[ ] AWS Account Summary Page (showing account ID)",
			"[ ] IAM Dashboard (showing MFA status)",
			"[ ] Password Policy Settings",
			"[ ] S3 Bucket List (showing encryption icons)",
			"[ ] S3 Public Access Settings (per bucket)",
			"[ ] CloudTrail Dashboard (showing logging enabled)",
			"[ ] Security Groups List (showing no 0.0.0.0/0)",
			"[ ] IAM Users List (showing MFA column)",
			"[ ] Access Key Age Report",
			"[ ] RDS Instance Encryption Settings",
			"[ ] EBS Volume Encryption Settings",
			"[ ] VPC Flow Logs Configuration",
			"[ ] AWS Config Dashboard",
			"[ ] GuardDuty Status (if enabled)",
			"[ ] Systems Manager Compliance Dashboard",
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
