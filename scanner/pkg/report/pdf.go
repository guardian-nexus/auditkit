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
	ScreenshotGuide string // Add this field
	ConsoleURL      string // Add this field
}

func GeneratePDF(result ComplianceResult, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// Header (keep existing)
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 15, "SOC2 Compliance Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, fmt.Sprintf("Generated: %s", result.Timestamp.Format("January 2, 2006 at 3:04 PM")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("AWS Account: %s", result.AccountID), "", 1, "C", false, 0, "")
	pdf.Ln(10)

	// Score Section (keep existing)
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

	// Critical Issues Summary
	pdf.SetTextColor(220, 53, 69)
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(0, 10, "CRITICAL - Fix These Immediately or Fail SOC2", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	criticalCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" && control.Severity == "CRITICAL" {
			criticalCount++
			pdf.SetTextColor(220, 53, 69)
			pdf.SetFont("Arial", "B", 11)
			pdf.CellFormat(0, 7, fmt.Sprintf("[CRITICAL] %s - %s", control.ID, control.Name), "", 1, "L", false, 0, "")

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

	// NEW: Detailed Evidence Collection Guide
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 10, "Screenshot Evidence Collection Guide", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.MultiCell(0, 5, "Your auditor needs screenshots proving each control is fixed. Follow these EXACT steps:", "", "L", false)
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
			pdf.CellFormat(0, 7, fmt.Sprintf("%d. %s - %s", i+1, control.ID, control.Name), "", 1, "L", false, 0, "")

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
					pdf.CellFormat(0, 4, step, "", 1, "L", false, 0, "")
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
			pdf.CellFormat(0, 5, fmt.Sprintf("%s - %s", control.ID, control.Name), "", 1, "L", false, 0, "")
		}
	}

	// Evidence Checklist Summary
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 10, "Evidence Collection Checklist", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, "Check off each item as you collect evidence", "", 1, "L", false, 0, "")
	pdf.Ln(5)

	// Create checklist
	pdf.SetFont("Arial", "", 10)
	checklistItems := []string{
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

	for _, item := range checklistItems {
		pdf.CellFormat(0, 6, item, "", 1, "L", false, 0, "")
	}

	// Footer
	pdf.SetY(-30)
	pdf.SetFont("Arial", "I", 9)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, "Generated by AuditKit - Open Source SOC2 Compliance Scanner", "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "https://github.com/guardian-nexus/auditkit", "", 1, "C", false, 0, "")

	return pdf.OutputFileAndClose(outputPath)
}
