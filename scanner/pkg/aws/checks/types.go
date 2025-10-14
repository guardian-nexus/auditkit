package checks

import (
	"fmt"
	"context"
	"time"
)

// Framework constants
const (
	FrameworkSOC2  = "SOC2"
	FrameworkPCI   = "PCI-DSS"
	FrameworkHIPAA = "HIPAA"
	FrameworkISO   = "ISO-27001"
)

type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, NOT_APPLICABLE, ERROR
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Priority          Priority          `json:"priority"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

type Priority struct {
	Level     string `json:"level"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail_audit"`
}

type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
	Name() string
}

// Framework mappings for all controls - AWS and Azure agnostic
var FrameworkMappings = map[string]map[string]string{
	"PUBLIC_ACCESS_BLOCK": {  // Works for S3 and Azure Storage
		FrameworkSOC2:  "CC6.2",
		FrameworkPCI:   "1.2.1, 1.3.4",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkISO:   "A.13.1.1",
	},
	"ENCRYPTION_AT_REST": {  // Works for S3, EBS, Azure Storage, Disks
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4, 3.4.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkISO:   "A.10.1.1",
	},
	"VERSIONING": {  // Works for S3 and Azure Storage
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkISO:   "A.12.3.1",
	},
	"ACCESS_LOGGING": {  // Works for S3, CloudTrail, Azure Activity Log
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkISO:   "A.12.4.1",
	},
	"ROOT_MFA": {  // Works for AWS Root and Azure Global Admin
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkISO:   "A.9.4.2",
	},
	"PASSWORD_POLICY": {  // Universal
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.3, 8.2.4, 8.2.5",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkISO:   "A.9.4.3",
	},
	"ACCESS_KEY_ROTATION": {  // Works for AWS keys and Azure service principals
		FrameworkSOC2:  "CC6.8",
		FrameworkPCI:   "8.2.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(B)",
		FrameworkISO:   "A.9.2.5",
	},
	"UNUSED_CREDENTIALS": {  // Universal
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkISO:   "A.9.2.6",
	},
	"NETWORK_SEGMENTATION": {  // Works for Security Groups and NSGs
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1, 1.3",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkISO:   "A.13.1.3",
	},
	"PUBLIC_INSTANCES": {  // Works for EC2 and Azure VMs
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.3.1, 1.3.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkISO:   "A.13.1.1",
	},
	"PATCH_MANAGEMENT": {  // Universal
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkISO:   "A.12.6.1",
	},
	"AUDIT_TRAIL": {  // Works for CloudTrail and Azure Activity Log
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.1, 10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkISO:   "A.12.4.1",
	},
	"LOG_INTEGRITY": {  // Universal
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.2, 10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkISO:   "A.12.4.2",
	},
}

// Helper function to get framework mappings for a control
func GetFrameworkMappings(controlType string) map[string]string {
	if mappings, exists := FrameworkMappings[controlType]; exists {
		return mappings
	}
	return make(map[string]string)
}

// Helper to format framework requirements in evidence
func FormatFrameworkRequirements(frameworks map[string]string) string {
	if len(frameworks) == 0 {
		return ""
	}
	
	result := " | Requirements: "
	for fw, requirement := range frameworks {
		result += fmt.Sprintf("%s %s, ", fw, requirement)
	}
	// Remove trailing comma and space
	if len(result) > 2 {
		result = result[:len(result)-2]
	}
	return result
}

var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail audit",
		TimeToFix: "Fix RIGHT NOW",
		WillFail:  true,
	}

	PriorityHigh = Priority{
		Level:     "HIGH",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	}

	PriorityMedium = Priority{
		Level:     "MEDIUM",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	}

	PriorityLow = Priority{
		Level:     "LOW",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	}

	PriorityInfo = Priority{
		Level:     "INFO",
		Impact:    "Good job, this passes",
		TimeToFix: "Already done",
		WillFail:  false,
	}
)

const (
	CriticalViolation = "CRITICAL VIOLATION:"
	HighRisk          = "HIGH RISK:"
	MediumRisk        = "MEDIUM RISK:"
	Compliant         = "COMPLIANT:"
	ManualReview      = "MANUAL REVIEW REQUIRED:"
)
