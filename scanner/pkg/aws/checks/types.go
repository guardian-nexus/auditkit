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
)

type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, NOT_APPLICABLE
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Priority          Priority          `json:"priority"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
	// NEW: Multi-framework mappings
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

type Priority struct {
	Level     string `json:"level"`
	Emoji     string `json:"emoji"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail_audit"`
}

type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
	Name() string
}

// Framework mappings for all controls
var FrameworkMappings = map[string]map[string]string{
	"S3_PUBLIC_ACCESS": {
		FrameworkSOC2:  "CC6.2",
		FrameworkPCI:   "1.2.1, 1.3.4",
		FrameworkHIPAA: "164.312(a)(1)",
	},
	"S3_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4, 3.4.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"S3_VERSIONING": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	"S3_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
	},
	"ROOT_MFA": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
	},
	"PASSWORD_POLICY": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.3, 8.2.4, 8.2.5",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
	},
	"ACCESS_KEY_ROTATION": {
		FrameworkSOC2:  "CC6.8",
		FrameworkPCI:   "8.2.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(B)",
	},
	"UNUSED_CREDENTIALS": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
	},
	"OPEN_SECURITY_GROUPS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1, 1.3",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"EBS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4, 3.4.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"PUBLIC_INSTANCES": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.3.1, 1.3.2",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"OLD_AMIS": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"CLOUDTRAIL_ENABLED": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.1, 10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"CLOUDTRAIL_MULTIREGION": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"CLOUDTRAIL_INTEGRITY": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.2, 10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
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
	return result[:len(result)-2]
}

// Priority definitions
var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Emoji:     "🔥",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail audit",
		TimeToFix: "Fix RIGHT NOW",
		WillFail:  true,
	}

	PriorityHigh = Priority{
		Level:     "HIGH",
		Emoji:     "⚠️",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	}

	PriorityMedium = Priority{
		Level:     "MEDIUM",
		Emoji:     "📋",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	}

	PriorityLow = Priority{
		Level:     "LOW",
		Emoji:     "💡",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	}

	PriorityInfo = Priority{
		Level:     "INFO",
		Emoji:     "✅",
		Impact:    "Good job, this passes",
		TimeToFix: "Already done",
		WillFail:  false,
	}
)
