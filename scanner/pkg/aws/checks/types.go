package checks

import (
	"context"
	"time"
)

type CheckResult struct {
	Control           string    `json:"control"`
	Name              string    `json:"name"`
	Status            string    `json:"status"` // PASS, FAIL, NOT_APPLICABLE
	Evidence          string    `json:"evidence"`
	Remediation       string    `json:"remediation,omitempty"`
	RemediationDetail string    `json:"remediation_detail,omitempty"`
	Severity          string    `json:"severity,omitempty"`
	Priority          Priority  `json:"priority"`
	ScreenshotGuide   string    `json:"screenshot_guide,omitempty"`
	ConsoleURL        string    `json:"console_url,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
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

// Priority definitions
var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Emoji:     "🔥",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail SOC2",
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
