package aws

type Priority struct {
	Level     string
	Emoji     string
	Impact    string
	TimeToFix string
	WillFail  bool
}

var PriorityMap = map[string]Priority{
	"CRITICAL": {
		Level:     "CRITICAL",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail SOC2",
		TimeToFix: "Fix TODAY",
		WillFail:  true,
	},
	"HIGH": {
		Level:     "HIGH",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	},
	"MEDIUM": {
		Level:     "MEDIUM",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	},
	"LOW": {
		Level:     "LOW",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	},
}
