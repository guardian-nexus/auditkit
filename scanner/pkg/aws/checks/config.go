package checks

import (
	"context"
	"fmt"
	"time"

	//save "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

// ConfigChecks for AWS Config and GuardDuty
type ConfigChecks struct {
	client *configservice.Client
}

func NewConfigChecks(client *configservice.Client) *ConfigChecks {
	return &ConfigChecks{client: client}
}

func (c *ConfigChecks) Name() string {
	return "AWS Config Compliance"
}

func (c *ConfigChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Check if Config is enabled and recording
	recorders, err := c.client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil || len(recorders.ConfigurationRecorders) == 0 {
		results = append(results, CheckResult{
			Control:         "CC7.1",
			Name:            "AWS Config Recording",
			Status:          "FAIL",
			Severity:        "HIGH",
			Evidence:        "🚨 AWS Config NOT enabled! Cannot track configuration changes!",
			Remediation:     "Enable AWS Config to record all resource configurations",
			ScreenshotGuide: "1. Go to AWS Config Console\n2. Click 'Get started'\n3. Enable recording for all resources\n4. Screenshot showing 'Recorder is ON'",
			ConsoleURL:      "https://console.aws.amazon.com/config/",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC7.1",
			Name:      "AWS Config Recording",
			Status:    "PASS",
			Evidence:  "AWS Config is recording configuration changes",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// GuardDuty checks
type GuardDutyChecks struct {
	client *guardduty.Client
}

func NewGuardDutyChecks(client *guardduty.Client) *GuardDutyChecks {
	return &GuardDutyChecks{client: client}
}

func (c *GuardDutyChecks) Name() string {
	return "GuardDuty Threat Detection"
}

func (c *GuardDutyChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	detectors, err := c.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil || len(detectors.DetectorIds) == 0 {
		results = append(results, CheckResult{
			Control:         "CC7.2",
			Name:            "GuardDuty Threat Detection",
			Status:          "FAIL",
			Severity:        "HIGH",
			Evidence:        "GuardDuty NOT enabled - missing threat detection!",
			Remediation:     "Enable GuardDuty for automated threat detection",
			ScreenshotGuide: "1. Go to GuardDuty Console\n2. Click 'Get Started'\n3. Enable GuardDuty\n4. Screenshot showing 'GuardDuty is ENABLED'",
			ConsoleURL:      "https://console.aws.amazon.com/guardduty/",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC7.2",
			Name:      "GuardDuty Threat Detection",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("GuardDuty enabled with %d detector(s)", len(detectors.DetectorIds)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}
