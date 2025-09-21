package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type CloudTrailChecks struct {
	client *cloudtrail.Client
}

func NewCloudTrailChecks(client *cloudtrail.Client) *CloudTrailChecks {
	return &CloudTrailChecks{client: client}
}

func (c *CloudTrailChecks) Name() string {
	return "CloudTrail Logging"
}

func (c *CloudTrailChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckTrailEnabled(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckMultiRegion(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLogFileValidation(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *CloudTrailChecks) CheckTrailEnabled(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "CloudTrail Logging Enabled",
			Status:     "FAIL",
			Evidence:   "Unable to check CloudTrail status",
			Severity:   "CRITICAL",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, err
	}

	if len(trails.Trails) == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Logging Enabled",
			Status:          "FAIL",
			Severity:        "CRITICAL",
			Evidence:        "🚨 NO CloudTrail configured! Zero audit logging | Violates PCI DSS 10.1 (implement audit trails) & HIPAA 164.312(b)",
			Remediation:     "aws cloudtrail create-trail --name audit-trail --s3-bucket-name YOUR_BUCKET && aws cloudtrail start-logging --name audit-trail",
			ScreenshotGuide: "1. Go to CloudTrail Console\n2. Click 'Create trail'\n3. Enable for all regions\n4. Screenshot showing trail is 'Logging' status\n5. This is MANDATORY for SOC2, PCI, and HIPAA!",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, nil
	}

	// Check if at least one trail is logging
	activeTrails := 0
	for _, trail := range trails.Trails {
		status, err := c.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err == nil && aws.ToBool(status.IsLogging) {
			activeTrails++
		}
	}

	if activeTrails == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Logging Enabled",
			Status:          "FAIL",
			Severity:        "CRITICAL",
			Evidence:        fmt.Sprintf("CloudTrail exists but is NOT logging! (%d trails configured, 0 active) | Fails PCI DSS 10.2.1", len(trails.Trails)),
			Remediation:     "aws cloudtrail start-logging --name YOUR_TRAIL_NAME",
			ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Click on your trail\n3. Click 'Start logging'\n4. Screenshot showing 'Logging: ON'\n5. For PCI: Document log retention period (90+ days required)",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, nil
	}

	return CheckResult{
		Control:         "CC7.1",
		Name:            "CloudTrail Logging Enabled",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("%d CloudTrail(s) actively logging API calls | Meets SOC2 CC7.1, PCI DSS 10.1, HIPAA 164.312(b)", activeTrails),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Screenshot showing your trail(s) with 'Logging: ON'\n3. Click into trail and screenshot configuration\n4. For PCI: Show retention settings",
		ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
	}, nil
}

func (c *CloudTrailChecks) CheckMultiRegion(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	multiRegionTrails := 0
	for _, trail := range trails.Trails {
		// Get trail details
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].IsMultiRegionTrail) {
				multiRegionTrails++
			}
		}
	}

	if multiRegionTrails == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "Multi-Region CloudTrail",
			Status:          "FAIL",
			Severity:        "HIGH",
			Evidence:        "CloudTrail only logs current region - missing activity in other regions | PCI DSS 10.2.1 requires all system activity logged",
			Remediation:     "aws cloudtrail update-trail --name YOUR_TRAIL --is-multi-region-trail",
			ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Click your trail\n3. Screenshot showing 'Multi-region trail: Yes'\n4. This catches attackers using other regions",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_MULTIREGION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "Multi-Region CloudTrail",
		Status:     "PASS",
		Evidence:   "CloudTrail configured to log all regions | Meets PCI DSS 10.2.1 comprehensive logging",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_MULTIREGION"),
	}, nil
}

func (c *CloudTrailChecks) CheckLogFileValidation(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	validationEnabled := 0
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].LogFileValidationEnabled) {
				validationEnabled++
			}
		}
	}

	if validationEnabled == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Log Integrity",
			Status:          "FAIL",
			Severity:        "MEDIUM",
			Evidence:        "Log file validation disabled - logs could be tampered with | PCI DSS 10.5.2 requires tamper protection",
			Remediation:     "aws cloudtrail update-trail --name YOUR_TRAIL --enable-log-file-validation",
			ScreenshotGuide: "1. Go to CloudTrail → Trails → Your Trail\n2. Screenshot showing 'Log file validation: Enabled'\n3. For HIPAA: Document integrity controls",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_INTEGRITY"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "CloudTrail Log Integrity",
		Status:     "PASS",
		Evidence:   "Log file validation enabled to prevent tampering | Meets PCI DSS 10.5.2 & HIPAA 164.312(c)(1)",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_INTEGRITY"),
	}, nil
}
