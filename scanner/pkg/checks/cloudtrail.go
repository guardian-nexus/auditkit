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
			Control:   "CC7.1",
			Name:      "CloudTrail Logging Enabled",
			Status:    "FAIL",
			Evidence:  "Unable to check CloudTrail status",
			Severity:  "CRITICAL",
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
		}, err
	}

	if len(trails.Trails) == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "CloudTrail Logging Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "🚨 NO CloudTrail configured! You have ZERO audit logging!",
			Remediation:       "Create CloudTrail immediately\nRun: aws cloudtrail create-trail",
			RemediationDetail: "aws cloudtrail create-trail --name audit-trail --s3-bucket-name YOUR_BUCKET && aws cloudtrail start-logging --name audit-trail",
			ScreenshotGuide:   "1. Go to CloudTrail Console\n2. Click 'Create trail'\n3. Enable for all regions\n4. Screenshot showing trail is 'Logging' status\n5. This is MANDATORY for SOC2!",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
		}, nil
	}

	// Check if at least one trail is logging
	activeTrails := 0
	inactiveTrailName := ""
	for _, trail := range trails.Trails {
		status, err := c.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err == nil && aws.ToBool(status.IsLogging) {
			activeTrails++
		} else if inactiveTrailName == "" && trail.Name != nil {
			inactiveTrailName = *trail.Name
		}
	}

	if activeTrails == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "CloudTrail Logging Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("CloudTrail exists but is NOT logging! (%d trails configured, 0 active)", len(trails.Trails)),
			Remediation:       fmt.Sprintf("Start logging on: %s", inactiveTrailName),
			RemediationDetail: fmt.Sprintf("aws cloudtrail start-logging --name %s", inactiveTrailName),
			ScreenshotGuide:   "1. Go to CloudTrail → Trails\n2. Click on your trail\n3. Click 'Start logging'\n4. Screenshot showing 'Logging: ON'",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:         "CC7.1",
		Name:            "CloudTrail Logging Enabled",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("%d CloudTrail(s) actively logging API calls", activeTrails),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Screenshot showing your trail(s) with 'Logging: ON'\n3. Click into trail and screenshot configuration",
		ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
	}, nil
}

func (c *CloudTrailChecks) CheckMultiRegion(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	multiRegionTrails := 0
	singleRegionTrail := ""
	for _, trail := range trails.Trails {
		// Get trail details
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].IsMultiRegionTrail) {
				multiRegionTrails++
			} else if singleRegionTrail == "" && details.TrailList[0].Name != nil {
				singleRegionTrail = *details.TrailList[0].Name
			}
		}
	}

	if multiRegionTrails == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "Multi-Region CloudTrail",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "CloudTrail only logs current region - missing activity in other regions",
			Remediation:       fmt.Sprintf("Enable multi-region on: %s", singleRegionTrail),
			RemediationDetail: fmt.Sprintf("aws cloudtrail update-trail --name %s --is-multi-region-trail", singleRegionTrail),
			ScreenshotGuide:   "1. Go to CloudTrail → Trails\n2. Click your trail\n3. Screenshot showing 'Multi-region trail: Yes'\n4. This catches attackers using other regions",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.1",
		Name:      "Multi-Region CloudTrail",
		Status:    "PASS",
		Evidence:  "CloudTrail configured to log all regions",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *CloudTrailChecks) CheckLogFileValidation(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	validationEnabled := 0
	noValidationTrail := ""
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].LogFileValidationEnabled) {
				validationEnabled++
			} else if noValidationTrail == "" && details.TrailList[0].Name != nil {
				noValidationTrail = *details.TrailList[0].Name
			}
		}
	}

	if validationEnabled == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "CloudTrail Log Integrity",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "Log file validation disabled - logs could be tampered with",
			Remediation:       fmt.Sprintf("Enable validation on: %s", noValidationTrail),
			RemediationDetail: fmt.Sprintf("aws cloudtrail update-trail --name %s --enable-log-file-validation", noValidationTrail),
			ScreenshotGuide:   "1. Go to CloudTrail → Trails → Your Trail\n2. Screenshot showing 'Log file validation: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.1",
		Name:      "CloudTrail Log Integrity",
		Status:    "PASS",
		Evidence:  "Log file validation enabled to prevent tampering",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}
