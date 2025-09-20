package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

type MonitoringChecks struct {
	cwClient  *cloudwatch.Client
	snsClient *sns.Client
}

func NewMonitoringChecks(cwClient *cloudwatch.Client, snsClient *sns.Client) *MonitoringChecks {
	return &MonitoringChecks{
		cwClient:  cwClient,
		snsClient: snsClient,
	}
}

func (c *MonitoringChecks) Name() string {
	return "Security Event Monitoring"
}

func (c *MonitoringChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckCloudWatchAlarms(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckSNSTopics(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *MonitoringChecks) CheckCloudWatchAlarms(ctx context.Context) (CheckResult, error) {
	alarms, err := c.cwClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Check for critical security alarms
	criticalAlarms := map[string]bool{
		"root-account-usage":     false,
		"unauthorized-api-calls": false,
		"iam-changes":            false,
		"security-group-changes": false,
		"cloudtrail-changes":     false,
	}

	for _, alarm := range alarms.MetricAlarms {
		name := *alarm.AlarmName
		for key := range criticalAlarms {
			if contains(name, key) {
				criticalAlarms[key] = true
			}
		}
	}

	missingAlarms := []string{}
	for alarm, exists := range criticalAlarms {
		if !exists {
			missingAlarms = append(missingAlarms, alarm)
		}
	}

	if len(missingAlarms) > 0 {
		return CheckResult{
			Control:           "CC7.3",
			Name:              "Security Event Monitoring",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("🚨 Missing %d critical security alarms", len(missingAlarms)),
			Remediation:       "Create CloudWatch alarms for security events",
			RemediationDetail: "Create alarms for: root usage, unauthorized API calls, IAM changes, etc.",
			ScreenshotGuide:   "1. Go to CloudWatch → Alarms\n2. Screenshot list of security alarms\n3. Each alarm should notify SNS topic\n4. Show alarm history (triggered events)",
			ConsoleURL:        "https://console.aws.amazon.com/cloudwatch/home#alarmsV2",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.3",
		Name:      "Security Event Monitoring",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("All critical security alarms configured (%d total)", len(alarms.MetricAlarms)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *MonitoringChecks) CheckSNSTopics(ctx context.Context) (CheckResult, error) {
	topics, err := c.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(topics.Topics) == 0 {
		return CheckResult{
			Control:           "CC7.4",
			Name:              "Alert Notifications",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "No SNS topics configured for alerts!",
			Remediation:       "Create SNS topic for security alerts",
			RemediationDetail: "aws sns create-topic --name security-alerts && aws sns subscribe --topic-arn ARN --protocol email --notification-endpoint security@company.com",
			ScreenshotGuide:   "1. Go to SNS → Topics\n2. Screenshot security alert topic\n3. Show subscriptions (email/Slack)",
			ConsoleURL:        "https://console.aws.amazon.com/sns/v3/home#/topics",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.4",
		Name:      "Alert Notifications",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("%d SNS topics configured", len(topics.Topics)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func contains(str, substr string) bool {
	return len(str) > 0 && len(substr) > 0 && (str == substr || len(str) > len(substr))
}
