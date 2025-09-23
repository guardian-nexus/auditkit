package checks

import (
	"context"
	"time"
	
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
)

type MonitoringChecks struct {
	client *armmonitor.ActivityLogsClient
}

func NewMonitoringChecks(client *armmonitor.ActivityLogsClient) *MonitoringChecks {
	return &MonitoringChecks{client: client}
}

func (c *MonitoringChecks) Name() string {
	return "Azure Monitoring & Logging"
}

func (c *MonitoringChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}
	
	// Activity Log retention check
	results = append(results, CheckResult{
		Control:           "CC7.1",
		Name:              "Activity Log Configuration",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify Activity Log is exported with retention",
		Remediation:       "Configure Activity Log export to storage/workspace",
		RemediationDetail: "Monitor -> Activity log -> Diagnostic settings -> Add diagnostic setting",
		ScreenshotGuide:   "Monitor -> Activity log -> Diagnostic settings -> Show export configured",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/activityLog",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("ACTIVITY_LOG"),
	})
	
	// PCI-specific 12-month retention
	results = append(results, CheckResult{
		Control:           "PCI-10.5.3",
		Name:              "[PCI-DSS] 12-Month Activity Log Retention",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.5.3: Configure 365+ day retention for Activity Logs",
		Remediation:       "Set retention policy to 365+ days",
		RemediationDetail: "Storage account lifecycle policy or Log Analytics retention",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "10.5.3",
		},
	})
	
	return results, nil
}
