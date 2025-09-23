package checks

import (
	"context"
	"time"
	
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
)

type SQLChecks struct {
    client *armsql.DatabasesClient
}

func NewSQLChecks(client *armsql.DatabasesClient) *SQLChecks {
    return &SQLChecks{client: client}
}

func (c *SQLChecks) Name() string {
    return "Azure SQL Database Security"
}

func (c *SQLChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // SQL TDE check placeholder
    results = append(results, CheckResult{
        Control:           "CC6.3",
        Name:              "SQL Transparent Data Encryption",
        Status:            "INFO",
        Evidence:          "MANUAL CHECK: Verify TDE is enabled for all SQL databases",
        Remediation:       "Enable TDE on all databases",
        RemediationDetail: "SQL Database → Transparent data encryption → Enable",
        ScreenshotGuide:   "Azure SQL → Security → Transparent data encryption → Show enabled",
        Priority:          PriorityHigh,
        Timestamp:         time.Now(),
        Frameworks:        GetFrameworkMappings("SQL_TDE"),
    })
    
    // SQL Auditing for PCI
    results = append(results, CheckResult{
        Control:           "PCI-10.2",
        Name:              "[PCI-DSS] SQL Database Auditing",
        Status:            "INFO",
        Evidence:          "PCI-DSS 10.2: Verify auditing is enabled for all databases",
        Remediation:       "Enable SQL auditing",
        RemediationDetail: "SQL Database → Auditing → Enable with storage/Log Analytics destination",
        Priority:          PriorityHigh,
        Timestamp:         time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "10.2",
        },
    })
    
    return results, nil
}
