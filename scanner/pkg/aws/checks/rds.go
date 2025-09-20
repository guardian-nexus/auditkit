package checks

import (
    "context"
    "fmt"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/rds"
    "time"
)

type RDSChecks struct {
    client *rds.Client
}

func NewRDSChecks(client *rds.Client) *RDSChecks {
    return &RDSChecks{client: client}
}

func (c *RDSChecks) Name() string {
    return "RDS Database Security"
}

func (c *RDSChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // Check RDS encryption
    instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
    if err != nil {
        return results, err
    }
    
    unencrypted := []string{}
    publiclyAccessible := []string{}
    noBackups := []string{}
    
    for _, instance := range instances.DBInstances {
        dbName := aws.ToString(instance.DBInstanceIdentifier)
        
        // Check encryption
        if !aws.ToBool(instance.StorageEncrypted) {
            unencrypted = append(unencrypted, dbName)
        }
        
        // Check public accessibility
        if aws.ToBool(instance.PubliclyAccessible) {
            publiclyAccessible = append(publiclyAccessible, dbName)
        }
        
        // Check backup retention
        if aws.ToInt32(instance.BackupRetentionPeriod) < 7 {
            noBackups = append(noBackups, fmt.Sprintf("%s (%d days)", dbName, aws.ToInt32(instance.BackupRetentionPeriod)))
        }
    }
    
    // Add encryption check result
    if len(unencrypted) > 0 {
        results = append(results, CheckResult{
            Control:     "CC6.3",
            Name:        "RDS Encryption at Rest",
            Status:      "FAIL",
            Severity:    "CRITICAL",
            Evidence:    fmt.Sprintf("🚨 %d RDS instances NOT encrypted: %s", len(unencrypted), unencrypted[0]),
            Remediation: "Enable RDS encryption (requires snapshot & restore)",
            RemediationDetail: "1. Create snapshot\n2. Copy snapshot with encryption\n3. Restore from encrypted snapshot",
            ScreenshotGuide: "1. Go to RDS Console\n2. Click on instance\n3. Screenshot 'Configuration' tab showing encryption status",
            ConsoleURL:  "https://console.aws.amazon.com/rds/",
            Priority:    PriorityCritical,
            Timestamp:   time.Now(),
        })
    } else if len(instances.DBInstances) > 0 {
        results = append(results, CheckResult{
            Control:   "CC6.3",
            Name:      "RDS Encryption at Rest",
            Status:    "PASS",
            Evidence:  fmt.Sprintf("All %d RDS instances are encrypted", len(instances.DBInstances)),
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
        })
    }
    
    // Add public access check
    if len(publiclyAccessible) > 0 {
        results = append(results, CheckResult{
            Control:     "CC6.1",
            Name:        "RDS Public Access",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("%d RDS instances are publicly accessible!", len(publiclyAccessible)),
            Remediation: "Disable public access on RDS instances",
            Priority:    PriorityHigh,
            Timestamp:   time.Now(),
        })
    }
    
    // Add backup check
    if len(noBackups) > 0 {
        results = append(results, CheckResult{
            Control:     "A1.2",
            Name:        "RDS Backup Retention",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("%d RDS instances have <7 day backup retention", len(noBackups)),
            Remediation: "Set backup retention to 7+ days",
            Priority:    PriorityHigh,
            Timestamp:   time.Now(),
        })
    }
    
    return results, nil
}
