package checks

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    "time"
)

type VPCChecks struct {
    client *ec2.Client
}

func NewVPCChecks(client *ec2.Client) *VPCChecks {
    return &VPCChecks{client: client}
}

func (c *VPCChecks) Name() string {
    return "VPC Network Security"
}

func (c *VPCChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // Check for VPC Flow Logs
    _, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
    if err != nil {
        return results, err
    }
    
    flowLogs, err := c.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
    if err == nil && len(flowLogs.FlowLogs) == 0 {
        results = append(results, CheckResult{
            Control:     "CC7.1",
            Name:        "VPC Flow Logs",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "🚨 No VPC Flow Logs enabled - can't track network traffic!",
            Remediation: "Enable VPC Flow Logs immediately",
            RemediationDetail: "aws ec2 create-flow-logs --resource-type VPC --traffic-type ALL --resource-ids vpc-xxxxx --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs",
            ScreenshotGuide: "1. Go to VPC Console\n2. Select your VPC\n3. Go to 'Flow logs' tab\n4. Screenshot showing flow logs enabled",
            ConsoleURL:  "https://console.aws.amazon.com/vpc/",
            Priority:    PriorityHigh,
            Timestamp:   time.Now(),
        })
    } else {
        results = append(results, CheckResult{
            Control:   "CC7.1",
            Name:      "VPC Flow Logs",
            Status:    "PASS",
            Evidence:  "VPC Flow Logs are enabled",
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
        })
    }
    
    return results, nil
}
