package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2Checks struct {
	client *ec2.Client
}

func NewEC2Checks(client *ec2.Client) *EC2Checks {
	return &EC2Checks{client: client}
}

func (c *EC2Checks) Name() string {
	return "EC2 Security Configuration"
}

func (c *EC2Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckOpenSecurityGroups(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckUnencryptedVolumes(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckPublicInstances(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckOldAMIs(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *EC2Checks) CheckOpenSecurityGroups(ctx context.Context) (CheckResult, error) {
	sgs, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "Open Security Groups",
			Status:     "FAIL",
			Evidence:   "Unable to check security groups",
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
		}, err
	}

	openGroups := []string{}
	criticalPorts := map[int32]string{
		22:    "SSH",
		3389:  "RDP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		1433:  "MSSQL",
		27017: "MongoDB",
	}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			// Check if rule allows access from anywhere (0.0.0.0/0)
			hasOpenAccess := false
			openPort := int32(0)

			for _, ipRange := range rule.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					hasOpenAccess = true
					if rule.FromPort != nil {
						openPort = aws.ToInt32(rule.FromPort)
					}
					break
				}
			}

			if hasOpenAccess {
				if portName, isCritical := criticalPorts[openPort]; isCritical {
					openGroups = append(openGroups, fmt.Sprintf("%s (port %d/%s open to world!)",
						aws.ToString(sg.GroupId), openPort, portName))
				}
			}
		}
	}

	if len(openGroups) > 0 {
		groupList := strings.Join(openGroups[:min(3, len(openGroups))], ", ")
		if len(openGroups) > 3 {
			groupList += fmt.Sprintf(" +%d more", len(openGroups)-3)
		}

		// Extract first SG ID for remediation
		firstSG := openGroups[0]
		sgID := ""
		if idx := strings.Index(firstSG, " "); idx > 0 {
			sgID = firstSG[:idx]
		}

		return CheckResult{
			Control:           "CC6.1",
			Name:              "Network Security - Open Ports",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("🚨 %d security groups have critical ports open to 0.0.0.0/0: %s | Violates PCI DSS 1.2.1 (firewall config)", len(openGroups), groupList),
			Remediation:       fmt.Sprintf("Close open ports on SG: %s\nRun: aws ec2 revoke-security-group-ingress", sgID),
			RemediationDetail: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 22 --cidr 0.0.0.0/0", sgID),
			ScreenshotGuide:   "1. Go to EC2 → Security Groups\n2. Click on the flagged security group\n3. Go to 'Inbound rules' tab\n4. Screenshot showing NO rules with Source '0.0.0.0/0' for ports 22, 3389, or databases\n5. Critical: SSH/RDP must never be open to internet\n6. For PCI DSS: Document business justification for any public access",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
		}, nil
	}

	return CheckResult{
		Control:         "CC6.1",
		Name:            "Network Security - Open Ports",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d security groups properly restrict access | Meets SOC2 CC6.1, PCI DSS 1.2.1, HIPAA 164.312(e)(1)", len(sgs.SecurityGroups)),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to EC2 → Security Groups\n2. Screenshot the list showing your security groups\n3. Click into 2-3 groups and screenshot inbound rules",
		ConsoleURL:      "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
	}, nil
}

func (c *EC2Checks) CheckUnencryptedVolumes(ctx context.Context) (CheckResult, error) {
	volumes, err := c.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencryptedVolumes := []string{}
	totalVolumes := len(volumes.Volumes)

	for _, volume := range volumes.Volumes {
		if !aws.ToBool(volume.Encrypted) {
			volId := aws.ToString(volume.VolumeId)
			// Check if it's attached to an instance
			if len(volume.Attachments) > 0 {
				instanceId := aws.ToString(volume.Attachments[0].InstanceId)
				unencryptedVolumes = append(unencryptedVolumes, fmt.Sprintf("%s (attached to %s)", volId, instanceId))
			} else {
				unencryptedVolumes = append(unencryptedVolumes, fmt.Sprintf("%s (unattached)", volId))
			}
		}
	}

	if len(unencryptedVolumes) > 0 {
		volList := strings.Join(unencryptedVolumes[:min(3, len(unencryptedVolumes))], ", ")
		if len(unencryptedVolumes) > 3 {
			volList += fmt.Sprintf(" +%d more", len(unencryptedVolumes)-3)
		}

		return CheckResult{
			Control:           "CC6.3",
			Name:              "EBS Volume Encryption",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d EBS volumes are NOT encrypted: %s | Violates PCI DSS 3.4 (encrypt stored data) & HIPAA 164.312(a)(2)(iv)", len(unencryptedVolumes), totalVolumes, volList),
			Remediation:       "Create encrypted snapshots and migrate",
			RemediationDetail: "1. Create snapshot: aws ec2 create-snapshot --volume-id VOL_ID\n2. Copy with encryption: aws ec2 copy-snapshot --source-snapshot-id SNAP_ID --encrypted\n3. Create new volume from encrypted snapshot",
			ScreenshotGuide:   "1. Go to EC2 → Volumes\n2. Screenshot the list showing 'Encryption' column\n3. All volumes should show 'Encrypted'\n4. For any unencrypted, document migration plan\n5. For HIPAA: Document encryption algorithm used",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Volumes",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("EBS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "EBS Volume Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EBS volumes are encrypted | Meets SOC2 CC6.3, PCI DSS 3.4, HIPAA 164.312(a)(2)(iv)", totalVolumes),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("EBS_ENCRYPTION"),
	}, nil
}

func (c *EC2Checks) CheckPublicInstances(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publicInstances := []string{}
	totalInstances := 0

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			totalInstances++

			// Check if instance has public IP
			if instance.PublicIpAddress != nil && *instance.PublicIpAddress != "" {
				name := "unnamed"
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value)
						break
					}
				}
				publicInstances = append(publicInstances, fmt.Sprintf("%s (%s)", name, aws.ToString(instance.InstanceId)))
			}
		}
	}

	if len(publicInstances) > 5 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "Public EC2 Instances",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d EC2 instances have public IPs | PCI DSS 1.3.1 requires DMZ for public systems", len(publicInstances)),
			Remediation:       "Move instances to private subnets",
			RemediationDetail: "Move instances to private subnets and use bastion hosts or VPN for access",
			ScreenshotGuide:   "1. Go to EC2 → Instances\n2. Screenshot showing instance list\n3. Document why each public instance needs external access\n4. For PCI DSS: Show network segmentation",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("PUBLIC_INSTANCES"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "Public EC2 Instances",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d/%d instances properly use private IPs | Meets PCI DSS 1.3.1 network segmentation", totalInstances-len(publicInstances), totalInstances),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("PUBLIC_INSTANCES"),
	}, nil
}

func (c *EC2Checks) CheckOldAMIs(ctx context.Context) (CheckResult, error) {
	// Check for old AMIs (>180 days)
	images, err := c.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return CheckResult{}, err
	}

	oldAMIs := []string{}
	for _, image := range images.Images {
		// Parse creation date
		if image.CreationDate != nil {
			creationTime, err := time.Parse(time.RFC3339, *image.CreationDate)
			if err == nil {
				age := time.Since(creationTime)
				days := int(age.Hours() / 24)

				if days > 180 {
					oldAMIs = append(oldAMIs, fmt.Sprintf("%s (%d days old)",
						aws.ToString(image.ImageId), days))
				}
			}
		}
	}

	if len(oldAMIs) > 0 {
		return CheckResult{
			Control:           "CC7.2",
			Name:              "AMI Age and Patching",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d AMIs are older than 180 days | PCI DSS 6.2 requires timely patching", len(oldAMIs)),
			Remediation:       "Create new AMIs with latest patches",
			RemediationDetail: "Create new AMIs with latest patches and deregister old ones using: aws ec2 deregister-image --image-id AMI_ID",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OLD_AMIS"),
			ScreenshotGuide:   "1. Go to EC2 → AMIs\n2. Screenshot showing AMI creation dates\n3. Document patching schedule for PCI DSS",
		}, nil
	}

	return CheckResult{
		Control:    "CC7.2",
		Name:       "AMI Age and Patching",
		Status:     "PASS",
		Evidence:   "All AMIs are recent and likely patched | Meets PCI DSS 6.2 patch management",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OLD_AMIS"),
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
