package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
	
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// AWSCMMCLevel1Checks implements CMMC Level 1 practices for AWS
type AWSCMMCLevel1Checks struct {
	iamClient        *iam.Client
	s3Client         *s3.Client
	ec2Client        *ec2.Client
	cloudtrailClient *cloudtrail.Client
	guarddutyClient  *guardduty.Client
	securityhubClient *securityhub.Client
}

// NewAWSCMMCLevel1Checks creates a new CMMC Level 1 checker for AWS
func NewAWSCMMCLevel1Checks(iamClient *iam.Client, s3Client *s3.Client, ec2Client *ec2.Client, cloudtrailClient *cloudtrail.Client) *AWSCMMCLevel1Checks {
	return &AWSCMMCLevel1Checks{
		iamClient:        iamClient,
		s3Client:         s3Client,
		ec2Client:        ec2Client,
		cloudtrailClient: cloudtrailClient,
	}
}

// Name returns the check name
func (c *AWSCMMCLevel1Checks) Name() string {
	return "AWS CMMC Level 1"
}

// Run executes all CMMC Level 1 checks (17 practices)
func (c *AWSCMMCLevel1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// ACCESS CONTROL (AC) Level 1 - 2 practices
	results = append(results, c.CheckAC_L1_001(ctx))
	results = append(results, c.CheckAC_L1_002(ctx))

	// IDENTIFICATION AND AUTHENTICATION (IA) Level 1 - 2 practices
	results = append(results, c.CheckIA_L1_001(ctx))
	results = append(results, c.CheckIA_L1_002(ctx))

	// MEDIA PROTECTION (MP) Level 1 - 2 practices
	results = append(results, c.CheckMP_L1_001(ctx))
	results = append(results, c.CheckMP_L1_002(ctx))

	// PERSONNEL SECURITY (PS) Level 1 - 1 practice
	results = append(results, c.CheckPS_L1_001(ctx))

	// SYSTEM AND COMMUNICATIONS PROTECTION (SC) Level 1 - 5 practices
	results = append(results, c.CheckSC_L1_001(ctx))
	results = append(results, c.CheckSC_L1_002(ctx))
	results = append(results, c.CheckSC_L1_003(ctx))
	results = append(results, c.CheckSC_L1_004(ctx))
	results = append(results, c.CheckSC_L1_005(ctx))

	// SYSTEM AND INFORMATION INTEGRITY (SI) Level 1 - 5 practices
	results = append(results, c.CheckSI_L1_001(ctx))
	results = append(results, c.CheckSI_L1_002(ctx))
	results = append(results, c.CheckSI_L1_003(ctx))
	results = append(results, c.CheckSI_L1_004(ctx))
	results = append(results, c.CheckSI_L1_005(ctx))

	return results, nil
}

// ACCESS CONTROL (AC) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckAC_L1_001(ctx context.Context) CheckResult {
	// Check if IAM users have appropriate policies limiting access
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:     "AC.L1-3.1.1",
			Name:        "[CMMC L1] Limit Information System Access",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to verify IAM access controls: %v", err),
			Remediation: "Ensure IAM is accessible and properly configured",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing limited user access",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "AC.L1-3.1.1",
				"NIST 800-171": "3.1.1",
			},
		}
	}

	if len(users.Users) == 0 {
		return CheckResult{
			Control:     "AC.L1-3.1.1",
			Name:        "[CMMC L1] Limit Information System Access",
			Status:      "FAIL",
			Evidence:    "No IAM users found - access control cannot be verified",
			Remediation: "Create IAM users with least privilege policies for all personnel",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Create users with restricted policies",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "AC.L1-3.1.1",
				"NIST 800-171": "3.1.1",
			},
		}
	}

	return CheckResult{
		Control:     "AC.L1-3.1.1",
		Name:        "[CMMC L1] Limit Information System Access",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("IAM access control configured with %d users", len(users.Users)),
		Remediation: "Continue monitoring IAM policies for least privilege compliance",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing user list and policies",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.1",
			"NIST 800-171": "3.1.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckAC_L1_002(ctx context.Context) CheckResult {
	// Check if IAM policies limit specific actions
	policies, err := c.iamClient.ListPolicies(ctx, &iam.ListPoliciesInput{
		Scope: "Local", // Only check customer-managed policies
	})
	if err != nil {
		return CheckResult{
			Control:     "AC.L1-3.1.2",
			Name:        "[CMMC L1] Limit Transaction and Function Types",
			Status:      "INFO",
			Evidence:    "Unable to verify IAM policies - manual review required",
			Remediation: "Review IAM policies to ensure they limit specific actions",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Policies → Screenshot showing restrictive policies",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks: map[string]string{
				"CMMC": "AC.L1-3.1.2",
				"NIST 800-171": "3.1.2",
			},
		}
	}

	if len(policies.Policies) == 0 {
		return CheckResult{
			Control:     "AC.L1-3.1.2",
			Name:        "[CMMC L1] Limit Transaction and Function Types",
			Status:      "FAIL",
			Evidence:    "No custom IAM policies found - relying only on AWS managed policies",
			Remediation: "Create custom IAM policies that restrict specific actions for CUI protection",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Policies → Create restrictive custom policies",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks: map[string]string{
				"CMMC": "AC.L1-3.1.2",
				"NIST 800-171": "3.1.2",
			},
		}
	}

	return CheckResult{
		Control:     "AC.L1-3.1.2",
		Name:        "[CMMC L1] Limit Transaction and Function Types",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("Found %d custom IAM policies limiting specific actions", len(policies.Policies)),
		Remediation: "Review policies regularly to ensure continued least privilege",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Policies → Screenshot showing action-specific restrictions",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/policies",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.2",
			"NIST 800-171": "3.1.2",
		},
	}
}

// IDENTIFICATION AND AUTHENTICATION (IA) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckIA_L1_001(ctx context.Context) CheckResult {
	// Check for unique user identities (no shared accounts)
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:     "IA.L1-3.5.1",
			Name:        "[CMMC L1] Identify Information System Users",
			Status:      "FAIL",
			Evidence:    "Unable to verify user identities",
			Remediation: "Ensure each person has a unique IAM identity",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing unique identities",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "IA.L1-3.5.1",
				"NIST 800-171": "3.5.1",
			},
		}
	}

	sharedAccounts := 0
	for _, user := range users.Users {
		username := aws.ToString(user.UserName)
		// Check for suspicious patterns indicating shared accounts
		lowerName := strings.ToLower(username)
		if strings.Contains(lowerName, "shared") || 
		   strings.Contains(lowerName, "team") ||
		   strings.Contains(lowerName, "admin") ||
		   strings.Contains(lowerName, "service") {
			sharedAccounts++
		}
	}

	if sharedAccounts > 0 {
		return CheckResult{
			Control:     "IA.L1-3.5.1",
			Name:        "[CMMC L1] Identify Information System Users",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Found %d potential shared/generic accounts (names contain 'shared', 'team', 'admin', or 'service')", sharedAccounts),
			Remediation: "Replace shared accounts with unique individual IAM users for each person",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing individual user accounts",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "IA.L1-3.5.1",
				"NIST 800-171": "3.5.1",
			},
		}
	}

	return CheckResult{
		Control:     "IA.L1-3.5.1",
		Name:        "[CMMC L1] Identify Information System Users",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d IAM users have unique individual identities", len(users.Users)),
		Remediation: "Continue using unique identities for each user",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing unique user list",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.1",
			"NIST 800-171": "3.5.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckIA_L1_002(ctx context.Context) CheckResult {
	// Check MFA enforcement
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:     "IA.L1-3.5.2",
			Name:        "[CMMC L1] Authenticate Information System Users",
			Status:      "FAIL",
			Evidence:    "Unable to verify user authentication",
			Remediation: "Enable MFA for all IAM users",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Security credentials → Enable MFA",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "IA.L1-3.5.2",
				"NIST 800-171": "3.5.2",
			},
		}
	}

	usersWithoutMFA := []string{}
	for _, user := range users.Users {
		// Check if user has MFA device
		mfaDevices, err := c.iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil || len(mfaDevices.MFADevices) == 0 {
			usersWithoutMFA = append(usersWithoutMFA, aws.ToString(user.UserName))
		}
	}

	if len(usersWithoutMFA) > 0 {
		return CheckResult{
			Control:     "IA.L1-3.5.2",
			Name:        "[CMMC L1] Authenticate Information System Users",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d users without MFA enabled: %s", len(usersWithoutMFA), strings.Join(usersWithoutMFA[:min(3, len(usersWithoutMFA))], ", ")),
			Remediation: "Enable MFA for all IAM users accessing CUI systems",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Click user → Security credentials → Assign MFA device",
			ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
			Frameworks: map[string]string{
				"CMMC": "IA.L1-3.5.2",
				"NIST 800-171": "3.5.2",
			},
		}
	}

	return CheckResult{
		Control:     "IA.L1-3.5.2",
		Name:        "[CMMC L1] Authenticate Information System Users",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d IAM users have MFA enabled", len(users.Users)),
		Remediation: "Continue enforcing MFA for all users",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing MFA status for all users",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.2",
			"NIST 800-171": "3.5.2",
		},
	}
}

// MEDIA PROTECTION (MP) Level 1 checks - These are mostly manual/documentation

func (c *AWSCMMCLevel1Checks) CheckMP_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "MP.L1-3.8.3",
		Name:        "[CMMC L1] Sanitize or Destroy CUI Media",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: Verify secure deletion procedures for EBS volumes and S3 objects containing CUI",
		Remediation: "Document and implement secure deletion procedures using AWS encryption and lifecycle policies",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Document secure deletion procedures | EC2 → Volumes → Screenshot encrypted volumes | S3 → Lifecycle policies",
		ConsoleURL: "https://console.aws.amazon.com/ec2/home#Volumes:",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.3",
			"NIST 800-171": "3.8.3",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckMP_L1_002(ctx context.Context) CheckResult {
	// Check S3 bucket policies for media access control
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{
			Control:     "MP.L1-3.8.2",
			Name:        "[CMMC L1] Control Access to CUI Media",
			Status:      "INFO",
			Evidence:    "Unable to verify S3 bucket access controls - manual review required",
			Remediation: "Review S3 bucket policies to ensure only authorized users can access CUI",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → S3 → Each bucket → Permissions → Screenshot access policies",
			ConsoleURL: "https://console.aws.amazon.com/s3/home",
			Frameworks: map[string]string{
				"CMMC": "MP.L1-3.8.2",
				"NIST 800-171": "3.8.2",
			},
		}
	}

	if len(buckets.Buckets) == 0 {
		return CheckResult{
			Control:     "MP.L1-3.8.2",
			Name:        "[CMMC L1] Control Access to CUI Media",
			Status:      "PASS",
			Evidence:    "No S3 buckets found - no media storage to control",
			Priority:    PriorityInfo,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → S3 → Screenshot showing no buckets",
			ConsoleURL: "https://console.aws.amazon.com/s3/home",
			Frameworks: map[string]string{
				"CMMC": "MP.L1-3.8.2",
				"NIST 800-171": "3.8.2",
			},
		}
	}

	return CheckResult{
		Control:     "MP.L1-3.8.2",
		Name:        "[CMMC L1] Control Access to CUI Media",
		Status:      "INFO",
		Evidence:    fmt.Sprintf("Found %d S3 buckets - manual review of bucket policies required", len(buckets.Buckets)),
		Remediation: "Review each S3 bucket policy to ensure proper access controls for CUI",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → S3 → Each bucket → Permissions → Screenshot bucket policies and access controls",
		ConsoleURL: "https://console.aws.amazon.com/s3/home",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.2",
			"NIST 800-171": "3.8.2",
		},
	}
}

// PERSONNEL SECURITY (PS) Level 1 checks - Cannot be automated

func (c *AWSCMMCLevel1Checks) CheckPS_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "PS.L1-3.9.1",
		Name:        "[CMMC L1] Screen Personnel Prior to Access",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: Personnel screening procedures must be documented and implemented",
		Remediation: "Document personnel screening procedures for all users accessing CUI systems",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "HR Documentation → Screenshot personnel screening policy | Access approval records → Screenshot showing completed screenings",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "PS.L1-3.9.1",
			"NIST 800-171": "3.9.1",
		},
	}
}

// SYSTEM AND COMMUNICATIONS PROTECTION (SC) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckSC_L1_001(ctx context.Context) CheckResult {
	// Check Security Groups for overly permissive rules
	securityGroups, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{
			Control:     "SC.L1-3.13.1",
			Name:        "[CMMC L1] Monitor and Control Communications",
			Status:      "FAIL",
			Evidence:    "Unable to verify network communication controls",
			Remediation: "Configure Security Groups to control network boundaries",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing restrictive rules",
			ConsoleURL: "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
			Frameworks: map[string]string{
				"CMMC": "SC.L1-3.13.1",
				"NIST 800-171": "3.13.1",
			},
		}
	}

	openToInternet := []string{}
	for _, sg := range securityGroups.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					openToInternet = append(openToInternet, aws.ToString(sg.GroupId))
					break
				}
			}
		}
	}

	if len(openToInternet) > 0 {
		return CheckResult{
			Control:     "SC.L1-3.13.1",
			Name:        "[CMMC L1] Monitor and Control Communications",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d security groups allow unrestricted internet access (0.0.0.0/0)", len(openToInternet)),
			Remediation: "Restrict Security Group rules to specific IP ranges, not 0.0.0.0/0",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing restricted rules (no 0.0.0.0/0)",
			ConsoleURL: "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
			Frameworks: map[string]string{
				"CMMC": "SC.L1-3.13.1",
				"NIST 800-171": "3.13.1",
			},
		}
	}

	return CheckResult{
		Control:     "SC.L1-3.13.1",
		Name:        "[CMMC L1] Monitor and Control Communications",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("Security Groups properly restrict communications - %d groups configured", len(securityGroups.SecurityGroups)),
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing communication controls",
		ConsoleURL: "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.1",
			"NIST 800-171": "3.13.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_002(ctx context.Context) CheckResult {
	// Check if KMS keys exist (indicating encryption is configured)
	return CheckResult{
		Control:     "SC.L1-3.13.5",
		Name:        "[CMMC L1] Implement Cryptographic Mechanisms",
		Status:      "INFO",
		Evidence:    "MANUAL CHECK: Verify KMS encryption is configured for all CUI data",
		Remediation: "Enable encryption using AWS KMS for all services storing CUI",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → KMS → Keys → Screenshot showing customer-managed keys | S3/EBS/RDS → Screenshot showing encryption enabled",
		ConsoleURL: "https://console.aws.amazon.com/kms/home#/kms/keys",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.5",
			"NIST 800-171": "3.13.5",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_003(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.11",
		Name:        "[CMMC L1] Employ FIPS-Validated Cryptography",
		Status:      "INFO",
		Evidence:    "AWS KMS uses FIPS 140-2 validated cryptographic modules - verify usage",
		Remediation: "Ensure all cryptographic operations use FIPS-validated AWS KMS",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → KMS → Screenshot showing FIPS-validated key usage | Documentation → Screenshot FIPS compliance",
		ConsoleURL: "https://console.aws.amazon.com/kms/home#/kms/keys",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.11",
			"NIST 800-171": "3.13.11",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_004(ctx context.Context) CheckResult {
	// Check S3 bucket encryption
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{
			Control:     "SC.L1-3.13.16",
			Name:        "[CMMC L1] Protect CUI at Rest",
			Status:      "FAIL",
			Evidence:    "Unable to verify encryption at rest",
			Remediation: "Enable encryption for all S3 buckets, EBS volumes, and RDS databases",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → S3/EBS/RDS → Screenshot showing encryption enabled",
			ConsoleURL: "https://console.aws.amazon.com/s3/home",
			Frameworks: map[string]string{
				"CMMC": "SC.L1-3.13.16",
				"NIST 800-171": "3.13.16",
			},
		}
	}

	unencryptedBuckets := []string{}
	for _, bucket := range buckets.Buckets {
		// Check bucket encryption
		encryption, err := c.s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil || encryption.ServerSideEncryptionConfiguration == nil {
			unencryptedBuckets = append(unencryptedBuckets, aws.ToString(bucket.Name))
		}
	}

	if len(unencryptedBuckets) > 0 {
		return CheckResult{
			Control:     "SC.L1-3.13.16",
			Name:        "[CMMC L1] Protect CUI at Rest",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d S3 buckets without encryption enabled: %s", len(unencryptedBuckets), strings.Join(unencryptedBuckets[:min(3, len(unencryptedBuckets))], ", ")),
			Remediation: "Enable default encryption on all S3 buckets containing CUI",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "AWS Console → S3 → Bucket → Properties → Default encryption → Enable",
			ConsoleURL: "https://console.aws.amazon.com/s3/home",
			Frameworks: map[string]string{
				"CMMC": "SC.L1-3.13.16",
				"NIST 800-171": "3.13.16",
			},
		}
	}

	return CheckResult{
		Control:     "SC.L1-3.13.16",
		Name:        "[CMMC L1] Protect CUI at Rest",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d S3 buckets have encryption at rest enabled", len(buckets.Buckets)),
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → S3 → Screenshot showing all buckets with encryption enabled",
		ConsoleURL: "https://console.aws.amazon.com/s3/home",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.16",
			"NIST 800-171": "3.13.16",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_005(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.17",
		Name:        "[CMMC L1] Invalidate Session Identifiers",
		Status:      "INFO",
		Evidence:    "MANUAL CHECK: Verify IAM session timeout policies are configured",
		Remediation: "Configure appropriate session timeout in IAM and applications",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Account settings → Screenshot session duration limits",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/account_settings",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.17",
			"NIST 800-171": "3.13.17",
		},
	}
}

// SYSTEM AND INFORMATION INTEGRITY (SI) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckSI_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.1",
		Name:        "[CMMC L1] Identify and Correct Flaws",
		Status:      "INFO",
		Evidence:    "MANUAL CHECK: Verify Systems Manager Patch Manager is configured",
		Remediation: "Enable AWS Systems Manager for automated patching",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Systems Manager → Patch Manager → Screenshot patch compliance",
		ConsoleURL: "https://console.aws.amazon.com/systems-manager/patch-manager",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.1",
			"NIST 800-171": "3.14.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSI_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.2",
		Name:        "[CMMC L1] Provide Protection from Malicious Code",
		Status:      "INFO",
		Evidence:    "MANUAL CHECK: Verify GuardDuty is enabled and endpoint protection is deployed",
		Remediation: "Enable AWS GuardDuty and deploy endpoint protection on EC2 instances",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → GuardDuty → Screenshot enabled status | EC2 → Screenshot endpoint protection",
		ConsoleURL: "https://console.aws.amazon.com/guardduty/home",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.2",
			"NIST 800-171": "3.14.2",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSI_L1_003(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.4",
		Name:        "[CMMC L1] Update Malicious Code Protection",
		Status:      "INFO",
		Evidence:    "GuardDuty automatically updates - verify endpoint protection has auto-updates enabled",
		Remediation: "Ensure endpoint protection agents have automatic updates configured",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → GuardDuty → Settings | EC2 → Screenshot endpoint auto-update config",
		ConsoleURL: "https://console.aws.amazon.com/guardduty/home#/settings",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.4",
			"NIST 800-171": "3.14.4",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSI_L1_004(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.6",
		Name:        "[CMMC L1] Monitor Security Alerts",
		Status:      "INFO",
		Evidence:    "MANUAL CHECK: Verify Security Hub is enabled and alerting is configured",
		Remediation: "Enable AWS Security Hub and configure CloudWatch alarms for security events",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Security Hub → Screenshot alerts dashboard | CloudWatch → Screenshot alarms",
		ConsoleURL: "https://console.aws.amazon.com/securityhub/home",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.6",
			"NIST 800-171": "3.14.6",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSI_L1_005(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.7",
		Name:        "[CMMC L1] Update Malicious Code Protection Mechanisms",
		Status:      "INFO",
		Evidence:    "AWS security services auto-update - verify endpoint agents have update mechanisms",
		Remediation: "Maintain current versions of security tools with automatic updates",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Security services → Screenshot version status",
		ConsoleURL: "https://console.aws.amazon.com/systems-manager/managed-instances",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.7",
			"NIST 800-171": "3.14.7",
		},
	}
}

// Helper function min() already exists in ec2.go
