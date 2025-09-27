package checks

import (
	"context"
	"time"
	
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// AWSCMMCLevel1Checks implements CMMC Level 1 practices for AWS
type AWSCMMCLevel1Checks struct {
	iamClient       *iam.Client
	s3Client        *s3.Client
	ec2Client       *ec2.Client
	cloudtrailClient *cloudtrail.Client
}

// NewAWSCMMCLevel1Checks creates a new CMMC Level 1 checker for AWS
func NewAWSCMMCLevel1Checks(iamClient *iam.Client, s3Client *s3.Client, ec2Client *ec2.Client, cloudtrailClient *cloudtrail.Client) *AWSCMMCLevel1Checks {
	return &AWSCMMCLevel1Checks{
		iamClient:       iamClient,
		s3Client:        s3Client,
		ec2Client:       ec2Client,
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
	results = append(results, c.CheckAC_L1_001(ctx))  // Limit information system access
	results = append(results, c.CheckAC_L1_002(ctx))  // Limit information system access to authorized users

	// IDENTIFICATION AND AUTHENTICATION (IA) Level 1 - 2 practices
	results = append(results, c.CheckIA_L1_001(ctx))  // Identify information system users
	results = append(results, c.CheckIA_L1_002(ctx))  // Authenticate information system users

	// MEDIA PROTECTION (MP) Level 1 - 2 practices
	results = append(results, c.CheckMP_L1_001(ctx))  // Sanitize or destroy CUI media
	results = append(results, c.CheckMP_L1_002(ctx))  // Control access to CUI media

	// PERSONNEL SECURITY (PS) Level 1 - 1 practice
	results = append(results, c.CheckPS_L1_001(ctx))  // Screen personnel prior to access

	// SYSTEM AND COMMUNICATIONS PROTECTION (SC) Level 1 - 5 practices
	results = append(results, c.CheckSC_L1_001(ctx))  // Monitor and control communications
	results = append(results, c.CheckSC_L1_002(ctx))  // Implement cryptographic mechanisms
	results = append(results, c.CheckSC_L1_003(ctx))  // Employ FIPS-validated cryptography
	results = append(results, c.CheckSC_L1_004(ctx))  // Protect CUI at rest
	results = append(results, c.CheckSC_L1_005(ctx))  // Invalidate session identifiers

	// SYSTEM AND INFORMATION INTEGRITY (SI) Level 1 - 5 practices
	results = append(results, c.CheckSI_L1_001(ctx))  // Identify and correct flaws
	results = append(results, c.CheckSI_L1_002(ctx))  // Provide protection from malicious code
	results = append(results, c.CheckSI_L1_003(ctx))  // Update malicious code protection
	results = append(results, c.CheckSI_L1_004(ctx))  // Monitor security alerts
	results = append(results, c.CheckSI_L1_005(ctx))  // Update malicious code protection mechanisms

	return results, nil
}

// ACCESS CONTROL (AC) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckAC_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "AC.L1-3.1.1",
		Name:        "[CMMC L1] Limit Information System Access",
		Status:      "INFO",
		Evidence:    "AWS IAM provides access control to limit CUI system access to authorized users only",
		Remediation: "Configure IAM policies with least privilege principles for all CUI resources",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing limited user access | Policies → Screenshot showing restrictive CUI access policies",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.1",
			"NIST 800-171": "3.1.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckAC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "AC.L1-3.1.2",
		Name:        "[CMMC L1] Limit Transaction and Function Types",
		Status:      "INFO",
		Evidence:    "AWS IAM policies limit transaction types and functions that authorized users can execute",
		Remediation: "Implement IAM policies that restrict specific actions and API calls for CUI protection",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Policies → Screenshot showing action-specific restrictions | Users → Permissions → Screenshot showing limited function access",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/policies",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.2",
			"NIST 800-171": "3.1.2",
		},
	}
}

// IDENTIFICATION AND AUTHENTICATION (IA) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckIA_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "IA.L1-3.5.1",
		Name:        "[CMMC L1] Identify Information System Users",
		Status:      "INFO",
		Evidence:    "AWS IAM provides unique identification for all users accessing CUI systems",
		Remediation: "Ensure each user has a unique IAM identity with no shared accounts for CUI access",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing unique user identities | CloudTrail → Screenshot showing user identification in logs",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.1",
			"NIST 800-171": "3.5.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckIA_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "IA.L1-3.5.2",
		Name:        "[CMMC L1] Authenticate Information System Users",
		Status:      "INFO",
		Evidence:    "AWS IAM authenticates users before allowing access to CUI systems",
		Remediation: "Enable MFA for all users accessing CUI and implement strong password policies",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Security credentials → Screenshot showing MFA enabled | Account settings → Screenshot showing password policy",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/account_settings",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.2",
			"NIST 800-171": "3.5.2",
		},
	}
}

// MEDIA PROTECTION (MP) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckMP_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "MP.L1-3.8.3",
		Name:        "[CMMC L1] Sanitize or Destroy CUI Media",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: AWS provides secure deletion capabilities for EBS volumes and S3 objects containing CUI",
		Remediation: "Implement secure deletion procedures using AWS encryption and S3 object versioning controls",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → EC2 → Volumes → Screenshot showing encrypted volumes for secure deletion | S3 → Versioning → Screenshot showing object lifecycle policies",
		ConsoleURL: "https://console.aws.amazon.com/ec2/home#Volumes:",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.3",
			"NIST 800-171": "3.8.3",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckMP_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "MP.L1-3.8.2",
		Name:        "[CMMC L1] Control Access to CUI Media",
		Status:      "INFO",
		Evidence:    "AWS IAM and S3 bucket policies control access to media containing CUI",
		Remediation: "Configure S3 bucket policies and IAM to restrict CUI media access to authorized personnel only",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → S3 → Bucket permissions → Screenshot showing access controls | IAM → Screenshot showing media access policies",
		ConsoleURL: "https://console.aws.amazon.com/s3/home",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.2",
			"NIST 800-171": "3.8.2",
		},
	}
}

// PERSONNEL SECURITY (PS) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckPS_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "PS.L1-3.9.1",
		Name:        "[CMMC L1] Screen Personnel Prior to Access",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: Personnel screening required before granting access to AWS CUI systems",
		Remediation: "Implement personnel screening procedures for all users requiring CUI access",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "HR Documentation → Screenshot showing personnel screening procedures | AWS Console → IAM → Users → Screenshot showing access approval documentation",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/users",
		Frameworks: map[string]string{
			"CMMC": "PS.L1-3.9.1",
			"NIST 800-171": "3.9.1",
		},
	}
}

// SYSTEM AND COMMUNICATIONS PROTECTION (SC) Level 1 checks

func (c *AWSCMMCLevel1Checks) CheckSC_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.1",
		Name:        "[CMMC L1] Monitor and Control Communications",
		Status:      "INFO",
		Evidence:    "AWS VPC Security Groups and NACLs monitor and control communications at CUI system boundaries",
		Remediation: "Configure Security Groups to monitor and control all CUI communications at network boundaries",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing communication controls | Network ACLs → Screenshot showing traffic monitoring rules",
		ConsoleURL: "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.1",
			"NIST 800-171": "3.13.1",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.5",
		Name:        "[CMMC L1] Implement Cryptographic Mechanisms",
		Status:      "INFO",
		Evidence:    "AWS KMS and encryption services provide cryptographic mechanisms to prevent unauthorized disclosure of CUI",
		Remediation: "Enable encryption for all CUI data using AWS KMS with customer-managed keys",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → KMS → Customer managed keys → Screenshot showing CUI encryption keys | S3 → Encryption → Screenshot showing bucket encryption enabled",
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
		Evidence:    "AWS KMS uses FIPS 140-2 validated cryptographic modules for CUI protection",
		Remediation: "Ensure all cryptographic operations use FIPS-validated algorithms through AWS KMS",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → KMS → Key usage → Screenshot showing FIPS-validated encryption | Documentation → Screenshot showing FIPS compliance status",
		ConsoleURL: "https://console.aws.amazon.com/kms/home#/kms/keys",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.11",
			"NIST 800-171": "3.13.11",
		},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_004(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.16",
		Name:        "[CMMC L1] Protect CUI at Rest",
		Status:      "INFO",
		Evidence:    "AWS encryption services protect CUI at rest in S3, EBS, and RDS",
		Remediation: "Enable encryption at rest for all AWS services storing CUI data",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → S3 → Encryption → Screenshot showing at-rest encryption | EBS → Volumes → Screenshot showing encrypted volumes | RDS → Encryption → Screenshot showing database encryption",
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
		Evidence:    "AWS IAM and application services invalidate session identifiers after logout or period of inactivity",
		Remediation: "Configure session timeout policies in AWS IAM and applications accessing CUI",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Account settings → Screenshot showing session duration limits | CloudTrail → Screenshot showing session invalidation events",
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
		Evidence:    "AWS Systems Manager Patch Manager and Inspector identify and help correct security flaws",
		Remediation: "Enable AWS Systems Manager for automated patching and vulnerability assessment",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Systems Manager → Patch Manager → Screenshot showing patch compliance | Inspector → Screenshot showing vulnerability findings",
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
		Evidence:    "AWS GuardDuty and third-party solutions provide malicious code protection for CUI systems",
		Remediation: "Enable AWS GuardDuty and deploy endpoint protection on EC2 instances processing CUI",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → GuardDuty → Screenshot showing malware detection | EC2 → Security → Screenshot showing endpoint protection status",
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
		Evidence:    "AWS GuardDuty automatically updates threat intelligence and malicious code signatures",
		Remediation: "Ensure GuardDuty is enabled and endpoint protection has automatic updates configured",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → GuardDuty → Settings → Screenshot showing automatic updates | EC2 → Screenshot showing endpoint protection update status",
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
		Evidence:    "AWS Security Hub and CloudWatch monitor security alerts and advisories for CUI systems",
		Remediation: "Enable AWS Security Hub and configure CloudWatch alarms for security events",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Security Hub → Screenshot showing security alerts dashboard | CloudWatch → Alarms → Screenshot showing security monitoring alerts",
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
		Evidence:    "AWS automatically updates security services and recommends updating endpoint protection mechanisms",
		Remediation: "Maintain current versions of all security tools and enable automatic updates where possible",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "AWS Console → Security services → Screenshot showing version status | Systems Manager → Screenshot showing security agent updates",
		ConsoleURL: "https://console.aws.amazon.com/systems-manager/managed-instances",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.7",
			"NIST 800-171": "3.14.7",
		},
	}
}
