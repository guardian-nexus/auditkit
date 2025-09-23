package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/guardian-nexus/auditkit/scanner/pkg/aws/checks"
)

// AWSScanner matches what main.go expects
type AWSScanner struct {
	cfg          aws.Config
	s3Client     *s3.Client
	iamClient    *iam.Client
	ec2Client    *ec2.Client
	ctClient     *cloudtrail.Client
	stsClient    *sts.Client
	configClient *configservice.Client
	gdClient     *guardduty.Client
	shClient     *securityhub.Client
	rdsClient    *rds.Client
	cwClient     *cloudwatch.Client
	snsClient    *sns.Client
	ssmClient    *ssm.Client
	asClient     *autoscaling.Client
	
	// Additional clients for complete SOC2 and PCI-DSS
	orgClient        *organizations.Client
	inspector2Client *inspector2.Client
	backupClient     *backup.Client
	kmsClient        *kms.Client
	lambdaClient     *lambda.Client
}

type ScanResult struct {
	Control           string
	Status            string
	Evidence          string
	Remediation       string
	RemediationDetail string
	Severity          string
	ScreenshotGuide   string
	ConsoleURL        string
	Frameworks        map[string]string
}

func NewScanner(profile string) (*AWSScanner, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	scanner := &AWSScanner{
		cfg:              cfg,
		s3Client:         s3.NewFromConfig(cfg),
		iamClient:        iam.NewFromConfig(cfg),
		ec2Client:        ec2.NewFromConfig(cfg),
		ctClient:         cloudtrail.NewFromConfig(cfg),
		stsClient:        sts.NewFromConfig(cfg),
		configClient:     configservice.NewFromConfig(cfg),
		gdClient:         guardduty.NewFromConfig(cfg),
		shClient:         securityhub.NewFromConfig(cfg),
		rdsClient:        rds.NewFromConfig(cfg),
		cwClient:         cloudwatch.NewFromConfig(cfg),
		snsClient:        sns.NewFromConfig(cfg),
		ssmClient:        ssm.NewFromConfig(cfg),
		asClient:         autoscaling.NewFromConfig(cfg),
		orgClient:        organizations.NewFromConfig(cfg),
		inspector2Client: inspector2.NewFromConfig(cfg),
		backupClient:     backup.NewFromConfig(cfg),
		kmsClient:        kms.NewFromConfig(cfg),
		lambdaClient:     lambda.NewFromConfig(cfg),
	}

	return scanner, nil
}

func (s *AWSScanner) GetAccountID(ctx context.Context) string {
	identity, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	return *identity.Account
}

// ScanServices runs the modular checks and converts to the format main.go expects
// Now properly handles framework selection
func (s *AWSScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
	// Check AWS connectivity first
	_, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if verbose {
			fmt.Println("Error: Not connected to AWS. Please configure AWS credentials.")
			fmt.Println("   Run: aws configure")
		}
		return nil, fmt.Errorf("AWS connection failed: %v. Please configure AWS credentials", err)
	}
	
	var results []ScanResult
	
	// Normalize framework name
	framework = strings.ToLower(framework)
	
	if verbose {
		if framework == "pci" {
			fmt.Println("Running PCI-DSS v4.0 compliance scan...")
			fmt.Println("   Checking requirements 1, 2, 3, 8, 10, 11")
		} else if framework == "soc2" {
			fmt.Println("Running complete SOC2 Common Criteria scan...")
			fmt.Println("   This includes all 64 controls across CC1-CC9")
		} else if framework == "all" {
			fmt.Println("Running multi-framework compliance scan...")
			fmt.Println("   SOC2 (64 controls) + PCI-DSS (40 controls)")
		}
	}

	// Run framework-specific checks
	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "hipaa":
		// For now, use basic checks with HIPAA mappings
		results = append(results, s.runBasicChecks(ctx, services, verbose)...)
		if verbose {
			fmt.Println(" HIPAA checks are experimental - limited coverage")
		}
	case "all":
		// Run everything
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	default:
		// Default to SOC2
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	if verbose {
		fmt.Printf("Scan complete - %d total checks performed\n", len(results))
	}

	return results, nil
}

// runSOC2Checks executes all SOC2 Common Criteria checks
func (s *AWSScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	// Initialize SOC2 checks
	soc2Checks := []checks.Check{
		// CC1 & CC2: Control Environment & Communication
		checks.NewCC1Checks(s.iamClient, s.orgClient, s.ssmClient),
		checks.NewCC2Checks(s.snsClient, s.ssmClient, s.iamClient),
		
		// CC3, CC4, CC5: Risk Assessment, Monitoring, Control Activities
		checks.NewCC3Checks(s.gdClient, s.shClient, s.inspector2Client),
		checks.NewCC4Checks(s.cwClient, s.configClient),
		checks.NewCC5Checks(s.backupClient, s.kmsClient),
		
		// CC6, CC7, CC8, CC9: Access Controls, Operations, Change Mgmt, Risk Mitigation
		checks.NewCC6Checks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient),
		checks.NewCC7Checks(s.ctClient, s.ssmClient, s.lambdaClient),
		checks.NewCC8Checks(s.lambdaClient, s.ec2Client),
		checks.NewCC9Checks(s.rdsClient, s.s3Client),
		
		// Also run traditional checks for backward compatibility
		checks.NewS3Checks(s.s3Client),
		checks.NewIAMChecks(s.iamClient),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewGuardDutyChecks(s.gdClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),
	}
	
	for _, check := range soc2Checks {
		if verbose {
			fmt.Printf("  Running %s checks...\n", check.Name())
		}
		
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    Warning in %s: %v\n", check.Name(), err)
		}
		
		// Convert CheckResult to ScanResult
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          cr.Severity,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	
	return results
}

// runPCIChecks executes PCI-DSS specific checks
func (s *AWSScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	// Check if pci_dss.go exists, if not fall back to basic checks with PCI mappings
	pciChecks := checks.NewPCIDSSChecks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient, s.configClient)
	
	if verbose {
		fmt.Printf("  Running PCI-DSS v4.0 requirement checks...\n")
	}
	
	checkResults, err := pciChecks.Run(ctx)
	if err != nil && verbose {
		fmt.Printf("     Warning in PCI-DSS checks: %v\n", err)
	}
	
	// Convert CheckResult to ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	
	// Also run basic checks but filter for PCI relevance
	basicChecks := []checks.Check{
		checks.NewIAMChecks(s.iamClient),      // For password policy, MFA, key rotation
		checks.NewS3Checks(s.s3Client),        // For encryption requirements
		checks.NewEC2Checks(s.ec2Client),      // For network segmentation
		checks.NewCloudTrailChecks(s.ctClient), // For logging requirements
	}
	
	for _, check := range basicChecks {
		checkResults, _ := check.Run(ctx)
		for _, cr := range checkResults {
			// Only include if it has PCI mapping
			if cr.Frameworks != nil && cr.Frameworks["PCI-DSS"] != "" {
				results = append(results, ScanResult{
					Control:           cr.Control,
					Status:            cr.Status,
					Evidence:          cr.Evidence + " | PCI-DSS: " + cr.Frameworks["PCI-DSS"],
					Remediation:       cr.Remediation,
					RemediationDetail: cr.RemediationDetail,
					Severity:          cr.Severity,
					ScreenshotGuide:   cr.ScreenshotGuide,
					ConsoleURL:        cr.ConsoleURL,
					Frameworks:        cr.Frameworks,
				})
			}
		}
	}
	
	return results
}

// runBasicChecks runs the original checks (for backward compatibility)
func (s *AWSScanner) runBasicChecks(ctx context.Context, services []string, verbose bool) []ScanResult {
	var results []ScanResult
	
	basicChecks := []checks.Check{
		checks.NewS3Checks(s.s3Client),
		checks.NewIAMChecks(s.iamClient),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewGuardDutyChecks(s.gdClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),
		checks.NewIAMAdvancedChecks(s.iamClient),
		checks.NewMonitoringChecks(s.cwClient, s.snsClient),
		checks.NewSystemsChecks(s.ssmClient, s.asClient),
	}
	
	for _, check := range basicChecks {
		if verbose {
			fmt.Printf("  Running %s checks...\n", check.Name())
		}
		
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("     Warning in %s: %v\n", check.Name(), err)
		}
		
		// Convert CheckResult to ScanResult
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          cr.Severity,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	
	return results
}
