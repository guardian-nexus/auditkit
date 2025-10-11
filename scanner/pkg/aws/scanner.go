package aws

import (
	"context"
	"fmt"
	"strings"
//	"time"

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

	return &AWSScanner{
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
	}, nil
}

func (s *AWSScanner) GetAccountID(ctx context.Context) string {
	identity, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	return *identity.Account
}

func (s *AWSScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
	_, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if verbose {
			fmt.Println("Error: Not connected to AWS. Please configure AWS credentials.")
		}
		return nil, fmt.Errorf("AWS connection failed: %v", err)
	}
	
	var results []ScanResult
	framework = strings.ToLower(framework)
	
	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "cmmc":
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	case "all":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

func (s *AWSScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	if verbose {
		fmt.Println("Running CMMC Level 1 (17 practices) - Open Source")
		fmt.Println("")
		fmt.Println("⚠️  IMPORTANT DISCLAIMER:")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("This scanner tests technical controls that can be automated.")
		fmt.Println("")
		fmt.Println("CMMC Level 1 requires 17 practices. Many controls require")
		fmt.Println("organizational documentation and policies that cannot be")
		fmt.Println("verified through automated scanning.")
		fmt.Println("")
		fmt.Println("A high automated check score does NOT mean you are CMMC")
		fmt.Println("compliant. This is a technical assessment tool, not a")
		fmt.Println("compliance certification.")
		fmt.Println("")
		fmt.Println("You still need to document policies, training, incident")
		fmt.Println("response procedures, and other organizational controls.")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("")
	}
	
	// ONLY Level 1 (17 practices)
	level1 := checks.NewAWSCMMCLevel1Checks(s.iamClient, s.s3Client, s.ec2Client, s.ctClient)
	results1, _ := level1.Run(ctx)
	for _, cr := range results1 {
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
	
	if verbose {
		fmt.Printf("\nCMMC Level 1 scan complete: %d controls tested\n", len(results))
		fmt.Println("")
		fmt.Println("🔓 UNLOCK CMMC LEVEL 2:")
		fmt.Println("  • 110 additional Level 2 practices for CUI")
		fmt.Println("  • Required for DoD contractors handling CUI")
		fmt.Println("  • Complete evidence collection guides")
		fmt.Println("  • November 10, 2025 deadline compliance")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro for full CMMC Level 2")
	}
	
	return results
}

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
			fmt.Printf("  Running %s ...\n", check.Name())
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

func (s *AWSScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	// Check if pci_dss.go exists, if not fall back to basic checks with PCI mappings
	pciChecks := checks.NewPCIDSSChecks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient, s.configClient)
	
	if verbose {
		fmt.Printf("  Running PCI-DSS v4.0 requirements...\n")
	}
	
	checkResults, err := pciChecks.Run(ctx)
	if err != nil && verbose {
		fmt.Printf("    Warning in PCI-DSS checks: %v\n", err)
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
	}
	
	return results
}
