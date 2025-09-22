package aws

import (
	"context"
	"fmt"

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
	
	// Additional clients for complete SOC2
	orgClient        *organizations.Client
	inspector2Client *inspector2.Client
	backupClient     *backup.Client
	kmsClient        *kms.Client
	lambdaClient     *lambda.Client
	
	checks []checks.Check
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

	// Initialize ALL checks including new SOC2 complete checks
	scanner.checks = []checks.Check{
		// Original checks (keep for backward compatibility)
		checks.NewS3Checks(scanner.s3Client),
		checks.NewIAMChecks(scanner.iamClient),
		checks.NewEC2Checks(scanner.ec2Client),
		checks.NewCloudTrailChecks(scanner.ctClient),
		checks.NewConfigChecks(scanner.configClient),
		checks.NewGuardDutyChecks(scanner.gdClient),
		checks.NewRDSChecks(scanner.rdsClient),
		checks.NewVPCChecks(scanner.ec2Client),
		checks.NewIAMAdvancedChecks(scanner.iamClient),
		checks.NewMonitoringChecks(scanner.cwClient, scanner.snsClient),
		checks.NewSystemsChecks(scanner.ssmClient, scanner.asClient),
		
		// NEW: Complete SOC2 Common Criteria checks
		checks.NewCC1Checks(scanner.iamClient, scanner.orgClient, scanner.ssmClient),
		checks.NewCC2Checks(scanner.snsClient, scanner.ssmClient, scanner.iamClient),
		checks.NewCC3Checks(scanner.gdClient, scanner.shClient, scanner.inspector2Client),
		checks.NewCC4Checks(scanner.cwClient, scanner.configClient),
		checks.NewCC5Checks(scanner.backupClient, scanner.kmsClient),
		checks.NewCC6Checks(scanner.iamClient, scanner.ec2Client, scanner.s3Client, scanner.ctClient),
		checks.NewCC7Checks(scanner.ctClient, scanner.ssmClient, scanner.lambdaClient),
		checks.NewCC8Checks(scanner.lambdaClient, scanner.ec2Client),
		checks.NewCC9Checks(scanner.rdsClient, scanner.s3Client),
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
func (s *AWSScanner) ScanServices(ctx context.Context, services []string, verbose bool) ([]ScanResult, error) {
    // Check AWS connectivity first
    _, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
    if err != nil {
        if verbose {
            fmt.Println("❌ Error: Not connected to AWS. Please configure AWS credentials.")
            fmt.Println("   Run: aws configure")
        }
        return nil, fmt.Errorf("AWS connection failed: %v. Please configure AWS credentials", err)
    }
    
    var results []ScanResult

    // Determine which checks to run based on services
    checksToRun := s.checks
	
	// If specific services requested, filter checks (optional enhancement)
	// For now, run all checks when "all" or SOC2 is requested
	
	if verbose {
		fmt.Println("🔍 Running complete SOC2 Common Criteria scan...")
		fmt.Println("   This includes all 64 controls across CC1-CC9")
	}

	// Run all checks
	for _, check := range checksToRun {
		if verbose {
			fmt.Printf("  📍 Running %s checks...\n", check.Name())
		}

		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    ⚠️  Warning in %s: %v\n", check.Name(), err)
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
			})
		}
	}

	if verbose {
		fmt.Printf("✅ Complete SOC2 scan finished - %d total checks performed\n", len(results))
	}

	return results, nil
}
