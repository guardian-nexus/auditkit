package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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
	checks       []checks.Check
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
}

func NewScanner(profile string) (*AWSScanner, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	scanner := &AWSScanner{
		cfg:          cfg,
		s3Client:     s3.NewFromConfig(cfg),
		iamClient:    iam.NewFromConfig(cfg),
		ec2Client:    ec2.NewFromConfig(cfg),
		ctClient:     cloudtrail.NewFromConfig(cfg),
		stsClient:    sts.NewFromConfig(cfg),
		configClient: configservice.NewFromConfig(cfg),
		gdClient:     guardduty.NewFromConfig(cfg),
		shClient:     securityhub.NewFromConfig(cfg),
		rdsClient:    rds.NewFromConfig(cfg),
		cwClient:     cloudwatch.NewFromConfig(cfg),
		snsClient:    sns.NewFromConfig(cfg),
		ssmClient:    ssm.NewFromConfig(cfg),
		asClient:     autoscaling.NewFromConfig(cfg),
	}

	scanner.checks = []checks.Check{
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
	var results []ScanResult

	// Run all checks
	for _, check := range s.checks {
		if verbose {
			fmt.Printf("  📍 Running %s checks...\n", check.Name())
		}

		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    ⚠️  Warning in %s: %v\n", check.Name(), err)
		}

		// Convert CheckResult to ScanResult - NOW INCLUDING SCREENSHOT DATA AND REMEDIATION DETAIL
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail, // ADD THIS LINE
				Severity:          cr.Severity,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
			})
		}
	}

	return results, nil
}
