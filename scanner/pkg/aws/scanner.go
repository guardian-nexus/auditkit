// /home/dijital/Documents/auditkit/scanner/pkg/aws/scanner.go
package aws

import (
    "context"
    "fmt"
    "strings"
    "time"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
    "github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSScanner struct {
    cfg       aws.Config
    s3Client  *s3.Client
    iamClient *iam.Client
    ec2Client *ec2.Client
    ctClient  *cloudtrail.Client
    stsClient *sts.Client
}

type ScanResult struct {
    Control     string
    Status      string
    Evidence    string
    Remediation string
    Severity    string
}

func NewScanner(profile string) (*AWSScanner, error) {
    cfg, err := config.LoadDefaultConfig(context.TODO(),
        config.WithSharedConfigProfile(profile),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %v", err)
    }
    
    return &AWSScanner{
        cfg:       cfg,
        s3Client:  s3.NewFromConfig(cfg),
        iamClient: iam.NewFromConfig(cfg),
        ec2Client: ec2.NewFromConfig(cfg),
        ctClient:  cloudtrail.NewFromConfig(cfg),
        stsClient: sts.NewFromConfig(cfg),
    }, nil
}

func (s *AWSScanner) GetAccountID(ctx context.Context) string {
    identity, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
    if err != nil {
        return "unknown"
    }
    return *identity.Account
}

func (s *AWSScanner) ScanServices(ctx context.Context, services []string, verbose bool) ([]ScanResult, error) {
    var results []ScanResult
    
    for _, service := range services {
        service = strings.TrimSpace(strings.ToLower(service))
        
        if verbose {
            fmt.Printf("  📍 Scanning %s...\n", service)
        }
        
        switch service {
        case "s3":
            s3Results, _ := s.checkS3Buckets(ctx)
            results = append(results, s3Results...)
        case "iam":
            iamResults, _ := s.checkIAM(ctx)
            results = append(results, iamResults...)
        case "ec2":
            sgResults, _ := s.checkSecurityGroups(ctx)
            results = append(results, sgResults...)
        case "cloudtrail":
            ctResults, _ := s.checkCloudTrail(ctx)
            results = append(results, ctResults...)
        }
    }
    
    return results, nil
}

func (s *AWSScanner) checkS3Buckets(ctx context.Context) ([]ScanResult, error) {
    var results []ScanResult
    
    resp, err := s.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
    if err != nil {
        return results, err
    }
    
    if len(resp.Buckets) == 0 {
        results = append(results, ScanResult{
            Control:  "CC6.2",
            Status:   "PASS",
            Evidence: "No S3 buckets found",
            Severity: "INFO",
        })
        return results, nil
    }
    
    publicBuckets := []string{}
    unencryptedBuckets := []string{}
    
    for _, bucket := range resp.Buckets {
        // Check public access block
        pab, err := s.s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
            Bucket: bucket.Name,
        })
        
        if err != nil || pab.PublicAccessBlockConfiguration == nil ||
           !aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls) ||
           !aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy) {
            publicBuckets = append(publicBuckets, *bucket.Name)
        }
        
        // Check encryption
        _, err = s.s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
            Bucket: bucket.Name,
        })
        
        if err != nil {
            unencryptedBuckets = append(unencryptedBuckets, *bucket.Name)
        }
    }
    
    // Report on public access
    if len(publicBuckets) > 0 {
        bucketList := strings.Join(publicBuckets, ", ")
        if len(publicBuckets) > 3 {
            bucketList = strings.Join(publicBuckets[:3], ", ") + fmt.Sprintf(" and %d more", len(publicBuckets)-3)
        }
        results = append(results, ScanResult{
            Control:     "CC6.2",
            Status:      "FAIL",
            Severity:    "CRITICAL",
            Evidence:    fmt.Sprintf("%d S3 buckets allow public access: %s", len(publicBuckets), bucketList),
            Remediation: fmt.Sprintf("aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"),
        })
    } else {
        results = append(results, ScanResult{
            Control:  "CC6.2",
            Status:   "PASS",
            Evidence: fmt.Sprintf("All %d S3 buckets block public access", len(resp.Buckets)),
            Severity: "INFO",
        })
    }
    
    // Report on encryption
    if len(unencryptedBuckets) > 0 {
        results = append(results, ScanResult{
            Control:     "CC6.3",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("%d/%d S3 buckets lack encryption", len(unencryptedBuckets), len(resp.Buckets)),
            Remediation: "aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
        })
    } else {
        results = append(results, ScanResult{
            Control:  "CC6.3",
            Status:   "PASS",
            Evidence: fmt.Sprintf("All %d S3 buckets have encryption enabled", len(resp.Buckets)),
            Severity: "INFO",
        })
    }
    
    return results, nil
}

func (s *AWSScanner) checkIAM(ctx context.Context) ([]ScanResult, error) {
    var results []ScanResult
    
    // Check root MFA
    summary, err := s.iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
    if err == nil && summary.SummaryMap != nil {
        if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 0 {
            results = append(results, ScanResult{
                Control:     "CC6.6",
                Status:      "FAIL",
                Severity:    "CRITICAL",
                Evidence:    "Root account lacks MFA protection",
                Remediation: "Enable MFA: https://console.aws.amazon.com/iam/home#/security_credentials",
            })
        } else if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val > 0 {
            results = append(results, ScanResult{
                Control:  "CC6.6",
                Status:   "PASS",
                Evidence: "Root account has MFA enabled",
                Severity: "INFO",
            })
        }
    }
    
    // Check password policy
    policy, err := s.iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
    if err != nil {
        results = append(results, ScanResult{
            Control:     "CC6.7",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "No password policy configured",
            Remediation: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
        })
    } else if policy.PasswordPolicy != nil {
        minLength := aws.ToInt32(policy.PasswordPolicy.MinimumPasswordLength)
        if minLength < 14 {
            results = append(results, ScanResult{
                Control:     "CC6.7",
                Status:      "FAIL",
                Severity:    "MEDIUM",
                Evidence:    fmt.Sprintf("Password minimum length is %d (should be 14+)", minLength),
                Remediation: "aws iam update-account-password-policy --minimum-password-length 14",
            })
        } else {
            results = append(results, ScanResult{
                Control:  "CC6.7",
                Status:   "PASS",
                Evidence: "Password policy meets security requirements",
                Severity: "INFO",
            })
        }
    }
    
    // Check access key age
    users, err := s.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
    if err != nil {
        return results, err
    }
    
    oldKeys := []string{}
    for _, user := range users.Users {
        keys, err := s.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
            UserName: user.UserName,
        })
        if err != nil {
            continue
        }
        
        for _, key := range keys.AccessKeyMetadata {
            if key.CreateDate != nil {
                age := time.Since(*key.CreateDate)
                if age > 90*24*time.Hour {
                    days := int(age.Hours() / 24)
                    oldKeys = append(oldKeys, fmt.Sprintf("%s (%d days)", *user.UserName, days))
                }
            }
        }
    }
    
    if len(oldKeys) > 0 {
        keyList := strings.Join(oldKeys, ", ")
        if len(oldKeys) > 3 {
            keyList = strings.Join(oldKeys[:3], ", ") + fmt.Sprintf(" and %d more", len(oldKeys)-3)
        }
        results = append(results, ScanResult{
            Control:     "CC6.8",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("%d access keys older than 90 days: %s", len(oldKeys), keyList),
            Remediation: "Rotate keys: aws iam create-access-key --user-name USERNAME && aws iam delete-access-key --access-key-id OLD_KEY --user-name USERNAME",
        })
    } else {
        results = append(results, ScanResult{
            Control:  "CC6.8",
            Status:   "PASS",
            Evidence: "All access keys rotated within 90 days",
            Severity: "INFO",
        })
    }
    
    return results, nil
}

func (s *AWSScanner) checkSecurityGroups(ctx context.Context) ([]ScanResult, error) {
    var results []ScanResult
    
    sgs, err := s.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
    if err != nil {
        return results, err
    }
    
    riskyGroups := []string{}
    for _, sg := range sgs.SecurityGroups {
        for _, rule := range sg.IpPermissions {
            for _, ipRange := range rule.IpRanges {
                if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
                    if rule.FromPort != nil {
                        port := aws.ToInt32(rule.FromPort)
                        // Check for sensitive ports
                        if port == 22 || port == 3389 || port == 3306 || port == 5432 || port == 1433 {
                            riskyGroups = append(riskyGroups, fmt.Sprintf("%s (port %d)", *sg.GroupId, port))
                        }
                    }
                }
            }
        }
    }
    
    if len(riskyGroups) > 0 {
        groupList := strings.Join(riskyGroups, ", ")
        if len(riskyGroups) > 3 {
            groupList = strings.Join(riskyGroups[:3], ", ") + fmt.Sprintf(" and %d more", len(riskyGroups)-3)
        }
        results = append(results, ScanResult{
            Control:     "CC6.1",
            Status:      "FAIL",
            Severity:    "CRITICAL",
            Evidence:    fmt.Sprintf("Security groups allow public access to sensitive ports: %s", groupList),
            Remediation: "Restrict to specific IPs: aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port PORT --cidr 0.0.0.0/0",
        })
    } else {
        results = append(results, ScanResult{
            Control:  "CC6.1",
            Status:   "PASS",
            Evidence: fmt.Sprintf("No security groups expose sensitive ports to 0.0.0.0/0 (%d groups checked)", len(sgs.SecurityGroups)),
            Severity: "INFO",
        })
    }
    
    return results, nil
}

func (s *AWSScanner) checkCloudTrail(ctx context.Context) ([]ScanResult, error) {
    var results []ScanResult
    
    trails, err := s.ctClient.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
    if err != nil {
        return results, err
    }
    
    if len(trails.Trails) == 0 {
        results = append(results, ScanResult{
            Control:     "CC7.1",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "No CloudTrail configured for audit logging",
            Remediation: "aws cloudtrail create-trail --name audit-trail --s3-bucket-name YOUR_BUCKET && aws cloudtrail start-logging --name audit-trail",
        })
        return results, nil
    }
    
    // Check if trails are actually logging
    activeTrails := 0
    for _, trail := range trails.Trails {
        if trail.TrailARN != nil {
            status, err := s.ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
                Name: trail.TrailARN,
            })
            if err == nil && status.IsLogging != nil && *status.IsLogging {
                activeTrails++
            }
        }
    }
    
    if activeTrails == 0 {
        results = append(results, ScanResult{
            Control:     "CC7.1",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("CloudTrail exists but not logging (found %d trails)", len(trails.Trails)),
            Remediation: "aws cloudtrail start-logging --name YOUR_TRAIL_NAME",
        })
    } else {
        results = append(results, ScanResult{
            Control:  "CC7.1",
            Status:   "PASS",
            Evidence: fmt.Sprintf("CloudTrail logging enabled (%d active trails)", activeTrails),
            Severity: "INFO",
        })
    }
    
    return results, nil
}
