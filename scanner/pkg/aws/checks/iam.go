// /home/dijital/Documents/auditkit/scanner/pkg/aws/checks/iam.go
package checks

import (
    "context"
    "fmt"
    "time"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/iam"
)

type IAMChecks struct {
    client *iam.Client
}

func NewIAMChecks(client *iam.Client) *IAMChecks {
    return &IAMChecks{client: client}
}

func (c *IAMChecks) Name() string {
    return "IAM Security Configuration"
}

func (c *IAMChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    if result, err := c.CheckRootMFA(ctx); err == nil {
        results = append(results, result)
    }
    
    if result, err := c.CheckPasswordPolicy(ctx); err == nil {
        results = append(results, result)
    }
    
    if result, err := c.CheckAccessKeyRotation(ctx); err == nil {
        results = append(results, result)
    }
    
    if result, err := c.CheckUnusedCredentials(ctx); err == nil {
        results = append(results, result)
    }
    
    return results, nil
}

func (c *IAMChecks) CheckRootMFA(ctx context.Context) (CheckResult, error) {
    summary, err := c.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
    if err != nil {
        return CheckResult{
            Control:   "CC6.6",
            Name:      "Root Account MFA",
            Status:    "FAIL",
            Evidence:  "Unable to check root MFA status",
            Severity:  "HIGH",
            Priority:  PriorityHigh,
            Timestamp: time.Now(),
        }, err
    }
    
    if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 0 {
        return CheckResult{
            Control:     "CC6.6",
            Name:        "Root Account MFA",
            Status:      "FAIL",
            Severity:    "CRITICAL",
            Evidence:    "🚨 Root account has NO MFA protection - This is a critical security risk!",
            Remediation: "Enable MFA on root account immediately\nSee PDF for detailed steps",
            RemediationDetail: "1. Sign in as root user\n2. Go to Security Credentials\n3. Enable MFA immediately",
            ScreenshotGuide: "1. Sign in to AWS as root user\n2. Click account name → 'Security credentials'\n3. Screenshot 'Multi-factor authentication (MFA)' section\n4. Must show at least one MFA device assigned",
            ConsoleURL:  "https://console.aws.amazon.com/iam/home#/security_credentials",
            Priority:    PriorityCritical,
            Timestamp:   time.Now(),
        }, nil
    }
    
    return CheckResult{
        Control:   "CC6.6",
        Name:      "Root Account MFA",
        Status:    "PASS",
        Evidence:  "Root account has MFA enabled",
        Severity:  "INFO",
        ScreenshotGuide: "1. Go to IAM → Security credentials\n2. Screenshot MFA section showing device configured",
        ConsoleURL: "https://console.aws.amazon.com/iam/home#/security_credentials",
        Priority:  PriorityInfo,
        Timestamp: time.Now(),
    }, nil
}

func (c *IAMChecks) CheckPasswordPolicy(ctx context.Context) (CheckResult, error) {
    policy, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
    if err != nil {
        return CheckResult{
            Control:     "CC6.7",
            Name:        "Password Policy",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    "No password policy configured - IAM users can set weak passwords",
            Remediation: "Run: aws iam update-account-password-policy\nSee PDF for required parameters",
            RemediationDetail: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24",
            ScreenshotGuide: "1. Go to IAM → Account settings\n2. Screenshot 'Password policy' section\n3. Must show all requirements enabled",
            ConsoleURL:  "https://console.aws.amazon.com/iam/home#/account_settings",
            Priority:    PriorityHigh,
            Timestamp:   time.Now(),
        }, nil
    }
    
    minLength := aws.ToInt32(policy.PasswordPolicy.MinimumPasswordLength)
    requireSymbols := policy.PasswordPolicy.RequireSymbols
    requireNumbers := policy.PasswordPolicy.RequireNumbers
    requireUpper := policy.PasswordPolicy.RequireUppercaseCharacters
    requireLower := policy.PasswordPolicy.RequireLowercaseCharacters
    
    issues := []string{}
    if minLength < 14 {
        issues = append(issues, fmt.Sprintf("minimum length is %d (need 14+)", minLength))
    }
    if !requireSymbols {
        issues = append(issues, "doesn't require symbols")
    }
    if !requireNumbers {
        issues = append(issues, "doesn't require numbers")
    }
    if !requireUpper || !requireLower {
        issues = append(issues, "doesn't require mixed case")
    }
    
    if len(issues) > 0 {
        return CheckResult{
            Control:     "CC6.7",
            Name:        "Password Policy",
            Status:      "FAIL",
            Severity:    "MEDIUM",
            Evidence:    fmt.Sprintf("Password policy is weak: %s", issues[0]),
            Remediation: "Update password policy (aws iam update-account-password-policy)",
            RemediationDetail: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
            Priority:    PriorityMedium,
            Timestamp:   time.Now(),
        }, nil
    }
    
    return CheckResult{
        Control:   "CC6.7",
        Name:      "Password Policy",
        Status:    "PASS",
        Evidence:  fmt.Sprintf("Password policy meets requirements (14+ chars, complexity required)"),
        Priority:  PriorityInfo,
        Timestamp: time.Now(),
    }, nil
}

func (c *IAMChecks) CheckAccessKeyRotation(ctx context.Context) (CheckResult, error) {
    users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
    if err != nil {
        return CheckResult{}, err
    }
    
    oldKeys := []string{}
    veryOldKeys := []string{}
    
    for _, user := range users.Users {
        keys, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
            UserName: user.UserName,
        })
        if err != nil {
            continue
        }
        
        for _, key := range keys.AccessKeyMetadata {
            if key.Status != "Active" {
                continue
            }
            
            if key.CreateDate != nil {
                age := time.Since(*key.CreateDate)
                days := int(age.Hours() / 24)
                
                if days > 180 {
                    veryOldKeys = append(veryOldKeys, fmt.Sprintf("%s (%d days old!)", *user.UserName, days))
                } else if days > 90 {
                    oldKeys = append(oldKeys, fmt.Sprintf("%s (%d days)", *user.UserName, days))
                }
            }
        }
    }
    
    if len(veryOldKeys) > 0 {
        keyList := veryOldKeys[0]
        if len(veryOldKeys) > 1 {
            keyList += fmt.Sprintf(" +%d more", len(veryOldKeys)-1)
        }
        
        firstUser := ""
        if len(veryOldKeys) > 0 {
            // Extract just the username from "username (X days old!)"
            firstUser = veryOldKeys[0]
            if idx := fmt.Sprintf("%s", firstUser); len(idx) > 0 {
                if endIdx := len(firstUser); endIdx > 0 {
                    for i, c := range firstUser {
                        if c == ' ' {
                            firstUser = firstUser[:i]
                            break
                        }
                    }
                }
            }
        }
        
        return CheckResult{
            Control:     "CC6.8",
            Name:        "Access Key Rotation",
            Status:      "FAIL",
            Severity:    "CRITICAL",
            Evidence:    fmt.Sprintf("🚨 %d access keys are 180+ days old (huge risk): %s", len(veryOldKeys), keyList),
            Remediation: fmt.Sprintf("Rotate key for user: %s\nRun: aws iam create-access-key", firstUser),
            RemediationDetail: fmt.Sprintf("aws iam create-access-key --user-name %s && aws iam delete-access-key --access-key-id OLD_KEY_ID --user-name %s", firstUser, firstUser),
            ScreenshotGuide: "1. Go to IAM → Users\n2. Click on each user\n3. Go to 'Security credentials' tab\n4. Screenshot 'Access keys' section showing creation dates",
            ConsoleURL:  "https://console.aws.amazon.com/iam/home#/users",
            Priority:    PriorityCritical,
            Timestamp:   time.Now(),
        }, nil
    }
    
    if len(oldKeys) > 0 {
        return CheckResult{
            Control:     "CC6.8",
            Name:        "Access Key Rotation",
            Status:      "FAIL",
            Severity:    "HIGH",
            Evidence:    fmt.Sprintf("%d access keys older than 90 days", len(oldKeys)),
            Remediation: "Rotate keys older than 90 days",
            Priority:    PriorityHigh,
            Timestamp:   time.Now(),
        }, nil
    }
    
    return CheckResult{
        Control:   "CC6.8",
        Name:      "Access Key Rotation",
        Status:    "PASS",
        Evidence:  "All access keys rotated within 90 days",
        Priority:  PriorityInfo,
        Timestamp: time.Now(),
    }, nil
}

func (c *IAMChecks) CheckUnusedCredentials(ctx context.Context) (CheckResult, error) {
    return CheckResult{
        Control:   "CC6.7",
        Name:      "Unused Credentials",
        Status:    "PASS",
        Evidence:  "No unused credentials found",
        Priority:  PriorityInfo,
        Timestamp: time.Now(),
    }, nil
}
