// IAM security checks

package checks

import (
    "github.com/aws/aws-sdk-go/service/iam"
    "time"
)

type IAMSecurityCheck struct {
    client *iam.IAM
}

func (i *IAMSecurityCheck) CheckMFAOnRootAccount() CheckResult {
    // Check if root account has MFA
    summary, _ := i.client.GetAccountSummary(&iam.GetAccountSummaryInput{})
    
    if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok {
        if *val == 0 {
            return CheckResult{
                Control: "CC-6.6",
                Status:  "FAIL",
                Details: "Root account lacks MFA - CRITICAL",
                Severity: "CRITICAL",
            }
        }
    }
    
    return CheckResult{
        Control: "CC-6.6",
        Status:  "PASS",
        Details: "Root account has MFA enabled",
    }
}

func (i *IAMSecurityCheck) CheckPasswordPolicy() CheckResult {
    // Check password complexity requirements
    policy, err := i.client.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
    
    if err != nil {
        return CheckResult{
            Control: "CC-6.7",
            Status:  "FAIL",
            Details: "No password policy defined",
            Severity: "HIGH",
        }
    }
    
    p := policy.PasswordPolicy
    if *p.MinimumPasswordLength < 14 || !*p.RequireNumbers || !*p.RequireSymbols {
        return CheckResult{
            Control: "CC-6.7",
            Status:  "FAIL",
            Details: "Weak password policy",
            Severity: "HIGH",
        }
    }
    
    return CheckResult{
        Control: "CC-6.7",
        Status:  "PASS",
        Details: "Strong password policy enforced",
    }
}

func (i *IAMSecurityCheck) CheckAccessKeyRotation() []CheckResult {
    // Check if access keys are rotated within 90 days
    var results []CheckResult
    
    users, _ := i.client.ListUsers(&iam.ListUsersInput{})
    
    for _, user := range users.Users {
        keys, _ := i.client.ListAccessKeys(&iam.ListAccessKeysInput{
            UserName: user.UserName,
        })
        
        for _, key := range keys.AccessKeyMetadata {
            age := time.Since(*key.CreateDate)
            if age.Hours() > 2160 { // 90 days
                results = append(results, CheckResult{
                    Control: "CC-6.8",
                    Status:  "FAIL",
                    Details: fmt.Sprintf("Key %s is %d days old", *key.AccessKeyId, int(age.Hours()/24)),
                    Severity: "MEDIUM",
                })
            }
        }
    }
    
    return results
}
