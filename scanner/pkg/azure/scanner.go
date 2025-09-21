package azure

import (
    "context"
    "fmt"
)

type Scanner struct {
    subscriptionID string
    tenantID      string
}

func NewScanner(subscriptionID, tenantID string) *Scanner {
    return &Scanner{
        subscriptionID: subscriptionID,
        tenantID:      tenantID,
    }
}

func (s *Scanner) ScanServices(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // Placeholder checks that show structure
    results = append(results, CheckResult{
        Control:  "CC6.6",
        Name:     "Azure AD MFA for Admins",
        Status:   "NOT_IMPLEMENTED",
        Evidence: "Azure support coming next Friday",
        ScreenshotGuide: "Azure Portal → Azure AD → Users → Check MFA Status column",
        ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade",
    })
    
    results = append(results, CheckResult{
        Control:  "CC6.2",
        Name:     "Storage Account Public Access",
        Status:   "NOT_IMPLEMENTED",
        Evidence: "Azure storage scanning coming soon",
    })
    
    return results, nil
}
