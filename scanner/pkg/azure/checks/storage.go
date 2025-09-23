package checks

import (
    "context"
    "fmt"
    "strings"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

type StorageChecks struct {
    client *armstorage.AccountsClient
}

func NewStorageChecks(client *armstorage.AccountsClient) *StorageChecks {
    return &StorageChecks{client: client}
}

func (c *StorageChecks) Name() string {
    return "Azure Storage Security"
}

func (c *StorageChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // Run individual checks
    results = append(results, c.CheckPublicAccess(ctx)...)
    results = append(results, c.CheckEncryption(ctx)...)
    results = append(results, c.CheckSecureTransfer(ctx)...)
    results = append(results, c.CheckBlobSoftDelete(ctx)...)
    results = append(results, c.CheckNetworkRestrictions(ctx)...)
    
    return results, nil
}

func (c *StorageChecks) CheckPublicAccess(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // List all storage accounts
    pager := c.client.NewListPager(nil)
    
    publicAccounts := []string{}
    totalAccounts := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            return append(results, CheckResult{
                Control:   "CC6.2",
                Name:      "Storage Account Public Access",
                Status:    "ERROR",
                Evidence:  fmt.Sprintf("Unable to check storage accounts: %v", err),
                Severity:  "HIGH",
                Priority:  PriorityHigh,
                Timestamp: time.Now(),
                Frameworks: GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
            })
        }
        
        for _, account := range page.Value {
            totalAccounts++
            
            // Check if public blob access is enabled
            if account.Properties != nil && account.Properties.AllowBlobPublicAccess != nil {
                if *account.Properties.AllowBlobPublicAccess {
                    publicAccounts = append(publicAccounts, *account.Name)
                }
            } else {
                // If not explicitly set to false, it might be public
                publicAccounts = append(publicAccounts, *account.Name)
            }
        }
    }
    
    if len(publicAccounts) > 0 {
        displayAccounts := publicAccounts
        if len(publicAccounts) > 3 {
            displayAccounts = publicAccounts[:3]
        }
        
        results = append(results, CheckResult{
            Control:           "CC6.2",
            Name:              "Storage Account Public Access",
            Status:            "FAIL",
            Severity:          "CRITICAL",
            Evidence:          fmt.Sprintf("CRITICAL: %d/%d storage accounts allow public blob access: %s | Violates PCI DSS 1.2.1", len(publicAccounts), totalAccounts, strings.Join(displayAccounts, ", ")),
            Remediation:       "Disable public blob access",
            RemediationDetail: fmt.Sprintf("az storage account update --name %s --resource-group <rg> --allow-blob-public-access false", publicAccounts[0]),
            ScreenshotGuide:   fmt.Sprintf("1. Azure Portal → Storage accounts\n2. Click '%s'\n3. Settings → Configuration\n4. Screenshot 'Allow Blob public access' = Disabled\n5. For PCI: Document no cardholder data stored", publicAccounts[0]),
            ConsoleURL:        fmt.Sprintf("https://portal.azure.com/#@/resource/subscriptions/%s/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/%s/configuration", "subscription-placeholder", publicAccounts[0]),
            Priority:          PriorityCritical,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
        })
    } else if totalAccounts > 0 {
        results = append(results, CheckResult{
            Control:    "CC6.2",
            Name:       "Storage Account Public Access",
            Status:     "PASS",
            Evidence:   fmt.Sprintf("All %d storage accounts block public access | Meets SOC2 CC6.2, PCI DSS 1.2.1", totalAccounts),
            Priority:   PriorityInfo,
            Timestamp:  time.Now(),
            Frameworks: GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
        })
    }
    
    return results
}

func (c *StorageChecks) CheckEncryption(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListPager(nil)
    
    unencryptedAccounts := []string{}
    weakEncryption := []string{}
    totalAccounts := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, account := range page.Value {
            totalAccounts++
            accountName := *account.Name
            
            if account.Properties != nil && account.Properties.Encryption != nil {
                // Check if using Microsoft-managed keys vs customer-managed
                if account.Properties.Encryption.KeySource == nil {
                    unencryptedAccounts = append(unencryptedAccounts, accountName)
                } else if *account.Properties.Encryption.KeySource == armstorage.KeySourceMicrosoftStorage {
                    // This is fine, Microsoft-managed keys
                    continue
                }
                
                // Check encryption for different services
                if account.Properties.Encryption.Services != nil {
                    services := account.Properties.Encryption.Services
                    if services.Blob != nil && services.Blob.Enabled != nil && !*services.Blob.Enabled {
                        weakEncryption = append(weakEncryption, fmt.Sprintf("%s (blob)", accountName))
                    }
                    if services.File != nil && services.File.Enabled != nil && !*services.File.Enabled {
                        weakEncryption = append(weakEncryption, fmt.Sprintf("%s (file)", accountName))
                    }
                }
            } else {
                unencryptedAccounts = append(unencryptedAccounts, accountName)
            }
        }
    }
    
    if len(unencryptedAccounts) > 0 {
        results = append(results, CheckResult{
            Control:           "CC6.3",
            Name:              "Storage Encryption at Rest",
            Status:            "FAIL",
            Severity:          "CRITICAL",
            Evidence:          fmt.Sprintf("%d storage accounts lack encryption | Violates PCI DSS 3.4, HIPAA 164.312(a)(2)(iv)", len(unencryptedAccounts)),
            Remediation:       "Enable encryption (automatic for new accounts)",
            RemediationDetail: "Storage encryption is enabled by default for all new accounts",
            Priority:          PriorityCritical,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("STORAGE_ENCRYPTION"),
        })
    } else if len(weakEncryption) > 0 {
        results = append(results, CheckResult{
            Control:           "CC6.3",
            Name:              "Storage Service Encryption",
            Status:            "FAIL",
            Severity:          "HIGH",
            Evidence:          fmt.Sprintf("%d storage services have encryption disabled: %s", len(weakEncryption), strings.Join(weakEncryption[:min(3, len(weakEncryption))], ", ")),
            Remediation:       "Enable encryption for all storage services",
            Priority:          PriorityHigh,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("STORAGE_ENCRYPTION"),
        })
    } else if totalAccounts > 0 {
        results = append(results, CheckResult{
            Control:    "CC6.3",
            Name:       "Storage Encryption at Rest",
            Status:     "PASS",
            Evidence:   fmt.Sprintf("All %d storage accounts encrypted | Meets SOC2 CC6.3, PCI DSS 3.4", totalAccounts),
            Priority:   PriorityInfo,
            Timestamp:  time.Now(),
            Frameworks: GetFrameworkMappings("STORAGE_ENCRYPTION"),
        })
    }
    
    return results
}

func (c *StorageChecks) CheckSecureTransfer(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListPager(nil)
    
    insecureAccounts := []string{}
    totalAccounts := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, account := range page.Value {
            totalAccounts++
            
            // Check if HTTPS only is enforced
            if account.Properties != nil && account.Properties.EnableHTTPSTrafficOnly != nil {
                if !*account.Properties.EnableHTTPSTrafficOnly {
                    insecureAccounts = append(insecureAccounts, *account.Name)
                }
            } else {
                // If not set, assume insecure
                insecureAccounts = append(insecureAccounts, *account.Name)
            }
        }
    }
    
    if len(insecureAccounts) > 0 {
        displayAccounts := insecureAccounts
        if len(insecureAccounts) > 3 {
            displayAccounts = insecureAccounts[:3]
        }
        
        results = append(results, CheckResult{
            Control:           "CC6.1",
            Name:              "Secure Transfer Required",
            Status:            "FAIL",
            Severity:          "HIGH",
            Evidence:          fmt.Sprintf("PCI-DSS Req 4.1: %d storage accounts allow unencrypted transfers: %s", len(insecureAccounts), strings.Join(displayAccounts, ", ")),
            Remediation:       "Enable secure transfer (HTTPS only)",
            RemediationDetail: fmt.Sprintf("az storage account update --name %s --https-only true", insecureAccounts[0]),
            ScreenshotGuide:   "Storage account → Configuration → Secure transfer required = Enabled",
            ConsoleURL:        "https://portal.azure.com/",
            Priority:          PriorityHigh,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
        })
    } else if totalAccounts > 0 {
        results = append(results, CheckResult{
            Control:    "CC6.1",
            Name:       "Secure Transfer Required",
            Status:     "PASS",
            Evidence:   fmt.Sprintf("All %d storage accounts require HTTPS | Meets PCI DSS 4.1", totalAccounts),
            Priority:   PriorityInfo,
            Timestamp:  time.Now(),
            Frameworks: GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
        })
    }
    
    return results
}

func (c *StorageChecks) CheckBlobSoftDelete(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListPager(nil)
    noSoftDelete := []string{}
    totalAccounts := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, account := range page.Value {
            totalAccounts++
            
            // Check if soft delete is enabled for blobs
            // Note: This requires additional API call to blob service properties
            // For now, we'll flag as informational
            noSoftDelete = append(noSoftDelete, *account.Name)
        }
    }
    
    if len(noSoftDelete) > 0 && totalAccounts > 0 {
        results = append(results, CheckResult{
            Control:           "A1.2",
            Name:              "Blob Soft Delete",
            Status:            "INFO",
            Evidence:          "Verify soft delete is enabled for blob recovery",
            Remediation:       "Enable soft delete with 7-30 day retention",
            RemediationDetail: "Storage account → Data protection → Enable soft delete for blobs",
            Priority:          PriorityMedium,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "SOC2": "A1.2",
                "PCI-DSS": "10.5.5",
            },
        })
    }
    
    return results
}

func (c *StorageChecks) CheckNetworkRestrictions(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListPager(nil)
    openAccounts := []string{}
    totalAccounts := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, account := range page.Value {
            totalAccounts++
            
            // Check network ACLs
            if account.Properties != nil && account.Properties.NetworkRuleSet != nil {
                acls := account.Properties.NetworkRuleSet
                
                // Check if default action is Allow (bad)
                if acls.DefaultAction != nil && *acls.DefaultAction == armstorage.DefaultActionAllow {
                    // Check if there are any IP rules or virtual network rules
                    hasRestrictions := false
                    if acls.IPRules != nil && len(acls.IPRules) > 0 {
                        hasRestrictions = true
                    }
                    if acls.VirtualNetworkRules != nil && len(acls.VirtualNetworkRules) > 0 {
                        hasRestrictions = true
                    }
                    
                    if !hasRestrictions {
                        openAccounts = append(openAccounts, *account.Name)
                    }
                }
            } else {
                // No network ACLs means open to all
                openAccounts = append(openAccounts, *account.Name)
            }
        }
    }
    
    if len(openAccounts) > 0 {
        displayAccounts := openAccounts
        if len(openAccounts) > 3 {
            displayAccounts = openAccounts[:3]
        }
        
        results = append(results, CheckResult{
            Control:           "CC6.1",
            Name:              "Storage Network Restrictions",
            Status:            "FAIL",
            Severity:          "MEDIUM",
            Evidence:          fmt.Sprintf("%d storage accounts accessible from any network: %s", len(openAccounts), strings.Join(displayAccounts, ", ")),
            Remediation:       "Restrict to specific VNets or IP ranges",
            RemediationDetail: "Storage account → Networking → Selected networks only",
            ScreenshotGuide:   "Storage → Networking → Show 'Selected networks' with firewall rules",
            Priority:          PriorityMedium,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "SOC2": "CC6.1",
                "PCI-DSS": "1.2.1",
            },
        })
    } else if totalAccounts > 0 {
        results = append(results, CheckResult{
            Control:   "CC6.1",
            Name:      "Storage Network Restrictions",
            Status:    "PASS",
            Evidence:  fmt.Sprintf("All %d storage accounts have network restrictions", totalAccounts),
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
        })
    }
    
    return results
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
