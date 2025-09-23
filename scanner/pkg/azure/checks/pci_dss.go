package checks

import (
    "context"
    "fmt"
    "strings"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
)

// AzurePCIChecks implements PCI-DSS v4.0 requirements for Azure
type AzurePCIChecks struct {
    storageClient  *armstorage.AccountsClient
    networkClient  *armnetwork.SecurityGroupsClient
    roleClient     *armauthorization.RoleAssignmentsClient
    sqlClient      *armsql.DatabasesClient
    monitorClient  *armmonitor.ActivityLogsClient
}

func NewAzurePCIChecks(
    storageClient *armstorage.AccountsClient,
    networkClient *armnetwork.SecurityGroupsClient,
    roleClient *armauthorization.RoleAssignmentsClient,
    sqlClient *armsql.DatabasesClient,
    monitorClient *armmonitor.ActivityLogsClient,
) *AzurePCIChecks {
    return &AzurePCIChecks{
        storageClient: storageClient,
        networkClient: networkClient,
        roleClient:    roleClient,
        sqlClient:     sqlClient,
        monitorClient: monitorClient,
    }
}

func (c *AzurePCIChecks) Name() string {
    return "Azure PCI-DSS v4.0 Requirements"
}

func (c *AzurePCIChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    // Requirement 1: Network Security
    results = append(results, c.CheckReq1_NetworkSegmentation(ctx)...)
    
    // Requirement 3: Encryption at Rest
    results = append(results, c.CheckReq3_StorageEncryption(ctx)...)
    
    // Requirement 4: Encryption in Transit
    results = append(results, c.CheckReq4_TransitEncryption(ctx)...)
    
    // Requirement 7: Access Control
    results = append(results, c.CheckReq7_AccessControl(ctx)...)
    
    // Requirement 8: Authentication (Azure AD checks)
    results = append(results, c.CheckReq8_Authentication(ctx)...)
    
    // Requirement 10: Logging
    results = append(results, c.CheckReq10_Logging(ctx)...)
    
    return results, nil
}

// Requirement 1: Network segmentation for CDE
func (c *AzurePCIChecks) CheckReq1_NetworkSegmentation(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // Check for network segmentation using NSGs
    pager := c.networkClient.NewListAllPager(nil)
    
    nsgCount := 0
    subnetAssociations := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, nsg := range page.Value {
            nsgCount++
            
            // Check if NSG is associated with subnets
            if nsg.Properties != nil && nsg.Properties.Subnets != nil {
                subnetAssociations += len(nsg.Properties.Subnets)
            }
        }
    }
    
    if nsgCount == 0 {
        results = append(results, CheckResult{
            Control:   "PCI-1.2.1",
            Name:      "[PCI-DSS] Network Segmentation",
            Status:    "FAIL",
            Severity:  "CRITICAL",
            Evidence:  "PCI-DSS 1.2.1 VIOLATION: No Network Security Groups found - no network segmentation",
            Remediation: "Create NSGs for network segmentation",
            RemediationDetail: "Create separate VNets/subnets for CDE with restrictive NSGs",
            Priority: PriorityCritical,
            ScreenshotGuide: "Azure Portal → Virtual networks → Show segmented CDE network",
            ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FvirtualNetworks",
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "1.2.1",
            },
        })
    } else if subnetAssociations < nsgCount {
        results = append(results, CheckResult{
            Control:   "PCI-1.2.3",
            Name:      "[PCI-DSS] NSG Subnet Associations",
            Status:    "FAIL",
            Severity:  "HIGH",
            Evidence:  fmt.Sprintf("PCI-DSS 1.2.3: %d NSGs but only %d subnet associations - incomplete segmentation", nsgCount, subnetAssociations),
            Remediation: "Associate NSGs with all subnets",
            RemediationDetail: "Every subnet should have an NSG for proper segmentation",
            Priority: PriorityHigh,
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "1.2.3",
            },
        })
    } else {
        results = append(results, CheckResult{
            Control:   "PCI-1.2.1",
            Name:      "[PCI-DSS] Network Segmentation",
            Status:    "PASS",
            Evidence:  fmt.Sprintf("%d NSGs with %d subnet associations configured", nsgCount, subnetAssociations),
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "1.2.1",
            },
        })
    }
    
    return results
}

// Requirement 3: Storage encryption for cardholder data
func (c *AzurePCIChecks) CheckReq3_StorageEncryption(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.storageClient.NewListPager(nil)
    
    unencryptedStorage := []string{}
    noCustomerKeys := []string{}
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
                // PCI prefers customer-managed keys
                if account.Properties.Encryption.KeySource != nil {
                    if *account.Properties.Encryption.KeySource == armstorage.KeySourceMicrosoftStorage {
                        noCustomerKeys = append(noCustomerKeys, accountName)
                    }
                }
            } else {
                unencryptedStorage = append(unencryptedStorage, accountName)
            }
        }
    }
    
    if len(unencryptedStorage) > 0 {
        results = append(results, CheckResult{
            Control:   "PCI-3.4",
            Name:      "[PCI-DSS] Storage Encryption (Mandatory)",
            Status:    "FAIL",
            Severity:  "CRITICAL",
            Evidence:  fmt.Sprintf("PCI-DSS 3.4 VIOLATION: %d storage accounts NOT encrypted", len(unencryptedStorage)),
            Remediation: "Enable encryption immediately",
            RemediationDetail: "All storage must be encrypted for PCI compliance",
            Priority: PriorityCritical,
            ScreenshotGuide: "Storage account → Encryption → Show encryption enabled",
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "3.4, 3.4.1",
            },
        })
    }
    
    if len(noCustomerKeys) > 0 && len(noCustomerKeys) == totalAccounts {
        results = append(results, CheckResult{
            Control:   "PCI-3.5",
            Name:      "[PCI-DSS] Encryption Key Management",
            Status:    "INFO",
            Evidence:  fmt.Sprintf("PCI-DSS 3.5: All storage uses Microsoft-managed keys - consider customer-managed keys for CDE", ),
            Remediation: "Consider Azure Key Vault for customer-managed keys",
            RemediationDetail: "Use customer-managed keys for cardholder data storage",
            Priority: PriorityMedium,
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "3.5, 3.6",
            },
        })
    }
    
    return results
}

// Requirement 4: Encryption in transit
func (c *AzurePCIChecks) CheckReq4_TransitEncryption(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // Check storage accounts for HTTPS enforcement
    pager := c.storageClient.NewListPager(nil)
    
    noHTTPS := []string{}
    noTLS12 := []string{}
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, account := range page.Value {
            accountName := *account.Name
            
            if account.Properties != nil {
                // Check HTTPS enforcement
                if account.Properties.EnableHTTPSTrafficOnly == nil || !*account.Properties.EnableHTTPSTrafficOnly {
                    noHTTPS = append(noHTTPS, accountName)
                }
                
                // Check minimum TLS version (PCI requires TLS 1.2+)
                if account.Properties.MinimumTLSVersion == nil || *account.Properties.MinimumTLSVersion == armstorage.MinimumTLSVersionTLS10 || *account.Properties.MinimumTLSVersion == armstorage.MinimumTLSVersionTLS11 {
                    noTLS12 = append(noTLS12, accountName)
                }
            }
        }
    }
    
    if len(noHTTPS) > 0 {
        results = append(results, CheckResult{
            Control:   "PCI-4.1",
            Name:      "[PCI-DSS] HTTPS Enforcement",
            Status:    "FAIL",
            Severity:  "CRITICAL",
            Evidence:  fmt.Sprintf("PCI-DSS 4.1 VIOLATION: %d storage accounts allow HTTP: %s", len(noHTTPS), strings.Join(noHTTPS[:min(3, len(noHTTPS))], ", ")),
            Remediation: "Enable HTTPS-only immediately",
            RemediationDetail: fmt.Sprintf("az storage account update --name %s --https-only true", noHTTPS[0]),
            Priority: PriorityCritical,
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "4.1",
            },
        })
    }
    
    if len(noTLS12) > 0 {
        results = append(results, CheckResult{
            Control:   "PCI-4.1",
            Name:      "[PCI-DSS] TLS 1.2+ Required",
            Status:    "FAIL",
            Severity:  "HIGH",
            Evidence:  fmt.Sprintf("PCI-DSS 4.1: %d storage accounts allow TLS < 1.2: %s", len(noTLS12), strings.Join(noTLS12[:min(3, len(noTLS12))], ", ")),
            Remediation: "Set minimum TLS version to 1.2",
            RemediationDetail: fmt.Sprintf("az storage account update --name %s --min-tls-version TLS1_2", noTLS12[0]),
            Priority: PriorityHigh,
            ScreenshotGuide: "Storage → Configuration → Minimum TLS version = 1.2",
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "4.1",
            },
        })
    }
    
    return results
}

// Requirement 7: Access control
func (c *AzurePCIChecks) CheckReq7_AccessControl(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // Check for excessive privileged roles
    pager := c.roleClient.NewListPager(nil)
    
    ownerCount := 0
    contributorCount := 0
    userAccessAdminCount := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, assignment := range page.Value {
            if assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
                roleID := *assignment.Properties.RoleDefinitionID
                
                // Check for privileged roles
                if strings.Contains(roleID, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
                    ownerCount++
                } else if strings.Contains(roleID, "b24988ac-6180-42a0-ab88-20f7382dd24c") {
                    contributorCount++
                } else if strings.Contains(roleID, "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9") {
                    userAccessAdminCount++
                }
            }
        }
    }
    
    totalPrivileged := ownerCount + contributorCount + userAccessAdminCount
    
    if totalPrivileged > 5 {
        results = append(results, CheckResult{
            Control:   "PCI-7.1",
            Name:      "[PCI-DSS] Least Privilege Violation",
            Status:    "FAIL",
            Severity:  "HIGH",
            Evidence:  fmt.Sprintf("PCI-DSS 7.1: %d users with privileged access (Owner: %d, Contributor: %d, UAA: %d) - excessive", totalPrivileged, ownerCount, contributorCount, userAccessAdminCount),
            Remediation: "Implement least privilege - use specific roles",
            RemediationDetail: "Review each privileged user and downgrade to specific roles",
            Priority: PriorityHigh,
            ScreenshotGuide: "Subscription → Access control → Show minimal privileged users",
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "7.1, 7.1.2",
            },
        })
    } else {
        results = append(results, CheckResult{
            Control:   "PCI-7.1",
            Name:      "[PCI-DSS] Least Privilege",
            Status:    "PASS",
            Evidence:  fmt.Sprintf("%d privileged users (acceptable for PCI)", totalPrivileged),
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "7.1",
            },
        })
    }
    
    return results
}

// Requirement 8: Authentication
func (c *AzurePCIChecks) CheckReq8_Authentication(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // MFA and password policy require Graph API - provide guidance
    results = append(results, CheckResult{
        Control:   "PCI-8.3.1",
        Name:      "[PCI-DSS] MFA for ALL Access",
        Status:    "INFO",
        Evidence:  "PCI-DSS 8.3.1: MANUAL CHECK - Verify MFA enabled for ALL users with console access",
        Remediation: "Enable MFA for every user - no exceptions",
        RemediationDetail: "Azure AD → Users → Per-user MFA → Enable for ALL",
        ScreenshotGuide: "Azure AD → Users → Show MFA status = Enabled/Enforced for ALL users",
        Priority: PriorityCritical,
        Timestamp: time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "8.3.1",
        },
    })
    
    results = append(results, CheckResult{
        Control:   "PCI-8.2.4",
        Name:      "[PCI-DSS] 90-Day Password Rotation",
        Status:    "INFO",
        Evidence:  "PCI-DSS 8.2.4: MANUAL CHECK - Passwords MUST expire every 90 days maximum",
        Remediation: "Configure 90-day password expiration",
        RemediationDetail: "Azure AD → Password policy → Maximum age = 90 days",
        Priority: PriorityCritical,
        Timestamp: time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "8.2.4",
        },
    })
    
    results = append(results, CheckResult{
        Control:   "PCI-8.1.8",
        Name:      "[PCI-DSS] 15-Minute Session Timeout",
        Status:    "INFO",
        Evidence:  "PCI-DSS 8.1.8: Configure 15-minute idle timeout for all sessions",
        Remediation: "Set session timeout to 15 minutes",
        RemediationDetail: "Azure AD → Conditional Access → Session policy = 15 minutes",
        Priority: PriorityHigh,
        Timestamp: time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "8.1.8",
        },
    })
    
    return results
}

// Requirement 10: Logging
func (c *AzurePCIChecks) CheckReq10_Logging(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    // Check if Activity Log is configured (simplified check)
    // Note: Full check requires querying log analytics workspace
    
    results = append(results, CheckResult{
        Control:   "PCI-10.1",
        Name:      "[PCI-DSS] Audit Logging Implementation",
        Status:    "INFO",
        Evidence:  "PCI-DSS 10.1: Verify Activity Log is exported to storage/workspace",
        Remediation: "Configure Activity Log export with 12-month retention",
        RemediationDetail: "Monitor → Activity log → Export → Storage account with 365+ day retention",
        ScreenshotGuide: "Monitor → Activity log → Diagnostic settings → Show export configured",
        ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/activityLog",
        Priority: PriorityHigh,
        Timestamp: time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "10.1, 10.2.1",
        },
    })
    
    results = append(results, CheckResult{
        Control:   "PCI-10.5.3",
        Name:      "[PCI-DSS] 12-Month Log Retention",
        Status:    "INFO",
        Evidence:  "PCI-DSS 10.5.3: Logs must be retained for 12+ months (3 months readily available)",
        Remediation: "Configure storage lifecycle for 365+ day retention",
        RemediationDetail: "Storage account → Lifecycle management → Archive after 90 days, delete after 365+",
        Priority: PriorityHigh,
        Timestamp: time.Now(),
        Frameworks: map[string]string{
            "PCI-DSS": "10.5.3",
        },
    })
    
    return results
}
