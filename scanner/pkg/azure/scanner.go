package azure

import (
    "context"
    "fmt"
    "os"
    "strings"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
    
    "github.com/guardian-nexus/auditkit/scanner/pkg/azure/checks"
)

// AzureScanner handles all Azure compliance scanning
type AzureScanner struct {
    subscriptionID string
    tenantID       string
    credential     azcore.TokenCredential
    
    // Azure service clients
    storageClient       *armstorage.AccountsClient
    networkClient       *armnetwork.SecurityGroupsClient
    computeClient       *armcompute.VirtualMachinesClient
    disksClient         *armcompute.DisksClient
    keyVaultClient      *armkeyvault.VaultsClient
    monitorClient       *armmonitor.ActivityLogsClient
    sqlClient           *armsql.DatabasesClient
    roleClient          *armauthorization.RoleAssignmentsClient
    roleDefClient       *armauthorization.RoleDefinitionsClient
}

// ScanResult matches AWS structure for consistency
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

// NewScanner creates a new Azure scanner with authentication
func NewScanner(profile string) (*AzureScanner, error) {
    // Get subscription ID from environment or profile
    subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
    if subscriptionID == "" {
        return nil, fmt.Errorf("AZURE_SUBSCRIPTION_ID environment variable not set")
    }
    
    tenantID := os.Getenv("AZURE_TENANT_ID")
    if tenantID == "" {
        // Try to get from profile or use default
        tenantID = "common"
    }
    
    // Use DefaultAzureCredential which tries multiple auth methods:
    // 1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    // 2. Managed Identity
    // 3. Azure CLI
    // 4. Interactive browser
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
    }
    
    scanner := &AzureScanner{
        subscriptionID: subscriptionID,
        tenantID:       tenantID,
        credential:     cred,
    }
    
    // Initialize all service clients
    if err := scanner.initializeClients(); err != nil {
        return nil, fmt.Errorf("failed to initialize Azure clients: %v", err)
    }
    
    return scanner, nil
}

func (s *AzureScanner) initializeClients() error {
    var err error
    
    // Storage client
    s.storageClient, err = armstorage.NewAccountsClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create storage client: %v", err)
    }
    
    // Network client
    s.networkClient, err = armnetwork.NewSecurityGroupsClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create network client: %v", err)
    }
    
    // Compute clients
    s.computeClient, err = armcompute.NewVirtualMachinesClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create compute client: %v", err)
    }
    
    s.disksClient, err = armcompute.NewDisksClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create disks client: %v", err)
    }
    
    // Key Vault client
    s.keyVaultClient, err = armkeyvault.NewVaultsClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create keyvault client: %v", err)
    }
    
    // Monitor client
    s.monitorClient, err = armmonitor.NewActivityLogsClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create monitor client: %v", err)
    }
    
    // SQL client
    s.sqlClient, err = armsql.NewDatabasesClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create SQL client: %v", err)
    }
    
    // Authorization clients
    s.roleClient, err = armauthorization.NewRoleAssignmentsClient(s.subscriptionID, s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create role assignments client: %v", err)
    }
    
    s.roleDefClient, err = armauthorization.NewRoleDefinitionsClient(s.credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create role definitions client: %v", err)
    }
    
    return nil
}

// GetAccountID returns the subscription ID for Azure (equivalent to AWS account ID)
func (s *AzureScanner) GetAccountID(ctx context.Context) string {
    return s.subscriptionID
}

// ScanServices runs Azure compliance checks based on framework
func (s *AzureScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
    // Test Azure connectivity first
    if verbose {
        fmt.Println("Checking Azure connectivity...")
    }
    
    // Try to list storage accounts as a connectivity test
    pager := s.storageClient.NewListPager(nil)
    _, err := pager.NextPage(ctx)
    if err != nil {
        if verbose {
            fmt.Println("   Error: Not connected to Azure. Please configure Azure credentials.")
            fmt.Println("   Run: az login")
            fmt.Println("   Or set: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID")
        }
        return nil, fmt.Errorf("Azure connection failed: %v. Please configure Azure credentials", err)
    }
    
    var results []ScanResult
    
    // Normalize framework name
    framework = strings.ToLower(framework)
    
    if verbose {
        if framework == "pci" {
            fmt.Println("Running PCI-DSS v4.0 compliance scan for Azure...")
        } else if framework == "soc2" {
            fmt.Println("Running SOC2 compliance scan for Azure...")
        } else if framework == "cmmc" {
            fmt.Println("Running CMMC Level 1 compliance scan for Azure...")
            fmt.Println("For Level 2 upgrade to Pro")
        } else if framework == "all" {
            fmt.Println("Running multi-framework compliance scan for Azure...")
        }
    }
    
    // Run framework-specific checks
    switch framework {
    case "soc2":
        results = append(results, s.runSOC2Checks(ctx, verbose)...)
    case "pci", "pci-dss":
        results = append(results, s.runPCIChecks(ctx, verbose)...)
    case "cmmc":
        results = append(results, s.runCMMCChecks(ctx, verbose)...)
        if verbose {
            fmt.Println("Azure CMMC Level 1 scan complete")
        }
    case "hipaa":
        results = append(results, s.runBasicChecks(ctx, services, verbose)...)
        if verbose {
            fmt.Println("HIPAA checks are experimental for Azure - limited coverage")
        }
    case "all":
        results = append(results, s.runSOC2Checks(ctx, verbose)...)
        results = append(results, s.runPCIChecks(ctx, verbose)...)
        results = append(results, s.runCMMCChecks(ctx, verbose)...)
    default:
        // Default to SOC2
        results = append(results, s.runSOC2Checks(ctx, verbose)...)
    }
    
    if verbose {
        fmt.Printf("Azure scan complete - %d total checks performed\n", len(results))
    }
    
    return results, nil
}

// runCMMCChecks executes CMMC Level 1 checks for Azure
func (s *AzureScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
    var results []ScanResult
    
    if verbose {
        fmt.Println("Running CMMC Level 1 (17 practices) for Azure")
    }
    
    level1 := checks.NewAzureCMMCLevel1Checks()
    checkResults, err := level1.Run(ctx)
    if err != nil && verbose {
        fmt.Printf("Warning in Azure CMMC Level 1: %v\n", err)
    }
    
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
    
    if verbose {
        fmt.Printf("CMMC Level 1 complete: %d controls\n", len(results))
        fmt.Println("")
        fmt.Println("UPGRADE TO CMMC LEVEL 2:")
        fmt.Println("  110 additional practices for CUI handling")
        fmt.Println("  Required for DoD contractors processing CUI")
        fmt.Println("  Complete evidence collection guides")
        fmt.Println("  November 10, 2025 deadline compliance")
        fmt.Println("")
        fmt.Println("Visit auditkit.io/pro or contact info@auditkit.io")
    }
    
    return results
}

// runSOC2Checks executes SOC2 compliance checks for Azure
func (s *AzureScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
    var results []ScanResult
    
    // Initialize Azure SOC2 checks
    azureChecks := []checks.Check{
        checks.NewAzureCC1Checks(s.roleClient, s.roleDefClient),
        checks.NewAzureCC2Checks(),
        checks.NewAzureCC3Checks(s.monitorClient),
        checks.NewAzureCC4Checks(s.monitorClient),
        checks.NewAzureCC5Checks(s.keyVaultClient),
        checks.NewAzureCC6Wrapper(),
        checks.NewAzureCC7Checks(),
        checks.NewAzureCC8Checks(),
        checks.NewAzureCC9Checks(),
        checks.NewStorageChecks(s.storageClient),
        checks.NewAADChecks(s.roleClient, s.roleDefClient),
        checks.NewNetworkChecks(s.networkClient),
        checks.NewComputeChecks(s.computeClient, s.disksClient),
        checks.NewKeyVaultChecks(s.keyVaultClient),
        checks.NewMonitoringChecks(s.monitorClient),
        checks.NewSQLChecks(s.sqlClient),
    }
    
    for _, check := range azureChecks {
        if verbose {
            fmt.Printf("   Running %s checks...\n", check.Name())
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

// runPCIChecks executes PCI-DSS specific checks for Azure
func (s *AzureScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
    var results []ScanResult
    
    // PCI-DSS specific checks for Azure
    pciChecks := checks.NewAzurePCIChecks(
        s.storageClient,
        s.networkClient,
        s.roleClient,
        s.sqlClient,
        s.monitorClient,
    )
    
    if verbose {
        fmt.Printf("   Running Azure PCI-DSS v4.0 requirement checks...\n")
    }
    
    checkResults, err := pciChecks.Run(ctx)
    if err != nil && verbose {
        fmt.Printf("      Warning in PCI-DSS checks: %v\n", err)
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
    
    // Also run basic checks with PCI mappings
    basicChecks := []checks.Check{
        checks.NewStorageChecks(s.storageClient),
        checks.NewAADChecks(s.roleClient, s.roleDefClient),
        checks.NewNetworkChecks(s.networkClient),
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

// runBasicChecks runs the core Azure checks
func (s *AzureScanner) runBasicChecks(ctx context.Context, services []string, verbose bool) []ScanResult {
    var results []ScanResult
    
    basicChecks := []checks.Check{
        checks.NewStorageChecks(s.storageClient),
        checks.NewAADChecks(s.roleClient, s.roleDefClient),
        checks.NewNetworkChecks(s.networkClient),
        checks.NewComputeChecks(s.computeClient, s.disksClient),
        checks.NewKeyVaultChecks(s.keyVaultClient),
        checks.NewMonitoringChecks(s.monitorClient),
        checks.NewSQLChecks(s.sqlClient),
    }
    
    for _, check := range basicChecks {
        if verbose {
            fmt.Printf("   Running %s checks...\n", check.Name())
        }
        
        checkResults, err := check.Run(ctx)
        if err != nil && verbose {
            fmt.Printf("     Warning in %s: %v\n", check.Name(), err)
        }
        
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
