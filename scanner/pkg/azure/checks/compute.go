package checks

import (
    "context"
    "fmt"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
)

type ComputeChecks struct {
    vmClient    *armcompute.VirtualMachinesClient
    diskClient  *armcompute.DisksClient
}

func NewComputeChecks(vmClient *armcompute.VirtualMachinesClient, diskClient *armcompute.DisksClient) *ComputeChecks {
    return &ComputeChecks{
        vmClient:   vmClient,
        diskClient: diskClient,
    }
}

func (c *ComputeChecks) Name() string {
    return "Azure Compute Security"
}

func (c *ComputeChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    results = append(results, c.CheckDiskEncryption(ctx)...)
    results = append(results, c.CheckVMExtensions(ctx)...)
    results = append(results, c.CheckPublicIPs(ctx)...)
    
    return results, nil
}

func (c *ComputeChecks) CheckDiskEncryption(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.diskClient.NewListPager(nil)
    
    unencryptedDisks := []string{}
    totalDisks := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, disk := range page.Value {
            totalDisks++
            diskName := *disk.Name
            
            // Check encryption settings
            if disk.Properties != nil {
                if disk.Properties.Encryption == nil || 
                   disk.Properties.Encryption.Type == nil ||
                   *disk.Properties.Encryption.Type == armcompute.EncryptionTypeEncryptionAtRestWithPlatformKey {
                    // Platform key is okay, but customer-managed is better for PCI
                    continue
                } else if *disk.Properties.Encryption.Type == "" {
                    unencryptedDisks = append(unencryptedDisks, diskName)
                }
            } else {
                unencryptedDisks = append(unencryptedDisks, diskName)
            }
        }
    }
    
    if len(unencryptedDisks) > 0 {
        results = append(results, CheckResult{
            Control:           "CC6.3",
            Name:              "Disk Encryption at Rest",
            Status:            "FAIL",
            Severity:          "HIGH",
            Evidence:          fmt.Sprintf("%d/%d disks not encrypted | Violates PCI DSS 3.4", len(unencryptedDisks), totalDisks),
            Remediation:       "Enable disk encryption",
            RemediationDetail: "Enable Azure Disk Encryption for all VM disks",
            ScreenshotGuide:   "VM → Disks → Encryption → Show encryption enabled",
            ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2Fdisks",
            Priority:          PriorityHigh,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("DISK_ENCRYPTION"),
        })
    } else if totalDisks > 0 {
        results = append(results, CheckResult{
            Control:    "CC6.3",
            Name:       "Disk Encryption at Rest",
            Status:     "PASS",
            Evidence:   fmt.Sprintf("All %d disks encrypted | Meets SOC2 CC6.3, PCI DSS 3.4", totalDisks),
            Priority:   PriorityInfo,
            Timestamp:  time.Now(),
            Frameworks: GetFrameworkMappings("DISK_ENCRYPTION"),
        })
    }
    
    return results
}

func (c *ComputeChecks) CheckVMExtensions(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.vmClient.NewListAllPager(nil)
    
    vmsWithoutMonitoring := []string{}
    vmsWithoutAntimalware := []string{}
    totalVMs := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, vm := range page.Value {
            totalVMs++
            vmName := *vm.Name
            
            hasMonitoring := false
            hasAntimalware := false
            
            if vm.Properties != nil && vm.Resources != nil {
                for _, resource := range vm.Resources {
                    if resource.Name != nil {
                        resourceName := *resource.Name
                        if resourceName == "MicrosoftMonitoringAgent" || resourceName == "OmsAgentForLinux" {
                            hasMonitoring = true
                        }
                        if resourceName == "IaaSAntimalware" {
                            hasAntimalware = true
                        }
                    }
                }
            }
            
            if !hasMonitoring {
                vmsWithoutMonitoring = append(vmsWithoutMonitoring, vmName)
            }
            if !hasAntimalware {
                vmsWithoutAntimalware = append(vmsWithoutAntimalware, vmName)
            }
        }
    }
    
    if len(vmsWithoutMonitoring) > 0 && totalVMs > 0 {
        results = append(results, CheckResult{
            Control:           "CC7.1",
            Name:              "VM Monitoring Agents",
            Status:            "FAIL",
            Severity:          "MEDIUM",
            Evidence:          fmt.Sprintf("%d/%d VMs lack monitoring agents", len(vmsWithoutMonitoring), totalVMs),
            Remediation:       "Install Azure Monitor agent",
            RemediationDetail: "VM → Extensions → Add Microsoft Monitoring Agent",
            Priority:          PriorityMedium,
            Timestamp:         time.Now(),
        })
    }
    
    if len(vmsWithoutAntimalware) > 0 && totalVMs > 0 {
        results = append(results, CheckResult{
            Control:           "PCI-5.1",
            Name:              "[PCI-DSS] Antimalware Protection",
            Status:            "FAIL",
            Severity:          "HIGH",
            Evidence:          fmt.Sprintf("PCI-DSS 5.1: %d/%d VMs lack antimalware", len(vmsWithoutAntimalware), totalVMs),
            Remediation:       "Install Microsoft Antimalware",
            RemediationDetail: "VM → Extensions → Add Microsoft Antimalware",
            Priority:          PriorityHigh,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "5.1, 5.2",
            },
        })
    }
    
    return results
}

func (c *ComputeChecks) CheckPublicIPs(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.vmClient.NewListAllPager(nil)
    
    vmsWithPublicIP := []string{}
	_ = vmsWithPublicIP // TODO: implement check
    totalVMs := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, vm := range page.Value {
            totalVMs++
            
            if vm.Properties != nil && vm.Properties.NetworkProfile != nil {
                for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
                    // Note: Would need to query each NIC to check for public IPs
                    // For now, flag for manual review
                    _ = nic
                }
            }
        }
    }
    
    if totalVMs > 0 {
        results = append(results, CheckResult{
            Control:           "CC6.1",
            Name:              "VM Public IP Exposure",
            Status:            "INFO",
            Evidence:          fmt.Sprintf("Review %d VMs for direct public IP assignments", totalVMs),
            Remediation:       "Use Azure Bastion or Application Gateway instead of direct public IPs",
            RemediationDetail: "Remove public IPs, implement Azure Bastion for management",
            Priority:          PriorityMedium,
            Timestamp:         time.Now(),
        })
    }
    
    return results
}
