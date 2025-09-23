// Path: /home/dijital/Documents/auditkit/scanner/pkg/azure/checks/network.go

package checks

import (
    "context"
    "fmt"
    "strings"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

type NetworkChecks struct {
    client *armnetwork.SecurityGroupsClient
}

func NewNetworkChecks(client *armnetwork.SecurityGroupsClient) *NetworkChecks {
    return &NetworkChecks{client: client}
}

func (c *NetworkChecks) Name() string {
    return "Azure Network Security"
}

func (c *NetworkChecks) Run(ctx context.Context) ([]CheckResult, error) {
    results := []CheckResult{}
    
    results = append(results, c.CheckOpenPorts(ctx)...)
    results = append(results, c.CheckDefaultNSG(ctx)...)
    results = append(results, c.CheckManagementPorts(ctx)...)
    
    return results, nil
}

func (c *NetworkChecks) CheckOpenPorts(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListAllPager(nil)
    
    openToInternet := []string{}
    totalNSGs := 0
    dangerousPorts := map[string]string{
        "22":   "SSH",
        "3389": "RDP",
        "1433": "SQL Server",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "445":  "SMB",
        "135":  "RPC",
        "21":   "FTP",
        "23":   "Telnet",
        "80":   "HTTP",
    }
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            return append(results, CheckResult{
                Control:   "CC6.1",
                Name:      "Network Security Groups",
                Status:    "ERROR",
                Evidence:  fmt.Sprintf("Unable to check NSGs: %v", err),
                Severity:  "HIGH",
                Priority:  PriorityHigh,
                Timestamp: time.Now(),
                Frameworks: GetFrameworkMappings("NETWORK_SECURITY_GROUPS"),
            })
        }
        
        for _, nsg := range page.Value {
            totalNSGs++
            nsgName := *nsg.Name
            
            if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
                for _, rule := range nsg.Properties.SecurityRules {
                    if rule.Properties != nil {
                        // Check if rule allows inbound from internet
                        if rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
                            if rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
                                // Check source
                                isInternet := false
                                if rule.Properties.SourceAddressPrefix != nil {
                                    source := *rule.Properties.SourceAddressPrefix
                                    if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
                                        isInternet = true
                                    }
                                }
                                
                                if isInternet {
                                    // Check destination port
                                    if rule.Properties.DestinationPortRange != nil {
                                        port := *rule.Properties.DestinationPortRange
                                        if port == "*" {
                                            openToInternet = append(openToInternet, fmt.Sprintf("%s (ALL PORTS!)", nsgName))
                                        } else if serviceName, isDangerous := dangerousPorts[port]; isDangerous {
                                            openToInternet = append(openToInternet, fmt.Sprintf("%s (%s port %s)", nsgName, serviceName, port))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if len(openToInternet) > 0 {
        displayNSGs := openToInternet
        if len(openToInternet) > 3 {
            displayNSGs = openToInternet[:3]
        }
        
        results = append(results, CheckResult{
            Control:           "CC6.1",
            Name:              "Open Security Group Rules",
            Status:            "FAIL",
            Severity:          "CRITICAL",
            Evidence:          fmt.Sprintf("PCI-DSS 1.2.1 VIOLATION: %d NSG rules allow internet access to sensitive ports: %s", len(openToInternet), strings.Join(displayNSGs, ", ")),
            Remediation:       "Remove or restrict internet access rules",
            RemediationDetail: "az network nsg rule update --name <rule> --nsg-name <nsg> --resource-group <rg> --source-address-prefixes <specific-ips>",
            ScreenshotGuide:   "1. Azure Portal → Network security groups\n2. Click each NSG\n3. Inbound rules → No 'Any' or 'Internet' sources\n4. For PCI: Document why each port is open",
            ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
            Priority:          PriorityCritical,
            Timestamp:         time.Now(),
            Frameworks:        GetFrameworkMappings("NETWORK_SECURITY_GROUPS"),
        })
    } else if totalNSGs > 0 {
        results = append(results, CheckResult{
            Control:    "CC6.1",
            Name:       "Network Security Groups",
            Status:     "PASS",
            Evidence:   fmt.Sprintf("All %d NSGs properly restrict internet access | Meets SOC2 CC6.1, PCI DSS 1.2.1", totalNSGs),
            Priority:   PriorityInfo,
            Timestamp:  time.Now(),
            Frameworks: GetFrameworkMappings("NETWORK_SECURITY_GROUPS"),
        })
    }
    
    return results
}

func (c *NetworkChecks) CheckDefaultNSG(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListAllPager(nil)
    
    defaultNSGsWithRules := []string{}
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, nsg := range page.Value {
            nsgName := strings.ToLower(*nsg.Name)
            
            // Check if this is a default NSG with custom rules
            if strings.Contains(nsgName, "default") {
                if nsg.Properties != nil && nsg.Properties.SecurityRules != nil && len(nsg.Properties.SecurityRules) > 0 {
                    defaultNSGsWithRules = append(defaultNSGsWithRules, *nsg.Name)
                }
            }
        }
    }
    
    if len(defaultNSGsWithRules) > 0 {
        results = append(results, CheckResult{
            Control:           "PCI-2.2.2",
            Name:              "[PCI-DSS] Default Configuration Changes",
            Status:            "INFO",
            Evidence:          fmt.Sprintf("PCI-DSS 2.2.2: %d default NSGs have custom rules - verify these are approved", len(defaultNSGsWithRules)),
            Remediation:       "Document why default NSGs were modified",
            RemediationDetail: "Create dedicated NSGs instead of modifying defaults",
            Priority:          PriorityMedium,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "2.2.2",
            },
        })
    }
    
    return results
}

func (c *NetworkChecks) CheckManagementPorts(ctx context.Context) []CheckResult {
    results := []CheckResult{}
    
    pager := c.client.NewListAllPager(nil)
    
    sshOpenCount := 0
    rdpOpenCount := 0
    
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, nsg := range page.Value {
            if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
                for _, rule := range nsg.Properties.SecurityRules {
                    if rule.Properties != nil &&
                       rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
                       rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
                        
                        // Check for SSH (22)
                        if rule.Properties.DestinationPortRange != nil && *rule.Properties.DestinationPortRange == "22" {
                            if rule.Properties.SourceAddressPrefix != nil {
                                source := *rule.Properties.SourceAddressPrefix
                                if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
                                    sshOpenCount++
                                }
                            }
                        }
                        
                        // Check for RDP (3389)
                        if rule.Properties.DestinationPortRange != nil && *rule.Properties.DestinationPortRange == "3389" {
                            if rule.Properties.SourceAddressPrefix != nil {
                                source := *rule.Properties.SourceAddressPrefix
                                if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
                                    rdpOpenCount++
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if sshOpenCount > 0 || rdpOpenCount > 0 {
        evidence := []string{}
        if sshOpenCount > 0 {
            evidence = append(evidence, fmt.Sprintf("%d SSH", sshOpenCount))
        }
        if rdpOpenCount > 0 {
            evidence = append(evidence, fmt.Sprintf("%d RDP", rdpOpenCount))
        }
        
        results = append(results, CheckResult{
            Control:           "CC6.1",
            Name:              "Management Port Exposure",
            Status:            "FAIL",
            Severity:          "CRITICAL",
            Evidence:          fmt.Sprintf("Management ports open to internet: %s | Major security risk", strings.Join(evidence, ", ")),
            Remediation:       "Use Azure Bastion or VPN instead",
            RemediationDetail: "Remove direct SSH/RDP access, implement Azure Bastion for secure management",
            ScreenshotGuide:   "1. Network security groups → Inbound rules\n2. Show no SSH/RDP from Internet\n3. Show Azure Bastion configured instead",
            ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FbastionHosts",
            Priority:          PriorityCritical,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "SOC2":    "CC6.1",
                "PCI-DSS": "1.3.1",
                "HIPAA":   "164.312(e)(1)",
            },
        })
    } else {
        results = append(results, CheckResult{
            Control:   "CC6.1",
            Name:      "Management Port Security",
            Status:    "PASS",
            Evidence:  "No SSH/RDP ports exposed to internet | Good security practice",
            Priority:  PriorityInfo,
            Timestamp: time.Now(),
        })
    }
    
    // Check for HTTP (unencrypted web traffic)
    httpCount := 0
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            break
        }
        
        for _, nsg := range page.Value {
            if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
                for _, rule := range nsg.Properties.SecurityRules {
                    if rule.Properties != nil &&
                       rule.Properties.DestinationPortRange != nil && *rule.Properties.DestinationPortRange == "80" &&
                       rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
                       rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
                        httpCount++
                    }
                }
            }
        }
    }
    
    if httpCount > 0 {
        results = append(results, CheckResult{
            Control:           "PCI-4.1",
            Name:              "[PCI-DSS] Unencrypted HTTP Traffic",
            Status:            "FAIL",
            Severity:          "HIGH",
            Evidence:          fmt.Sprintf("PCI-DSS 4.1: %d NSG rules allow HTTP (unencrypted) - use HTTPS only", httpCount),
            Remediation:       "Use HTTPS (443) instead of HTTP (80)",
            RemediationDetail: "Remove port 80 rules, redirect all traffic to HTTPS",
            Priority:          PriorityHigh,
            Timestamp:         time.Now(),
            Frameworks: map[string]string{
                "PCI-DSS": "4.1",
            },
        })
    }
    
    return results
}
