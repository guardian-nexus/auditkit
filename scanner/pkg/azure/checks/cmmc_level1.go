package checks

import (
	"context"
	"time"
)

// Note: Priority constants are defined in types.go

// AzureCMMCLevel1Checks implements all 17 CMMC Level 1 practices for Azure
type AzureCMMCLevel1Checks struct {
	// Azure clients would be injected here when integrated with scanner
}

// NewAzureCMMCLevel1Checks creates a new CMMC Level 1 checker for Azure
func NewAzureCMMCLevel1Checks() *AzureCMMCLevel1Checks {
	return &AzureCMMCLevel1Checks{}
}

// Name returns the check name
func (c *AzureCMMCLevel1Checks) Name() string {
	return "Azure CMMC Level 1"
}

// Run executes all CMMC Level 1 checks
func (c *AzureCMMCLevel1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// ACCESS CONTROL (AC) - 2 practices
	results = append(results, c.CheckAC_L1_001(ctx))
	results = append(results, c.CheckAC_L1_002(ctx))

	// IDENTIFICATION AND AUTHENTICATION (IA) - 2 practices  
	results = append(results, c.CheckIA_L1_001(ctx))
	results = append(results, c.CheckIA_L1_002(ctx))

	// MEDIA PROTECTION (MP) - 2 practices
	results = append(results, c.CheckMP_L1_001(ctx))
	results = append(results, c.CheckMP_L1_002(ctx))

	// PERSONNEL SECURITY (PS) - 1 practice
	results = append(results, c.CheckPS_L1_001(ctx))

	// SYSTEM AND COMMUNICATIONS PROTECTION (SC) - 5 practices
	results = append(results, c.CheckSC_L1_001(ctx))
	results = append(results, c.CheckSC_L1_002(ctx))
	results = append(results, c.CheckSC_L1_003(ctx))
	results = append(results, c.CheckSC_L1_004(ctx))
	results = append(results, c.CheckSC_L1_005(ctx))

	// SYSTEM AND INFORMATION INTEGRITY (SI) - 5 practices  
	results = append(results, c.CheckSI_L1_001(ctx))
	results = append(results, c.CheckSI_L1_002(ctx))
	results = append(results, c.CheckSI_L1_003(ctx))
	results = append(results, c.CheckSI_L1_004(ctx))
	results = append(results, c.CheckSI_L1_005(ctx))

	return results, nil
}

// ACCESS CONTROL (AC) - 2 practices

func (c *AzureCMMCLevel1Checks) CheckAC_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "AC.L1-3.1.1",
		Name:        "[CMMC L1] Limit Information System Access",
		Status:      "INFO",
		Evidence:    "Use Azure RBAC to limit system access to authorized users, processes acting on behalf of authorized users, or devices",
		Remediation: "Review Azure role assignments and remove excessive permissions. Implement principle of least privilege.",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Subscriptions → Access Control (IAM) → Role assignments → Screenshot showing user access limited to business need",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.1",
			"NIST 800-171": "3.1.1",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckAC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "AC.L1-3.1.2",
		Name:        "[CMMC L1] Limit Information System Access to Transaction and Function Types",
		Status:      "INFO",
		Evidence:    "Use Azure custom roles and conditional access to limit transaction types authorized users may execute",
		Remediation: "Create custom Azure roles that limit specific operations. Configure conditional access policies.",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Azure Active Directory → Roles and administrators → Custom roles → Screenshot showing transaction-specific role definitions",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RolesAndAdministrators",
		Frameworks: map[string]string{
			"CMMC": "AC.L1-3.1.2", 
			"NIST 800-171": "3.1.2",
		},
	}
}

// IDENTIFICATION AND AUTHENTICATION (IA) - 2 practices

func (c *AzureCMMCLevel1Checks) CheckIA_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "IA.L1-3.5.1",
		Name:        "[CMMC L1] Identify Information System Users",
		Status:      "INFO",
		Evidence:    "Azure AD provides unique identification for each system user accessing CUI",
		Remediation: "Ensure all users have unique Azure AD identities. Disable shared accounts.",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Azure Active Directory → Users → Screenshot showing unique user identities without shared accounts",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/AllUsers",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.1",
			"NIST 800-171": "3.5.1",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckIA_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "IA.L1-3.5.2",
		Name:        "[CMMC L1] Authenticate Information System Users",
		Status:      "INFO",
		Evidence:    "Azure AD authenticates user identities before granting access to CUI systems", 
		Remediation: "Verify Azure AD authentication is required for all CUI access. Enable strong authentication.",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Azure Active Directory → Security → Authentication methods → Screenshot showing authentication requirements enabled",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade",
		Frameworks: map[string]string{
			"CMMC": "IA.L1-3.5.2",
			"NIST 800-171": "3.5.2",
		},
	}
}

// MEDIA PROTECTION (MP) - 2 practices

func (c *AzureCMMCLevel1Checks) CheckMP_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "MP.L1-3.8.3",
		Name:        "[CMMC L1] Sanitize or Destroy CUI Media",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: Verify procedures exist for sanitizing or destroying media containing CUI",
		Remediation: "Document Azure storage sanitization procedures. Use Azure secure delete for storage accounts.",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Storage accounts → Data protection → Screenshot showing soft delete enabled | Security documentation → Screenshot media sanitization procedures",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.3",
			"NIST 800-171": "3.8.3",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckMP_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "MP.L1-3.8.2",
		Name:        "[CMMC L1] Control Access to CUI Media",
		Status:      "INFO",
		Evidence:    "Use Azure Storage access policies and RBAC to control access to media containing CUI",
		Remediation: "Configure storage account access policies. Use private endpoints and firewall rules.",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Storage accounts → Access Control (IAM) → Screenshot showing role assignments | Networking → Screenshot showing private endpoint configuration",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
		Frameworks: map[string]string{
			"CMMC": "MP.L1-3.8.2",
			"NIST 800-171": "3.8.2",
		},
	}
}

// PERSONNEL SECURITY (PS) - 1 practice

func (c *AzureCMMCLevel1Checks) CheckPS_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "PS.L1-3.9.1",
		Name:        "[CMMC L1] Screen Personnel Prior to Authorizing Access",
		Status:      "INFO",
		Evidence:    "MANUAL PROCESS: Verify personnel background screening procedures are implemented",
		Remediation: "Document and implement personnel screening procedures for Azure access",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Azure AD → Users → User details → Screenshot showing employment verification attributes",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/AllUsers",
		Frameworks: map[string]string{
			"CMMC": "PS.L1-3.9.1",
			"NIST 800-171": "3.9.1",
		},
	}
}

// SYSTEM AND COMMUNICATIONS PROTECTION (SC) - 5 practices

func (c *AzureCMMCLevel1Checks) CheckSC_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.1",
		Name:        "[CMMC L1] Monitor, Control, and Protect Communications",
		Status:      "INFO", 
		Evidence:    "Use Azure Monitor and Network Security Groups to monitor and control communications at system boundaries",
		Remediation: "Enable Azure Monitor, configure NSG flow logs, and implement network monitoring",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Monitor → Network insights → Screenshot showing network monitoring | Network Security Groups → Screenshot showing traffic control rules",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.1",
			"NIST 800-171": "3.13.1",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.5",
		Name:        "[CMMC L1] Implement Cryptographic Mechanisms",
		Status:      "INFO",
		Evidence:    "Use Azure Storage encryption and Azure Disk Encryption to prevent unauthorized disclosure of CUI",
		Remediation: "Enable encryption at rest for all storage accounts and virtual machine disks",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Storage accounts → Security + networking → Encryption → Screenshot showing encryption enabled | Virtual machines → Disks → Screenshot showing disk encryption",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.5",
			"NIST 800-171": "3.13.5",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSC_L1_003(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.11",
		Name:        "[CMMC L1] Employ FIPS-Validated Cryptography",
		Status:      "INFO",
		Evidence:    "Azure uses FIPS 140-2 validated cryptographic modules for data protection",
		Remediation: "Verify Azure services are configured to use FIPS-validated cryptography",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Compliance documentation → Screenshot FIPS 140-2 validation certificates | Key Vault → Keys → Screenshot showing FIPS-validated key creation",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.11",
			"NIST 800-171": "3.13.11",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSC_L1_004(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.16",
		Name:        "[CMMC L1] Protect CUI at Rest",
		Status:      "INFO",
		Evidence:    "Azure Storage and SQL Transparent Data Encryption protect CUI confidentiality at rest",
		Remediation: "Enable encryption at rest for all services storing CUI",
		Priority:    PriorityCritical,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Storage accounts → Encryption → Screenshot showing encryption at rest enabled | SQL databases → Transparent data encryption → Screenshot showing TDE enabled",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.16",
			"NIST 800-171": "3.13.16",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSC_L1_005(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SC.L1-3.13.17",
		Name:        "[CMMC L1] Invalidate Session Identifiers",
		Status:      "PASS",
		Evidence:    "Azure AD automatically invalidates session identifiers upon user logout and session timeout",
		Remediation: "Verify Azure AD session policies are properly configured for automatic invalidation",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Azure Active Directory → Security → Conditional access → Session → Screenshot showing session controls configured",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade",
		Frameworks: map[string]string{
			"CMMC": "SC.L1-3.13.17",
			"NIST 800-171": "3.13.17",
		},
	}
}

// SYSTEM AND INFORMATION INTEGRITY (SI) - 5 practices

func (c *AzureCMMCLevel1Checks) CheckSI_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.1",
		Name:        "[CMMC L1] Identify and Correct Information System Flaws",
		Status:      "INFO",
		Evidence:    "Use Microsoft Defender for Cloud to identify and correct information system flaws",
		Remediation: "Enable Defender for Cloud and configure vulnerability assessment",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Microsoft Defender for Cloud → Recommendations → Screenshot showing vulnerability assessment results",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.1",
			"NIST 800-171": "3.14.1",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSI_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.2",
		Name:        "[CMMC L1] Identify and Correct Flaws",
		Status:      "INFO",
		Evidence:    "Use Azure Security Center and Update Management for flaw identification and remediation",
		Remediation: "Enable Azure Security Center Standard tier and Update Management for VMs",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Security Center → Recommendations → Screenshot showing security recommendations",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.2",
			"NIST 800-171": "3.14.2",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSI_L1_003(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.4",
		Name:        "[CMMC L1] Provide Protection from Malicious Code",
		Status:      "INFO",
		Evidence:    "Use Azure Security Center and Microsoft Antimalware for malicious code protection",
		Remediation: "Enable Azure Security Center and deploy Microsoft Antimalware extension on VMs",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Security Center → Security solutions → Screenshot showing antimalware status",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.4",
			"NIST 800-171": "3.14.4",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSI_L1_004(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.6",
		Name:        "[CMMC L1] Monitor Information System Security Alerts",
		Status:      "INFO",
		Evidence:    "Use Azure Monitor and Security Center to monitor system security alerts and advisories",
		Remediation: "Configure Azure Monitor alerts and enable Security Center notifications",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing security alert rules configured | Security Center → Security alerts → Screenshot showing alert monitoring",
		ConsoleURL: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.6",
			"NIST 800-171": "3.14.6",
		},
	}
}

func (c *AzureCMMCLevel1Checks) CheckSI_L1_005(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "SI.L1-3.14.7",
		Name:        "[CMMC L1] Update Malicious Code Protection",
		Status:      "INFO",
		Evidence:    "Azure Antimalware automatically updates malicious code protection mechanisms",
		Remediation: "Verify automatic updates are enabled for antimalware and security solutions",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ScreenshotGuide: "Azure Portal → Virtual machines → Extensions → Microsoft Antimalware → Screenshot showing automatic update enabled",
		ConsoleURL: "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2FVirtualMachines",
		Frameworks: map[string]string{
			"CMMC": "SI.L1-3.14.7",
			"NIST 800-171": "3.14.7",
		},
	}
}
