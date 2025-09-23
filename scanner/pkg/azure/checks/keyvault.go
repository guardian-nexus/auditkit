package checks

import (
	"context"
	"time"
	
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

type KeyVaultChecks struct {
	client *armkeyvault.VaultsClient
}

func NewKeyVaultChecks(client *armkeyvault.VaultsClient) *KeyVaultChecks {
	return &KeyVaultChecks{client: client}
}

func (c *KeyVaultChecks) Name() string {
	return "Azure Key Vault Security"
}

func (c *KeyVaultChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}
	
	// For now, just return manual checks since the SDK structure varies
	results = append(results, CheckResult{
		Control:           "CC6.3",
		Name:              "Key Vault Purge Protection",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify purge protection is enabled on Key Vaults",
		Remediation:       "Enable purge protection to prevent permanent deletion",
		RemediationDetail: "az keyvault update --name <vault> --enable-purge-protection true",
		ScreenshotGuide:   "Key Vault -> Properties -> Show Purge protection enabled",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("KEYVAULT_PURGE"),
	})
	
	results = append(results, CheckResult{
		Control:           "CC6.3",
		Name:              "Key Vault Soft Delete",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify soft delete is enabled with 90-day retention",
		Remediation:       "Enable soft delete for key recovery",
		RemediationDetail: "az keyvault update --name <vault> --enable-soft-delete true --soft-delete-retention-days 90",
		ScreenshotGuide:   "Key Vault -> Properties -> Show Soft delete enabled",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("KEYVAULT_PURGE"),
	})
	
	return results, nil
}
