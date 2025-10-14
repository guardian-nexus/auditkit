// Framework Crosswalk - Derives NIST 800-53 mappings from existing frameworks
// This allows 800-53 scanning without modifying individual check files

package mappings

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Crosswalk holds mappings between frameworks and NIST 800-53
type Crosswalk struct {
	SOC2ToCIS  map[string][]string `yaml:"soc2_to_800_53"`
	PCIToCIS   map[string][]string `yaml:"pci_to_800_53"`
	CMMCToCIS  map[string][]string `yaml:"cmmc_to_800_53"`
	HIPAAToCIS map[string][]string `yaml:"hipaa_to_800_53"`
}

var globalCrosswalk *Crosswalk

// LoadCrosswalk loads the framework crosswalk from YAML
func LoadCrosswalk(filepath string) (*Crosswalk, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read crosswalk file: %w", err)
	}

	var crosswalk Crosswalk
	if err := yaml.Unmarshal(data, &crosswalk); err != nil {
		return nil, fmt.Errorf("failed to parse crosswalk YAML: %w", err)
	}

	globalCrosswalk = &crosswalk
	return &crosswalk, nil
}

// GetCrosswalk returns the global crosswalk (loads if not already loaded)
func GetCrosswalk() (*Crosswalk, error) {
	if globalCrosswalk != nil {
		return globalCrosswalk, nil
	}

	// Try to load from default location
	filepath := "pkg/mappings/framework-crosswalk.yaml"
	return LoadCrosswalk(filepath)
}

// Get800_53Controls returns NIST 800-53 control IDs for a given control across all frameworks
func (c *Crosswalk) Get800_53Controls(frameworks map[string]string) []string {
	if frameworks == nil {
		return nil
	}

	controlSet := make(map[string]bool)

	// Check SOC2 mappings
	if soc2ID, exists := frameworks["SOC2"]; exists {
		if controls, found := c.SOC2ToCIS[soc2ID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check PCI mappings
	if pciID, exists := frameworks["PCI-DSS"]; exists {
		// PCI IDs might be comma-separated (e.g., "1.2.1, 1.3.4")
		pciIDs := strings.Split(pciID, ",")
		for _, id := range pciIDs {
			id = strings.TrimSpace(id)
			if controls, found := c.PCIToCIS[fmt.Sprintf("PCI-%s", id)]; found {
				for _, ctrl := range controls {
					controlSet[ctrl] = true
				}
			}
		}
	}

	// Check CMMC mappings
	if cmmcID, exists := frameworks["CMMC"]; exists {
		if controls, found := c.CMMCToCIS[cmmcID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check HIPAA mappings
	if hipaaID, exists := frameworks["HIPAA"]; exists {
		if controls, found := c.HIPAAToCIS[hipaaID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Convert set to slice
	var result []string
	for ctrl := range controlSet {
		result = append(result, ctrl)
	}

	return result
}

// Get800_53ByControlID looks up 800-53 mappings directly by control ID (e.g., "CC3.2", "PCI-1.2.1")
// This is a fallback for controls that don't have Frameworks map populated
func (c *Crosswalk) Get800_53ByControlID(controlID string) []string {
	// Try SOC2 mapping first (most common: CC1.1, CC6.2, etc.)
	if controls, found := c.SOC2ToCIS[controlID]; found {
		return controls
	}
	
	// Try PCI mapping (e.g., "PCI-1.2.1" or "1.2.1")
	if strings.HasPrefix(controlID, "PCI-") {
		if controls, found := c.PCIToCIS[controlID]; found {
			return controls
		}
	} else {
		// Try adding PCI- prefix
		if controls, found := c.PCIToCIS[fmt.Sprintf("PCI-%s", controlID)]; found {
			return controls
		}
	}
	
	// Try CMMC mapping
	if controls, found := c.CMMCToCIS[controlID]; found {
		return controls
	}
	
	// Try HIPAA mapping
	if controls, found := c.HIPAAToCIS[controlID]; found {
		return controls
	}
	
	return nil
}

// Get800_53StringByControlID returns comma-separated 800-53 IDs by control ID
func (c *Crosswalk) Get800_53StringByControlID(controlID string) string {
	controls := c.Get800_53ByControlID(controlID)
	if len(controls) == 0 {
		return ""
	}
	return strings.Join(controls, ", ")
}

// ControlHas800_53 checks if a control maps to any 800-53 controls
// First tries using the Frameworks map, then falls back to control ID lookup
func (c *Crosswalk) ControlHas800_53(frameworks map[string]string, controlID string) bool {
	// Try using Frameworks map first (if populated)
	if len(c.Get800_53Controls(frameworks)) > 0 {
		return true
	}
	
	// Fallback: try direct control ID lookup
	if len(c.Get800_53ByControlID(controlID)) > 0 {
		return true
	}
	
	return false
}

// Get800_53String returns comma-separated 800-53 control IDs
// First tries using the Frameworks map, then falls back to control ID lookup
func (c *Crosswalk) Get800_53String(frameworks map[string]string, controlID string) string {
	// Try using Frameworks map first (if populated)
	controls := c.Get800_53Controls(frameworks)
	if len(controls) > 0 {
		return strings.Join(controls, ", ")
	}
	
	// Fallback: try direct control ID lookup
	return c.Get800_53StringByControlID(controlID)
}
