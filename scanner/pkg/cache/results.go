// /home/dijital/Documents/auditkit/scanner/pkg/cache/results.go
package cache

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type CachedScan struct {
    Timestamp time.Time              `json:"timestamp"`
    AccountID string                 `json:"account_id"`
    Results   map[string]interface{} `json:"results"`
}

func SaveResults(accountID string, results interface{}) error {
    homeDir, _ := os.UserHomeDir()
    cacheDir := filepath.Join(homeDir, ".auditkit", "cache")
    os.MkdirAll(cacheDir, 0755)
    
    cache := CachedScan{
        Timestamp: time.Now(),
        AccountID: accountID,
        Results:   map[string]interface{}{"scan": results},
    }
    
    data, _ := json.MarshalIndent(cache, "", "  ")
    cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s_last_scan.json", accountID))
    
    return os.WriteFile(cacheFile, data, 0644)
}

func LoadLastScan(accountID string) (*CachedScan, error) {
    homeDir, _ := os.UserHomeDir()
    cacheFile := filepath.Join(homeDir, ".auditkit", "cache", fmt.Sprintf("%s_last_scan.json", accountID))
    
    data, err := os.ReadFile(cacheFile)
    if err != nil {
        return nil, err
    }
    
    var cache CachedScan
    err = json.Unmarshal(data, &cache)
    return &cache, err
}
