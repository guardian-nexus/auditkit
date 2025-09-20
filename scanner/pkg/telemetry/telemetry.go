package telemetry

import (
 // "bytes"
    "crypto/sha256"
    "encoding/json"
    "fmt"
 // "net/http"
    "os"
    "path/filepath"
    "runtime"
    "time"
)

const TelemetryVersion = "1.0"
const CurrentAuditKitVersion = "v0.4.0"

type ControlResult struct {
    ID       string
    Status   string
    Severity string
}

type TelemetryData struct {
    EventType    string    `json:"event_type"`
    Version      string    `json:"version"`
    Provider     string    `json:"provider"`
    ControlCount int       `json:"control_count"`
    Score        float64   `json:"score"`
    OS           string    `json:"os"`
    Timestamp    time.Time `json:"timestamp"`
    SessionID    string    `json:"session_id"`
    
    // Enhanced fields (only if opted in)
    FailedChecks []string `json:"failed_checks,omitempty"`
    ScanDuration int      `json:"scan_duration_seconds,omitempty"`
}

func IsOptedIn() bool {
    // Environment variable overrides everything
    if os.Getenv("AUDITKIT_NO_TELEMETRY") == "1" {
        return false
    }
    
    // Check stored preference
    homeDir, _ := os.UserHomeDir()
    optFile := filepath.Join(homeDir, ".auditkit", "telemetry")
    
    if data, err := os.ReadFile(optFile); err == nil {
        return string(data) == "yes"
    }
    
    // First time - ask user
    return RequestOptIn()
}

func RequestOptIn() bool {
    fmt.Println("\n📊 Help improve AuditKit?")
    fmt.Println("Share anonymous usage data to help us fix common issues.")
    fmt.Println("We track: version, OS, score, failed control types")
    fmt.Println("We DON'T track: account details, resource names, or IPs")
    fmt.Print("\nEnable telemetry? (yes/no): ")
    
    var response string
    fmt.Scanln(&response)
    
    // Save preference
    homeDir, _ := os.UserHomeDir()
    os.MkdirAll(filepath.Join(homeDir, ".auditkit"), 0755)
    optFile := filepath.Join(homeDir, ".auditkit", "telemetry")
    os.WriteFile(optFile, []byte(response), 0644)
    
    if response == "yes" {
        fmt.Println("Thanks! You can disable anytime with: export AUDITKIT_NO_TELEMETRY=1")
    }
    
    return response == "yes"
}

func SendTelemetry(accountID string, score float64, controls []ControlResult, duration time.Duration) {
    if !IsOptedIn() {
        return
    }
    
    // Create anonymous session ID
    hash := sha256.Sum256([]byte(accountID))
    sessionID := fmt.Sprintf("%x", hash[:8])
    
    // Collect failed checks (just the IDs, no sensitive data)
    var failedChecks []string
    for _, control := range controls {
        if control.Status == "FAIL" {
            failedChecks = append(failedChecks, control.ID)
        }
    }
    
    data := TelemetryData{
        EventType:    "scan_completed",
        Version:      CurrentAuditKitVersion,
        Provider:     "aws",
        ControlCount: len(controls),
        Score:        score,
        OS:           runtime.GOOS,
        Timestamp:    time.Now(),
        SessionID:    sessionID,
        FailedChecks: failedChecks,
        ScanDuration: int(duration.Seconds()),
    }
    
    // Send async
    go func() {
        jsonData, _ := json.Marshal(data)
        // For now, just print to stderr until you set up endpoint
        fmt.Fprintf(os.Stderr, "DEBUG: Would send telemetry: %s\n", string(jsonData))
        
        // When ready, uncomment:
        // http.Post("https://api.auditkit.io/telemetry", 
        //     "application/json", 
        //     bytes.NewBuffer(jsonData))
    }()
}
