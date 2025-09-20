// /home/dijital/Documents/auditkit/scanner/pkg/updater/updater.go
package updater

import (
    "encoding/json"
    "fmt"
    "net/http"
)

const CurrentVersion = "v0.3.0"

type ReleaseInfo struct {
    TagName string `json:"tag_name"`
    Body    string `json:"body"`
    URL     string `json:"html_url"`
}

func CheckForUpdates() {
    // Check GitHub releases API
    resp, err := http.Get("https://api.github.com/repos/guardian-nexus/auditkit/releases/latest")
    if err != nil {
        fmt.Println("Unable to check for updates")
        return
    }
    defer resp.Body.Close()
    
    var release ReleaseInfo
    json.NewDecoder(resp.Body).Decode(&release)
    
    if release.TagName > CurrentVersion {
        fmt.Printf("\n🎉 New version available: %s (you have %s)\n", release.TagName, CurrentVersion)
        fmt.Printf("   Update: go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest\n")
        fmt.Printf("   Or download: %s\n\n", release.URL)
    } else {
        fmt.Printf("✅ You're on the latest version (%s)\n", CurrentVersion)
    }
}
