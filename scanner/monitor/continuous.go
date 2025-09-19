// Continuous monitoring that actually catches changes

package monitor

type ContinuousMonitor struct {
    interval time.Duration
    checks   []Check
    alerts   AlertChannel
}

func (m *ContinuousMonitor) Start() {
    ticker := time.NewTicker(m.interval)
    
    for range ticker.C {
        results := m.runAllChecks()
        
        // This is the magic - catch changes in real-time
        for _, result := range results {
            if result.Status == "FAIL" && result.IsNew {
                m.alerts.Send(Alert{
                    Title: "SOC2 Control Failed",
                    Body:  fmt.Sprintf("%s: %s", result.Control, result.Details),
                    Severity: result.Severity,
                })
            }
        }
    }
}
