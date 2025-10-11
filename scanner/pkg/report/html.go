package report

import (
	"fmt"
	"strings"
)

func GenerateHTML(result ComplianceResult) string {
	// Count automated vs manual checks
	automated := 0
	manual := 0
	passed := 0
	failed := 0
	
	for _, control := range result.Controls {
		if control.Status == "INFO" {
			manual++
		} else {
			automated++
			if control.Status == "PASS" {
				passed++
			} else if control.Status == "FAIL" {
				failed++
			}
		}
	}
	
	automatedScore := 0.0
	if automated > 0 {
		automatedScore = float64(passed) / float64(automated) * 100
	}
	
	// Generate the disclaimer banner HTML
	disclaimerHTML := fmt.Sprintf(`
        <div class="disclaimer-banner">
            <h3>⚠️ Important: Automated Technical Checks Only</h3>
            <p>This report shows <strong>%d automated technical checks</strong> out of <strong>%d total controls</strong>. 
               The %.1f%% score represents automated infrastructure checks only.</p>
            
            <div class="disclaimer-grid">
                <div class="disclaimer-box automated">
                    <h4>✓ Automated Checks (%d controls)</h4>
                    <ul>
                        <li>Infrastructure configurations</li>
                        <li>Access control policies</li>
                        <li>Encryption settings</li>
                        <li>Network security rules</li>
                        <li>Logging and monitoring</li>
                    </ul>
                </div>
                
                <div class="disclaimer-box manual">
                    <h4>✗ Manual Documentation Required (%d controls)</h4>
                    <ul>
                        <li>Organizational policies</li>
                        <li>Training records</li>
                        <li>Incident response plans</li>
                        <li>Third-party assessments</li>
                        <li>Business processes</li>
                    </ul>
                </div>
            </div>
            
            <p style="margin-top: 20px;"><strong>Full compliance requires:</strong></p>
            <ul>
                <li>Documentation of all %d manual controls</li>
                <li>Evidence collection with screenshots and artifacts</li>
                <li>Organizational policies and procedures implementation</li>
                <li>%s</li>
            </ul>
            
            <p style="margin-top: 15px; font-weight: 600; color: #721c24;">
                ⚠️ THIS TOOL DOES NOT PROVIDE CERTIFICATION. 
                Formal assessment by qualified auditor is required.
            </p>
        </div>
    `, automated, automated+manual, automatedScore, automated, manual, manual, getAssessorType(result.Framework))

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuditKit %s Compliance Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f6f8fa;
            color: #24292e;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #0366d6 0%%, #0256c7 100%%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .score-card {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .score-circle {
            width: 200px;
            height: 200px;
            margin: 0 auto 20px;
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            border: 8px solid;
        }
        
        .score-excellent {
            border-color: #28a745;
            color: #28a745;
            background: rgba(40, 167, 69, 0.1);
        }
        
        .score-good {
            border-color: #ffc107;
            color: #ffc107;
            background: rgba(255, 193, 7, 0.1);
        }
        
        .score-poor {
            border-color: #dc3545;
            color: #dc3545;
            background: rgba(220, 53, 69, 0.1);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 30px;
        }
        
        .stat-box {
            padding: 20px;
            background: #f6f8fa;
            border-radius: 6px;
            text-align: center;
        }
        
        .stat-box .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-box .label {
            color: #586069;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .disclaimer-banner {
            background: linear-gradient(135deg, #fff3cd 0%%, #ffe69c 100%%);
            border: 3px solid #ffc107;
            border-radius: 8px;
            padding: 25px;
            margin: 30px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .disclaimer-banner h3 {
            color: #856404;
            margin-bottom: 15px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .disclaimer-banner p {
            color: #533f03;
            margin-bottom: 10px;
            line-height: 1.8;
        }
        
        .disclaimer-banner ul {
            margin: 15px 0;
            padding-left: 20px;
        }
        
        .disclaimer-banner li {
            color: #533f03;
            margin: 8px 0;
        }
        
        .disclaimer-banner strong {
            color: #000;
        }
        
        .disclaimer-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        
        .disclaimer-box {
            padding: 15px;
            border-radius: 6px;
            border: 2px solid;
        }
        
        .disclaimer-box.automated {
            background: #d4edda;
            border-color: #28a745;
        }
        
        .disclaimer-box.manual {
            background: #f8d7da;
            border-color: #dc3545;
        }
        
        .disclaimer-box h4 {
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .disclaimer-box.automated h4 {
            color: #155724;
        }
        
        .disclaimer-box.manual h4 {
            color: #721c24;
        }
        
        .summary {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .summary h2 {
            color: #24292e;
            margin-bottom: 15px;
            font-size: 1.8em;
        }
        
        .summary p {
            color: #586069;
            font-size: 1.1em;
            line-height: 1.8;
        }
        
        .priority-actions {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .priority-actions h2 {
            color: #24292e;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .action-item {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 6px;
            border-left: 4px solid;
        }
        
        .action-critical {
            background: #fef2f2;
            border-color: #dc3545;
        }
        
        .action-high {
            background: #fffbeb;
            border-color: #ffc107;
        }
        
        .action-medium {
            background: #f0f9ff;
            border-color: #0366d6;
        }
        
        .controls-section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .controls-section h2 {
            color: #24292e;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .section-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e1e4e8;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 1em;
            color: #586069;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .tab:hover {
            color: #0366d6;
        }
        
        .tab.active {
            color: #0366d6;
            border-bottom-color: #0366d6;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .control-card {
            background: #f6f8fa;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 6px;
            border-left: 4px solid;
        }
        
        .control-card.critical {
            border-color: #dc3545;
            background: #fef2f2;
        }
        
        .control-card.high {
            border-color: #ffc107;
            background: #fffbeb;
        }
        
        .control-card.pass {
            border-color: #28a745;
            background: #f0fdf4;
        }
        
        .control-card.info {
            border-color: #0366d6;
            background: #f0f9ff;
        }
        
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }
        
        .control-title {
            font-weight: 600;
            font-size: 1.1em;
            color: #24292e;
        }
        
        .control-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-fail {
            background: #dc3545;
            color: white;
        }
        
        .badge-pass {
            background: #28a745;
            color: white;
        }
        
        .badge-info {
            background: #0366d6;
            color: white;
        }
        
        .control-issue {
            color: #586069;
            margin-bottom: 10px;
            padding: 10px;
            background: white;
            border-radius: 4px;
        }
        
        .control-fix {
            background: #24292e;
            color: #f6f8fa;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 10px;
        }
        
        .control-evidence {
            margin-top: 15px;
            padding: 15px;
            background: white;
            border-radius: 4px;
            border: 1px solid #e1e4e8;
        }
        
        .evidence-title {
            font-weight: 600;
            color: #0366d6;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .evidence-steps {
            list-style: none;
            padding-left: 0;
        }
        
        .evidence-steps li {
            padding: 6px 0;
            color: #586069;
        }
        
        .evidence-steps li:before {
            content: "→ ";
            color: #0366d6;
            font-weight: bold;
            margin-right: 8px;
        }
        
        .console-link {
            display: inline-block;
            padding: 8px 16px;
            background: #0366d6;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.9em;
            margin-top: 10px;
            transition: background 0.3s;
        }
        
        .console-link:hover {
            background: #0256c7;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #586069;
            font-size: 0.9em;
            background: white;
            margin-top: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .footer a {
            color: #0366d6;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                max-width: 100%%;
            }
            .control-card {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>%s</h1>
            <div class="subtitle">Generated %s | Account: %s</div>
        </div>
        
        <div class="score-card">
            <div class="score-circle %s">
                %.0f%%
            </div>
            <h2>Automated Check Score</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="number">%d</div>
                    <div class="label">Total Controls</div>
                </div>
                <div class="stat-box">
                    <div class="number" style="color: #28a745;">%d</div>
                    <div class="label">Passed</div>
                </div>
                <div class="stat-box">
                    <div class="number" style="color: #dc3545;">%d</div>
                    <div class="label">Failed</div>
                </div>
            </div>
        </div>
        
        %s
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>%s</p>
        </div>
        
        %s
        
        <div class="controls-section">
            <h2>Control Details</h2>
            <div class="section-tabs">
                <button class="tab active" onclick="showTab('failed')">Failed Controls (%d)</button>
                <button class="tab" onclick="showTab('passed')">Passed Controls (%d)</button>
                <button class="tab" onclick="showTab('info')">Manual Documentation (%d)</button>
            </div>
            
            <div id="failed" class="tab-content active">
                %s
            </div>
            
            <div id="passed" class="tab-content">
                %s
            </div>
            
            <div id="info" class="tab-content">
                %s
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by <strong>AuditKit</strong> - Multi-Cloud Compliance Scanner</p>
            <p><a href="https://github.com/guardian-nexus/auditkit" target="_blank">Learn More</a></p>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabName).classList.add('active');
            
            event.target.classList.add('active');
        }
    </script>
</body>
</html>`,
		getFrameworkLabel(result.Framework),
		getFrameworkLabel(result.Framework),
		result.Timestamp.Format("January 2, 2006 at 3:04 PM"),
		result.AccountID,
		getScoreClass(result.Score),
		result.Score,
		result.TotalControls,
		result.PassedControls,
		result.FailedControls,
		disclaimerHTML,
		generateSummaryText(result),
		generatePriorityActions(result),
		countByStatus(result.Controls, "FAIL"),
		countByStatus(result.Controls, "PASS"),
		countByStatus(result.Controls, "INFO"),
		generateFailedControlsHTML(result),
		generatePassedControlsHTML(result),
		generateInfoControlsHTML(result),
	)
}

func getFrameworkLabel(framework string) string {
	if framework == "" || framework == "all" {
		return "Multi-Framework Compliance Report"
	}
	return strings.ToUpper(framework) + " Compliance Report"
}

func getScoreClass(score float64) string {
	if score >= 80 {
		return "score-excellent"
	} else if score >= 60 {
		return "score-good"
	}
	return "score-poor"
}

func getAssessorType(framework string) string {
	switch strings.ToLower(framework) {
	case "cmmc":
		return "Formal assessment by C3PAO (Certified Third Party Assessor)"
	case "pci", "pci-dss":
		return "Formal assessment by QSA (Qualified Security Assessor)"
	case "hipaa":
		return "HIPAA Security Risk Assessment by qualified auditor"
	default:
		return "Third-party assessment by qualified auditor"
	}
}

func generateSummaryText(result ComplianceResult) string {
	status := "requires immediate attention"
	if result.Score >= 80 {
		status = "is in good standing"
	} else if result.Score >= 60 {
		status = "needs improvement"
	}
	
	criticalCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" && control.Severity == "CRITICAL" {
			criticalCount++
		}
	}
	
	return fmt.Sprintf(
		"Your %s environment %s with a compliance score of %.1f%%. Out of %d controls evaluated, %d passed and %d failed. "+
			"Immediate action is required on %d critical issues to achieve compliance.",
		strings.ToUpper(result.Provider),
		status,
		result.Score,
		result.TotalControls,
		result.PassedControls,
		result.FailedControls,
		criticalCount,
	)
}

func generatePriorityActions(result ComplianceResult) string {
	if len(result.Recommendations) == 0 {
		return ""
	}
	
	html := `<div class="priority-actions">
            <h2>Top Priority Actions</h2>`
	
	for i, rec := range result.Recommendations {
		if i >= 5 {
			break
		}
		
		class := "action-medium"
		if strings.Contains(rec, "CRITICAL") || strings.Contains(strings.ToUpper(rec), "FAIL") {
			class = "action-critical"
		} else if strings.Contains(rec, "HIGH") {
			class = "action-high"
		}
		
		html += fmt.Sprintf(`
            <div class="action-item %s">
                <strong>%d.</strong> %s
            </div>`, class, i+1, rec)
	}
	
	html += `</div>`
	return html
}

func generateFailedControlsHTML(result ComplianceResult) string {
	html := ""
	
	failedCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" {
			failedCount++
			
			severityClass := "control-card"
			if control.Severity == "CRITICAL" {
				severityClass += " critical"
			} else if control.Severity == "HIGH" {
				severityClass += " high"
			}
			
			html += fmt.Sprintf(`
                <div class="%s">
                    <div class="control-header">
                        <div class="control-title">%d. [%s] %s</div>
                        <span class="control-badge badge-fail">FAIL</span>
                    </div>
                    <div class="control-issue">
                        <strong>Issue:</strong> %s
                    </div>`,
				severityClass,
				failedCount,
				control.ID,
				control.Name,
				control.Evidence,
			)
			
			if control.Remediation != "" {
				html += fmt.Sprintf(`
                    <div class="control-fix">$ %s</div>`,
					control.Remediation,
				)
			}
			
			if control.ScreenshotGuide != "" || control.ConsoleURL != "" {
				html += `<div class="control-evidence">
                        <div class="evidence-title">
                            <span>Evidence Collection Guide</span>
                        </div>`
				
				if control.ScreenshotGuide != "" {
					html += `<ul class="evidence-steps">`
					steps := strings.Split(control.ScreenshotGuide, "\n")
					for _, step := range steps {
						step = strings.TrimSpace(step)
						if len(step) > 0 {
							html += fmt.Sprintf(`<li>%s</li>`, step)
						}
					}
					html += `</ul>`
				}
				
				if control.ConsoleURL != "" {
					html += fmt.Sprintf(`
                        <a href="%s" target="_blank" class="console-link">Open Console →</a>`,
						control.ConsoleURL,
					)
				}
				
				html += `</div>`
			}
			
			html += `</div>`
		}
	}
	
	if failedCount == 0 {
		html = `<div class="control-card pass">
                    <div class="control-title">[PASS] All controls passed - excellent work!</div>
                </div>`
	}
	
	return html
}

func generatePassedControlsHTML(result ComplianceResult) string {
	html := ""
	
	passedCount := 0
	for _, control := range result.Controls {
		if control.Status == "PASS" {
			passedCount++
			
			html += fmt.Sprintf(`
                <div class="control-card pass">
                    <div class="control-header">
                        <div class="control-title">%d. [%s] %s</div>
                        <span class="control-badge badge-pass">PASS</span>
                    </div>
                    <div class="control-issue">%s</div>
                </div>`,
				passedCount,
				control.ID,
				control.Name,
				control.Evidence,
			)
		}
	}
	
	if passedCount == 0 {
		html = `<div class="control-card">
                    <div class="control-title">No controls passed yet. Review the failed controls and start fixing issues.</div>
                </div>`
	}
	
	return html
}

func generateInfoControlsHTML(result ComplianceResult) string {
	html := ""
	
	infoCount := 0
	for _, control := range result.Controls {
		if control.Status == "INFO" {
			infoCount++
			
			html += fmt.Sprintf(`
                <div class="control-card info">
                    <div class="control-header">
                        <div class="control-title">%d. [%s] %s</div>
                        <span class="control-badge badge-info">MANUAL</span>
                    </div>
                    <div class="control-issue">
                        <strong>Documentation Required:</strong> %s
                    </div>`,
				infoCount,
				control.ID,
				control.Name,
				control.Evidence,
			)
			
			if control.ScreenshotGuide != "" || control.ConsoleURL != "" {
				html += `<div class="control-evidence">
                        <div class="evidence-title">
                            <span>Evidence Collection Guide</span>
                        </div>`
				
				if control.ScreenshotGuide != "" {
					html += `<ul class="evidence-steps">`
					steps := strings.Split(control.ScreenshotGuide, "\n")
					for _, step := range steps {
						step = strings.TrimSpace(step)
						if len(step) > 0 {
							html += fmt.Sprintf(`<li>%s</li>`, step)
						}
					}
					html += `</ul>`
				}
				
				if control.ConsoleURL != "" {
					html += fmt.Sprintf(`
                        <a href="%s" target="_blank" class="console-link">View in Console →</a>`,
						control.ConsoleURL,
					)
				}
				
				html += `</div>`
			}
			
			html += `</div>`
		}
	}
	
	if infoCount == 0 {
		html = `<div class="control-card info">
                    <div class="control-title">No manual documentation controls for this framework.</div>
                </div>`
	}
	
	return html
}

func countByStatus(controls []ControlResult, status string) int {
	count := 0
	for _, control := range controls {
		if control.Status == status {
			count++
		}
	}
	return count
}
