package webui

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
	<title>Zoraxy Crowdsec Bouncer Debug UI</title>
	<meta charset="UTF-8">
	<style>
        /* Make the page inherit parent theme colors */
        html, body {
            background-color: transparent !important;
            color: inherit;
            font-family: inherit;
            margin: 0;
            padding: 20px;
        }
        
        /* Ensure links are visible in both themes */
        a {
            color: #007bff;
        }
        
        /* Dark theme adjustments */
        @media (prefers-color-scheme: dark) {
            a {
                color: #4dabf7;
            }
            
            pre {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 4px;
                padding: 10px;
            }
        }
        
        /* Light theme adjustments */
        @media (prefers-color-scheme: light) {
            pre {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
        }
        
        /* Tooltip styling */
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
            color: #dc3545;
        }
        
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 300px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1000;
            bottom: 125%%;
            left: 50%%;
            margin-left: -150px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 12px;
            word-wrap: break-word;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        .tooltip .tooltiptext::after {
            content: "";
            position: absolute;
            top: 100%%;
            left: 50%%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #333 transparent transparent transparent;
        }
        
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        
        /* Better pre formatting for both themes */
        pre {
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        /* Metrics dashboard styling */
        .metrics-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .metric-card {
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        @media (prefers-color-scheme: dark) {
            .metric-card {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
        }
        
        @media (prefers-color-scheme: light) {
            .metric-card {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
            }
        }
        
        .metric-title {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
            color: inherit;
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .metric-description {
            font-size: 12px;
            opacity: 0.8;
        }
        
        .metric-breakdown {
            margin-top: 15px;
        }
        
        .metric-breakdown-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid rgba(128,128,128,0.2);
        }
        
        .metric-breakdown-item:last-child {
            border-bottom: none;
        }
        
        .metric-label {
            font-weight: 500;
        }
        
        .metric-count {
            font-weight: bold;
        }
    </style>
</head>
<body>
	<h1>Zoraxy Crowdsec Bouncer Debug UI</h1>
	<h2>Plugin Information</h2>
	<p>Version: %s</p>
	<p>
	GitHub Repository: <a href="https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer">https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer</a>
	</p>
	<h2>Metrics</h2>
	<div class="metrics-dashboard">
%s
	</div>

	<h2>[Received Headers]</h2>
	<pre>
%s
	</pre>
</body>
</html>
`
)

// RenderHeaders renders the headers received in the request as HTML.
func RenderHeaders(r *http.Request) string {
	var headerOutput string = ""

	headerKeys := make([]string, 0, len(r.Header))
	for name := range r.Header {
		headerKeys = append(headerKeys, name)
	}
	sort.Strings(headerKeys)

	for _, name := range headerKeys {
		values := r.Header[name]
		for _, value := range values {
			headerOutput += fmt.Sprintf("%s: %s\n", name, html.EscapeString(value))
		}
	}

	return headerOutput
}

// RenderMetrics renders the current metrics as HTML dashboard cards
func RenderMetrics() string {
	var output string

	// Get metrics from Prometheus
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Sprintf(`<div class="metric-card"><div class="metric-title">Error</div><div class="metric-description">Failed to gather metrics: %s</div></div>`, html.EscapeString(err.Error()))
	}

	// Track metrics by name
	metricData := make(map[string]map[string]float64)

	for _, mf := range metricFamilies {
		metricName := mf.GetName()

		// Only process our bouncer metrics
		if metricName != string(metrics.BLOCKED_REQUESTS) && metricName != string(metrics.PROCESSED_REQUESTS) {
			continue
		}

		metricData[metricName] = make(map[string]float64)

		for _, metric := range mf.GetMetric() {
			var origin string = "unknown"

			// Extract origin label
			for _, label := range metric.GetLabel() {
				if label.GetName() == "origin" {
					origin = label.GetValue()
					break
				}
			}

			value := metric.GetGauge().GetValue()
			metricData[metricName][origin] = value
		}
	}

	// Render blocked requests card
	if blocked, exists := metricData[string(metrics.BLOCKED_REQUESTS)]; exists {
		total := 0.0
		breakdown := ""

		for origin, count := range blocked {
			total += count
			breakdown += fmt.Sprintf(`<div class="metric-breakdown-item"><span class="metric-label">%s</span><span class="metric-count">%.0f</span></div>`,
				html.EscapeString(origin), count)
		}

		if breakdown == "" {
			breakdown = `<div class="metric-breakdown-item"><span class="metric-label">No data</span><span class="metric-count">0</span></div>`
		}

		output += fmt.Sprintf(`
		<div class="metric-card">
			<div class="metric-title">Blocked Requests</div>
			<div class="metric-value">%.0f</div>
			<div class="metric-description">Total requests blocked by CrowdSec decisions</div>
			<div class="metric-breakdown">
				%s
			</div>
		</div>`, total, breakdown)
	}

	// Render processed requests card
	if processed, exists := metricData[string(metrics.PROCESSED_REQUESTS)]; exists {
		total := 0.0
		breakdown := ""

		for origin, count := range processed {
			total += count
			breakdown += fmt.Sprintf(`<div class="metric-breakdown-item"><span class="metric-label">%s</span><span class="metric-count">%.0f</span></div>`,
				html.EscapeString(origin), count)
		}

		if breakdown == "" {
			breakdown = `<div class="metric-breakdown-item"><span class="metric-label">No data</span><span class="metric-count">0</span></div>`
		}

		output += fmt.Sprintf(`
		<div class="metric-card">
			<div class="metric-title">Processed Requests</div>
			<div class="metric-value">%.0f</div>
			<div class="metric-description">Total requests processed by the bouncer</div>
			<div class="metric-breakdown">
				%s
			</div>
		</div>`, total, breakdown)
	}

	// Calculate and show block rate if we have both metrics
	if blocked, blockedExists := metricData[string(metrics.BLOCKED_REQUESTS)]; blockedExists {
		if processed, processedExists := metricData[string(metrics.PROCESSED_REQUESTS)]; processedExists {
			totalBlocked := 0.0
			totalProcessed := 0.0

			for _, count := range blocked {
				totalBlocked += count
			}
			for _, count := range processed {
				totalProcessed += count
			}

			blockRate := 0.0
			if totalProcessed > 0 {
				blockRate = (totalBlocked / totalProcessed) * 100
			}

			output += fmt.Sprintf(`
			<div class="metric-card">
				<div class="metric-title">Block Rate</div>
				<div class="metric-value">%.1f%%</div>
				<div class="metric-description">Percentage of requests blocked</div>
			</div>`, blockRate)
		}
	}

	// If no metrics found, show placeholder
	if output == "" {
		output = `<div class="metric-card"><div class="metric-title">No Metrics Available</div><div class="metric-description">Start processing requests to see metrics data</div></div>`
	}

	return output
}

// Uses the GitHub API to check the latest version of the plugin.
// Returns both the latest version and the release page URL.
func versionCheck() (string, string, error) {
	const ENDPOINT = "https://api.github.com/repos/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/tags"
	const HEADER_KEY = "Accept"
	const HEADER_VALUE = "application/vnd.github.v3+json"

	// build the request
	req, err := http.NewRequest("GET", ENDPOINT, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set(HEADER_KEY, HEADER_VALUE)

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// parse the response
	type releaseInfo struct {
		Name string `json:"name"`
	}

	var releases []releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", "", fmt.Errorf("failed to decode response: %w", err)
	}
	if len(releases) == 0 {
		return "", "", fmt.Errorf("no releases found")
	}

	// get the latest version
	latestRelease := releases[0].Name
	releaseLink := fmt.Sprintf("https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases/tag/%s", latestRelease)

	return latestRelease, releaseLink, nil
}

// Render the debug UI
func RenderDebugUI(w http.ResponseWriter, r *http.Request) {
	headersSection := RenderHeaders(r)
	metricsSection := RenderMetrics()
	versionSection, link, err := versionCheck()
	if err != nil {
		versionSection = fmt.Sprintf(`%s <span class="tooltip">(version check failed)<span class="tooltiptext">%s</span></span>`,
			html.EscapeString(info.VERSION_STRING),
			html.EscapeString(err.Error()))
	} else if versionSection == info.VERSION_STRING {
		versionSection += " (latest)"
	} else {
		versionSection = fmt.Sprintf("%s  <a href=\"%s\">(update available)</a>", info.VERSION_STRING, html.EscapeString(link))
	}

	fmt.Fprintf(w, TEMPLATE, versionSection, metricsSection, headersSection)
	w.Header().Set("Content-Type", "text/html")
}
