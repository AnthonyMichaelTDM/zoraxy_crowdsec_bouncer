package web

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

const (
	STYLE = `
<style>
        /* Make the page inherit parent theme colors */
        html, body {
            color: inherit;
			background-color: var(--theme_bg_primary) !important;
            font-family: inherit;
            margin: 0;
            padding: 20px;
        }
		
        /* Ensure links are visible in both themes */
        a {
			color: #4dabf7 !important;
		}

		h1, h2, h3, h4, h5, h6 {
			color: var(--item_color) !important;
		}
		
		p {
			color: var(--item_color) !important;
		}

		pre {
			background-color: var(--theme_bg);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 4px;
			padding: 10px;
			color: var(--item_color);
			font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
		}
       
        /* Tooltip styling */
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
            color: --color(--theme_red);
        }
        
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 300px;
            background-color: var(--theme_bg);
            color: var(--text_color);
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
            border-color: var(--theme_divider) transparent transparent transparent;
        }
        
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        
        /* Metrics dashboard styling */
        .metrics-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .metric-card {
			background-color: var(--theme_bg);
            border: 1px solid var(--theme_divider);
			color: var(--text_color);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .metric-title {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
			color: var(--text_color);
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
			color: var(--text_color);
        }
        
        .metric-description {
            font-size: 12px;
            opacity: 0.8;
			color: var(--text_color);
        }
    
        
        .metric-label {
            font-weight: 500;
			color: var(--text_color);
        }
        
        .metric-count {
            font-weight: bold;
			color: var(--text_color);
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

        /* Metrics header with refresh button */
        .metrics-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .refresh-button {
            background-color: transparent;
            color: inherit;
            border: 1px solid rgba(128, 128, 128, 0.3);
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s ease;
            opacity: 0.7;
			color: var(--text_color);
        }
        
        .refresh-button:hover {
            opacity: 1;
            border-color: rgba(128, 128, 128, 0.5);
            background-color: rgba(128, 128, 128, 0.1);
			color: var(--text_color);
        }
        
        .refresh-button:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            border-color: rgba(128, 128, 128, 0.2);
			color: var(--text_color_inverted);
        }

        .spinner {
            display: inline-block;
            width: 8px;
            height: 8px;
            border: 2px solid var(--theme_bg_inverted);
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
	`
	SCRIPT = `
<script>
		// Function to refresh metrics dashboard
        let refreshing = false;
        async function refreshMetrics() {
            if (refreshing) return;
            
            refreshing = true;
            const button = document.getElementById('refresh-btn');
            const originalText = button.innerHTML;
            
            // Show loading state
            button.disabled = true;
            button.innerHTML = '<span class="spinner"></span> Refreshing...';
            
            try {
                // Fetch updated metrics
                const response = await fetch(window.location.href);
                const html = await response.text();
                
                // Parse the response and extract just the metrics section
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newMetrics = doc.querySelector('.metrics-dashboard');
                
                // Replace the current metrics dashboard
                if (newMetrics) {
                    document.querySelector('.metrics-dashboard').innerHTML = newMetrics.innerHTML;
                }
                
                // Show success feedback briefly
                button.innerHTML = '✓ Refreshed';
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                    refreshing = false;
                }, 1000);
                
            } catch (error) {
                console.error('Failed to refresh metrics:', error);
                button.innerHTML = '✗ Failed';
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                    refreshing = false;
                }, 2000);
            }
        }
    </script>
`
	TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
	<title>Zoraxy Crowdsec Bouncer Debug UI</title>
	<meta charset="UTF-8">
	<!-- style section --> %s
    <!-- script section --> %s
	<link rel="stylesheet" href="https://zoraxy.anthonyrubick.com/main.css">
	<link rel="stylesheet" href="https://zoraxy.anthonyrubick.com/darktheme.css">
	<script src="https://zoraxy.anthonyrubick.com/script/jquery-3.6.0.min.js"></script>
	<script defer src="https://zoraxy.anthonyrubick.com/script/darktheme.js"></script>
</head>
<body>
	<h1>Zoraxy Crowdsec Bouncer Debug UI</h1>
	<h2>Plugin Information</h2>
	<p>Version: <!-- version section --> %s</p>
	<p>
	GitHub Repository: <a href="https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer">https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer</a>
	</p>
	<div class="metrics-header">
		<h2>Metrics</h2>
		<button id="refresh-btn" class="refresh-button" onclick="refreshMetrics()">Refresh</button>
	</div>
	<div class="metrics-dashboard">
<!-- metrics --> %s
	</div>

	<h2>[Received Headers]</h2>
	<pre>
<!-- headers --> %s
	</pre>
</body>
</html>
`
)

// RenderHeaders renders the headers received in the request as HTML.
func renderHeaders(r *http.Request) string {
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
func renderMetrics() string {
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
		if metricName != string(metrics.DROPPED_REQUESTS) && metricName != string(metrics.PROCESSED_REQUESTS) {
			continue
		}

		metricData[metricName] = make(map[string]float64)

		for _, metric := range mf.GetMetric() {
			var hostname string = "unknown"

			// Extract origin label
			for _, label := range metric.GetLabel() {
				if label.GetName() == "hostname" {
					hostname = label.GetValue()
					break
				}
			}

			value := metric.GetGauge().GetValue()
			metricData[metricName][hostname] = value
		}
	}

	// Render blocked requests card
	if blocked, exists := metricData[string(metrics.DROPPED_REQUESTS)]; exists {
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

		for hostname, count := range processed {
			total += count
			breakdown += fmt.Sprintf(`<div class="metric-breakdown-item"><span class="metric-label">%s</span><span class="metric-count">%.0f</span></div>`,
				html.EscapeString(hostname), count)
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
	if blocked, blockedExists := metricData[string(metrics.DROPPED_REQUESTS)]; blockedExists {
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

var (
	versionCheckOnce   sync.Once
	versionCheckResult struct {
		LatestVersion string
		ReleaseLink   string
		err           error
	}
	versionCheckRateLimit = 24 * time.Hour // Check for updates at most once every 24 hours
	versionCheckLastCheck = time.Time{}
)

func storeVersionCheckResult(latestVersion, releaseLink string, err error) {
	versionCheckResult = struct {
		LatestVersion string
		ReleaseLink   string
		err           error
	}{
		LatestVersion: latestVersion,
		ReleaseLink:   releaseLink,
		err:           err,
	}
	if err != nil {
		versionCheckLastCheck = time.Now()
	}
}

// Uses the GitHub API to check the latest version of the plugin.
// Returns both the latest version and the release page URL.
func versionCheck() (string, string, error) {
	const ENDPOINT = "https://api.github.com/repos/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/tags"
	const HEADER_KEY = "Accept"
	const HEADER_VALUE = "application/vnd.github.v3+json"

	if time.Since(versionCheckLastCheck) < versionCheckRateLimit {
		versionCheckOnce = sync.Once{} // Reset for next call
	}

	versionCheckOnce.Do(func() {
		// build the request
		req, err := http.NewRequest("GET", ENDPOINT, nil)
		if err != nil {
			storeVersionCheckResult("", "", fmt.Errorf("failed to create request: %w", err))
			return
		}
		req.Header.Set(HEADER_KEY, HEADER_VALUE)

		// send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			storeVersionCheckResult("", "", fmt.Errorf("failed to send request: %w", err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			storeVersionCheckResult("", "", fmt.Errorf("unexpected status code: %d", resp.StatusCode))
			return
		}

		// parse the response
		type releaseInfo struct {
			Name string `json:"name"`
		}

		var releases []releaseInfo
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			storeVersionCheckResult("", "", fmt.Errorf("failed to decode response: %w", err))
			return
		}
		if len(releases) == 0 {
			storeVersionCheckResult("", "", fmt.Errorf("no releases found"))
			return
		}

		// get the latest version
		latestRelease := releases[0].Name
		releaseLink := fmt.Sprintf("https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases/tag/%s", latestRelease)

		// store the result
		storeVersionCheckResult(latestRelease, releaseLink, nil)
	})

	if versionCheckResult.err != nil {
		versionCheckOnce = sync.Once{} // Reset for next call
		return "", "", versionCheckResult.err
	} else {
		return versionCheckResult.LatestVersion, versionCheckResult.ReleaseLink, nil
	}
}

// Render the debug UI
func renderDebugUI(w http.ResponseWriter, r *http.Request) {
	headersSection := renderHeaders(r)
	metricsSection := renderMetrics()
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

	fmt.Fprintf(w, TEMPLATE, STYLE, SCRIPT, versionSection, metricsSection, headersSection)
	w.Header().Set("Content-Type", "text/html")
}

func InitWebUI(g *errgroup.Group, port int) {
	http.HandleFunc(info.UI_PATH+"/", renderDebugUI)
	g.Go(func() error {
		serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
		fmt.Printf("Zoraxy Crowdsec Bouncer started at %s/%s\n", serverAddr, info.UI_PATH)
		return http.ListenAndServe(serverAddr, nil)
	})
}
