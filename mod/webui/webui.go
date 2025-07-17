package webui

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
)

const (
	TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
	<title>Zoraxy Crowdsec Bouncer Debug UI</title>
	<meta charset="UTF-8">
	<style>
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
            color: #dc3545;
        }
        
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 300px;
            background-color: #555;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%%;
            left: 50%%;
            margin-left: -150px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 12px;
            word-wrap: break-word;
        }
        
        .tooltip .tooltiptext::after {
            content: "";
            position: absolute;
            top: 100%%;
            left: 50%%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #555 transparent transparent transparent;
        }
        
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
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

	fmt.Fprintf(w, TEMPLATE, versionSection, headersSection)
	w.Header().Set("Content-Type", "text/html")
}
