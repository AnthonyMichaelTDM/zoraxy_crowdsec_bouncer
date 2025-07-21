package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

//go:embed www/*
var content embed.FS

// API response structures
type VersionInfo struct {
	Version    string `json:"version"`
	Latest     string `json:"latest,omitempty"`
	UpdateLink string `json:"updateLink,omitempty"`
	IsLatest   bool   `json:"isLatest"`
	CheckError string `json:"checkError,omitempty"`
}

type MetricsResponse struct {
	BlockedRequests   map[string]float64 `json:"blockedRequests"`
	ProcessedRequests map[string]float64 `json:"processedRequests"`
	BlockRate         float64            `json:"blockRate"`
	Error             string             `json:"error,omitempty"`
}

type HeadersResponse struct {
	Headers map[string][]string `json:"headers"`
}

// API handlers
func apiVersionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := VersionInfo{
		Version: info.VERSION_STRING,
	}

	// Check for latest version
	latest, err := versionCheck()
	if err != nil {
		response.CheckError = err.Error()
		response.IsLatest = false
	} else {
		response.Latest = latest
		response.IsLatest = (latest == info.VERSION_STRING)
		if !response.IsLatest {
			response.UpdateLink = fmt.Sprintf("https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases/tag/%s", latest)
		}
	}

	json.NewEncoder(w).Encode(response)
}

func apiMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := MetricsResponse{
		BlockedRequests:   make(map[string]float64),
		ProcessedRequests: make(map[string]float64),
	}

	// Get metrics from Prometheus
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		response.Error = fmt.Sprintf("Failed to gather metrics: %s", err.Error())
		json.NewEncoder(w).Encode(response)
		return
	}

	// Process metrics
	for _, mf := range metricFamilies {
		metricName := mf.GetName()

		// Only process our bouncer metrics
		if metricName != string(metrics.DROPPED_REQUESTS) && metricName != string(metrics.PROCESSED_REQUESTS) {
			continue
		}

		for _, metric := range mf.GetMetric() {
			var hostname string = "unknown"

			// Extract hostname label
			for _, label := range metric.GetLabel() {
				if label.GetName() == "hostname" {
					hostname = label.GetValue()
					break
				}
			}

			value := metric.GetGauge().GetValue()

			if metricName == string(metrics.DROPPED_REQUESTS) {
				response.BlockedRequests[hostname] = value
			} else if metricName == string(metrics.PROCESSED_REQUESTS) {
				response.ProcessedRequests[hostname] = value
			}
		}
	}

	// Calculate block rate
	totalBlocked := 0.0
	totalProcessed := 0.0

	for _, count := range response.BlockedRequests {
		totalBlocked += count
	}
	for _, count := range response.ProcessedRequests {
		totalProcessed += count
	}

	if totalProcessed > 0 {
		response.BlockRate = (totalBlocked / totalProcessed) * 100
	} else {
		response.BlockRate = 0.0
	}

	json.NewEncoder(w).Encode(response)
}

func apiHeadersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := HeadersResponse{
		Headers: make(map[string][]string),
	}

	// Copy all headers
	for name, values := range r.Header {
		response.Headers[name] = values
	}

	json.NewEncoder(w).Encode(response)
}

// Version checking with caching
var (
	versionCheckOnce   sync.Once
	versionCheckResult struct {
		LatestVersion string
		err           error
	}
	versionCheckRateLimit = 24 * time.Hour // Check for updates at most once every 24 hours
	versionCheckLastCheck = time.Time{}
)

func storeVersionCheckResult(latestVersion string, err error) {
	versionCheckResult = struct {
		LatestVersion string
		err           error
	}{
		LatestVersion: latestVersion,
		err:           err,
	}
	if err != nil {
		versionCheckLastCheck = time.Now()
	}
}

// Uses the GitHub API to check the latest version of the plugin.
// Returns both the latest version and the release page URL.
func versionCheck() (string, error) {
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
			storeVersionCheckResult("", fmt.Errorf("failed to create request: %w", err))
			return
		}
		req.Header.Set(HEADER_KEY, HEADER_VALUE)

		// send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			storeVersionCheckResult("", fmt.Errorf("failed to send request: %w", err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			storeVersionCheckResult("", fmt.Errorf("unexpected status code: %d", resp.StatusCode))
			return
		}

		// parse the response
		type releaseInfo struct {
			Name string `json:"name"`
		}

		var releases []releaseInfo
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			storeVersionCheckResult("", fmt.Errorf("failed to decode response: %w", err))
			return
		}
		if len(releases) == 0 {
			storeVersionCheckResult("", fmt.Errorf("no releases found"))
			return
		}

		// get the latest version
		latestRelease := releases[0].Name

		// store the result
		storeVersionCheckResult(latestRelease, nil)
	})

	if versionCheckResult.err != nil {
		versionCheckOnce = sync.Once{} // Reset for next call
		return "", versionCheckResult.err
	} else {
		return versionCheckResult.LatestVersion, nil
	}
}

// InitWebServer initializes the web server and serves the plugin UI.
// Also sets up a shutdown handler for graceful shutdown.
//
// Runs everything on the default serve mux.
func InitWebServer(logger *logrus.Logger, g *errgroup.Group, ctx context.Context, port int) {
	mux := http.DefaultServeMux

	// webui and API
	embedWebRouter := zoraxy_plugin.NewPluginEmbedUIRouter(info.PLUGIN_ID, &content, info.WEB_ROOT, info.UI_PATH)
	embedWebRouter.AttachHandlerToMux(mux)

	// Add API endpoints
	mux.HandleFunc(info.UI_PATH+"api/version", apiVersionHandler)
	mux.HandleFunc(info.UI_PATH+"api/metrics", apiMetricsHandler)
	mux.HandleFunc(info.UI_PATH+"api/headers", apiHeadersHandler)

	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
	server := &http.Server{
		Addr:    serverAddr,
		Handler: mux,
	}

	g.Go(func() error {
		fmt.Printf("Zoraxy Crowdsec Bouncer started at %s%s\n", serverAddr, info.UI_PATH)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("web server failed: %w", err)
		}
		return nil
	})
	// Start a graceful shutdown handler
	g.Go(func() error {
		<-ctx.Done() // Wait for cancellation signal
		return ShutdownWebServer(server, 30*time.Second)
	})
}

// ShutdownWebServer gracefully shuts down the web server with a timeout
func ShutdownWebServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logrus.Info("Shutting down web server...")
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("web server shutdown failed: %w", err)
	}
	logrus.Info("Web server shutdown complete")
	return nil
}
