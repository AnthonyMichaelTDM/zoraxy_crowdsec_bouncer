package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
	LogLevelString            string `yaml:"log_level"`
	IsProxiedBehindCloudflare bool   `yaml:"is_proxied_behind_cloudflare"`

	LogLevel logrus.Level `yaml:"-"`
}

func (p *PluginConfig) loadConfig() error {
	configFile, err := os.Open(info.CONFIGURATION_FILE)
	if err != nil {
		return fmt.Errorf("unable to open config file: %w", err)
	}
	defer configFile.Close()

	content, err := io.ReadAll(configFile)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, p)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	// parse the log level string into a logrus Level
	p.LogLevel, err = logrus.ParseLevel(p.LogLevelString)
	if err != nil {
		return fmt.Errorf("unable to parse log level: %w", err)
	}

	return nil
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func main() {
	// Serve the plugin introspect
	// This will print the plugin introspect and exit if the -introspect flag is provided
	pluginIntoSpect := &plugin.IntroSpect{
		ID:            info.PLUGIN_ID,
		Name:          "Crowdsec Bouncer Plugin for Zoraxy",
		Author:        "Anthony Rubick",
		AuthorContact: "",
		Description:   "This plugin is a Crowdsec bouncer for Zoraxy. It will block requests based on Crowdsec decisions.",
		URL:           "https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer",
		Type:          plugin.PluginType_Router,
		VersionMajor:  info.VERSION_MAJOR,
		VersionMinor:  info.VERSION_MINOR,
		VersionPatch:  info.VERSION_PATCH,

		DynamicCaptureSniff:   info.DYNAMIC_CAPTURE_SNIFF,
		DynamicCaptureIngress: info.DYNAMIC_CAPTURE_INGRESS,

		UIPath: info.UI_PATH,
	}
	runtimeCfg, err := plugin.ServeAndRecvSpec(pluginIntoSpect)
	if err != nil {
		//Terminate or enter standalone mode here
		panic(err)
	}

	// load the configuration, we do this first in case there are any errors
	config := &PluginConfig{}
	if err := config.loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		panic(err)
	}

	// initialize the logger
	logger := logrus.StandardLogger()
	logger.Level = config.LogLevel

	// Initialize the Crowdsec bouncer
	bouncer := &csbouncer.LiveBouncer{
		APIKey:    config.APIKey,
		APIUrl:    config.AgentUrl,
		UserAgent: info.BOUNCER_TYPE + "-" + info.VERSION_STRING,
	}
	if err := bouncer.Init(); err != nil {
		logger.Fatalf("unable to initialize bouncer: %v", err)
		panic(err)
	}

	// initialize the path router
	pathRouter := plugin.NewPathRouter()
	pathRouter.SetDebugPrintMode(config.LogLevel >= logrus.DebugLevel)

	// errGroup and context for the metrics provider and bouncer
	g, ctx := errgroup.WithContext(context.Background())

	// initialize and start a metrics provider
	metricsHandler := metrics.NewMetricsHandler(logger)
	metricsProvider, err := csbouncer.NewMetricsProvider(
		bouncer.APIClient,
		info.BOUNCER_TYPE,
		metricsHandler.MetricsUpdater,
		logger,
	)
	if err != nil {
		logger.Warnf("unable to initialize metrics provider, continuing anyway: %v", err)
	}
	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})

	/*
		Dynamic Captures

		If there is not a decision matching the requests IP, we will skip the request so
		that it can be handled by the next plugin or Zoraxy itself.
		If there is a decision for the request IP, we will accept the request and handle it in the dynamic capture handler.
		We will also print the request information to the console for debugging purposes.
	*/
	pathRouter.RegisterDynamicSniffHandler("/d_sniff", http.DefaultServeMux, func(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		metricsHandler.MarkRequestProcessed()
		return SniffHandler(logger, ctx, config, dsfr, bouncer)
	})
	pathRouter.RegisterDynamicCaptureHandle(info.DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		metricsHandler.MarkRequestBlocked()
		CaptureHandler(logger, w, r)
	})
	http.HandleFunc(info.UI_PATH+"/", RenderDebugUI)

	fmt.Println("Zoraxy Crowdsec Bouncer started at http://127.0.0.1:" + strconv.Itoa(runtimeCfg.Port))
	http.ListenAndServe("127.0.0.1:"+strconv.Itoa(runtimeCfg.Port), nil)

	// Handle signals
	g.Go(func() error {
		if err := HandleSignals(ctx); err != nil {
			logger.Warnf("Received signal: %v", err)
			return err
		}
		return nil
	})

	// wait for the goroutine to finish
	if err := g.Wait(); err != nil {
		logger.Fatalf("process terminated with error: %v", err)
	} else {
		logger.Info("process terminated gracefully")
	}
}

// ExtractHeader extracts the values of a header from the request headers map
// If the header is not found, behavior depends on the searchIfNotFound flag:
//   - If true, will search all the keys in the headers map to find a case-insensitive match
//   - If false, will return an empty string
func ExtractHeader(headers map[string][]string, key string, searchIfNotFound bool) (string, error) {
	// first, try accessing the header directly
	if values, ok := headers[key]; ok {
		if concattenated := strings.Join(values, ", "); concattenated != "" {
			return concattenated, nil
		} else {
			return "", fmt.Errorf("header %s found but has no values", key)
		}
	}

	if searchIfNotFound {
		// If not found, search for a case-insensitive match
		for k, v := range headers {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return strings.Join(v, ", "), nil
			}
		}
	}

	return "", fmt.Errorf("header %s not found", key)
}

// GetRealIP extracts the real IP address from the request headers.
// It checks for the `X-Real-IP`, `CF-Connecting-IP`, and `X-Forwarded-For` headers
//
// # Arguments:
//   - dsfr: The DynamicSniffForwardRequest object containing the request headers and remote
//   - isProxiedBehindCloudflare: If true, it will prioritize the `CF-Connecting-IP` header
//   - debug: If true, it will print extra debug information to the console
func GetRealIP(logger *logrus.Logger, dsfr *plugin.DynamicSniffForwardRequest, isProxiedBehindCloudflare bool) (string, error) {
	// Get the real IP address from the request
	realIP := ""

	// Check for the `X-Real-IP`, `CF-Connecting-IP`, and `X-Forwarded-For` headers
	if headers := dsfr.Header; headers != nil {
		// Check for X-Real-IP header, we don't really expect to see this so we won't log an error if it is not found
		X_Real_IP, err := ExtractHeader(headers, "X-Real-IP", false)
		if err == nil && X_Real_IP != "" {
			// Use X-Real-IP header
			realIP = X_Real_IP
			goto IPFound
		}

		// Check for CF-Connecting-IP header
		CF_Connecting_IP, err := ExtractHeader(headers, "CF-Connecting-IP", isProxiedBehindCloudflare)
		if err != nil && isProxiedBehindCloudflare {
			logger.Debugf("GetRealIP failed to extract CF-Connecting-IP for request with UUID %s: %v", dsfr.GetRequestUUID(), err)
		} else if CF_Connecting_IP == "" {
			logger.Debugf("GetRealIP got an empty string for CF-Connecting-IP for request with UUID %s", dsfr.GetRequestUUID())
		} else if CF_Connecting_IP != "" {
			// Use CF Connecting IP
			realIP = CF_Connecting_IP
			goto IPFound
		}

		// Check for X-Forwarded-For header
		// We take the first IP in the list, as it is the original client IP
		X_Forwarded_For, err := ExtractHeader(headers, "X-Forwarded-For", true)
		if err != nil {
			logger.Debugf("GetRealIP failed to extract X-Forwarded-For for request with UUID %s: %v", dsfr.GetRequestUUID(), err)
		} else if X_Forwarded_For == "" {
			logger.Debugf("GetRealIP got an empty string for X-Forwarded-For for request with UUID %s", dsfr.GetRequestUUID())
		} else if X_Forwarded_For != "" {
			// Use X-Forwarded-For header
			// We take the first IP in the list, as it is the original client IP
			ips := strings.Split(X_Forwarded_For, ",")
			if len(ips) > 0 {
				realIP = strings.TrimSpace(ips[0])
			}
			goto IPFound
		}
	}
	// If no headers are found, we will use the RemoteAddr, if it is not empty
	if dsfr.RemoteAddr != "" {
		logger.Debugf("GetRealIP using RemoteAddr for request with UUID %s: %s", dsfr.GetRequestUUID(), dsfr.RemoteAddr)
		realIP = dsfr.RemoteAddr
	} else {
		return "", fmt.Errorf("no valid IP address found in headers")
	}
IPFound:
	realIP = strings.TrimSpace(realIP)

	// extract the IP address from what is potentially a host:port format
	ip, _, err := net.SplitHostPort(realIP)
	if err != nil {
		// If SplitHostPort fails, it means there is no port, so we can use the whole string as the IP
		ip = realIP
	}

	// Validate the IP address
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	return ip, nil
}

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(logger *logrus.Logger, parent context.Context, config *PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, bouncer *csbouncer.LiveBouncer) plugin.SniffResult {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	// Check if the request has a response in the bouncer
	ip, err := GetRealIP(logger, dsfr, config.IsProxiedBehindCloudflare)
	if err != nil {
		logger.Warnf("GetRealIP Got an error: %v for request: %s", err, dsfr.GetRequest().RequestURI)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}

	response, err := bouncer.Get(ctx, ip)
	if err != nil {
		logger.Warnf("Error getting decisions: %v", err)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}
	if len(*response) == 0 {
		logger.Debugf("No decision found for IP: %s", ip)
		return plugin.SniffResultSkip // Skip the request if there is no decision
	}

	// Print the decisions for debugging
	for _, decision := range *response {
		logger.Debugf("decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
	}

	// Since we have a decision, and this is a naive bouncer, we
	// will ban all requests that have a decision
	logger.Debugf("Decision found for IP: %s", ip)
	return plugin.SniffResultAccept // Accept the request to be handled by the Capture handler)
}

// The Capture handler is what handles the requests that were accepted by the Sniff handler
// It is called for each request that was accepted by the Sniff handler.
//
// If the request was accepted, that means that there is a decision for the request IP,
//
// TODO: implement a way to present a captcha if the decision is to present a captcha
func CaptureHandler(logger *logrus.Logger, w http.ResponseWriter, r *http.Request) {
	// This is the dynamic capture handler where it actually captures and handle the request

	// it would be really funny if we could return a 5 petabyte zip bomb or something,
	// but let's not...

	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Forbidden"))
	logger.Infof("Request blocked: %s", r.RequestURI)
}

// Render the debug UI
func RenderDebugUI(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "**Zoraxy Crowdsec Bouncer UI Debug Interface**\n\n[Recv Headers] \n")

	headerKeys := make([]string, 0, len(r.Header))
	for name := range r.Header {
		headerKeys = append(headerKeys, name)
	}
	sort.Strings(headerKeys)
	for _, name := range headerKeys {
		values := r.Header[name]
		for _, value := range values {
			fmt.Fprintf(w, "%s: %s\n", name, html.EscapeString(value))
		}
	}
	w.Header().Set("Content-Type", "text/html")
}
