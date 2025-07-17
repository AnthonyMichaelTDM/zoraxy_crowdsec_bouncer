package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
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

	// load the configuration
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
		logger.Fatalf("unable to initialize metrics provider: %v", err)
		panic(err)
	}

	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})

	metrics.Map.MustRegisterAll()

	prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)

	/*
		Dynamic Captures

		If there is not a decision matching the requests IP, we will skip the request so
		that it can be handled by the next plugin or Zoraxy itself.
		If there is a decision for the request IP, we will accept the request and handle it in the dynamic capture handler.
		We will also print the request information to the console for debugging purposes.
	*/
	pathRouter.RegisterDynamicSniffHandler("/d_sniff", http.DefaultServeMux, func(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		return SniffHandler(logger, metricsHandler, ctx, config, dsfr, bouncer)
	})
	pathRouter.RegisterDynamicCaptureHandle(info.DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		CaptureHandler(logger, w, r)
	})

	web.InitWebUI(g, runtimeCfg.Port)

	// Handle signals
	utils.StartSignalHandler(logger, g)

	// wait for the goroutine to finish
	if err := g.Wait(); err != nil {
		logger.Fatalf("process terminated with error: %v", err)
	} else {
		logger.Info("process terminated gracefully")
	}
}

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, parent context.Context, config *PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, bouncer *csbouncer.LiveBouncer) plugin.SniffResult {
	defer metricsHandler.MarkRequestProcessed(dsfr.Hostname)

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	// Check if the request has a response in the bouncer
	ip, err := utils.GetRealIP(logger, dsfr, config.IsProxiedBehindCloudflare)
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

	// If we have one or more decisions, we will use the first one
	var decision *models.Decision
	for _, d := range *response {
		if *d.Type == "ban" {
			decision = d
			break // We found a ban decision, we can stop looking
		}
	}

	// Print the decisions for debugging
	for _, d := range *response {
		logger.Debugf("decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *d.Value, *d.Scenario, *d.Duration, *d.Scope)
	}

	// Since we have a decision, and this is a naive bouncer, we
	// will ban all requests that have a decision
	logger.Debugf("Decision found for IP: %s", ip)
	metricsHandler.MarkRequestDropped(dsfr.Hostname, decision)
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
