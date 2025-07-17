package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/dynamiccapture"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

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
	pluginConfig := &config.PluginConfig{}
	if err := pluginConfig.LoadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		panic(err)
	}

	// initialize the logger
	logger := logrus.StandardLogger()
	logger.Level = pluginConfig.LogLevel

	// Initialize the Crowdsec bouncer
	bouncer := &csbouncer.LiveBouncer{
		APIKey:    pluginConfig.APIKey,
		APIUrl:    pluginConfig.AgentUrl,
		UserAgent: info.BOUNCER_TYPE + "-" + info.VERSION_STRING,
	}
	if err := bouncer.Init(); err != nil {
		logger.Fatalf("unable to initialize bouncer: %v", err)
		panic(err)
	}

	// initialize the path router
	pathRouter := plugin.NewPathRouter()
	pathRouter.SetDebugPrintMode(pluginConfig.LogLevel >= logrus.DebugLevel)

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
		return dynamiccapture.SniffHandler(logger, metricsHandler, ctx, pluginConfig, dsfr, bouncer)
	})
	pathRouter.RegisterDynamicCaptureHandle(info.DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		dynamiccapture.CaptureHandler(logger, w, r)
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
