package dynamiccapture

import (
	"context"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/sirupsen/logrus"
)

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, parent context.Context, config *config.PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, bouncer *csbouncer.LiveBouncer) plugin.SniffResult {
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
	return plugin.SniffResultAccept // Accept the request to be handled by the Capture handler
}
