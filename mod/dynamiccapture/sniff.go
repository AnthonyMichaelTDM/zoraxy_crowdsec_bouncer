package dynamiccapture

import (
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/events"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/sirupsen/logrus"
)

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, blockedEvents *events.BlockedEvents, config *config.PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, decisions *decisions.Cache) plugin.SniffResult {
	defer metricsHandler.MarkRequestProcessed(dsfr.Hostname)

	// Look up the request IP in the local decision cache.
	ip, err := utils.GetRealIP(logger, dsfr, config.IsProxiedBehindCloudflare)
	if err != nil {
		logger.Warnf("GetRealIP Got an error: %v for request: %s", err, dsfr.GetRequest().RequestURI)
		return plugin.SniffResultSkip // Skip the request if there is an error
	}

	decision := decisions.GetBan(ip)
	if decision == nil {
		logger.Debugf("No decision found for IP: %s", ip)
		return plugin.SniffResultSkip // Skip the request if there is no decision
	}

	// This bouncer currently remediates ban decisions by handing the request
	// to the capture handler, which returns a forbidden response.
	logger.Debugf("Decision found for IP: %s", ip)
	metricsHandler.MarkRequestDropped(dsfr.Hostname, decision)
	blockedEvents.Record(dsfr, ip, decision)
	return plugin.SniffResultAccept // Accept the request to be handled by the Capture handler
}
