package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const DefaultStreamUpdateFrequency = "10s"
const PlaceholderAPIKey = "<CROWDSEC_BOUNCER_API_KEY>"

var ErrConfigCreated = errors.New("config file created")

const defaultConfigTemplate = `# Crowdsec Bouncer Configuration
# api_key: "YOUR_CROWDSEC_BOUNCER_API_KEY"
agent_url: http://127.0.0.1:8080
# How frequently to request decision deltas from CrowdSec's stream endpoint.
stream_update_frequency: 10s
# Log level for the bouncer, options: trace, debug, info, warning, error
log_level: warning
# Set to true if zoraxy is proxied behind Cloudflare
is_proxied_behind_cloudflare: true
# Persisted rolling 24-hour block aggregation (contains only timestamp, hostname and origin)
blocked_requests_aggregation_file: blocked-requests-24h.json
# Optional dedicated Prometheus listener, e.g. :2112. Leave empty to disable.
prometheus_listen_addr: ""
`

type PluginConfig struct {
	APIKey                         string `yaml:"api_key"`
	AgentUrl                       string `yaml:"agent_url"`
	StreamUpdateFrequency          string `yaml:"stream_update_frequency"`
	LogLevelString                 string `yaml:"log_level"`
	IsProxiedBehindCloudflare      bool   `yaml:"is_proxied_behind_cloudflare"`
	BlockedRequestsAggregationFile string `yaml:"blocked_requests_aggregation_file"`
	PrometheusListenAddr           string `yaml:"prometheus_listen_addr"`

	LogLevel logrus.Level `yaml:"-"`
}

func (p *PluginConfig) MissingRequiredFields() []string {
	missing := make([]string, 0, 2)

	trimmedAPIKey := strings.TrimSpace(p.APIKey)
	if trimmedAPIKey == "" || trimmedAPIKey == PlaceholderAPIKey {
		missing = append(missing, "api_key")
	}

	if strings.TrimSpace(p.AgentUrl) == "" {
		missing = append(missing, "agent_url")
	}

	return missing
}

func (p *PluginConfig) PostProcess() error {
	// This function can be used to perform any post-processing on the configuration
	// For now, it populates the LogLevel based on the LogLevelString
	// parse the log level string into a logrus Level
	if p.LogLevelString == "" {
		p.LogLevelString = "warning"
	}

	level, err := logrus.ParseLevel(p.LogLevelString)
	if err != nil {
		return fmt.Errorf("unable to parse log level: %w", err)
	}
	p.LogLevel = level

	if p.StreamUpdateFrequency == "" {
		p.StreamUpdateFrequency = DefaultStreamUpdateFrequency
	}
	p.PrometheusListenAddr = strings.TrimSpace(p.PrometheusListenAddr)
	p.BlockedRequestsAggregationFile = strings.TrimSpace(p.BlockedRequestsAggregationFile)
	if p.BlockedRequestsAggregationFile == "" {
		p.BlockedRequestsAggregationFile = metrics.DefaultBlockedRequestsAggregationFile
	}
	return nil
}

func (p *PluginConfig) LoadConfig() error {
	configFile, err := os.Open(info.CONFIGURATION_FILE)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if writeErr := os.WriteFile(info.CONFIGURATION_FILE, []byte(defaultConfigTemplate), 0o644); writeErr != nil {
				return fmt.Errorf("unable to create default config file: %w", writeErr)
			}
			return fmt.Errorf("%w: %s (please edit api_key and agent_url, then restart)", ErrConfigCreated, info.CONFIGURATION_FILE)
		}
		return fmt.Errorf("unable to open config file: %w", err)
	}
	defer configFile.Close()

	content, err := io.ReadAll(configFile)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	if err := yaml.Unmarshal(content, p); err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	// parse the log level string into a logrus Level
	if err := p.PostProcess(); err != nil {
		return fmt.Errorf("unable to post-process config: %w", err)
	}

	return nil
}
