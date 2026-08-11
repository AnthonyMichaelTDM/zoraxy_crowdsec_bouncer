package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const DefaultStreamUpdateFrequency = "10s"

var ErrConfigCreated = errors.New("config file created")

const defaultConfigTemplate = `# Crowdsec Bouncer Configuration
api_key: <CROWDSEC_BOUNCER_API_KEY>
agent_url: http://127.0.0.1:8080
# How frequently to request decision deltas from CrowdSec's stream endpoint.
stream_update_frequency: 10s
# Log level for the bouncer, options: trace, debug, info, warning, error
log_level: warning
# Set to true if zoraxy is proxied behind Cloudflare
is_proxied_behind_cloudflare: true
`

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
	StreamUpdateFrequency     string `yaml:"stream_update_frequency"`
	LogLevelString            string `yaml:"log_level"`
	IsProxiedBehindCloudflare bool   `yaml:"is_proxied_behind_cloudflare"`

	LogLevel logrus.Level `yaml:"-"`
}

func (p *PluginConfig) PostProcess() error {
	// This function can be used to perform any post-processing on the configuration
	// For now, it populates the LogLevel based on the LogLevelString
	// parse the log level string into a logrus Level
	level, err := logrus.ParseLevel(p.LogLevelString)
	if err != nil {
		return fmt.Errorf("unable to parse log level: %w", err)
	}
	p.LogLevel = level
	if p.StreamUpdateFrequency == "" {
		p.StreamUpdateFrequency = DefaultStreamUpdateFrequency
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
