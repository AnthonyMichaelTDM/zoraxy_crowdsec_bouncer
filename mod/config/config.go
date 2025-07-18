package config

import (
	"fmt"
	"io"
	"os"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
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
	return nil
}

func (p *PluginConfig) LoadConfig() error {
	configFile, err := os.Open(info.CONFIGURATION_FILE)
	if err != nil {
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
