package config

import "testing"

func TestPostProcessDefaultsStreamUpdateFrequency(t *testing.T) {
	pluginConfig := PluginConfig{LogLevelString: "warning"}

	if err := pluginConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}
	if pluginConfig.StreamUpdateFrequency != DefaultStreamUpdateFrequency {
		t.Fatalf("StreamUpdateFrequency = %q, want %q", pluginConfig.StreamUpdateFrequency, DefaultStreamUpdateFrequency)
	}
}
