package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPostProcessDefaultsStreamUpdateFrequency(t *testing.T) {
	pluginConfig := PluginConfig{LogLevelString: "warning"}

	if err := pluginConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}
	if pluginConfig.StreamUpdateFrequency != DefaultStreamUpdateFrequency {
		t.Fatalf("StreamUpdateFrequency = %q, want %q", pluginConfig.StreamUpdateFrequency, DefaultStreamUpdateFrequency)
	}
}

func TestLoadConfigCreatesDefaultOnMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir(%q) error = %v", tmpDir, err)
	}

	pluginConfig := PluginConfig{}
	err = pluginConfig.LoadConfig()
	if !errors.Is(err, ErrConfigCreated) {
		t.Fatalf("LoadConfig() error = %v, want ErrConfigCreated", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(config.yaml) error = %v", err)
	}
	if len(content) == 0 {
		t.Fatal("config.yaml should not be empty")
	}
}
