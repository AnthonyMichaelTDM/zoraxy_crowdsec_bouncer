package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	PORT = 3000
)

func main() {
	config := &config.PluginConfig{
		APIKey:                    "your_api_key_here",
		AgentUrl:                  "http://localhost:8080",
		LogLevelString:            "info",
		IsProxiedBehindCloudflare: false,
	}
	if err := config.PostProcess(); err != nil {
		logrus.Fatalf("Failed to process config: %v", err)
		os.Exit(1)
	}

	// initialize the logger
	logger := logrus.StandardLogger()
	logger.Level = config.LogLevel

	g, ctx := errgroup.WithContext(context.Background())

	// Initialize the web UI
	web.InitWebServer(logger, g, ctx, 3000)

	// Handle signals
	utils.StartSignalHandler(logrus.StandardLogger(), g, ctx)

	// wait for the goroutine to finish
	if err := g.Wait(); err != nil && !(errors.Is(err, utils.SignalTermError) || errors.Is(err, utils.SignalIntError)) {
		fmt.Printf("Process terminated with error of type %T: %v\n", err, err)
		logrus.Fatalf("process terminated with error: %v", err)
	} else {
		logrus.Info("process terminated gracefully")
	}
}
