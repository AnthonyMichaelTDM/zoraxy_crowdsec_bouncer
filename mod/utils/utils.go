package utils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ExtractHeader extracts the values of a header from the request headers map
// If the header is not found, behavior depends on the searchIfNotFound flag:
//   - If true, will search all the keys in the headers map to find a case-insensitive match
//   - If false, will return an empty string
func ExtractHeader(headers map[string][]string, key string, searchIfNotFound bool) (string, error) {
	// first, try accessing the header directly
	if values, ok := headers[key]; ok {
		if concattenated := strings.Join(values, ", "); concattenated != "" {
			return concattenated, nil
		} else {
			return "", fmt.Errorf("header %s found but has no values", key)
		}
	}

	if searchIfNotFound {
		// If not found, search for a case-insensitive match
		for k, v := range headers {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return strings.Join(v, ", "), nil
			}
		}
	}

	return "", fmt.Errorf("header %s not found", key)
}

func handleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func StartSignalHandler(logger *logrus.Logger, g *errgroup.Group) {
	g.Go(func() error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := handleSignals(ctx); err != nil {
			logger.Warnf("Signal handler received an error: %v", err)
			return err
		}

		return nil
	})
}
