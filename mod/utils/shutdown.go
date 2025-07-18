package utils

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type signalType string

const (
	signalTerm signalType = "SIGTERM"
	signalInt  signalType = "interrupt"
)

type InterruptError struct {
	kind signalType
}

func (e *InterruptError) Error() string {
	return fmt.Sprintf("interrupt error: %s", e.kind)
}

var (
	SignalTermError *InterruptError = &InterruptError{kind: signalTerm}
	SignalIntError  *InterruptError = &InterruptError{kind: signalInt}
)

func handleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return SignalTermError
		case os.Interrupt: // cross-platform SIGINT
			return SignalIntError
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func StartSignalHandler(logger *logrus.Logger, g *errgroup.Group, ctx context.Context) {
	g.Go(func() error {
		if err := handleSignals(ctx); err != nil {
			logger.Warnf("Signal handler received an error: %v", err)
			return err
		}

		return nil
	})
}
