package metrics

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBlockedRequestsAggregatorPersistsAndPrunesEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked-requests-24h.json")
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)

	aggregator, err := NewBlockedRequestsAggregator(path)
	if err != nil {
		t.Fatalf("NewBlockedRequestsAggregator() error = %v", err)
	}
	aggregator.now = func() time.Time { return base }
	if _, err := aggregator.Record("home.example", "crowdsec"); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := aggregator.Record("home.example", "crowdsec"); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	reloaded, err := NewBlockedRequestsAggregator(path)
	if err != nil {
		t.Fatalf("NewBlockedRequestsAggregator(reload) error = %v", err)
	}
	reloaded.now = func() time.Time { return base.Add(23 * time.Hour) }
	if got := reloaded.Snapshot()[BlockedRequestKey{Hostname: "home.example", Origin: "crowdsec"}]; got != 2 {
		t.Fatalf("persisted count = %d, want 2", got)
	}

	reloaded.now = func() time.Time { return base.Add(25 * time.Hour) }
	if got := len(reloaded.Snapshot()); got != 0 {
		t.Fatalf("pruned snapshot length = %d, want 0", got)
	}
}
