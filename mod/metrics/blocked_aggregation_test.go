package metrics

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBlockedRequestsAggregatorPersistsMinuteBucketsAndRetains72Hours(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked-requests-24h.json")
	base := time.Date(2026, time.August, 11, 12, 0, 15, 0, time.UTC)

	aggregator, err := NewBlockedRequestsAggregator(path)
	if err != nil {
		t.Fatalf("NewBlockedRequestsAggregator() error = %v", err)
	}
	aggregator.now = func() time.Time { return base }
	if _, err := aggregator.Record("home.example", "crowdsec"); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	aggregator.now = func() time.Time { return base.Add(30 * time.Second) }
	if _, err := aggregator.Record("home.example", "crowdsec"); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	reloaded, err := NewBlockedRequestsAggregator(path)
	if err != nil {
		t.Fatalf("NewBlockedRequestsAggregator(reload) error = %v", err)
	}
	reloaded.now = func() time.Time { return base.Add(25 * time.Hour) }
	if got := len(reloaded.Snapshot(BlockedRequestsMetricWindow)); got != 0 {
		t.Fatalf("24-hour snapshot length = %d, want 0", got)
	}
	if got := reloaded.Snapshot(BlockedRequestsAggregationWindow)[BlockedRequestKey{Hostname: "home.example", Origin: "crowdsec"}]; got != 2 {
		t.Fatalf("72-hour retained count = %d, want 2", got)
	}

	reloaded.now = func() time.Time { return base.Add(73 * time.Hour) }
	if got := len(reloaded.Snapshot(BlockedRequestsAggregationWindow)); got != 0 {
		t.Fatalf("72-hour snapshot length = %d, want 0", got)
	}
}
