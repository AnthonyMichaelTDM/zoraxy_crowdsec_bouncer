package metrics

import (
	"os"
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

func TestBlockedRequestsAggregatorLoadsSampleData(t *testing.T) {
	fixturePath := filepath.Join("testdata", "blocked-requests-sample.json")
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", fixturePath, err)
	}
	path := filepath.Join(t.TempDir(), "blocked-requests-24h.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	now := time.Date(2026, time.August, 11, 14, 42, 0, 0, time.UTC)
	aggregator, err := newBlockedRequestsAggregator(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newBlockedRequestsAggregator() error = %v", err)
	}

	snapshot := aggregator.Snapshot(BlockedRequestsMetricWindow)
	var total uint64
	for _, count := range snapshot {
		total += count
	}
	if total != 18 {
		t.Fatalf("total blocks = %d, want 18", total)
	}
	if got := snapshot[BlockedRequestKey{Hostname: "pve2.patking73.ch", Origin: "crowdsec"}]; got != 9 {
		t.Fatalf("pve2 CrowdSec blocks = %d, want 9", got)
	}
	if got := snapshot[BlockedRequestKey{Hostname: "pve2.patking73.ch", Origin: "cscli"}]; got != 5 {
		t.Fatalf("pve2 cscli blocks = %d, want 5", got)
	}
}
