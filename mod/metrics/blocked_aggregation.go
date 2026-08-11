package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const BlockedRequestsAggregationWindow = 24 * time.Hour

type BlockedRequestEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Origin    string    `json:"origin"`
}

type BlockedRequestKey struct {
	Hostname string
	Origin   string
}

// BlockedRequestsAggregator keeps only the events needed to calculate an
// exact rolling 24-hour block count. It intentionally stores no client IP,
// request path, headers, or body.
type BlockedRequestsAggregator struct {
	mu     sync.Mutex
	path   string
	now    func() time.Time
	events []BlockedRequestEvent
}

func NewBlockedRequestsAggregator(path string) (*BlockedRequestsAggregator, error) {
	a := &BlockedRequestsAggregator{path: path, now: time.Now}
	if err := a.load(); err != nil {
		return a, err
	}
	return a, nil
}

func (a *BlockedRequestsAggregator) Record(hostname, origin string) (map[BlockedRequestKey]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now().UTC()
	a.events = append(a.events, BlockedRequestEvent{Timestamp: now, Hostname: hostname, Origin: origin})
	a.pruneLocked(now)
	if err := a.saveLocked(); err != nil {
		return a.snapshotLocked(), err
	}
	return a.snapshotLocked(), nil
}

func (a *BlockedRequestsAggregator) Snapshot() map[BlockedRequestKey]uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(a.now().UTC())
	return a.snapshotLocked()
}

func (a *BlockedRequestsAggregator) load() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	content, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read blocked request aggregation: %w", err)
	}
	if err := json.Unmarshal(content, &a.events); err != nil {
		return fmt.Errorf("decode blocked request aggregation: %w", err)
	}
	a.pruneLocked(a.now().UTC())
	return nil
}

func (a *BlockedRequestsAggregator) pruneLocked(now time.Time) {
	cutoff := now.Add(-BlockedRequestsAggregationWindow)
	first := sort.Search(len(a.events), func(i int) bool {
		return !a.events[i].Timestamp.Before(cutoff)
	})
	if first > 0 {
		a.events = append([]BlockedRequestEvent(nil), a.events[first:]...)
	}
}

func (a *BlockedRequestsAggregator) snapshotLocked() map[BlockedRequestKey]uint64 {
	snapshot := make(map[BlockedRequestKey]uint64)
	for _, event := range a.events {
		snapshot[BlockedRequestKey{Hostname: event.Hostname, Origin: event.Origin}]++
	}
	return snapshot
}

func (a *BlockedRequestsAggregator) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return fmt.Errorf("create blocked request aggregation directory: %w", err)
	}
	content, err := json.Marshal(a.events)
	if err != nil {
		return fmt.Errorf("encode blocked request aggregation: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(a.path), ".blocked-requests-*.json")
	if err != nil {
		return fmt.Errorf("create blocked request aggregation temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write blocked request aggregation: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set blocked request aggregation permissions: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close blocked request aggregation: %w", err)
	}
	if err := os.Rename(temporaryPath, a.path); err != nil {
		return fmt.Errorf("replace blocked request aggregation: %w", err)
	}
	return nil
}
