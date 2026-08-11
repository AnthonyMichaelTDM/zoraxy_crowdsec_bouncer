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

const (
	BlockedRequestsAggregationWindow = 72 * time.Hour
	BlockedRequestsMetricWindow      = 24 * time.Hour
	BlockedRequestsBucketDuration    = time.Minute
)

type BlockedRequestBucket struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Origin    string    `json:"origin"`
	Count     uint64    `json:"count,omitempty"`
}

type BlockedRequestKey struct {
	Hostname string
	Origin   string
}

type blockedRequestBucketKey struct {
	Timestamp time.Time
	Hostname  string
	Origin    string
}

// BlockedRequestsAggregator retains 72 hours of per-minute block counts. It
// intentionally stores no client IP, request path, headers, or body.
type BlockedRequestsAggregator struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	buckets map[blockedRequestBucketKey]uint64
}

func NewBlockedRequestsAggregator(path string) (*BlockedRequestsAggregator, error) {
	a := &BlockedRequestsAggregator{path: path, now: time.Now, buckets: make(map[blockedRequestBucketKey]uint64)}
	if err := a.load(); err != nil {
		return a, err
	}
	return a, nil
}

func (a *BlockedRequestsAggregator) Record(hostname, origin string) (map[BlockedRequestKey]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now().UTC()
	bucketTime := now.Truncate(BlockedRequestsBucketDuration)
	a.buckets[blockedRequestBucketKey{Timestamp: bucketTime, Hostname: hostname, Origin: origin}]++
	a.pruneLocked(now)
	snapshot := a.snapshotLocked(now, BlockedRequestsMetricWindow)
	if err := a.saveLocked(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (a *BlockedRequestsAggregator) Snapshot(window time.Duration) map[BlockedRequestKey]uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	a.pruneLocked(now)
	return a.snapshotLocked(now, window)
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
	var buckets []BlockedRequestBucket
	if err := json.Unmarshal(content, &buckets); err != nil {
		return fmt.Errorf("decode blocked request aggregation: %w", err)
	}
	for _, bucket := range buckets {
		// Version 1 stored one event per item without a count. Preserve those
		// historical entries when upgrading to per-minute buckets.
		if bucket.Count == 0 {
			bucket.Count = 1
		}
		bucket.Timestamp = bucket.Timestamp.UTC().Truncate(BlockedRequestsBucketDuration)
		a.buckets[blockedRequestBucketKey{Timestamp: bucket.Timestamp, Hostname: bucket.Hostname, Origin: bucket.Origin}] += bucket.Count
	}
	a.pruneLocked(a.now().UTC())
	return nil
}

func (a *BlockedRequestsAggregator) pruneLocked(now time.Time) {
	cutoff := now.Add(-BlockedRequestsAggregationWindow).Truncate(BlockedRequestsBucketDuration)
	for key := range a.buckets {
		if key.Timestamp.Before(cutoff) {
			delete(a.buckets, key)
		}
	}
}

func (a *BlockedRequestsAggregator) snapshotLocked(now time.Time, window time.Duration) map[BlockedRequestKey]uint64 {
	cutoff := now.Add(-window).Truncate(BlockedRequestsBucketDuration)
	snapshot := make(map[BlockedRequestKey]uint64)
	for key, count := range a.buckets {
		if !key.Timestamp.Before(cutoff) {
			snapshot[BlockedRequestKey{Hostname: key.Hostname, Origin: key.Origin}] += count
		}
	}
	return snapshot
}

func (a *BlockedRequestsAggregator) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return fmt.Errorf("create blocked request aggregation directory: %w", err)
	}
	buckets := make([]BlockedRequestBucket, 0, len(a.buckets))
	for key, count := range a.buckets {
		buckets = append(buckets, BlockedRequestBucket{Timestamp: key.Timestamp, Hostname: key.Hostname, Origin: key.Origin, Count: count})
	}
	sort.Slice(buckets, func(i, j int) bool {
		if !buckets[i].Timestamp.Equal(buckets[j].Timestamp) {
			return buckets[i].Timestamp.Before(buckets[j].Timestamp)
		}
		if buckets[i].Hostname != buckets[j].Hostname {
			return buckets[i].Hostname < buckets[j].Hostname
		}
		return buckets[i].Origin < buckets[j].Origin
	})
	content, err := json.Marshal(buckets)
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
