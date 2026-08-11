// Package events keeps a small, privacy-conscious history for the plugin UI.
package events

import (
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	DefaultCapacity = 200
	IPModeMasked    = "masked"
	IPModeFull      = "full"
)

// BlockedEvent deliberately excludes headers, request bodies, and query strings,
// which can contain credentials or other secrets.
type BlockedEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Hostname      string    `json:"hostname"`
	ClientAddress string    `json:"clientAddress"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Origin        string    `json:"origin"`
	Scenario      string    `json:"scenario"`
	DecisionType  string    `json:"decisionType"`
	Scope         string    `json:"scope"`
	Until         string    `json:"until,omitempty"`
}

// BlockedEvents is an in-memory, bounded newest-first event store.
type BlockedEvents struct {
	mu       sync.RWMutex
	capacity int
	ipMode   string
	events   []BlockedEvent
}

func NewBlockedEvents(capacity int, ipMode string) *BlockedEvents {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if ipMode != IPModeFull {
		ipMode = IPModeMasked
	}
	return &BlockedEvents{capacity: capacity, ipMode: ipMode, events: make([]BlockedEvent, 0, capacity)}
}

func (b *BlockedEvents) Record(request *zoraxy_plugin.DynamicSniffForwardRequest, clientIP string, decision *models.Decision) {
	if b == nil || request == nil || decision == nil {
		return
	}

	event := BlockedEvent{
		Timestamp:     time.Now().UTC(),
		Hostname:      request.Hostname,
		ClientAddress: formatClientIP(clientIP, b.ipMode),
		Method:        request.Method,
		Path:          safePath(request.RequestURI),
		Origin:        dereference(decision.Origin),
		Scenario:      dereference(decision.Scenario),
		DecisionType:  dereference(decision.Type),
		Scope:         dereference(decision.Scope),
		Until:         decision.Until,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) < b.capacity {
		b.events = append(b.events, BlockedEvent{})
	}
	copy(b.events[1:], b.events[:len(b.events)-1])
	b.events[0] = event
}

func (b *BlockedEvents) Snapshot() []BlockedEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]BlockedEvent, len(b.events))
	copy(result, b.events)
	return result
}

func dereference(value *string) string {
	if value == nil {
		return "unknown"
	}
	return *value
}

func formatClientIP(value, mode string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "unknown"
	}
	if mode == IPModeFull {
		return address.String()
	}
	if address.Is4() {
		return netip.PrefixFrom(address, 24).Masked().String()
	}
	return netip.PrefixFrom(address, 64).Masked().String()
}

func safePath(requestURI string) string {
	parsed, err := url.ParseRequestURI(requestURI)
	if err != nil || parsed.EscapedPath() == "" {
		return "/"
	}
	return parsed.EscapedPath()
}
