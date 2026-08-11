package events

import (
	"testing"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func stringPtr(value string) *string { return &value }

func TestBlockedEventsRetainsSafeNewestEvents(t *testing.T) {
	store := NewBlockedEvents(2)
	decision := &models.Decision{
		Origin:   stringPtr("crowdsec"),
		Scenario: stringPtr("crowdsecurity/http-probing"),
		Type:     stringPtr("ban"),
		Scope:    stringPtr("ip"),
	}

	store.Record(&zoraxy_plugin.DynamicSniffForwardRequest{Hostname: "one.example", Method: "GET", RequestURI: "/first?token=secret"}, "192.0.2.42", decision)
	store.Record(&zoraxy_plugin.DynamicSniffForwardRequest{Hostname: "two.example", Method: "POST", RequestURI: "/second"}, "2001:db8:abcd:1234::1", decision)
	store.Record(&zoraxy_plugin.DynamicSniffForwardRequest{Hostname: "three.example", Method: "GET", RequestURI: "/third"}, "invalid", decision)

	snapshot := store.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("expected 2 events, got %d", len(snapshot))
	}
	if snapshot[0].Hostname != "three.example" || snapshot[1].Hostname != "two.example" {
		t.Fatalf("events are not newest-first: %#v", snapshot)
	}
	if snapshot[1].ClientNetwork != "2001:db8:abcd:1234::/64" {
		t.Fatalf("unexpected IPv6 mask: %q", snapshot[1].ClientNetwork)
	}
	if snapshot[0].ClientNetwork != "unknown" {
		t.Fatalf("unexpected invalid IP value: %q", snapshot[0].ClientNetwork)
	}
	if snapshot[1].Path != "/second" {
		t.Fatalf("unexpected path: %q", snapshot[1].Path)
	}
}

func TestSafePathDropsQueryString(t *testing.T) {
	if got := safePath("/login?password=secret"); got != "/login" {
		t.Fatalf("safePath() = %q, want /login", got)
	}
}
