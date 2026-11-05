package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/events"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func webStringPtr(value string) *string { return &value }

func TestAPIBlockedEventsHandlerReturnsSanitizedEvents(t *testing.T) {
	store := events.NewBlockedEvents(1, events.IPModeMasked)
	store.Record(&zoraxy_plugin.DynamicSniffForwardRequest{
		Hostname:   "service.example",
		Method:     http.MethodPost,
		RequestURI: "/login?token=secret",
	}, "198.51.100.24", &models.Decision{
		Origin:   webStringPtr("crowdsec"),
		Scenario: webStringPtr("crowdsecurity/http-probing"),
		Type:     webStringPtr("ban"),
		Scope:    webStringPtr("ip"),
	})
	blockedEventsStore = store

	response := httptest.NewRecorder()
	apiBlockedEventsHandler(response, httptest.NewRequest(http.MethodGet, "/api/blocked-events", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}

	var got []events.BlockedEvent
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].ClientAddress != "198.51.100.0/24" || got[0].Path != "/login" {
		t.Fatalf("unexpected events: %#v", got)
	}
}
