package web

import "testing"

func TestAddMetricValueAggregatesBlockedRequestOrigins(t *testing.T) {
	response := MetricsResponse{
		BlockedRequests:   make(map[string]float64),
		ProcessedRequests: make(map[string]float64),
	}

	addMetricValue(&response, "zoraxy_bouncer_blocked_requests", "pve2.example", 9)
	addMetricValue(&response, "zoraxy_bouncer_blocked_requests", "pve2.example", 5)
	addMetricValue(&response, "zoraxy_bouncer_processed_requests", "pve2.example", 20)

	if got := response.BlockedRequests["pve2.example"]; got != 14 {
		t.Fatalf("blocked requests = %v, want 14", got)
	}
	if got := response.ProcessedRequests["pve2.example"]; got != 20 {
		t.Fatalf("processed requests = %v, want 20", got)
	}
}
