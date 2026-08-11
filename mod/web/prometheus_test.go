package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestPrometheusMetricsHandlerExposesTextFormat(t *testing.T) {
	metrics.Map.MustRegisterAll()
	t.Cleanup(func() {
		for _, metric := range metrics.Map {
			metric.Gauge.Reset()
			prometheus.Unregister(metric.Gauge)
		}
	})
	metrics.Map[metrics.DROPPED_REQUESTS].Gauge.With(prometheus.Labels{"origin": "crowdsec", "hostname": "service.example"}).Set(3)
	metrics.Map[metrics.PROCESSED_REQUESTS].Gauge.With(prometheus.Labels{"hostname": "service.example"}).Set(10)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	prometheusMetricsHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("Content-Type = %q, want Prometheus text format", contentType)
	}
	body := response.Body.String()
	if !strings.Contains(body, "zoraxy_bouncer_blocked_requests{hostname=\"service.example\",origin=\"crowdsec\"} 3") {
		t.Fatalf("blocked metric missing from response: %s", body)
	}
	if !strings.Contains(body, "zoraxy_bouncer_processed_requests{hostname=\"service.example\"} 10") {
		t.Fatalf("processed metric missing from response: %s", body)
	}
}
