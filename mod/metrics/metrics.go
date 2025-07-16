package metrics

// Since I couldn't find documentation for how crowdsec handles metrics, I used
// https://github.com/crowdsecurity/cs-firewall-bouncer/blob/main/pkg/metrics/metrics.go
// as a reference implementation.

import (
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/sirupsen/logrus"
)

type MetricName string

const (
	RequestsDropped   MetricName = "zoraxy_bouncer_dropped_requests"
	RequestsAccepted  MetricName = "zoraxy_bouncer_accepted_requests"
	RequestsProcessed MetricName = "zoraxy_bouncer_processed_requests"
)

// NOTE: Currently, all metrics are treated as absolute counts.
type Metric struct {
	Name   string
	Value  float64
	Labels map[string]string
	Unit   string
	Help   string
	// Updater csbouncer.MetricsUpdater
}

func defaultZoraxyRequestsBlockedMetric() *Metric {
	return &Metric{
		Name:   string(RequestsDropped),
		Value:  0.0,
		Labels: map[string]string{"bouncer_type": "zoraxy", "bouncer_version": info.VERSION_STRING},
		Unit:   "request",
		Help:   "Total number of requests blocked by the Zoraxy bouncer",
	}
}

func defaultZoraxyRequestsAcceptedMetric() *Metric {
	return &Metric{
		Name:   string(RequestsAccepted),
		Value:  0.0,
		Labels: map[string]string{"bouncer_type": "zoraxy", "bouncer_version": info.VERSION_STRING},
		Unit:   "request",
		Help:   "Total number of requests accepted by the Zoraxy bouncer",
	}
}

type MetricsHandler struct {
	Lock    sync.RWMutex
	Metrics map[MetricName]*Metric
	logger  *logrus.Logger
}

func NewMetricsHandler(logger *logrus.Logger) *MetricsHandler {
	// Initialization logic for MetricsHandler if needed
	mh := &MetricsHandler{
		logger:  logger,
		Lock:    sync.RWMutex{},
		Metrics: make(map[MetricName]*Metric),
	}
	// Initialize the metrics map
	mh.Metrics[RequestsDropped] = defaultZoraxyRequestsBlockedMetric()
	mh.Metrics[RequestsAccepted] = defaultZoraxyRequestsAcceptedMetric()

	return mh
}

func (mh *MetricsHandler) MarkRequestBlocked() {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	if metric, exists := mh.Metrics[RequestsDropped]; exists {
		metric.Value++
	} else {
		mh.Metrics[RequestsDropped] = defaultZoraxyRequestsBlockedMetric()
		mh.Metrics[RequestsDropped].Value++
	}
}

func (mh *MetricsHandler) MarkRequestAccepted() {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	if metric, exists := mh.Metrics[RequestsAccepted]; exists {
		metric.Value++
	} else {
		mh.Metrics[RequestsAccepted] = defaultZoraxyRequestsAcceptedMetric()
		mh.Metrics[RequestsAccepted].Value++
	}
}

func (mh *MetricsHandler) getProcessedRequests() float64 {
	accepted := 0.
	if metric, exists := mh.Metrics[RequestsAccepted]; exists {
		accepted = metric.Value
	}
	blocked := 0.
	if metric, exists := mh.Metrics[RequestsDropped]; exists {
		blocked = metric.Value
	}
	return accepted + blocked
}

// MetricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func (mh *MetricsHandler) MetricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	// Implementation goes here
	mh.logger.Debug("Updating metrics...")

	mh.Lock.RLock()
	defer mh.Lock.RUnlock()

	// Most of the common fields are set automatically by the metrics provider
	// We only need to care about the metrics themselves

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(updateInterval.Seconds())),
		},
	})

	for _, metric := range mh.Metrics {
		met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
			Name:   ptr.Of(metric.Name),
			Labels: metric.Labels,
			Unit:   ptr.Of(metric.Unit),
			Value:  &metric.Value,
		})
	}

	// also report the total number of requests processed
	met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
		Name:   ptr.Of(string(RequestsProcessed)),
		Labels: map[string]string{"bouncer_type": "zoraxy", "bouncer_version": info.VERSION_STRING},
		Unit:   ptr.Of("request"),
		Value:  ptr.Of(mh.getProcessedRequests()),
	})
}
