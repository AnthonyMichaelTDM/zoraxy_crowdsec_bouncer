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
type MetricUnit string

const (
	BLOCKED   MetricName = "dropped"
	PROCESSED MetricName = "processed"

	REQUESTS MetricUnit = "requests"
)

// NOTE: Currently, all metrics are treated as absolute counts.
type Metric struct {
	Name   string
	Unit   string
	Value  float64
	Labels map[string]string
	Help   string
	// Updater csbouncer.MetricsUpdater
}

func newBlockedRequestsMetric() *Metric {
	return &Metric{
		Name:   string(BLOCKED),
		Unit:   string(REQUESTS),
		Value:  0.0,
		Labels: map[string]string{"bouncer_type": "zoraxy", "bouncer_version": info.VERSION_STRING},
		Help:   "Total number of requests blocked by the Zoraxy bouncer",
	}
}

func newProcessedRequestsMetric() *Metric {
	return &Metric{
		Name:   string(PROCESSED),
		Unit:   string(REQUESTS),
		Value:  0.0,
		Labels: map[string]string{"bouncer_type": "zoraxy", "bouncer_version": info.VERSION_STRING},
		Help:   "Total number of requests processed by the Zoraxy bouncer",
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
	mh.Metrics[BLOCKED] = newBlockedRequestsMetric()
	mh.Metrics[PROCESSED] = newProcessedRequestsMetric()

	return mh
}

func (mh *MetricsHandler) MarkRequestBlocked() {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	if metric, exists := mh.Metrics[BLOCKED]; exists {
		metric.Value++
	} else {
		mh.Metrics[BLOCKED] = newBlockedRequestsMetric()
		mh.Metrics[BLOCKED].Value++
	}
}

func (mh *MetricsHandler) MarkRequestProcessed() {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	if metric, exists := mh.Metrics[PROCESSED]; exists {
		metric.Value++
	} else {
		mh.Metrics[PROCESSED] = newProcessedRequestsMetric()
		mh.Metrics[PROCESSED].Value++
	}
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
}
