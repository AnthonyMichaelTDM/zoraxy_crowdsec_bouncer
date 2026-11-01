package metrics

// Since I couldn't find documentation for how crowdsec handles metrics, I used
// https://github.com/crowdsecurity/cs-firewall-bouncer/blob/main/pkg/metrics/metrics.go
// as a reference implementation.
// Both it, and this repo, are licensed under the MIT license, so this is fine.

import (
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
)

type metricName string
type MetricUnit string

const (
	DROPPED_REQUESTS     metricName = "zoraxy_bouncer_blocked_requests"
	PROCESSED_REQUESTS   metricName = "zoraxy_bouncer_processed_requests"
	DROPPED_REQUESTS_24H metricName = "zoraxy_bouncer_blocked_requests_24h"
)

const DefaultBlockedRequestsAggregationFile = "blocked-requests-24h.json"

type Metric struct {
	Name         string
	Unit         string
	Counter      *prometheus.CounterVec
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*io_prometheus_client.LabelPair) string
}

type metricMap map[metricName]*Metric

func (m metricMap) MustRegisterAll() {
	for _, met := range m {
		prometheus.MustRegister(met.Counter)
	}
	prometheus.MustRegister(blockedRequests24h)
}

var blockedRequests24h = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: string(DROPPED_REQUESTS_24H),
	Help: "Exact rolling 24-hour count of requests blocked by the Zoraxy bouncer",
}, []string{"origin", "hostname"})

var Map = metricMap{
	DROPPED_REQUESTS: {
		Name: "dropped",
		Unit: "request",
		Counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: string(DROPPED_REQUESTS),
			Help: "Total number of requests blocked by the Zoraxy bouncer",
		}, []string{"origin", "hostname"}),
		LabelKeys:    []string{"origin", "hostname"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "hostname")
		},
	},
	PROCESSED_REQUESTS: {
		Name: "processed",
		Unit: "request",
		Counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: string(PROCESSED_REQUESTS),
			Help: "Total number of requests processed by the Zoraxy bouncer",
		}, []string{"hostname"}),
		LabelKeys:    []string{"hostname"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "hostname")
		},
	},
}

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

type MetricsHandler struct {
	Lock                      sync.RWMutex
	logger                    *logrus.Logger
	blockedRequestsAggregator *BlockedRequestsAggregator
}

func NewMetricsHandler(logger *logrus.Logger, aggregationPath string) *MetricsHandler {
	aggregator, err := NewBlockedRequestsAggregator(aggregationPath)
	if err != nil {
		logger.WithError(err).Warn("Unable to load persisted blocked request aggregation; starting with an empty in-memory aggregation")
	}
	mh := &MetricsHandler{
		logger:                    logger,
		Lock:                      sync.RWMutex{},
		blockedRequestsAggregator: aggregator,
	}
	mh.refreshBlockedRequests24hMetric(aggregator.Snapshot(BlockedRequestsMetricWindow))

	return mh
}

func (mh *MetricsHandler) MarkRequestDropped(hostname string, decision *models.Decision) {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	// Increment the dropped requests metric
	// This is a simple counter, so we just increment the value
	origin := "unknown"
	if decision.Origin != nil {
		origin = *decision.Origin
	}
	Map[DROPPED_REQUESTS].Counter.With(prometheus.Labels{"origin": origin, "hostname": hostname}).Inc()

	snapshot, err := mh.blockedRequestsAggregator.Record(hostname, origin)
	if err != nil {
		mh.logger.WithError(err).Warn("Unable to persist blocked request aggregation")
	}
	mh.refreshBlockedRequests24hMetric(snapshot)
}

func (mh *MetricsHandler) refreshBlockedRequests24hMetric(snapshot map[BlockedRequestKey]uint64) {
	blockedRequests24h.Reset()
	for key, count := range snapshot {
		blockedRequests24h.With(prometheus.Labels{"origin": key.Origin, "hostname": key.Hostname}).Set(float64(count))
	}
}

func (mh *MetricsHandler) MarkRequestProcessed(hostname string) {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	// Increment the processed requests metric
	// This is a simple counter, so we just increment the value
	Map[PROCESSED_REQUESTS].Counter.With(prometheus.Labels{"hostname": hostname}).Inc()
}

// MetricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func (mh *MetricsHandler) MetricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	// Implementation goes here
	mh.logger.Debug("Updating metrics...")

	mh.Lock.RLock()
	defer mh.Lock.RUnlock()
	mh.refreshBlockedRequests24hMetric(mh.blockedRequestsAggregator.Snapshot(BlockedRequestsMetricWindow))

	// Most of the common fields are set automatically by the metrics provider
	// We only need to care about the metrics themselves

	promMetrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		mh.logger.Errorf("unable to gather prometheus metrics: %s", err)
		return
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(updateInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	})

	for _, pm := range promMetrics {
		cfg, ok := Map[metricName(pm.GetName())]
		if !ok {
			mh.logger.Debugf("unknown metric %s, skipping", pm.GetName())
			continue
		}

		for _, metric := range pm.GetMetric() {
			labels := metric.GetLabel()
			counterValue := metric.GetCounter().GetValue()

			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			valueToReport := counterValue
			if cfg.LastValueMap == nil {
				// always send absolute values
				mh.logger.Debugf("Sending %s for %+v %f", cfg.Name, labelMap, valueToReport)
			} else {
				// the final value to send must be relative, and never negative
				// because the firewall counter may have been reset since last collection.
				key := cfg.KeyFunc(labels)

				// no need to guard access to LastValueMap, as we are in the main thread -- the
				// counter is updated by the request handlers.
				valueToReport = counterValue - cfg.LastValueMap[key]

				if valueToReport < 0 {
					valueToReport = -valueToReport

					mh.logger.Warningf("metric value for %s %+v is negative, assuming external counter was reset", cfg.Name, labelMap)
				}

				cfg.LastValueMap[key] = counterValue
				mh.logger.Debugf("Sending %s for %+v %f | current value: %f | previous value: %f", cfg.Name, labelMap, valueToReport, counterValue, cfg.LastValueMap[key])
			}

			met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
				Name:   ptr.Of(cfg.Name),
				Value:  &valueToReport,
				Labels: labelMap,
				Unit:   ptr.Of(cfg.Unit),
			})
		}
	}
}
