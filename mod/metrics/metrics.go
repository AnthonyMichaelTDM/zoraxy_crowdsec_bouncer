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
	BLOCKED_REQUESTS   metricName = "zoraxy_bouncer_blocked_requests"
	PROCESSED_REQUESTS metricName = "zoraxy_bouncer_processed_requests"
)

// NOTE: Currently, all metrics are treated as absolute counts.
type Metric struct {
	Name         string
	Unit         string
	Gauge        *prometheus.GaugeVec
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*io_prometheus_client.LabelPair) string
}

type metricMap map[metricName]*Metric

func (m metricMap) MustRegisterAll() {
	for _, met := range m {
		prometheus.MustRegister(met.Gauge)
	}
}

var Map = metricMap{
	BLOCKED_REQUESTS: {
		Name: "blocked",
		Unit: "request",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(BLOCKED_REQUESTS),
			Help: "Denotes the total number of requests blocked by the Zoraxy bouncer",
		}, []string{"origin"}),
		LabelKeys:    []string{"origin"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin")
		},
	},
	PROCESSED_REQUESTS: {
		Name: "processed",
		Unit: "request",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(PROCESSED_REQUESTS),
			Help: "Denotes the total number of requests processed by the Zoraxy bouncer",
		}, []string{"origin"}),
		LabelKeys:    []string{"origin"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin")
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
	Lock   sync.RWMutex
	logger *logrus.Logger
}

func NewMetricsHandler(logger *logrus.Logger) *MetricsHandler {
	// Initialization logic for MetricsHandler if needed
	mh := &MetricsHandler{
		logger: logger,
		Lock:   sync.RWMutex{},
	}

	return mh
}

func (mh *MetricsHandler) MarkRequestBlocked(origin string) {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	// Increment the blocked requests metric
	// This is a simple counter, so we just increment the value
	Map[BLOCKED_REQUESTS].Gauge.With(prometheus.Labels{"origin": origin}).Inc()
}

func (mh *MetricsHandler) MarkRequestProcessed(origin string) {
	mh.Lock.Lock()
	defer mh.Lock.Unlock()

	// Increment the processed requests metric
	// This is a simple counter, so we just increment the value
	Map[PROCESSED_REQUESTS].Gauge.With(prometheus.Labels{"origin": origin}).Inc()
}

// MetricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func (mh *MetricsHandler) MetricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	// Implementation goes here
	mh.logger.Debug("Updating metrics...")

	mh.Lock.RLock()
	defer mh.Lock.RUnlock()

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
			gaugeValue := metric.GetGauge().GetValue()

			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			valueToReport := gaugeValue
			if cfg.LastValueMap == nil {
				// always send absolute values
				mh.logger.Debugf("Sending %s for %+v %f", cfg.Name, labelMap, valueToReport)
			} else {
				// the final value to send must be relative, and never negative
				// because the firewall counter may have been reset since last collection.
				key := cfg.KeyFunc(labels)

				// no need to guard access to LastValueMap, as we are in the main thread -- it's
				// the gauge that is updated by the requests
				valueToReport = gaugeValue - cfg.LastValueMap[key]

				if valueToReport < 0 {
					valueToReport = -valueToReport

					mh.logger.Warningf("metric value for %s %+v is negative, assuming external counter was reset", cfg.Name, labelMap)
				}

				cfg.LastValueMap[key] = gaugeValue
				mh.logger.Debugf("Sending %s for %+v %f | current value: %f | previous value: %f", cfg.Name, labelMap, valueToReport, gaugeValue, cfg.LastValueMap[key])
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
