// Package collector implements the composite prometheus.Collector that performs
// a live SNMP read on every scrape and fans out to per-subsystem sub-collectors.
package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/config"
	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// Namespace is the metric prefix for every device metric.
const Namespace = "sophos"

// scrapeTimeoutFactor bounds the whole scrape relative to the per-op SNMP
// timeout. gosnmp's own Timeout/Retries bound each Get/Walk; this context is a
// hard ceiling so a scrape can never hang indefinitely.
const scrapeTimeoutFactor = 8

// subCollector produces the metrics for one firewall subsystem from a live SNMP
// session. Update returns an error only on a hard failure (e.g. transport error)
// that should mark the sub-collector unsuccessful; missing optional scalars are
// skipped silently.
type subCollector interface {
	Name() string
	Describe(ch chan<- *prometheus.Desc)
	Update(q snmp.Querier, ch chan<- prometheus.Metric) error
}

// Collector is the composite scrape collector. Metrics are produced on each
// Prometheus scrape (scrape-on-request); there is no background poller.
type Collector struct {
	cfg  config.Config
	log  *slog.Logger
	subs []subCollector

	up               *prometheus.Desc
	scrapeDuration   *prometheus.Desc
	collectorSuccess *prometheus.Desc
}

// New builds the composite collector, wiring in each sub-collector enabled by
// config.
func New(cfg config.Config, log *slog.Logger) *Collector {
	var subs []subCollector
	if cfg.Collectors.Device {
		subs = append(subs, newDeviceCollector())
	}
	if cfg.Collectors.Hits {
		subs = append(subs, newHitsCollector())
	}
	if cfg.Collectors.Services {
		subs = append(subs, newServicesCollector())
	}
	if cfg.Collectors.License {
		subs = append(subs, newLicenseCollector())
	}
	if cfg.Collectors.Interfaces {
		subs = append(subs, newInterfacesCollector())
	}
	// vpn sub-collector is wired in P5.

	return &Collector{
		cfg:  cfg,
		log:  log,
		subs: subs,
		up: prometheus.NewDesc(
			Namespace+"_up",
			"1 if the scrape fully succeeded (all collectors), 0 otherwise.",
			nil, nil,
		),
		scrapeDuration: prometheus.NewDesc(
			Namespace+"_scrape_duration_seconds",
			"Duration of the SNMP scrape in seconds.",
			nil, nil,
		),
		collectorSuccess: prometheus.NewDesc(
			Namespace+"_scrape_collector_success",
			"1 if the named sub-collector succeeded on this scrape, 0 otherwise.",
			[]string{"collector"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.scrapeDuration
	ch <- c.collectorSuccess
	for _, s := range c.subs {
		s.Describe(ch)
	}
}

// Collect implements prometheus.Collector. It never panics or hangs: on any SNMP
// failure it still emits sophos_up 0 and sophos_scrape_duration_seconds.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	defer func() {
		ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, time.Since(start).Seconds())
	}()

	base := c.cfg.SNMP.Timeout
	if base <= 0 {
		base = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), base*scrapeTimeoutFactor)
	defer cancel()

	q, err := snmp.Connect(ctx, c.cfg.SNMP)
	if err != nil {
		c.log.Error("snmp connect failed", "target", c.cfg.SNMP.Target, "err", err)
		for _, s := range c.subs {
			ch <- prometheus.MustNewConstMetric(c.collectorSuccess, prometheus.GaugeValue, 0, s.Name())
		}
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	defer q.Close()

	allOK := true
	for _, s := range c.subs {
		success := 1.0
		if err := s.Update(q, ch); err != nil {
			success = 0
			allOK = false
			c.log.Warn("collector failed", "collector", s.Name(), "err", err)
		}
		ch <- prometheus.MustNewConstMetric(c.collectorSuccess, prometheus.GaugeValue, success, s.Name())
	}

	up := 0.0
	if allOK {
		up = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, up)
}
