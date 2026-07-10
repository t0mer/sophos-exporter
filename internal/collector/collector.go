// Package collector implements the composite prometheus.Collector that performs
// a live SNMP read on every scrape and fans out to per-subsystem sub-collectors.
package collector

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace is the metric prefix for every device metric.
const Namespace = "sophos"

// Collector is the composite scrape collector. Metrics are produced on each
// Prometheus scrape (scrape-on-request); there is no background poller.
//
// P0: emits only sophos_up (hardcoded 1) and sophos_scrape_duration_seconds.
// Real SNMP reads and sub-collectors are wired in later phases.
type Collector struct {
	up             *prometheus.Desc
	scrapeDuration *prometheus.Desc
}

// New builds the composite collector.
func New() *Collector {
	return &Collector{
		up: prometheus.NewDesc(
			Namespace+"_up",
			"1 if the scrape fully succeeded, 0 otherwise.",
			nil, nil,
		),
		scrapeDuration: prometheus.NewDesc(
			Namespace+"_scrape_duration_seconds",
			"Duration of the SNMP scrape in seconds.",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.scrapeDuration
}

// Collect implements prometheus.Collector. It never panics: on any failure it
// still emits sophos_up and sophos_scrape_duration_seconds.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()

	// P0 placeholder: the scrape always "succeeds" until real SNMP is wired.
	up := 1.0

	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, up)
	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, time.Since(start).Seconds())
}
