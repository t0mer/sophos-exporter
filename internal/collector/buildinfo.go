package collector

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/t0mer/sophos-exporter/internal/version"
)

// NewBuildInfo returns the always-on sophos_exporter_build_info collector.
func NewBuildInfo() prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sophos_exporter_build_info",
		Help: "Build metadata for the sophos-exporter binary; value is always 1.",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"commit":    version.Commit,
			"date":      version.Date,
			"goversion": runtime.Version(),
		},
	})
	g.Set(1)
	return g
}
