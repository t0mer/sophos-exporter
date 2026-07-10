package collector

import (
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// licenseModules maps the sfosXGLicenseDetails index (1..9) to its module label.
var licenseModules = []string{
	"", "basefw", "netprotection", "webprotection", "mailprotection",
	"webserverprotection", "sandstorm", "enhancedsupport", "enhancedplussupport",
	"centralorchestration",
}

// expiryLayouts are the date formats attempted for the ExpiryDate DisplayString.
// SFOS has shipped several; parsing is best-effort and skipped on failure (D7).
var expiryLayouts = []string{
	"2 Jan 2006",
	"02 Jan 2006",
	"Jan 2 2006",
	"Jan 02 2006",
	"2006-01-02",
	"2006-01-02 15:04:05",
	"02/01/2006",
	"01/02/2006",
	time.RFC3339,
}

type licenseCollector struct {
	status *prometheus.Desc
	expiry *prometheus.Desc
}

func newLicenseCollector() *licenseCollector {
	return &licenseCollector{
		status: prometheus.NewDesc(Namespace+"_license_status",
			"License subscription status enum: none(0) evaluating(1) notsubscribed(2) subscribed(3) expired(4) deactivated(5).",
			[]string{"module"}, nil),
		expiry: prometheus.NewDesc(Namespace+"_license_expiry_timestamp_seconds",
			"License expiry as a Unix timestamp (seconds); absent when the date does not parse.",
			[]string{"module"}, nil),
	}
}

func (l *licenseCollector) Name() string { return "license" }

func (l *licenseCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- l.status
	ch <- l.expiry
}

func (l *licenseCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	oids := make([]string, 0, len(licenseModules)*2)
	type oidPair struct{ status, expiry string }
	pairs := make([]struct {
		module string
		oidPair
	}, 0, len(licenseModules))

	for n := 1; n < len(licenseModules); n++ {
		statusOID := fmt.Sprintf("%s.%d.1.0", oidLicenseBase, n)
		expiryOID := fmt.Sprintf("%s.%d.2.0", oidLicenseBase, n)
		oids = append(oids, statusOID, expiryOID)
		pairs = append(pairs, struct {
			module string
			oidPair
		}{licenseModules[n], oidPair{statusOID, expiryOID}})
	}

	res, err := q.Get(oids)
	if err != nil {
		return fmt.Errorf("license details: %w", err)
	}

	for _, p := range pairs {
		if v, ok := uintOf(res, p.status); ok {
			ch <- prometheus.MustNewConstMetric(l.status, prometheus.GaugeValue, float64(v), p.module)
		}
		if s := str(res, p.expiry); s != "" {
			if ts, ok := parseExpiry(s); ok {
				ch <- prometheus.MustNewConstMetric(l.expiry, prometheus.GaugeValue, float64(ts.Unix()), p.module)
			}
		}
	}
	return nil
}

// parseExpiry tries the known SFOS date layouts, returning ok=false when none match.
func parseExpiry(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range expiryLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
