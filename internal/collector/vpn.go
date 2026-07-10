package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// vpnCollector emits IPsec tunnel metrics. It is optional (collectors.vpn) and
// off by default; an unconfigured IPsec table simply yields no series.
type vpnCollector struct {
	active *prometheus.Desc
	status *prometheus.Desc
}

func newVPNCollector() *vpnCollector {
	return &vpnCollector{
		active: prometheus.NewDesc(Namespace+"_ipsec_tunnel_active",
			"IPsec tunnel active count (sfosIPSecVpnActiveTunnel).",
			[]string{"name", "mode", "type"}, nil),
		status: prometheus.NewDesc(Namespace+"_ipsec_tunnel_status",
			"IPsec tunnel connection status enum: inactive(0) active(1) partially-active(2).",
			[]string{"name"}, nil),
	}
}

func (v *vpnCollector) Name() string { return "vpn" }

func (v *vpnCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- v.active
	ch <- v.status
}

func (v *vpnCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	names, err := walkStrings(q, oidVPNConnName)
	if err != nil {
		return fmt.Errorf("ipsec connName: %w", err)
	}
	modes, err := walkStrings(q, oidVPNConnMode)
	if err != nil {
		return fmt.Errorf("ipsec connMode: %w", err)
	}
	types, err := walkUints(q, oidVPNConnType)
	if err != nil {
		return fmt.Errorf("ipsec connType: %w", err)
	}
	active, err := walkUints(q, oidVPNActiveTunnel)
	if err != nil {
		return fmt.Errorf("ipsec activeTunnel: %w", err)
	}
	status, err := walkUints(q, oidVPNConnStatus)
	if err != nil {
		return fmt.Errorf("ipsec connStatus: %w", err)
	}

	for idx, name := range names {
		mode := modes[idx]
		typeName := snmp.VPNConnType(types[idx]).String()
		if a, ok := active[idx]; ok {
			ch <- prometheus.MustNewConstMetric(v.active, prometheus.GaugeValue, float64(a), name, mode, typeName)
		}
		if s, ok := status[idx]; ok {
			ch <- prometheus.MustNewConstMetric(v.status, prometheus.GaugeValue, float64(s), name)
		}
	}
	return nil
}
