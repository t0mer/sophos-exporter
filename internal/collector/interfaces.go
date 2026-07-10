package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// interfacesCollector emits per-interface IF-MIB counters, labelled by ifName.
type interfacesCollector struct {
	rxBytes   *prometheus.Desc
	txBytes   *prometheus.Desc
	rxPackets *prometheus.Desc
	txPackets *prometheus.Desc
	rxErrors  *prometheus.Desc
	txErrors  *prometheus.Desc
	up        *prometheus.Desc
}

func newInterfacesCollector() *interfacesCollector {
	c := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(Namespace+"_"+name, help, []string{"interface"}, nil)
	}
	return &interfacesCollector{
		rxBytes:   c("interface_receive_bytes_total", "Total bytes received on the interface (ifHCInOctets)."),
		txBytes:   c("interface_transmit_bytes_total", "Total bytes transmitted on the interface (ifHCOutOctets)."),
		rxPackets: c("interface_receive_packets_total", "Total unicast packets received (ifHCInUcastPkts)."),
		txPackets: c("interface_transmit_packets_total", "Total unicast packets transmitted (ifHCOutUcastPkts)."),
		rxErrors:  c("interface_receive_errors_total", "Total inbound errors (ifInErrors)."),
		txErrors:  c("interface_transmit_errors_total", "Total outbound errors (ifOutErrors)."),
		up:        c("interface_up", "1 if ifOperStatus is up(1), 0 otherwise."),
	}
}

func (i *interfacesCollector) Name() string { return "interfaces" }

func (i *interfacesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- i.rxBytes
	ch <- i.txBytes
	ch <- i.rxPackets
	ch <- i.txPackets
	ch <- i.rxErrors
	ch <- i.txErrors
	ch <- i.up
}

func (i *interfacesCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	// ifName provides the label; without it there is nothing to attribute.
	names, err := walkStrings(q, oidIfName)
	if err != nil {
		return fmt.Errorf("ifName: %w", err)
	}

	// Each counter column is emitted as a Counter metric keyed by ifIndex.
	columns := []struct {
		oid  string
		desc *prometheus.Desc
	}{
		{oidIfHCInOctets, i.rxBytes},
		{oidIfHCOutOctets, i.txBytes},
		{oidIfHCInUcast, i.rxPackets},
		{oidIfHCOutUcast, i.txPackets},
		{oidIfInErrors, i.rxErrors},
		{oidIfOutErrors, i.txErrors},
	}
	for _, col := range columns {
		vals, err := walkUints(q, col.oid)
		if err != nil {
			return fmt.Errorf("interface counter %s: %w", col.oid, err)
		}
		for idx, v := range vals {
			ch <- prometheus.MustNewConstMetric(col.desc, prometheus.CounterValue, float64(v), ifLabel(names, idx))
		}
	}

	// ifOperStatus: up(1) -> 1, everything else -> 0.
	status, err := walkUints(q, oidIfOperStatus)
	if err != nil {
		return fmt.Errorf("ifOperStatus: %w", err)
	}
	for idx, v := range status {
		up := 0.0
		if v == 1 {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(i.up, prometheus.GaugeValue, up, ifLabel(names, idx))
	}
	return nil
}

// ifLabel returns the interface name for an ifIndex, falling back to the index.
func ifLabel(names map[string]string, idx string) string {
	if n, ok := names[idx]; ok && n != "" {
		return n
	}
	return idx
}

// walkStrings walks a string column into an ifIndex->value map.
func walkStrings(q snmp.Querier, oid string) (map[string]string, error) {
	pdus, err := q.Walk(oid)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(pdus))
	for _, pdu := range pdus {
		if s, ok := snmp.String(pdu); ok {
			out[snmp.LastIndex(pdu.Name)] = s
		}
	}
	return out, nil
}

// walkUints walks a numeric column into an ifIndex->value map.
func walkUints(q snmp.Querier, oid string) (map[string]uint64, error) {
	pdus, err := q.Walk(oid)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(pdus))
	for _, pdu := range pdus {
		if v, ok := snmp.Uint64(pdu); ok {
			out[snmp.LastIndex(pdu.Name)] = v
		}
	}
	return out, nil
}
