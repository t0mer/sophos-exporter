package collector

import (
	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// str returns the string value at oid, or "" if absent/unusable.
func str(res map[string]gosnmp.SnmpPDU, oid string) string {
	if pdu, ok := res[oid]; ok {
		if s, ok := snmp.String(pdu); ok {
			return s
		}
	}
	return ""
}

// uintOf returns the unsigned value at oid.
func uintOf(res map[string]gosnmp.SnmpPDU, oid string) (uint64, bool) {
	if pdu, ok := res[oid]; ok {
		return snmp.Uint64(pdu)
	}
	return 0, false
}

// floatOf returns the numeric value at oid as float64.
func floatOf(res map[string]gosnmp.SnmpPDU, oid string) (float64, bool) {
	if pdu, ok := res[oid]; ok {
		return snmp.Float64(pdu)
	}
	return 0, false
}

// emitGauge emits a gauge scaled by factor, skipping the metric when the OID is
// absent (so unlicensed/unpopulated scalars produce no series rather than a 0).
func emitGauge(ch chan<- prometheus.Metric, desc *prometheus.Desc, res map[string]gosnmp.SnmpPDU, oid string, factor float64, labels ...string) {
	if v, ok := floatOf(res, oid); ok {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v*factor, labels...)
	}
}

// emitCounter emits a counter, skipping absent OIDs.
func emitCounter(ch chan<- prometheus.Metric, desc *prometheus.Desc, res map[string]gosnmp.SnmpPDU, oid string, labels ...string) {
	if v, ok := floatOf(res, oid); ok {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, v, labels...)
	}
}
