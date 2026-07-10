package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// serviceLabels maps the sfosXGServiceStatus index (1..21) to its service label,
// taken from SOPHOS-XG-MIB.mib. Index 0 is unused.
var serviceLabels = []string{
	"", "pop3", "imap4", "smtp", "ftp", "http", "av", "as", "dns", "ha", "ips",
	"apache", "ntp", "tomcat", "sslvpn", "ipsecvpn", "database", "network",
	"garner", "drouting", "sshd", "dgd",
}

// servicesCollector emits per-service status/running plus HA enabled/state.
// HA has no dedicated config toggle, so it rides along with the services
// collector (both are operational status).
type servicesCollector struct {
	status    *prometheus.Desc
	running   *prometheus.Desc
	haEnabled *prometheus.Desc
	haState   *prometheus.Desc
}

func newServicesCollector() *servicesCollector {
	return &servicesCollector{
		status: prometheus.NewDesc(Namespace+"_service_status",
			"Service status enum: untouched(0) stopped(1) initializing(2) running(3) exiting(4) dead(5) frozen(6) unregistered(7).",
			[]string{"service"}, nil),
		running: prometheus.NewDesc(Namespace+"_service_running",
			"1 if the service is in the running(3) state, 0 otherwise.",
			[]string{"service"}, nil),
		haEnabled: prometheus.NewDesc(Namespace+"_ha_enabled",
			"HA status: 1 if enabled, 0 if disabled.", nil, nil),
		haState: prometheus.NewDesc(Namespace+"_ha_state",
			"HA state enum: notApplicable(0) auxiliary(1) standAlone(2) primary(3) faulty(4) ready(5).",
			nil, nil),
	}
}

func (s *servicesCollector) Name() string { return "services" }

func (s *servicesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.status
	ch <- s.running
	ch <- s.haEnabled
	ch <- s.haState
}

func (s *servicesCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	oids := make([]string, 0, len(serviceLabels)+1)
	oidToLabel := make(map[string]string, len(serviceLabels))
	for n := 1; n < len(serviceLabels); n++ {
		oid := fmt.Sprintf("%s.%d.0", oidServiceBase, n)
		oids = append(oids, oid)
		oidToLabel[oid] = serviceLabels[n]
	}
	oids = append(oids, oidHAStatus, oidHACurrentState)

	res, err := q.Get(oids)
	if err != nil {
		return fmt.Errorf("service status: %w", err)
	}

	for oid, label := range oidToLabel {
		v, ok := uintOf(res, oid)
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(s.status, prometheus.GaugeValue, float64(v), label)
		running := 0.0
		if snmp.ServiceStatus(v).IsRunning() {
			running = 1
		}
		ch <- prometheus.MustNewConstMetric(s.running, prometheus.GaugeValue, running, label)
	}

	emitGauge(ch, s.haEnabled, res, oidHAStatus, 1)
	emitGauge(ch, s.haState, res, oidHACurrentState, 1)
	return nil
}
