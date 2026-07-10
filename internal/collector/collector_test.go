package collector

import (
	"fmt"
	"sort"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// fakeQuerier returns canned PDUs for Get/Walk.
type fakeQuerier struct {
	get     map[string]gosnmp.SnmpPDU
	walk    map[string][]gosnmp.SnmpPDU
	getErr  error
	walkErr error
}

func (f *fakeQuerier) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make(map[string]gosnmp.SnmpPDU)
	for _, o := range oids {
		if p, ok := f.get[o]; ok {
			out[o] = p
		}
	}
	return out, nil
}

func (f *fakeQuerier) Walk(root string) ([]gosnmp.SnmpPDU, error) {
	if f.walkErr != nil {
		return nil, f.walkErr
	}
	return f.walk[root], nil
}

func (f *fakeQuerier) Close() error { return nil }

func oct(name, s string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: []byte(s)}
}
func num(name string, t gosnmp.Asn1BER, v interface{}) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: t, Value: v}
}

// subAdapter turns a subCollector into a prometheus.Collector for gathering.
type subAdapter struct {
	s subCollector
	q snmp.Querier
	t *testing.T
}

func (a subAdapter) Describe(ch chan<- *prometheus.Desc) { a.s.Describe(ch) }
func (a subAdapter) Collect(ch chan<- prometheus.Metric) {
	if err := a.s.Update(a.q, ch); err != nil {
		a.t.Fatalf("%s Update() error = %v", a.s.Name(), err)
	}
}

// gather collects a sub-collector's metrics into a name{,labels}->value map.
func gather(t *testing.T, s subCollector, q snmp.Querier) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(subAdapter{s: s, q: q, t: t})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			labels := make([]string, 0, len(m.Label))
			for _, lp := range m.Label {
				labels = append(labels, fmt.Sprintf("%s=%s", lp.GetName(), lp.GetValue()))
			}
			sort.Strings(labels)
			key := mf.GetName()
			for _, l := range labels {
				key += "," + l
			}
			switch {
			case m.Gauge != nil:
				out[key] = m.Gauge.GetValue()
			case m.Counter != nil:
				out[key] = m.Counter.GetValue()
			}
		}
	}
	return out
}

func TestDeviceCollector(t *testing.T) {
	q := &fakeQuerier{
		get: map[string]gosnmp.SnmpPDU{
			oidDeviceName:         oct(oidDeviceName, "fw"),
			oidDeviceType:         oct(oidDeviceType, "SFVH"),
			oidDeviceFWVersion:    oct(oidDeviceFWVersion, "SFOS 22.0.1 MR-1"),
			oidDeviceAppKey:       oct(oidDeviceAppKey, "APPKEY"),
			oidWebcatVersion:      oct(oidWebcatVersion, "1.2"),
			oidIPSVersion:         oct(oidIPSVersion, "9.8"),
			oidUpTime:             num(oidUpTime, gosnmp.TimeTicks, uint32(100000)), // 1000s
			oidLiveUsersCount:     num(oidLiveUsersCount, gosnmp.Gauge32, uint(5)),
			oidMemoryPercentUsage: num(oidMemoryPercentUsage, gosnmp.Gauge32, uint(40)),
			oidMemoryCapacity:     num(oidMemoryCapacity, gosnmp.Gauge32, uint(2048)), // MB
			oidDiskPercentUsage:   num(oidDiskPercentUsage, gosnmp.Gauge32, uint(20)),
			oidDiskCapacity:       num(oidDiskCapacity, gosnmp.Gauge32, uint(10240)),
			// swap omitted to exercise "skip absent scalar".
		},
		walk: map[string][]gosnmp.SnmpPDU{
			oidHrProcessorLoad: {
				num(oidHrProcessorLoad+".1", gosnmp.Integer, 10),
				num(oidHrProcessorLoad+".2", gosnmp.Integer, 30),
			},
		},
	}

	got := gather(t, newDeviceCollector(), q)

	checks := map[string]float64{
		"sophos_uptime_seconds":             1000,
		"sophos_live_users":                 5,
		"sophos_memory_usage_percent":       40,
		"sophos_memory_capacity_bytes":      2048 * 1024 * 1024,
		"sophos_disk_capacity_bytes":        10240 * 1024 * 1024,
		"sophos_cpu_usage_percent,core=1":   10,
		"sophos_cpu_usage_percent,core=2":   30,
		"sophos_cpu_usage_percent,core=avg": 20,
		"sophos_device_info,appkey=APPKEY,firmware=SFOS 22.0.1 MR-1,ips_version=9.8,model=SFVH,name=fw,webcat_version=1.2": 1,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	// Swap was absent -> no series emitted.
	if _, ok := got["sophos_swap_capacity_bytes"]; ok {
		t.Error("expected no swap_capacity_bytes series when OID absent")
	}
}

func TestHitsCollector(t *testing.T) {
	q := &fakeQuerier{
		get: map[string]gosnmp.SnmpPDU{
			oidHTTPHits: num(oidHTTPHits, gosnmp.Counter64, uint64(12345)),
			oidSmtpHits: num(oidSmtpHits, gosnmp.Counter64, uint64(42)),
		},
	}
	got := gather(t, newHitsCollector(), q)
	if got["sophos_http_hits_total"] != 12345 {
		t.Errorf("http hits = %v, want 12345", got["sophos_http_hits_total"])
	}
	if got["sophos_smtp_hits_total"] != 42 {
		t.Errorf("smtp hits = %v, want 42", got["sophos_smtp_hits_total"])
	}
	if _, ok := got["sophos_ftp_hits_total"]; ok {
		t.Error("expected no ftp series when OID absent")
	}
}

func TestDeviceCollectorGetErrorFails(t *testing.T) {
	q := &fakeQuerier{getErr: fmt.Errorf("timeout")}
	d := newDeviceCollector()
	ch := make(chan prometheus.Metric, 32)
	if err := d.Update(q, ch); err == nil {
		t.Fatal("Update() error = nil, want error on Get failure")
	}
}
