package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// deviceCollector emits device info, CPU (from HOST-RESOURCES-MIB), memory,
// disk, swap, live users and uptime.
type deviceCollector struct {
	info        *prometheus.Desc
	cpu         *prometheus.Desc
	memUsage    *prometheus.Desc
	memCapacity *prometheus.Desc
	diskUsage   *prometheus.Desc
	diskCap     *prometheus.Desc
	swapUsage   *prometheus.Desc
	swapCap     *prometheus.Desc
	liveUsers   *prometheus.Desc
	uptime      *prometheus.Desc
}

func newDeviceCollector() *deviceCollector {
	g := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(Namespace+"_"+name, help, labels, nil)
	}
	return &deviceCollector{
		info: prometheus.NewDesc(Namespace+"_device_info",
			"Static device information; value is always 1.",
			[]string{"name", "model", "firmware", "appkey", "webcat_version", "ips_version"}, nil),
		cpu:         g("cpu_usage_percent", "Per-core CPU utilisation percent (core=\"avg\" is the mean).", "core"),
		memUsage:    g("memory_usage_percent", "Memory utilisation percent."),
		memCapacity: g("memory_capacity_bytes", "Total memory capacity in bytes."),
		diskUsage:   g("disk_usage_percent", "Disk utilisation percent."),
		diskCap:     g("disk_capacity_bytes", "Total disk capacity in bytes."),
		swapUsage:   g("swap_usage_percent", "Swap utilisation percent."),
		swapCap:     g("swap_capacity_bytes", "Total swap capacity in bytes."),
		liveUsers:   g("live_users", "Number of live users."),
		uptime:      g("uptime_seconds", "Device uptime in seconds."),
	}
}

func (d *deviceCollector) Name() string { return "device" }

func (d *deviceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.info
	ch <- d.cpu
	ch <- d.memUsage
	ch <- d.memCapacity
	ch <- d.diskUsage
	ch <- d.diskCap
	ch <- d.swapUsage
	ch <- d.swapCap
	ch <- d.liveUsers
	ch <- d.uptime
}

func (d *deviceCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	scalars := []string{
		oidDeviceName, oidDeviceType, oidDeviceFWVersion, oidDeviceAppKey,
		oidWebcatVersion, oidIPSVersion,
		oidUpTime, oidLiveUsersCount,
		oidMemoryPercentUsage, oidMemoryCapacity,
		oidDiskPercentUsage, oidDiskCapacity,
		oidSwapPercentUsage, oidSwapCapacity,
	}
	res, err := q.Get(scalars)
	if err != nil {
		return fmt.Errorf("device scalars: %w", err)
	}

	// Device info — string labels, missing -> empty.
	ch <- prometheus.MustNewConstMetric(d.info, prometheus.GaugeValue, 1,
		str(res, oidDeviceName), str(res, oidDeviceType), str(res, oidDeviceFWVersion),
		str(res, oidDeviceAppKey), str(res, oidWebcatVersion), str(res, oidIPSVersion))

	// Uptime: TimeTicks are 1/100 s.
	if v, ok := uintOf(res, oidUpTime); ok {
		ch <- prometheus.MustNewConstMetric(d.uptime, prometheus.GaugeValue, float64(v)/100)
	}
	emitGauge(ch, d.liveUsers, res, oidLiveUsersCount, 1)
	emitGauge(ch, d.memUsage, res, oidMemoryPercentUsage, 1)
	emitGauge(ch, d.memCapacity, res, oidMemoryCapacity, bytesPerMB)
	emitGauge(ch, d.diskUsage, res, oidDiskPercentUsage, 1)
	emitGauge(ch, d.diskCap, res, oidDiskCapacity, bytesPerMB)
	emitGauge(ch, d.swapUsage, res, oidSwapPercentUsage, 1)
	emitGauge(ch, d.swapCap, res, oidSwapCapacity, bytesPerMB)

	d.collectCPU(q, ch)
	return nil
}

// collectCPU walks hrProcessorLoad. Per contract D3, if the table is absent on
// the VM we simply emit nothing (drop the panel) rather than fail the collector.
func (d *deviceCollector) collectCPU(q snmp.Querier, ch chan<- prometheus.Metric) {
	pdus, err := q.Walk(oidHrProcessorLoad)
	if err != nil {
		return
	}
	var sum float64
	var n int
	for _, pdu := range pdus {
		v, ok := snmp.Float64(pdu)
		if !ok {
			continue
		}
		core := snmp.LastIndex(pdu.Name)
		ch <- prometheus.MustNewConstMetric(d.cpu, prometheus.GaugeValue, v, core)
		sum += v
		n++
	}
	if n > 0 {
		ch <- prometheus.MustNewConstMetric(d.cpu, prometheus.GaugeValue, sum/float64(n), "avg")
	}
}
