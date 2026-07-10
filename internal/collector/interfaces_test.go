package collector

import (
	"fmt"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestInterfacesCollector(t *testing.T) {
	// Two interfaces: Port1 (idx 1, up), Port2 (idx 2, down).
	q := &fakeQuerier{
		walk: map[string][]gosnmp.SnmpPDU{
			oidIfName: {
				oct(oidIfName+".1", "Port1"),
				oct(oidIfName+".2", "Port2"),
			},
			oidIfHCInOctets: {
				num(oidIfHCInOctets+".1", gosnmp.Counter64, uint64(1000)),
				num(oidIfHCInOctets+".2", gosnmp.Counter64, uint64(2000)),
			},
			oidIfHCOutOctets: {
				num(oidIfHCOutOctets+".1", gosnmp.Counter64, uint64(500)),
			},
			oidIfInErrors: {
				num(oidIfInErrors+".1", gosnmp.Counter32, uint(3)),
			},
			oidIfOperStatus: {
				num(oidIfOperStatus+".1", gosnmp.Integer, 1), // up
				num(oidIfOperStatus+".2", gosnmp.Integer, 2), // down
			},
		},
	}

	got := gather(t, newInterfacesCollector(), q)

	checks := map[string]float64{
		"sophos_interface_receive_bytes_total,interface=Port1":  1000,
		"sophos_interface_receive_bytes_total,interface=Port2":  2000,
		"sophos_interface_transmit_bytes_total,interface=Port1": 500,
		"sophos_interface_receive_errors_total,interface=Port1": 3,
		"sophos_interface_up,interface=Port1":                   1,
		"sophos_interface_up,interface=Port2":                   0,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

func TestInterfacesCollectorWalkErrorFails(t *testing.T) {
	q := &fakeQuerier{walkErr: fmt.Errorf("walk failed")}
	// Update returns before touching the channel, so a nil channel is safe here.
	if err := newInterfacesCollector().Update(q, nil); err == nil {
		t.Fatal("Update() error = nil, want error on ifName walk failure")
	}
}
