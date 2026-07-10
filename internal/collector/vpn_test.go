package collector

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestVPNCollector(t *testing.T) {
	q := &fakeQuerier{
		walk: map[string][]gosnmp.SnmpPDU{
			oidVPNConnName:     {oct(oidVPNConnName+".1", "branch")},
			oidVPNConnMode:     {oct(oidVPNConnMode+".1", "Main")},
			oidVPNConnType:     {num(oidVPNConnType+".1", gosnmp.Integer, 2)}, // site-to-site
			oidVPNActiveTunnel: {num(oidVPNActiveTunnel+".1", gosnmp.Integer, 1)},
			oidVPNConnStatus:   {num(oidVPNConnStatus+".1", gosnmp.Integer, 1)}, // active
		},
	}
	got := gather(t, newVPNCollector(), q)

	if got["sophos_ipsec_tunnel_active,mode=Main,name=branch,type=site-to-site"] != 1 {
		t.Errorf("tunnel active label/value wrong: %#v", got)
	}
	if got["sophos_ipsec_tunnel_status,name=branch"] != 1 {
		t.Errorf("tunnel status = %v, want 1", got["sophos_ipsec_tunnel_status,name=branch"])
	}
}

func TestVPNCollectorEmptyTable(t *testing.T) {
	// No IPsec configured: walks return nothing, collector succeeds with 0 series.
	q := &fakeQuerier{}
	got := gather(t, newVPNCollector(), q)
	if len(got) != 0 {
		t.Errorf("expected no series for empty IPsec table, got %#v", got)
	}
}
