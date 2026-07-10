package collector

import (
	"fmt"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestServicesCollector(t *testing.T) {
	// http (index 5) running(3); ftp (index 4) stopped(1); plus HA.
	q := &fakeQuerier{
		get: map[string]gosnmp.SnmpPDU{
			fmt.Sprintf("%s.5.0", oidServiceBase): num(oidServiceBase+".5.0", gosnmp.Integer, 3),
			fmt.Sprintf("%s.4.0", oidServiceBase): num(oidServiceBase+".4.0", gosnmp.Integer, 1),
			oidHAStatus:                           num(oidHAStatus, gosnmp.Integer, 0),
			oidHACurrentState:                     num(oidHACurrentState, gosnmp.Integer, 2), // standAlone
		},
	}
	got := gather(t, newServicesCollector(), q)

	checks := map[string]float64{
		"sophos_service_status,service=http":  3,
		"sophos_service_running,service=http": 1,
		"sophos_service_status,service=ftp":   1,
		"sophos_service_running,service=ftp":  0,
		"sophos_ha_enabled":                   0,
		"sophos_ha_state":                     2,
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	// A service not returned by SNMP emits no series.
	if _, ok := got["sophos_service_status,service=dgd"]; ok {
		t.Error("expected no series for absent service dgd")
	}
}

func TestLicenseCollector(t *testing.T) {
	q := &fakeQuerier{
		get: map[string]gosnmp.SnmpPDU{
			fmt.Sprintf("%s.1.1.0", oidLicenseBase): num(oidLicenseBase+".1.1.0", gosnmp.Integer, 3), // basefw subscribed
			fmt.Sprintf("%s.1.2.0", oidLicenseBase): oct(oidLicenseBase+".1.2.0", "31 Dec 2027"),
			fmt.Sprintf("%s.2.1.0", oidLicenseBase): num(oidLicenseBase+".2.1.0", gosnmp.Integer, 4), // netprotection expired
			fmt.Sprintf("%s.2.2.0", oidLicenseBase): oct(oidLicenseBase+".2.2.0", "n/a"),             // unparseable
		},
	}
	got := gather(t, newLicenseCollector(), q)

	if got["sophos_license_status,module=basefw"] != 3 {
		t.Errorf("basefw status = %v, want 3", got["sophos_license_status,module=basefw"])
	}
	if got["sophos_license_status,module=netprotection"] != 4 {
		t.Errorf("netprotection status = %v, want 4", got["sophos_license_status,module=netprotection"])
	}
	wantTS := float64(time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC).Unix())
	if got["sophos_license_expiry_timestamp_seconds,module=basefw"] != wantTS {
		t.Errorf("basefw expiry = %v, want %v", got["sophos_license_expiry_timestamp_seconds,module=basefw"], wantTS)
	}
	// Unparseable expiry -> no series.
	if _, ok := got["sophos_license_expiry_timestamp_seconds,module=netprotection"]; ok {
		t.Error("expected no expiry series for unparseable date")
	}
}

func TestParseExpiry(t *testing.T) {
	cases := map[string]bool{
		"31 Dec 2027":  true,
		"01 Jan 2026":  true,
		"2026-01-01":   true,
		"Jan 2 2026":   true,
		"":             false,
		"never":        false,
		"garbage-date": false,
	}
	for in, wantOK := range cases {
		if _, ok := parseExpiry(in); ok != wantOK {
			t.Errorf("parseExpiry(%q) ok = %v, want %v", in, ok, wantOK)
		}
	}
}
