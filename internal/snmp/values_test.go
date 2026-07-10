package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func pdu(t gosnmp.Asn1BER, v interface{}) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: ".1.3.6", Type: t, Value: v}
}

func TestString(t *testing.T) {
	got, ok := String(pdu(gosnmp.OctetString, []byte("SFVH\x00")))
	if !ok || got != "SFVH" {
		t.Errorf("String() = %q,%v want SFVH,true", got, ok)
	}
	if _, ok := String(pdu(gosnmp.NoSuchObject, nil)); ok {
		t.Error("String() on NoSuchObject should be false")
	}
	if _, ok := String(pdu(gosnmp.Integer, 5)); ok {
		t.Error("String() on Integer should be false")
	}
}

func TestUint64(t *testing.T) {
	cases := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want uint64
		ok   bool
	}{
		{"counter64", pdu(gosnmp.Counter64, uint64(1<<40)), 1 << 40, true},
		{"gauge32", pdu(gosnmp.Gauge32, uint(42)), 42, true},
		{"timeticks", pdu(gosnmp.TimeTicks, uint32(123456)), 123456, true},
		{"integer", pdu(gosnmp.Integer, 7), 7, true},
		{"nosuch", pdu(gosnmp.NoSuchInstance, nil), 0, false},
		{"octetstring", pdu(gosnmp.OctetString, []byte("x")), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Uint64(c.pdu)
			if got != c.want || ok != c.ok {
				t.Errorf("Uint64() = %d,%v want %d,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestLastIndex(t *testing.T) {
	cases := map[string]string{
		"1.3.6.1.2.1.31.1.1.1.6.7": "7",
		".1.3.6.1.2.1.2.2.1.8.12":  "12",
		"5":                        "5",
	}
	for in, want := range cases {
		if got := LastIndex(in); got != want {
			t.Errorf("LastIndex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnumStrings(t *testing.T) {
	if ServiceRunning.String() != "running" || !ServiceRunning.IsRunning() {
		t.Error("ServiceRunning decode wrong")
	}
	if ServiceStatus(99).String() != "unknown" {
		t.Error("out-of-range service status should be unknown")
	}
	if LicenseSubscribed.String() != "subscribed" {
		t.Error("LicenseSubscribed decode wrong")
	}
	if HAStandAlone.String() != "standAlone" {
		t.Error("HAStandAlone decode wrong")
	}
}
