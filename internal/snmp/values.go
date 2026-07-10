package snmp

import (
	"strings"

	"github.com/gosnmp/gosnmp"
)

// IsUsable reports whether a PDU carries a real value (not NoSuchObject/
// NoSuchInstance/EndOfMibView, which SFOS returns for unpopulated scalars).
func IsUsable(pdu gosnmp.SnmpPDU) bool {
	switch pdu.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return false
	default:
		return pdu.Value != nil
	}
}

// String extracts a DisplayString/OctetString value. Returns ("", false) if the
// PDU is not usable or not a string.
func String(pdu gosnmp.SnmpPDU) (string, bool) {
	if !IsUsable(pdu) {
		return "", false
	}
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimRight(string(v), "\x00"), true
	case string:
		return v, true
	default:
		return "", false
	}
}

// Uint64 extracts an unsigned integer (Counter32/64, Gauge32, TimeTicks,
// Integer). Returns (0, false) if the PDU is not usable or not numeric.
func Uint64(pdu gosnmp.SnmpPDU) (uint64, bool) {
	if !IsUsable(pdu) {
		return 0, false
	}
	switch pdu.Type {
	case gosnmp.OctetString, gosnmp.ObjectIdentifier, gosnmp.IPAddress, gosnmp.Boolean:
		return 0, false
	}
	bi := gosnmp.ToBigInt(pdu.Value)
	if bi == nil {
		return 0, false
	}
	if bi.Sign() < 0 {
		return 0, false
	}
	return bi.Uint64(), true
}

// Int64 extracts a signed integer. Returns (0, false) if the PDU is not usable
// or not numeric.
func Int64(pdu gosnmp.SnmpPDU) (int64, bool) {
	if !IsUsable(pdu) {
		return 0, false
	}
	switch pdu.Type {
	case gosnmp.OctetString, gosnmp.ObjectIdentifier, gosnmp.IPAddress, gosnmp.Boolean:
		return 0, false
	}
	bi := gosnmp.ToBigInt(pdu.Value)
	if bi == nil {
		return 0, false
	}
	return bi.Int64(), true
}

// Float64 extracts a numeric value as float64.
func Float64(pdu gosnmp.SnmpPDU) (float64, bool) {
	if v, ok := Int64(pdu); ok {
		return float64(v), true
	}
	return 0, false
}

// LastIndex returns the final sub-identifier of an OID (the table row index),
// e.g. "1.3.6.1.2.1.31.1.1.1.6.7" -> "7".
func LastIndex(oid string) string {
	oid = strings.TrimRight(oid, ".")
	if i := strings.LastIndex(oid, "."); i >= 0 {
		return oid[i+1:]
	}
	return oid
}
