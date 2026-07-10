package snmp

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/t0mer/sophos-exporter/internal/config"
)

func TestBuildV2c(t *testing.T) {
	g, err := build(config.SNMPConfig{
		Target:    "192.168.1.1:161",
		Version:   config.VersionV2c,
		Community: "public",
		Timeout:   3 * time.Second,
		Retries:   2,
	})
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if g.Version != gosnmp.Version2c {
		t.Errorf("version = %v, want Version2c", g.Version)
	}
	if g.Target != "192.168.1.1" || g.Port != 161 {
		t.Errorf("target/port = %s:%d, want 192.168.1.1:161", g.Target, g.Port)
	}
	if g.Community != "public" {
		t.Errorf("community = %q, want public", g.Community)
	}
	if g.Timeout != 3*time.Second || g.Retries != 2 {
		t.Errorf("timeout/retries = %v/%d, want 3s/2", g.Timeout, g.Retries)
	}
}

func TestBuildV3AuthPriv(t *testing.T) {
	g, err := build(config.SNMPConfig{
		Target:        "fw.local",
		Version:       config.VersionV3,
		SecurityLevel: config.SecurityAuthPriv,
		Username:      "monitor",
		AuthProtocol:  "SHA256",
		AuthPassword:  "authpass",
		PrivProtocol:  "AES256",
		PrivPassword:  "privpass",
	})
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if g.Version != gosnmp.Version3 {
		t.Fatalf("version = %v, want Version3", g.Version)
	}
	if g.Port != defaultPort {
		t.Errorf("port = %d, want default %d", g.Port, defaultPort)
	}
	if g.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		t.Errorf("msgflags = %v, want AuthPriv", g.MsgFlags)
	}
	usm, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatalf("security params type = %T, want *UsmSecurityParameters", g.SecurityParameters)
	}
	if usm.UserName != "monitor" {
		t.Errorf("username = %q, want monitor", usm.UserName)
	}
	if usm.AuthenticationProtocol != gosnmp.SHA256 {
		t.Errorf("auth proto = %v, want SHA256", usm.AuthenticationProtocol)
	}
	if usm.PrivacyProtocol != gosnmp.AES256 {
		t.Errorf("priv proto = %v, want AES256", usm.PrivacyProtocol)
	}
}

func TestBuildV3AuthNoPriv(t *testing.T) {
	g, err := build(config.SNMPConfig{
		Target:        "fw.local:1161",
		Version:       config.VersionV3,
		SecurityLevel: config.SecurityAuthNoPriv,
		Username:      "monitor",
		AuthProtocol:  "SHA",
		AuthPassword:  "authpass",
	})
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if g.MsgFlags&gosnmp.AuthNoPriv != gosnmp.AuthNoPriv {
		t.Errorf("msgflags = %v, want AuthNoPriv", g.MsgFlags)
	}
	if g.Port != 1161 {
		t.Errorf("port = %d, want 1161", g.Port)
	}
}

func TestBuildErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.SNMPConfig
	}{
		{"bad auth proto", config.SNMPConfig{
			Target: "x", Version: config.VersionV3, SecurityLevel: config.SecurityAuthNoPriv,
			Username: "u", AuthProtocol: "BOGUS", AuthPassword: "p",
		}},
		{"bad priv proto", config.SNMPConfig{
			Target: "x", Version: config.VersionV3, SecurityLevel: config.SecurityAuthPriv,
			Username: "u", AuthProtocol: "SHA", AuthPassword: "p", PrivProtocol: "BOGUS", PrivPassword: "p",
		}},
		{"empty target", config.SNMPConfig{Version: config.VersionV2c, Community: "c"}},
		{"unknown version", config.SNMPConfig{Target: "x", Version: "9"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := build(tt.cfg); err == nil {
				t.Fatalf("build() error = nil, want error")
			}
		})
	}
}

func TestSplitTarget(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"192.168.1.1:161", "192.168.1.1", 161, false},
		{"fw.local", "fw.local", 161, false},
		{"[2001:db8::1]:161", "2001:db8::1", 161, false},
		{"fw.local:abc", "", 0, true},
		{"", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			host, port, err := splitTarget(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("splitTarget(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("splitTarget(%q) = %s:%d, want %s:%d", tt.in, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}
