package config

import (
	"testing"
	"time"
)

// baseV3 returns a minimal valid authPriv v3 config to mutate in table tests.
func baseV3() Config {
	return Config{
		Listen:   ":9835",
		LogLevel: "info",
		SNMP: SNMPConfig{
			Target:        "192.168.1.1:161",
			Version:       VersionV3,
			Timeout:       5 * time.Second,
			SecurityLevel: SecurityAuthPriv,
			Username:      "monitor",
			AuthProtocol:  "SHA",
			AuthPassword:  "authpass",
			PrivProtocol:  "AES",
			PrivPassword:  "privpass",
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr bool
	}{
		{"valid v3 authPriv", func(*Config) {}, false},
		{
			"valid v2c",
			func(c *Config) {
				c.SNMP.Version = VersionV2c
				c.SNMP.Community = "public"
			},
			false,
		},
		{
			"v2c missing community",
			func(c *Config) {
				c.SNMP.Version = VersionV2c
				c.SNMP.Community = ""
			},
			true,
		},
		{
			"valid v3 authNoPriv",
			func(c *Config) {
				c.SNMP.SecurityLevel = SecurityAuthNoPriv
				c.SNMP.PrivProtocol = ""
				c.SNMP.PrivPassword = ""
			},
			false,
		},
		{
			"v3 authPriv missing priv password",
			func(c *Config) { c.SNMP.PrivPassword = "" },
			true,
		},
		{
			"v3 authNoPriv missing auth password",
			func(c *Config) {
				c.SNMP.SecurityLevel = SecurityAuthNoPriv
				c.SNMP.AuthPassword = ""
			},
			true,
		},
		{
			"unknown version",
			func(c *Config) { c.SNMP.Version = "1" },
			true,
		},
		{
			"unknown security level",
			func(c *Config) { c.SNMP.SecurityLevel = "bogus" },
			true,
		},
		{
			"missing target",
			func(c *Config) { c.SNMP.Target = "" },
			true,
		},
		{
			"invalid log level",
			func(c *Config) { c.LogLevel = "verbose" },
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseV3()
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("SOPHOS_EXPORTER_SNMP_TARGET", "10.0.0.1:161")
	t.Setenv("SOPHOS_EXPORTER_SNMP_VERSION", VersionV2c)
	t.Setenv("SOPHOS_EXPORTER_SNMP_COMMUNITY", "s3cret")
	t.Setenv("SOPHOS_EXPORTER_LISTEN", ":1234")

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SNMP.Target != "10.0.0.1:161" {
		t.Errorf("target = %q, want 10.0.0.1:161", cfg.SNMP.Target)
	}
	if cfg.SNMP.Community != "s3cret" {
		t.Errorf("community = %q, want s3cret", cfg.SNMP.Community)
	}
	if cfg.Listen != ":1234" {
		t.Errorf("listen = %q, want :1234", cfg.Listen)
	}
	if cfg.SNMP.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s (default)", cfg.SNMP.Timeout)
	}
}
