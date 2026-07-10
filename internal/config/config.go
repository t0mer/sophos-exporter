// Package config loads and validates the exporter configuration.
//
// Precedence is flags > env (SOPHOS_EXPORTER_) > YAML, implemented with Viper.
// The config file is searched for as ./config.yml then
// /etc/sophos-exporter/config.yml.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// EnvPrefix is the prefix for all environment-variable overrides.
const EnvPrefix = "SOPHOS_EXPORTER"

// SNMP transport versions.
const (
	VersionV2c = "2c"
	VersionV3  = "3"
)

// SNMPv3 security levels.
const (
	SecurityNoAuthNoPriv = "noAuthNoPriv"
	SecurityAuthNoPriv   = "authNoPriv"
	SecurityAuthPriv     = "authPriv"
)

// Config is the fully-resolved exporter configuration.
type Config struct {
	Listen     string           `mapstructure:"listen"`
	LogLevel   string           `mapstructure:"log_level"`
	SNMP       SNMPConfig       `mapstructure:"snmp"`
	Collectors CollectorsConfig `mapstructure:"collectors"`
}

// SNMPConfig holds transport and authentication settings for the firewall.
type SNMPConfig struct {
	Target  string        `mapstructure:"target"`
	Version string        `mapstructure:"version"`
	Timeout time.Duration `mapstructure:"timeout"`
	Retries int           `mapstructure:"retries"`

	// v2c
	Community string `mapstructure:"community"`

	// v3
	SecurityLevel string `mapstructure:"security_level"`
	Username      string `mapstructure:"username"`
	AuthProtocol  string `mapstructure:"auth_protocol"`
	AuthPassword  string `mapstructure:"auth_password"`
	PrivProtocol  string `mapstructure:"priv_protocol"`
	PrivPassword  string `mapstructure:"priv_password"`
}

// CollectorsConfig toggles each sub-collector on or off.
type CollectorsConfig struct {
	Device     bool `mapstructure:"device"`
	Interfaces bool `mapstructure:"interfaces"`
	Services   bool `mapstructure:"services"`
	License    bool `mapstructure:"license"`
	Hits       bool `mapstructure:"hits"`
	VPN        bool `mapstructure:"vpn"`
}

// setDefaults registers every key with a default so that AutomaticEnv overrides
// are visible to Unmarshal (Viper only maps env vars for keys it knows about).
func setDefaults(v *viper.Viper) {
	v.SetDefault("listen", ":9835")
	v.SetDefault("log_level", "info")

	v.SetDefault("snmp.target", "")
	v.SetDefault("snmp.version", VersionV3)
	v.SetDefault("snmp.timeout", "5s")
	v.SetDefault("snmp.retries", 1)
	v.SetDefault("snmp.community", "")
	v.SetDefault("snmp.security_level", SecurityAuthPriv)
	v.SetDefault("snmp.username", "")
	v.SetDefault("snmp.auth_protocol", "SHA")
	v.SetDefault("snmp.auth_password", "")
	v.SetDefault("snmp.priv_protocol", "AES")
	v.SetDefault("snmp.priv_password", "")

	v.SetDefault("collectors.device", true)
	v.SetDefault("collectors.interfaces", true)
	v.SetDefault("collectors.services", true)
	v.SetDefault("collectors.license", true)
	v.SetDefault("collectors.hits", true)
	v.SetDefault("collectors.vpn", false)
}

// Load resolves and validates the configuration from (in precedence order)
// flags, environment, and the YAML config file. cfgFile, when non-empty,
// overrides the search path. flags may be nil (e.g. in tests).
func Load(cfgFile string, flags *pflag.FlagSet) (*Config, error) {
	cfg, err := resolve(cfgFile, flags)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ListenAddress resolves only the listen address, skipping SNMP validation. It
// backs the healthcheck subcommand, which must work even when SNMP is
// unconfigured (e.g. inside a container HEALTHCHECK).
func ListenAddress(cfgFile string, flags *pflag.FlagSet) (string, error) {
	cfg, err := resolve(cfgFile, flags)
	if err != nil {
		return "", err
	}
	return cfg.Listen, nil
}

// resolve applies the flags > env > YAML > defaults precedence without validating.
func resolve(cfgFile string, flags *pflag.FlagSet) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/sophos-exporter")
	}

	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if flags != nil {
		// Map dash-style flag names to their (possibly underscored) config keys.
		// Only flags actually registered on the set are bound.
		flagToKey := map[string]string{
			"listen":    "listen",
			"log-level": "log_level",
		}
		for flagName, key := range flagToKey {
			if f := flags.Lookup(flagName); f != nil {
				if err := v.BindPFlag(key, f); err != nil {
					return nil, fmt.Errorf("binding flag %q: %w", flagName, err)
				}
			}
		}
	}

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is fine: env/flags/defaults may fully configure.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}

// Validate fails fast with a clear message on any invalid combination.
func (c *Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log_level %q (want debug|info|warn|error)", c.LogLevel)
	}

	if c.SNMP.Target == "" {
		return fmt.Errorf("snmp.target is required")
	}

	switch c.SNMP.Version {
	case VersionV2c:
		if c.SNMP.Community == "" {
			return fmt.Errorf("snmp.community is required when snmp.version is %q", VersionV2c)
		}
	case VersionV3:
		return c.validateV3()
	default:
		return fmt.Errorf("invalid snmp.version %q (want %q or %q)", c.SNMP.Version, VersionV2c, VersionV3)
	}
	return nil
}

func (c *Config) validateV3() error {
	switch c.SNMP.SecurityLevel {
	case SecurityNoAuthNoPriv:
		if c.SNMP.Username == "" {
			return fmt.Errorf("snmp.username is required for SNMPv3")
		}
	case SecurityAuthNoPriv:
		if c.SNMP.Username == "" || c.SNMP.AuthProtocol == "" || c.SNMP.AuthPassword == "" {
			return fmt.Errorf("snmp.username, snmp.auth_protocol and snmp.auth_password are required for %q", SecurityAuthNoPriv)
		}
	case SecurityAuthPriv:
		if c.SNMP.Username == "" || c.SNMP.AuthProtocol == "" || c.SNMP.AuthPassword == "" {
			return fmt.Errorf("snmp.username, snmp.auth_protocol and snmp.auth_password are required for %q", SecurityAuthPriv)
		}
		if c.SNMP.PrivProtocol == "" || c.SNMP.PrivPassword == "" {
			return fmt.Errorf("snmp.priv_protocol and snmp.priv_password are required for %q", SecurityAuthPriv)
		}
	default:
		return fmt.Errorf("invalid snmp.security_level %q (want %q, %q or %q)",
			c.SNMP.SecurityLevel, SecurityAuthPriv, SecurityAuthNoPriv, SecurityNoAuthNoPriv)
	}
	return nil
}
