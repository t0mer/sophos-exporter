// Package snmp is a thin, typed wrapper over gosnmp. It builds a client from the
// exporter config (SNMPv2c or SNMPv3, authNoPriv/authPriv), performs GETs for
// scalars and BulkWalks for tables, and exposes typed value extraction and
// enum decoders used by the collectors.
package snmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/t0mer/sophos-exporter/internal/config"
)

// defaultPort is used when snmp.target omits a port.
const defaultPort = 161

// Querier is the subset of client behaviour the collectors depend on. It is an
// interface so collectors can be unit-tested with a fake.
type Querier interface {
	// Get fetches the given scalar OIDs, returning a map keyed by the OID.
	Get(oids []string) (map[string]gosnmp.SnmpPDU, error)
	// Walk BulkWalks the subtree rooted at oid and returns all leaf PDUs.
	Walk(oid string) ([]gosnmp.SnmpPDU, error)
	// Close releases the underlying connection.
	Close() error
}

// Client is a connected SNMP session implementing Querier.
type Client struct {
	g *gosnmp.GoSNMP
}

// build constructs (but does not connect) a gosnmp client from the config.
// It is separated from Connect so the parameter mapping can be unit-tested.
func build(cfg config.SNMPConfig) (*gosnmp.GoSNMP, error) {
	host, port, err := splitTarget(cfg.Target)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Timeout:   timeout,
		Retries:   cfg.Retries,
		Transport: "udp",
		MaxOids:   gosnmp.MaxOids,
	}

	switch cfg.Version {
	case config.VersionV2c:
		g.Version = gosnmp.Version2c
		g.Community = cfg.Community
	case config.VersionV3:
		if err := applyV3(g, cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported snmp version %q", cfg.Version)
	}
	return g, nil
}

func applyV3(g *gosnmp.GoSNMP, cfg config.SNMPConfig) error {
	g.Version = gosnmp.Version3
	g.SecurityModel = gosnmp.UserSecurityModel

	usm := &gosnmp.UsmSecurityParameters{UserName: cfg.Username}

	switch cfg.SecurityLevel {
	case config.SecurityNoAuthNoPriv:
		g.MsgFlags = gosnmp.NoAuthNoPriv
	case config.SecurityAuthNoPriv:
		g.MsgFlags = gosnmp.AuthNoPriv
		ap, err := authProtocol(cfg.AuthProtocol)
		if err != nil {
			return err
		}
		usm.AuthenticationProtocol = ap
		usm.AuthenticationPassphrase = cfg.AuthPassword
	case config.SecurityAuthPriv:
		g.MsgFlags = gosnmp.AuthPriv
		ap, err := authProtocol(cfg.AuthProtocol)
		if err != nil {
			return err
		}
		pp, err := privProtocol(cfg.PrivProtocol)
		if err != nil {
			return err
		}
		usm.AuthenticationProtocol = ap
		usm.AuthenticationPassphrase = cfg.AuthPassword
		usm.PrivacyProtocol = pp
		usm.PrivacyPassphrase = cfg.PrivPassword
	default:
		return fmt.Errorf("unsupported security level %q", cfg.SecurityLevel)
	}

	g.SecurityParameters = usm
	return nil
}

// authProtocol maps a config auth protocol name to gosnmp. SHA family + MD5.
func authProtocol(name string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return gosnmp.NoAuth, fmt.Errorf("unsupported auth protocol %q", name)
	}
}

// privProtocol maps a config priv protocol name to gosnmp. AES family + DES.
func privProtocol(name string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DES":
		return gosnmp.DES, nil
	case "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	default:
		return gosnmp.NoPriv, fmt.Errorf("unsupported priv protocol %q", name)
	}
}

// splitTarget parses "host:port" (port optional, default 161).
func splitTarget(target string) (string, uint16, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("empty snmp target")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// No port present — treat the whole string as the host.
		return target, defaultPort, nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in target %q: %w", target, err)
	}
	return host, uint16(port), nil
}

// Connect builds the client from cfg and opens the UDP socket. ctx bounds the
// overall scrape (gosnmp honours it as a deadline/cancellation across ops).
func Connect(ctx context.Context, cfg config.SNMPConfig) (*Client, error) {
	g, err := build(cfg)
	if err != nil {
		return nil, err
	}
	g.Context = ctx
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect to %s: %w", cfg.Target, err)
	}
	return &Client{g: g}, nil
}

// Get fetches scalar OIDs. gosnmp caps a single request at MaxOids, so requests
// are chunked and merged.
func (c *Client) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := make(map[string]gosnmp.SnmpPDU, len(oids))
	for chunk := range chunkOIDs(oids, c.g.MaxOids) {
		res, err := c.g.Get(chunk)
		if err != nil {
			return nil, fmt.Errorf("snmp get: %w", err)
		}
		for _, pdu := range res.Variables {
			out[strings.TrimPrefix(pdu.Name, ".")] = pdu
		}
	}
	return out, nil
}

// Walk BulkWalks the subtree rooted at oid.
func (c *Client) Walk(oid string) ([]gosnmp.SnmpPDU, error) {
	var pdus []gosnmp.SnmpPDU
	err := c.g.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		pdus = append(pdus, pdu)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snmp walk %s: %w", oid, err)
	}
	return pdus, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	if c.g == nil || c.g.Conn == nil {
		return nil
	}
	return c.g.Conn.Close()
}

// chunkOIDs yields slices of oids no larger than size (>=1).
func chunkOIDs(oids []string, size int) func(func([]string) bool) {
	if size < 1 {
		size = 1
	}
	return func(yield func([]string) bool) {
		for i := 0; i < len(oids); i += size {
			end := i + size
			if end > len(oids) {
				end = len(oids)
			}
			if !yield(oids[i:end]) {
				return
			}
		}
	}
}
