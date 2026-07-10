// Command sophos-exporter scrapes a Sophos Firewall (SFOS) over SNMP and exposes
// Prometheus metrics on /metrics.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/t0mer/sophos-exporter/internal/collector"
	"github.com/t0mer/sophos-exporter/internal/config"
	"github.com/t0mer/sophos-exporter/internal/httpserver"
	"github.com/t0mer/sophos-exporter/internal/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var cfgFile string

	root := &cobra.Command{
		Use:           "sophos-exporter",
		Short:         "Prometheus exporter for Sophos Firewall (SFOS) over SNMP",
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cfgFile, cmd)
		},
	}

	flags := root.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "", "path to config file (default: ./config.yml then /etc/sophos-exporter/config.yml)")
	flags.String("listen", ":9835", "address to listen on")
	flags.String("log-level", "info", "log level: debug|info|warn|error")

	root.AddCommand(versionCmd())
	root.AddCommand(healthcheckCmd(&cfgFile))
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build metadata",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "sophos-exporter %s (commit %s, built %s)\n",
				version.Version, version.Commit, version.Date)
		},
	}
}

// healthcheckCmd performs an internal GET to /healthz and exits 0/1. It backs
// the container HEALTHCHECK on the shell-less scratch image.
func healthcheckCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe the local /healthz endpoint (exit 0 = healthy)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			listen, err := config.ListenAddress(*cfgFile, cmd.Root().PersistentFlags())
			if err != nil {
				return err
			}
			url := "http://" + hostPort(listen) + "/healthz"
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("healthcheck: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

func run(cfgFile string, cmd *cobra.Command) error {
	cfg, err := config.Load(cfgFile, cmd.Root().PersistentFlags())
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	log.Info("starting sophos-exporter",
		"version", version.Version,
		"target", cfg.SNMP.Target,
		"snmp_version", cfg.SNMP.Version,
	)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector.NewBuildInfo())
	reg.MustRegister(collector.New(*cfg, log))

	srv := httpserver.New(cfg.Listen, reg, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// hostPort turns a listen address like ":9835" or "0.0.0.0:9835" into a dialable
// host:port aimed at the local loopback.
func hostPort(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1" + listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "[::]") {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
