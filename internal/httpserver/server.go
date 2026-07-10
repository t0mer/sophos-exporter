// Package httpserver exposes the exporter's HTTP surface: /metrics, /healthz and
// a bare index. It uses chi for routing and log/slog for request logging, and
// shuts down gracefully on SIGINT/SIGTERM.
package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/t0mer/sophos-exporter/internal/version"
)

// Server wraps the chi router and the underlying http.Server.
type Server struct {
	addr   string
	log    *slog.Logger
	http   *http.Server
	router chi.Router
}

// New constructs a Server listening on addr, serving metrics from reg.
func New(addr string, reg *prometheus.Registry, log *slog.Logger) *Server {
	r := chi.NewRouter()
	r.Use(requestLogger(log))

	r.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	r.Get("/healthz", healthz)
	r.Get("/", index)

	return &Server{
		addr:   addr,
		log:    log,
		router: r,
		http: &http.Server{
			Addr:              addr,
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
}

// Run starts serving and blocks until ctx is cancelled, then shuts down
// gracefully with a short timeout.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", s.addr)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
	})
}

func index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<html><head><title>sophos-exporter</title></head>` +
		`<body><h1>sophos-exporter</h1><p>See <a href="/metrics">/metrics</a>.</p></body></html>`))
}

// requestLogger is a minimal slog-based access logger.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			log.Debug("request",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"duration", time.Since(start).String(),
			)
		})
	}
}
