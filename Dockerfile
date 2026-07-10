# Minimal runtime image. goreleaser cross-compiles the static, CGO-free binary
# and drops the correct per-arch build into the context as `sophos-exporter`.
#
# No CA certificates are copied: the exporter makes no outbound TLS calls (SNMP
# is UDP; /metrics and /healthz are plain HTTP). scratch keeps the image tiny.
FROM scratch

COPY sophos-exporter /sophos-exporter

EXPOSE 9835
USER 65534

# scratch has no shell, so the healthcheck runs the binary's own subcommand,
# which does an internal GET to /healthz and exits 0 (healthy) / 1 (unhealthy).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/sophos-exporter", "healthcheck"]

ENTRYPOINT ["/sophos-exporter"]
