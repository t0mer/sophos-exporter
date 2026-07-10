# sophos-exporter

A single, static, headless [Prometheus](https://prometheus.io/) exporter that
scrapes a **Sophos Firewall (SFOS)** over **SNMP** and exposes metrics on
`/metrics`, ready to feed a Grafana dashboard.

- **Stateless** — no database, no persistence. Every scrape is a live SNMP read
  (scrape-on-request).
- **SNMPv2c and SNMPv3** are both first-class (v3 `authPriv`/`authNoPriv`).
- **Single static binary** (`CGO_ENABLED=0`), multi-arch Docker image
  (`linux/amd64`, `linux/arm64`) on a `scratch` base (~10 MB).
- Ships a starter **Grafana dashboard** (`dashboards/sophos-firewall.json`).

Tested against **SFVH — Sophos Firewall Virtual Home**, `SFOS 22.0.1 MR-1`.

---

## Contents

- [Metrics](#metrics)
- [Setup on the firewall](#setup-on-the-firewall)
- [Configuration](#configuration)
- [CLI](#cli)
- [Environment variables](#environment-variables)
- [Running](#running)
- [Prometheus & Grafana](#prometheus--grafana)
- [Notes for virtual appliances (SFVH)](#notes-for-virtual-appliances-sfvh)
- [Building from source](#building-from-source)
- [License](#license)

---

## Metrics

All metrics use the `sophos_` prefix; base units are bytes and seconds. Counters
end in `_total`; percentages end in `_percent`.

### Exporter-internal (always emitted)

| Metric | Description |
|---|---|
| `sophos_up` | `1` if the whole scrape succeeded, else `0`. |
| `sophos_scrape_duration_seconds` | Duration of the SNMP scrape. |
| `sophos_scrape_collector_success{collector}` | `1`/`0` per sub-collector. |
| `sophos_exporter_build_info{version,commit,date,goversion}` | Always `1`. |

### Device (`collectors.device`)

| Metric | Description |
|---|---|
| `sophos_device_info{name,model,firmware,appkey,webcat_version,ips_version}` | Static device info, value `1`. |
| `sophos_cpu_usage_percent{core}` | Per-core CPU (plus `core="avg"`), from HOST-RESOURCES-MIB. |
| `sophos_memory_usage_percent` / `sophos_memory_capacity_bytes` | Memory. |
| `sophos_disk_usage_percent` / `sophos_disk_capacity_bytes` | Disk. |
| `sophos_swap_usage_percent` / `sophos_swap_capacity_bytes` | Swap. |
| `sophos_live_users` | Live users count. |
| `sophos_uptime_seconds` | Device uptime. |

### Traffic hits (`collectors.hits`)

`sophos_http_hits_total`, `sophos_ftp_hits_total`, `sophos_pop3_hits_total`,
`sophos_imap_hits_total`, `sophos_smtp_hits_total`.

### Services & HA (`collectors.services`)

| Metric | Description |
|---|---|
| `sophos_service_status{service}` | Enum: `untouched(0) stopped(1) initializing(2) running(3) exiting(4) dead(5) frozen(6) unregistered(7)`. |
| `sophos_service_running{service}` | `1` iff the service is `running(3)`. |
| `sophos_ha_enabled` | `1` if HA is enabled. |
| `sophos_ha_state` | Enum: `notApplicable(0) auxiliary(1) standAlone(2) primary(3) faulty(4) ready(5)`. |

### License (`collectors.license`)

| Metric | Description |
|---|---|
| `sophos_license_status{module}` | Enum: `none(0) evaluating(1) notsubscribed(2) subscribed(3) expired(4) deactivated(5)`. |
| `sophos_license_expiry_timestamp_seconds{module}` | Unix expiry (omitted when the date does not parse). |

### Interfaces (`collectors.interfaces`)

`sophos_interface_receive_bytes_total{interface}`,
`sophos_interface_transmit_bytes_total{interface}`,
`sophos_interface_receive_packets_total{interface}`,
`sophos_interface_transmit_packets_total{interface}`,
`sophos_interface_receive_errors_total{interface}`,
`sophos_interface_transmit_errors_total{interface}`,
`sophos_interface_up{interface}`.

### IPsec VPN (`collectors.vpn`, off by default)

`sophos_ipsec_tunnel_active{name,mode,type}`, `sophos_ipsec_tunnel_status{name}`.

---

## Setup on the firewall

1. **Administration → SNMP**: enable the SNMP agent and configure **either**
   a v2c community **or** an SNMPv3 user (`authPriv`, SHA + AES) matching your
   exporter config.
2. **Administration → Device Access**: allow **SNMP** from the exporter's zone
   (e.g. LAN). Ordinary firewall rules do **not** cover traffic *to* the
   appliance — this is the Local ACL / Device Access control. If scrapes time
   out, check this first, then packet-capture the ingress interface.
3. SNMP is UDP/161 by default; confirm reachability from the exporter host.

> The reference MIB is committed at `mibs/SOPHOS-XG-MIB.mib`. If you upgrade
> SFOS, re-download and diff it.

---

## Configuration

Resolution precedence is **flags > environment (`SOPHOS_EXPORTER_`) > YAML**.
The config file is searched for as `./config.yml` then
`/etc/sophos-exporter/config.yml`, or set explicitly with `--config`.

```yaml
listen: ":9835"          # HTTP listen address for /metrics and /healthz
log_level: "info"        # debug | info | warn | error

snmp:
  target: "192.168.1.1:161"
  version: "3"           # "2c" | "3" — both fully supported
  timeout: "5s"
  retries: 1

  # --- SNMPv2c ---
  community: ""          # required for v2c; cleartext — keep on a mgmt zone

  # --- SNMPv3 ---
  security_level: "authPriv"   # authPriv | authNoPriv | noAuthNoPriv (discouraged)
  username: ""
  auth_protocol: "SHA"         # MD5, SHA, SHA224, SHA256, SHA384, SHA512
  auth_password: ""
  priv_protocol: "AES"         # DES, AES, AES192, AES256 (used only at authPriv)
  priv_password: ""

collectors:
  device: true
  interfaces: true
  services: true
  license: true
  hits: true
  vpn: false             # IPsec tunnel table; enable only if IPsec is configured
```

A full example lives in [`config.example.yml`](config.example.yml). A populated
`config.yml` is gitignored — **never commit secrets**.

### Validation (fails fast on startup)

- `version: "2c"` → `community` required.
- `version: "3"` + `authNoPriv` → `username`, `auth_protocol`, `auth_password`.
- `version: "3"` + `authPriv` → the above **plus** `priv_protocol`, `priv_password`.
- Unknown `version` / `security_level`, or a missing `target`, refuse to start.

---

## CLI

```
sophos-exporter [flags]         # run the exporter (default)
sophos-exporter version         # print version and build metadata
sophos-exporter healthcheck     # GET the local /healthz; exit 0 healthy / 1 not
```

| Flag | Default | Purpose |
|---|---|---|
| `--config` | (search path) | Path to config file. |
| `--listen` | `:9835` | HTTP listen address. |
| `--log-level` | `info` | `debug` / `info` / `warn` / `error`. |
| `--version` / `--help` | | Version / usage. |

`healthcheck` backs the container HEALTHCHECK on the shell-less `scratch` image;
it resolves only the listen address, so it works even without SNMP configured.

---

## Environment variables

Any config key maps to `SOPHOS_EXPORTER_` + the uppercased, `_`-joined path:

| Variable | Config key |
|---|---|
| `SOPHOS_EXPORTER_LISTEN` | `listen` |
| `SOPHOS_EXPORTER_LOG_LEVEL` | `log_level` |
| `SOPHOS_EXPORTER_SNMP_TARGET` | `snmp.target` |
| `SOPHOS_EXPORTER_SNMP_VERSION` | `snmp.version` |
| `SOPHOS_EXPORTER_SNMP_COMMUNITY` | `snmp.community` |
| `SOPHOS_EXPORTER_SNMP_USERNAME` | `snmp.username` |
| `SOPHOS_EXPORTER_SNMP_AUTH_PASSWORD` | `snmp.auth_password` |
| `SOPHOS_EXPORTER_SNMP_PRIV_PASSWORD` | `snmp.priv_password` |
| `SOPHOS_EXPORTER_COLLECTORS_VPN` | `collectors.vpn` |

Secrets are never logged. Prefer environment variables (or a secrets manager)
for `community`, `auth_password` and `priv_password`.

---

## Running

### Binary

```sh
./sophos-exporter --config /etc/sophos-exporter/config.yml
curl -s localhost:9835/metrics | grep '^sophos_'
```

### Docker (v2c example)

```sh
docker run -d --name sophos-exporter -p 9835:9835 \
  -e SOPHOS_EXPORTER_SNMP_TARGET=192.168.1.1:161 \
  -e SOPHOS_EXPORTER_SNMP_VERSION=2c \
  -e SOPHOS_EXPORTER_SNMP_COMMUNITY=public \
  techblog/sophos-exporter:latest
```

Images are published to Docker Hub (`techblog/sophos-exporter`) and GHCR
(`ghcr.io/t0mer/sophos-exporter`), tagged `:latest` and `:<YYYY.M.PATCH>`.

### docker-compose

See [`deploy/docker-compose.yml`](deploy/docker-compose.yml) (SNMPv3 example;
put secrets in a `.env` file next to it).

---

## Prometheus & Grafana

Add a scrape job (see [`deploy/prometheus-scrape.yml`](deploy/prometheus-scrape.yml)):

```yaml
scrape_configs:
  - job_name: sophos-exporter
    scrape_interval: 60s
    scrape_timeout: 30s
    static_configs:
      - targets: ["sophos-exporter:9835"]
```

> Keep `scrape_timeout` comfortably above `snmp.timeout × (retries + 1)` so a slow
> firewall reply doesn't abort the scrape.

Then import `dashboards/sophos-firewall.json` in Grafana (Dashboards → New →
Import) and pick your Prometheus data source.

---

## Notes for virtual appliances (SFVH)

- **CPU** is read from `HOST-RESOURCES-MIB::hrProcessorLoad`; the Sophos MIB has
  no CPU object. If the table is absent on your VM, the CPU series simply isn't
  emitted (the panel stays empty) rather than showing fabricated data.
- **Capacity units**: SFOS reports memory/disk/swap capacity in MB; the exporter
  converts to bytes. Verify against a live `snmpget` for your build.
- Hardware/radio subtrees (`sfosXGSystemHealth`, `sfosXGWiFiInfo`) and SNMP traps
  are intentionally **not** collected — they don't apply to a virtual appliance.
- Some scalars (VPN, mail proxy, certain licenses) only populate when the feature
  is licensed/configured; absent scalars produce no series.

---

## Building from source

Requires Go (see `go.mod` for the version).

```sh
go build ./cmd/sophos-exporter        # build
go test ./... -race                   # test
```

Releases are cut with [goreleaser](https://goreleaser.com/) on a `v<version>`
tag (date-based `YYYY.M.PATCH`, e.g. `v2026.7.0`).

---

## License

[Apache-2.0](LICENSE).
