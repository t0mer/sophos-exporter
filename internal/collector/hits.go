package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t0mer/sophos-exporter/internal/snmp"
)

// hitsCollector emits the per-protocol hit counters (http/ftp/pop3/imap/smtp).
type hitsCollector struct {
	http *prometheus.Desc
	ftp  *prometheus.Desc
	pop3 *prometheus.Desc
	imap *prometheus.Desc
	smtp *prometheus.Desc
}

func newHitsCollector() *hitsCollector {
	c := func(name, proto string) *prometheus.Desc {
		return prometheus.NewDesc(Namespace+"_"+name,
			fmt.Sprintf("Total %s hits processed by the firewall.", proto), nil, nil)
	}
	return &hitsCollector{
		http: c("http_hits_total", "HTTP"),
		ftp:  c("ftp_hits_total", "FTP"),
		pop3: c("pop3_hits_total", "POP3"),
		imap: c("imap_hits_total", "IMAP"),
		smtp: c("smtp_hits_total", "SMTP"),
	}
}

func (h *hitsCollector) Name() string { return "hits" }

func (h *hitsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- h.http
	ch <- h.ftp
	ch <- h.pop3
	ch <- h.imap
	ch <- h.smtp
}

func (h *hitsCollector) Update(q snmp.Querier, ch chan<- prometheus.Metric) error {
	res, err := q.Get([]string{oidHTTPHits, oidFTPHits, oidPOP3Hits, oidImapHits, oidSmtpHits})
	if err != nil {
		return fmt.Errorf("hit counters: %w", err)
	}
	emitCounter(ch, h.http, res, oidHTTPHits)
	emitCounter(ch, h.ftp, res, oidFTPHits)
	emitCounter(ch, h.pop3, res, oidPOP3Hits)
	emitCounter(ch, h.imap, res, oidImapHits)
	emitCounter(ch, h.smtp, res, oidSmtpHits)
	return nil
}
