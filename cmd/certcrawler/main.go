package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
	"golang.org/x/net/publicsuffix"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var userAgent = fmt.Sprintf("Certstream v%s (github.com/d-Rickyy-b/certstream-server-go)", config.Version)

// CertificateRow holds the fields to insert into ClickHouse
// (matches the Rust struct)
type CertificateRow struct {
	CertIndex                    int64
	CertLink                     string
	Domain                       string
	Hostnames                    string // JSON array
	TLD                          string
	RootDomain                   string
	Fingerprint                  string
	NotAfter                     int64
	NotBefore                    int64
	SerialNumber                 string
	C                            string
	CN                           string
	L                            string
	O                            string
	OU                           string
	ST                           string
	Aggregated                   string
	EmailAddress                 string
	AuthorityInfoAccess          string
	AuthorityKeyIdentifier       string
	BasicConstraints             string
	CertificatePolicies          string
	CtlSignedCertificateTimestamp string
	ExtendedKeyUsage             string
	KeyUsage                     string
	SubjectAltName               string
	SubjectKeyIdentifier         string
	SignatureAlgorithm           string
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Helper: parse subject aggregated string to map
func parseSubjectAggregated(agg string) map[string]string {
	m := make(map[string]string)
	parts := strings.Split(agg, "/")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

// Helper: check if string is IP address
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// Helper: reformat cert fields for ClickHouse row (matches Rust logic)
func reformatCertFields(data *models.Data) CertificateRow {
	aggMap := map[string]string{}
	if data.LeafCert.Subject.Aggregated != nil && *data.LeafCert.Subject.Aggregated != "" {
		aggMap = parseSubjectAggregated(*data.LeafCert.Subject.Aggregated)
	}
	getField := func(key string, orig *string) string {
		if orig != nil && *orig != "" {
			return *orig
		}
		if v, ok := aggMap[key]; ok {
			return v
		}
		return ""
	}
	cn := getField("CN", data.LeafCert.Subject.CN)
	subjectAltName := strOr(data.LeafCert.Extensions.SubjectAltName)
	// Find domain
	allDomains := data.LeafCert.AllDomains
	domain := ""
	if len(allDomains) > 0 {
		domain = allDomains[0]
	} else if cn != "" {
		domain = cn
	}
	domain = strings.TrimPrefix(domain, "*.")
	// Hostnames set
	hostnamesSet := make(map[string]struct{})
	// Extract from subjectAltName
	for _, entry := range strings.Split(subjectAltName, ",") {
		entry = strings.TrimSpace(entry)
		if strings.HasPrefix(entry, "DNS:") {
			host := strings.TrimPrefix(entry, "DNS:")
			hostnamesSet[host] = struct{}{}
		} else if strings.HasPrefix(entry, "IP Address:") {
			ip := strings.TrimPrefix(entry, "IP Address:")
			hostnamesSet[ip] = struct{}{}
		}
	}
	// Add all domains
	for _, d := range allDomains {
		hostnamesSet[d] = struct{}{}
	}
	// Add CN if not already in set
	if cn != "" {
		hostnamesSet[cn] = struct{}{}
	}
	// To sorted array
	hostnames := make([]string, 0, len(hostnamesSet))
	for h := range hostnamesSet {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)
	hostnamesJSON, _ := json.Marshal(hostnames)
	// Only set tld/rootDomain when domain is a real hostname (not IP/empty)
	tld, rootDomain := "", ""
	if domain != "" && !isIP(domain) {
		if tldVal, _ := publicsuffix.PublicSuffix(domain); tldVal != "" {
			tld = tldVal
		}
		if rootVal, rootErr := publicsuffix.EffectiveTLDPlusOne(domain); rootErr == nil {
			rootDomain = rootVal
		}
	}
	return CertificateRow{
		CertIndex:    int64(data.CertIndex),
		CertLink:     data.CertLink,
		Fingerprint:  data.LeafCert.Fingerprint,
		NotAfter:     data.LeafCert.NotAfter,
		NotBefore:    data.LeafCert.NotBefore,
		SerialNumber: data.LeafCert.SerialNumber,
		C:            getField("C", data.LeafCert.Subject.C),
		CN:           getField("CN", data.LeafCert.Subject.CN),
		L:            getField("L", data.LeafCert.Subject.L),
		O:            getField("O", data.LeafCert.Subject.O),
		OU:           getField("OU", data.LeafCert.Subject.OU),
		ST:           getField("ST", data.LeafCert.Subject.ST),
		Aggregated:   strOr(data.LeafCert.Subject.Aggregated),
		EmailAddress: getField("emailAddress", data.LeafCert.Subject.EmailAddress),
		Domain:       domain,
		Hostnames:    string(hostnamesJSON),
		TLD:          tld,
		RootDomain:   rootDomain,
		AuthorityInfoAccess:          strOr(data.LeafCert.Extensions.AuthorityInfoAccess),
		AuthorityKeyIdentifier:       strOr(data.LeafCert.Extensions.AuthorityKeyIdentifier),
		BasicConstraints:             strOr(data.LeafCert.Extensions.BasicConstraints),
		CertificatePolicies:          strOr(data.LeafCert.Extensions.CertificatePolicies),
		CtlSignedCertificateTimestamp: strOr(data.LeafCert.Extensions.CtlSignedCertificateTimestamp),
		ExtendedKeyUsage:             strOr(data.LeafCert.Extensions.ExtendedKeyUsage),
		KeyUsage:                     strOr(data.LeafCert.Extensions.KeyUsage),
		SubjectAltName:               strOr(data.LeafCert.Extensions.SubjectAltName),
		SubjectKeyIdentifier:         strOr(data.LeafCert.Extensions.SubjectKeyIdentifier),
		SignatureAlgorithm:           data.LeafCert.SignatureAlgorithm,
	}
}

// ---- interval set for resume tracking ----

type interval struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// intervalSet holds sorted, disjoint, non-adjacent inclusive intervals.
// Owned by the aggregator goroutine - no locking needed.
type intervalSet struct {
	set []interval
}

func (s *intervalSet) add(iv interval) {
	newIv := iv
	// fresh backing array: appending into s.set[:0] would overwrite elements
	// still pending iteration once the output position overtakes the reader
	out := make([]interval, 0, len(s.set)+1)
	inserted := false
	for _, cur := range s.set {
		switch {
		case cur.End < newIv.Start-1:
			out = append(out, cur)
		case newIv.End < cur.Start-1:
			if !inserted {
				out = append(out, newIv)
				inserted = true
			}
			out = append(out, cur)
		default:
			if cur.Start < newIv.Start {
				newIv.Start = cur.Start
			}
			if cur.End > newIv.End {
				newIv.End = cur.End
			}
		}
	}
	if !inserted {
		out = append(out, newIv)
	}
	s.set = out
}

func (s *intervalSet) covered() int64 {
	var n int64
	for _, iv := range s.set {
		n += iv.End - iv.Start + 1
	}
	return n
}

// gaps returns the sub-intervals of [lo,hi] not covered by the set.
func (s *intervalSet) gaps(lo, hi int64) []interval {
	var gaps []interval
	cur := lo
	for _, iv := range s.set {
		if iv.End < cur {
			continue
		}
		if iv.Start > hi {
			break
		}
		if iv.Start > cur {
			gaps = append(gaps, interval{cur, iv.Start - 1})
		}
		if iv.End >= cur {
			cur = iv.End + 1
		}
		if cur > hi {
			return gaps
		}
	}
	if cur <= hi {
		gaps = append(gaps, interval{cur, hi})
	}
	return gaps
}

// splitGroups splits intervals into job-sized chunks.
func splitGroups(ivs []interval, groupSize int64) []interval {
	var out []interval
	for _, iv := range ivs {
		for s := iv.Start; s <= iv.End; s += groupSize {
			e := s + groupSize - 1
			if e > iv.End {
				e = iv.End
			}
			out = append(out, interval{s, e})
		}
	}
	return out
}

// ---- persistent state ----

type crawlState struct {
	Log       string     `json:"log"`
	Start     int64      `json:"start"`
	End       int64      `json:"end"`
	EntryType string     `json:"entry_type"`
	Done      []interval `json:"done"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func writeState(path string, st *crawlState) error {
	tmp := path + ".tmp"
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadState(path string) (*crawlState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st crawlState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ---- rate limiter ----

type rateLimiter struct {
	tokens chan struct{}
}

func newRateLimiter(qps float64) *rateLimiter {
	if qps <= 0 {
		return nil
	}
	burst := int(qps)
	if burst < 1 {
		burst = 1
	}
	r := &rateLimiter{tokens: make(chan struct{}, burst)}
	intervalDur := time.Duration(float64(time.Second) / qps)
	go func() {
		tk := time.NewTicker(intervalDur)
		defer tk.Stop()
		for range tk.C {
			select {
			case r.tokens <- struct{}{}:
			default:
			}
		}
	}()
	return r
}

func (r *rateLimiter) take(ctx context.Context) error {
	if r == nil {
		return nil
	}
	select {
	case <-r.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---- crawler ----

type stats struct {
	fetched         atomic.Int64
	shortReads      atomic.Int64
	parsed          atomic.Int64
	typeSkip        atomic.Int64
	parseErrors     atomic.Int64
	inserted        atomic.Int64
	retries         atomic.Int64
	failed          atomic.Int64
	verifyMismatch  atomic.Int64
	verifyDiffShown atomic.Int64
}

type groupResult struct {
	done     []interval // sub-ranges completed (group minus shortfall)
	failed   []interval // sub-ranges that exhausted retries
	lines    []string
	inserted int
	aborted  bool
}

var (
	flagLog          = flag.String("log", "", "URL of the CT log - e.g. ct.googleapis.com/logs/eu1/xenon2025h2")
	flagStart        = flag.Int64("start", 0, "Start index of the CT log range (inclusive)")
	flagEnd          = flag.Int64("end", 0, "End index (inclusive), or -1 to resolve to current tree head")
	flagFetchBatch   = flag.Int64("batch-size", 256, "Entries per get-entries request (log may cap this)")
	flagGroupSize    = flag.Int64("group-size", 4096, "Entries per ClickHouse insert / resume unit")
	flagAsDER        = flag.Bool("asder", false, "Include DER encoding of the certificate")
	flagConcurrency  = flag.Int("concurrency", 4, "Concurrent fetch+insert workers")
	flagEntryType    = flag.String("entry-type", "all", "Which leaf entries to keep: all|precert|x509")
	flagTiled        = flag.Bool("tiled", false, "Log is a static-CT (tiled) log - fetch binary tiles instead of get-entries")
	flagQPS          = flag.Float64("qps", 0, "Max get-entries requests per second (0 = unlimited)")
	flagMaxRetries   = flag.Int("max-retries", 8, "Retries per fetch/insert before giving up")
	flagMaxPasses    = flag.Int("max-passes", 3, "Extra passes over failed ranges")
	flagStateFile    = flag.String("state-file", "", "Resume state file (enables resume/checkpointing)")
	flagFresh        = flag.Bool("fresh", false, "Ignore an existing state file")
	flagSrc6         = flag.String("src6", "", "Rotate source IPv6 within this prefix (e.g. 2a01:d0:ffff:342e::/64) - requires AAAA on the log host")
	flagTmpIP        = flag.Bool("tmpip", false, "Rotate source IPv6 across all Devices in /etc/tmpiprest.conf")
	flagTmpIPConf    = flag.String("tmpip-conf", "/etc/tmpiprest.conf", "tmpiprest config path (used with -tmpip)")
	flagSrc6PerReq   = flag.Bool("src6-per-request", false, "New source IP per request instead of per connection (slower: TLS per request)")
	flagVerify       = flag.Bool("verify", false, "Differential-test fastRow against the full parser per entry; log mismatches")
	flagProgress     = flag.Duration("progress-every", 30*time.Second, "Progress log interval")
	flagCHDSN        = flag.String("clickhouse-dsn", "", "ClickHouse host:port, e.g. '127.0.0.1:9000'")
	flagCHDB         = flag.String("clickhouse-database", "certstream", "ClickHouse database")
	flagCHTable      = flag.String("clickhouse-table", "certs", "ClickHouse table name")
	flagCHUser       = flag.String("clickhouse-user", "default", "ClickHouse user")
	flagCHPass       = flag.String("clickhouse-password", "", "ClickHouse password")
	flagQuiet        = flag.Bool("quiet", false, "Do not write JSON entries to stdout")
)

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func fetchWithRetry(ctx context.Context, jsonClient *client.LogClient, limiter *rateLimiter, st *stats, start, end int64) (*ct.GetEntriesResponse, error) {
	delay := 500 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt <= *flagMaxRetries; attempt++ {
		if err := limiter.take(ctx); err != nil {
			return nil, err
		}
		fctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		resp, err := jsonClient.GetRawEntries(fctx, start, end)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		st.retries.Add(1)
		var rspErr jsonclient.RspError
		is429 := errors.As(err, &rspErr) && rspErr.StatusCode == http.StatusTooManyRequests
		sleep := delay + time.Duration(rand.Int63n(int64(delay)))
		if is429 && sleep < 5*time.Second {
			sleep = 5 * time.Second
		}
		log.Printf("fetch %d-%d failed (attempt %d/%d): %v - retrying in %v", start, end, attempt+1, *flagMaxRetries+1, err, sleep)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
		delay *= 2
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
	}
	return nil, lastErr
}

func insertWithRetry(ctx context.Context, chConn clickhouse.Conn, db, table string, rows []CertificateRow, st *stats, group interval) error {
	delay := 500 * time.Millisecond
	var lastErr error
	// deterministic dedup token: identical retried blocks are deduped server-side
	dedupCtx := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		"insert_deduplicate":         true,
		"insert_deduplication_token": fmt.Sprintf("certcrawler-%s-%d-%d-%s", db, group.Start, group.End, *flagEntryType),
	}))
	for attempt := 0; attempt <= *flagMaxRetries; attempt++ {
		batch, err := chConn.PrepareBatch(dedupCtx, fmt.Sprintf(`INSERT INTO %s.%s (
			cert_index, cert_link, domain, hostnames, tld, root_domain, fingerprint, not_after, not_before, serial_number, c, cn, l, o, ou, st, aggregated, email_address, authority_info_access, authority_key_identifier, basic_constraints, certificate_policies, ctl_signed_certificate_timestamp, extended_key_usage, key_usage, subject_alt_name, subject_key_identifier, signature_algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, db, table))
		if err != nil {
			lastErr = err
		} else {
			appendFailed := false
			for i := range rows {
				r := &rows[i]
				if appendErr := batch.Append(
					r.CertIndex, r.CertLink, r.Domain, r.Hostnames, r.TLD, r.RootDomain,
					r.Fingerprint, r.NotAfter, r.NotBefore, r.SerialNumber,
					r.C, r.CN, r.L, r.O, r.OU, r.ST, r.Aggregated, r.EmailAddress,
					r.AuthorityInfoAccess, r.AuthorityKeyIdentifier, r.BasicConstraints,
					r.CertificatePolicies, r.CtlSignedCertificateTimestamp, r.ExtendedKeyUsage,
					r.KeyUsage, r.SubjectAltName, r.SubjectKeyIdentifier, r.SignatureAlgorithm,
				); appendErr != nil {
					lastErr = appendErr
					appendFailed = true
					break
				}
			}
			if !appendFailed {
				if sendErr := batch.Send(); sendErr == nil {
					return nil
				} else {
					lastErr = sendErr
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st.retries.Add(1)
		sleep := delay + time.Duration(rand.Int63n(int64(delay)))
		log.Printf("clickhouse insert failed (attempt %d/%d): %v - retrying in %v", attempt+1, *flagMaxRetries+1, lastErr, sleep)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
	return lastErr
}

// tilePath encodes a tile index into the static-CT path format (xNNN/NNN groups).
func tilePath(index uint64) string {
	if index == 0 {
		return "000"
	}
	var groups []uint64
	for n := index; n > 0; n /= 1000 {
		groups = append(groups, n%1000)
	}
	var b strings.Builder
	for i := len(groups) - 1; i >= 0; i-- {
		if i < len(groups)-1 {
			b.WriteByte('/')
		}
		if i > 0 {
			b.WriteByte('x')
		}
		fmt.Fprintf(&b, "%03d", groups[i])
	}
	return b.String()
}

func fetchTileWithRetry(ctx context.Context, hc *http.Client, baseURL string, limiter *rateLimiter, st *stats, tileIndex uint64) ([]certificatetransparency.TileLeaf, error) {
	url := fmt.Sprintf("%s/tile/data/%s", strings.TrimRight(baseURL, "/"), tilePath(tileIndex))
	delay := 500 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt <= *flagMaxRetries; attempt++ {
		if err := limiter.take(ctx); err != nil {
			return nil, err
		}
		fctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		req, reqErr := http.NewRequestWithContext(fctx, http.MethodGet, url, nil)
		var leaves []certificatetransparency.TileLeaf
		if reqErr == nil {
			req.Header.Set("User-Agent", userAgent)
			var resp *http.Response
			resp, lastErr = hc.Do(req)
			if lastErr == nil {
				if resp.StatusCode == http.StatusOK {
					var data []byte
					data, lastErr = io.ReadAll(resp.Body)
					resp.Body.Close()
					if lastErr == nil {
						leaves, lastErr = certificatetransparency.ParseTileData(data)
					}
				} else {
					resp.Body.Close()
					lastErr = fmt.Errorf("got HTTP Status %q", resp.Status)
				}
			}
		} else {
			lastErr = reqErr
		}
		cancel()
		if lastErr == nil {
			return leaves, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		st.retries.Add(1)
		sleep := delay + time.Duration(rand.Int63n(int64(delay)))
		if strings.Contains(lastErr.Error(), "429") && sleep < 5*time.Second {
			sleep = 5 * time.Second
		}
		log.Printf("tile %d fetch failed (attempt %d/%d): %v - retrying in %v", tileIndex, attempt+1, *flagMaxRetries+1, lastErr, sleep)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
		delay *= 2
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
	}
	return nil, lastErr
}

func processGroup(ctx context.Context, g interval, jsonClient *client.LogClient, hc *http.Client, limiter *rateLimiter, chConn clickhouse.Conn, st *stats) groupResult {
	res := groupResult{}
	var rows []CertificateRow
	var lines []string

	logType := models.SourceIsRFC6962
	if *flagTiled {
		logType = models.SourceIsTiled
	}

	emit := func(idx int64, rawLogEntry *ct.RawLogEntry, leafType ct.LogEntryType, hasType bool) {
		if rawLogEntry == nil {
			st.parseErrors.Add(1)
			return
		}
		// cheap leaf-type check before x509 parsing
		if hasType {
			if (*flagEntryType == "precert" && leafType != ct.PrecertLogEntryType) ||
				(*flagEntryType == "x509" && leafType != ct.X509LogEntryType) {
				st.typeSkip.Add(1)
				return
			}
		}
		isPrecert := hasType && leafType == ct.PrecertLogEntryType
		if *flagVerify {
			verifyEntry(rawLogEntry, isPrecert, idx, st, *flagLog, logType, *flagTiled)
			return
		}
		if chConn == nil && *flagQuiet {
			return // no output sink configured - nothing to emit
		}
		// fast path for ClickHouse rows: DER-walk the leaf only, no full
		// x509.ParseCertificate, no chain handling.
		if chConn != nil {
			row, ferr := fastRow(rawLogEntry, isPrecert, idx, *flagLog, *flagTiled)
			if ferr != nil {
				st.parseErrors.Add(1)
				return
			}
			rows = append(rows, *row)
		}
		// full slim parse only needed for stdout JSON output
		if !*flagQuiet {
			entry, parseErr := certificatetransparency.ParseCertstreamEntrySlim(rawLogEntry, "certcrawler", "certcrawler", *flagLog, logType)
			if parseErr != nil {
				st.parseErrors.Add(1)
				return
			}
			// parser hardcodes X509LogEntry - the caller (watcher/crawler) sets the real type
			if isPrecert {
				entry.Data.UpdateType = "PrecertLogEntry"
			}
			if !*flagAsDER {
				entry.Data.LeafCert.AsDER = ""
				for i := range entry.Data.Chain {
					entry.Data.Chain[i].AsDER = ""
				}
			}
			if line, marshalErr := json.Marshal(entry); marshalErr == nil {
				lines = append(lines, string(line))
			}
		}
		st.parsed.Add(1)
	}

	if *flagTiled {
		// tile path: 256 entries per tile
		for tileIdx := uint64(g.Start) / 256; uint64(tileIdx)*256 <= uint64(g.End); tileIdx++ {
			leaves, err := fetchTileWithRetry(ctx, hc, *flagLog, limiter, st, tileIdx)
			if err != nil {
				if ctx.Err() != nil {
					res.aborted = true
					return res
				}
				// remaining tiles of this group failed
				from := int64(tileIdx) * 256
				if from < g.Start {
					from = g.Start
				}
				res.failed = append(res.failed, interval{from, g.End})
				break
			}
			base := int64(tileIdx) * 256
			st.fetched.Add(int64(len(leaves)))
			for i := range leaves {
				idx := base + int64(i)
				if idx < g.Start || idx > g.End {
					continue
				}
				lt := ct.X509LogEntryType
				if leaves[i].EntryType == 1 {
					lt = ct.PrecertLogEntryType
				}
				emit(idx, certificatetransparency.ConvertTileLeafToRawLogEntry(leaves[i], uint64(idx)), lt, true)
			}
			// partial tile inside a bounded range: remainder is a gap to retry later
			if base+int64(len(leaves))-1 < g.End && int64(len(leaves)) < 256 {
				res.failed = append(res.failed, interval{base + int64(len(leaves)), min64(base+255, g.End)})
			}
		}
	} else {
		fetchBatch := *flagFetchBatch
		for off := g.Start; off <= g.End; {
			bEnd := min64(off+fetchBatch-1, g.End)
			resp, err := fetchWithRetry(ctx, jsonClient, limiter, st, off, bEnd)
			if err != nil {
				if ctx.Err() != nil {
					res.aborted = true
					return res
				}
				// whole remaining sub-range failed
				res.failed = append(res.failed, interval{off, g.End})
				break
			}
			n := len(resp.Entries)
			if n == 0 {
				// log returned nothing within the tree - cannot progress here
				res.failed = append(res.failed, interval{off, g.End})
				break
			}
			st.fetched.Add(int64(n))
			for i := 0; i < n; i++ {
				idx := off + int64(i)
				rawLogEntry, rerr := ct.RawLogEntryFromLeaf(idx, &resp.Entries[i])
				if rerr != nil || rawLogEntry == nil {
					st.parseErrors.Add(1)
					continue
				}
				lt := ct.X509LogEntryType
				hasType := rawLogEntry.Leaf.TimestampedEntry != nil
				if hasType {
					lt = rawLogEntry.Leaf.TimestampedEntry.EntryType
				}
				emit(idx, rawLogEntry, lt, hasType)
			}
			if n < int(bEnd-off+1) {
				st.shortReads.Add(1)
			}
			// advance by what was actually returned - short reads are fetched
			// immediately rather than deferred to a later pass
			off += int64(n)
		}
	}

	// single insert per group - atomic, so the group is all-or-nothing
	if len(rows) > 0 && chConn != nil {
		if err := insertWithRetry(ctx, chConn, *flagCHDB, *flagCHTable, rows, st, g); err != nil {
			if ctx.Err() != nil {
				res.aborted = true
				return res
			}
			// insert failed: nothing was committed, whole group must be redone
			res.failed = []interval{g}
			res.done = nil
			res.lines = nil
			res.inserted = 0
			return res
		}
		res.inserted = len(rows)
		st.inserted.Add(int64(len(rows)))
	}
	res.lines = lines
	// done = group minus failed sub-ranges
	var fs intervalSet
	for _, f := range res.failed {
		fs.add(f)
	}
	for _, gap := range fs.gaps(g.Start, g.End) {
		res.done = append(res.done, gap)
	}
	return res
}

// randIPv6InPrefix returns a random IPv6 address within prefix, preserving the
// network bits and randomizing the host bits (tmpiprest-style source rotation).
func randIPv6InPrefix(prefix *net.IPNet) net.IP {
	ones, _ := prefix.Mask.Size()
	base := prefix.IP.To16()
	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		pbits := ones - i*8
		if pbits <= 0 {
			ip[i] = byte(rand.Uint32())
		} else if pbits >= 8 {
			ip[i] = base[i]
		} else {
			mask := byte(0xFF << (8 - pbits))
			ip[i] = (base[i] & mask) | (byte(rand.Uint32()) &^ mask)
		}
	}
	return ip
}

// rotatingDialContext returns a DialContext that binds each connection to a
// fresh random IPv6 source address, picked uniformly across pools. Forces
// tcp6 - the target must have a AAAA record when rotation is used.
func rotatingDialContext(pools []*net.IPNet) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: randIPv6InPrefix(pools[rand.Intn(len(pools))])},
			Timeout:   15 * time.Second,
		}
		return d.DialContext(ctx, "tcp6", addr)
	}
}

// loadTmpIPPools parses a tmpiprest.conf file into rotation pools. Device
// prefixes may carry a trailing ':' or '::' (as written for tmpip.py); mask
// defaults to 48. Ignore lists are skipped - in a >= /56 the collision
// probability with a configured address is negligible.
func loadTmpIPPools(path string) ([]*net.IPNet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf struct {
		Devices []struct {
			Prefix string `json:"prefix"`
			If     string `json:"if"`
			Mask   int    `json:"mask"`
		} `json:"Devices"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	var pools []*net.IPNet
	for _, d := range conf.Devices {
		mask := d.Mask
		if mask == 0 {
			mask = 48
		}
		_, pfx, err := net.ParseCIDR(strings.TrimRight(d.Prefix, ":") + "::/" + strconv.Itoa(mask))
		if err != nil {
			return nil, fmt.Errorf("tmpip device %q: %w", d.If, err)
		}
		pools = append(pools, pfx)
	}
	if len(pools) == 0 {
		return nil, fmt.Errorf("no Devices in %s", path)
	}
	return pools, nil
}

func main() {
	flag.Parse()

	ctLog := *flagLog
	if ctLog == "" {
		log.Fatalln("CT log URL is required")
	}
	if !strings.HasPrefix(ctLog, "https://") {
		ctLog = "https://" + ctLog
	}
	*flagLog = ctLog // normalized form used everywhere
	start := *flagStart
	end := *flagEnd
	concurrency := *flagConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	switch *flagEntryType {
	case "all", "precert", "x509":
	default:
		log.Fatalf("invalid -entry-type %q (want all|precert|x509)", *flagEntryType)
	}

	hc := &http.Client{Timeout: 60 * time.Second}
	if *flagTmpIP && *flagSrc6 != "" {
		log.Fatalln("use either -tmpip or -src6, not both")
	}
	var pools []*net.IPNet
	if *flagTmpIP {
		var perr error
		pools, perr = loadTmpIPPools(*flagTmpIPConf)
		if perr != nil {
			log.Fatalf("tmpiprest config: %v", perr)
		}
	} else if *flagSrc6 != "" {
		_, pfx, perr := net.ParseCIDR(*flagSrc6)
		if perr != nil {
			log.Fatalf("invalid -src6 %q: %v", *flagSrc6, perr)
		}
		pools = []*net.IPNet{pfx}
	}
	for _, pfx := range pools {
		if ones, _ := pfx.Mask.Size(); ones > 64 {
			log.Fatalf("rotation prefix %s is narrower than /64 - refusing (per-IP rate limits may aggregate)", pfx)
		}
	}
	if len(pools) > 0 {
		hc.Transport = &http.Transport{
			DialContext:           rotatingDialContext(pools),
			DisableKeepAlives:     *flagSrc6PerReq, // per-request rotation costs a TLS handshake each time
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			MaxConnsPerHost:       concurrency * 2,
		}
		mode := "per-connection"
		if *flagSrc6PerReq {
			mode = "per-request"
		}
		var names []string
		for _, p := range pools {
			names = append(names, p.String())
		}
		log.Printf("rotating source IPv6 across %s (%s)", strings.Join(names, ", "), mode)
	}
	jsonClient, err := client.New(ctLog, hc, jsonclient.Options{UserAgent: userAgent})
	if err != nil {
		log.Fatalln("Error creating JSON client:", err)
	}

	// -end -1 resolves to the current tree head
	if end < 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if *flagTiled {
			cp, cpErr := certificatetransparency.FetchCheckpoint(ctx, hc, ctLog)
			cancel()
			if cpErr != nil {
				log.Fatalf("Error resolving checkpoint: %v", cpErr)
			}
			end = int64(cp.Size) - 1
		} else {
			sth, sthErr := jsonClient.GetSTH(ctx)
			cancel()
			if sthErr != nil {
				log.Fatalf("Error resolving tree head: %v", sthErr)
			}
			end = int64(sth.TreeSize) - 1
		}
		log.Printf("resolved -end -1 to tree head %d", end)
	}
	if end < start {
		log.Fatalln("End index must be >= start index")
	}

	// ClickHouse setup
	var chConn clickhouse.Conn
	if *flagCHDSN != "" {
		chConn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{strings.TrimPrefix(strings.TrimPrefix(*flagCHDSN, "tcp://"), "clickhouse://")},
			Auth: clickhouse.Auth{
				Database: *flagCHDB,
				Username: *flagCHUser,
				Password: *flagCHPass,
			},
			DialTimeout: 10 * time.Second,
			Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		})
		if err != nil {
			log.Fatalf("Failed to connect to ClickHouse: %v", err)
		}
	}

	// resume state
	done := &intervalSet{}
	if *flagStateFile != "" && !*flagFresh {
		if st, err := loadState(*flagStateFile); err == nil {
			if st.Log == ctLog && st.Start == start && st.End == end && st.EntryType == *flagEntryType {
				for _, iv := range st.Done {
					done.add(iv)
				}
				log.Printf("resumed from %s: %d intervals / %d entries already done", *flagStateFile, len(st.Done), done.covered())
			} else {
				log.Fatalf("state file %s covers different range/type (log=%s start=%d end=%d type=%s) - use a different -state-file or -fresh to discard", *flagStateFile, st.Log, st.Start, st.End, st.EntryType)
			}
		}
	}

	st := &stats{}
	limiter := newRateLimiter(*flagQPS)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	totalSpan := end - start + 1
	remaining := totalSpan - done.covered()
	log.Printf("crawl %s [%d-%d] total=%d remaining=%d groupsize=%d workers=%d entryType=%s",
		ctLog, start, end, totalSpan, remaining, *flagGroupSize, concurrency, *flagEntryType)

	// progress reporter - reads doneCovered which the collector updates atomically
	var doneCovered atomic.Int64
	go func() {
		tk := time.NewTicker(*flagProgress)
		defer tk.Stop()
		var lastDone int64
		lastT := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				d := doneCovered.Load()
				dt := time.Since(lastT).Seconds()
				rate := float64(d-lastDone) / dt
				lastDone, lastT = d, time.Now()
				pct := float64(d) / float64(totalSpan) * 100
				eta := ""
				if rate > 0 {
					eta = fmt.Sprintf(" eta=%s", time.Duration(float64(totalSpan-d)/rate*float64(time.Second)).Round(time.Minute))
				}
				log.Printf("progress: %d/%d entries done (%.2f%%), %.0f entries/s%s | fetched=%d typeSkipped=%d parsed=%d inserted=%d retries=%d shortReads=%d parseErrs=%d",
					d, totalSpan, pct, rate, eta, st.fetched.Load(), st.typeSkip.Load(), st.parsed.Load(), st.inserted.Load(), st.retries.Load(), st.shortReads.Load(), st.parseErrors.Load())
			}
		}
	}()

	checkpoint := func() {
		if *flagStateFile == "" {
			return
		}
		st2 := &crawlState{Log: ctLog, Start: start, End: end, EntryType: *flagEntryType, Done: done.set, UpdatedAt: time.Now()}
		if err := writeState(*flagStateFile, st2); err != nil {
			log.Printf("state write failed: %v", err)
		}
	}

	allDone := false
	for pass := 1; pass <= *flagMaxPasses && !allDone; pass++ {
		jobs := splitGroups(done.gaps(start, end), *flagGroupSize)
		if len(jobs) == 0 {
			allDone = true
			break
		}
		if pass > 1 {
			log.Printf("pass %d: retrying %d failed groups", pass, len(jobs))
		}

		jobCh := make(chan interval)
		resCh := make(chan groupResult, concurrency*2)

		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for g := range jobCh {
					resCh <- processGroup(ctx, g, jsonClient, hc, limiter, chConn, st)
				}
			}()
		}
		go func() {
			defer close(jobCh)
			for _, j := range jobs {
				select {
				case jobCh <- j:
				case <-ctx.Done():
					return
				}
			}
		}()
		go func() {
			wg.Wait()
			close(resCh)
		}()

		tick := time.NewTicker(15 * time.Second)
		for res := range resCh {
			if res.aborted {
				continue
			}
			for _, iv := range res.done {
				done.add(iv)
			}
			doneCovered.Store(done.covered())
			for range res.failed {
				st.failed.Add(1)
			}
			for _, line := range res.lines {
				os.Stdout.Write([]byte(line))
				os.Stdout.Write([]byte("\n"))
			}
			select {
			case <-tick.C:
				checkpoint()
			default:
			}
		}
		tick.Stop()
		checkpoint()
		if ctx.Err() != nil {
			log.Printf("interrupted - state saved to %s", *flagStateFile)
			return
		}
	}

	if allDone || done.covered() == totalSpan {
		log.Printf("crawl complete: %d entries covered, inserted=%d typeSkipped=%d parseErrs=%d verifyMismatch=%d",
			done.covered(), st.inserted.Load(), st.typeSkip.Load(), st.parseErrors.Load(), st.verifyMismatch.Load())
	} else {
		remaining := totalSpan - done.covered()
		log.Printf("crawl finished with %d entries still uncovered (state in %s) - rerun to retry",
			remaining, *flagStateFile)
		os.Exit(1)
	}
}
