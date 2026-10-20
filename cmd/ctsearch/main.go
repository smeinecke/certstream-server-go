// ctsearch - crt.sh-style web UI over certstream.certs in ClickHouse.
// Read-only; deploy behind a reverse proxy that terminates TLS + auth.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

var (
	flagListen     = flag.String("listen", "127.0.0.1:8088", "listen address")
	flagDSN        = flag.String("clickhouse-dsn", "127.0.0.1:9000", "clickhouse host:port (native protocol)")
	flagDB         = flag.String("clickhouse-db", "certstream", "clickhouse database")
	flagTable      = flag.String("clickhouse-table", "certs", "clickhouse table")
	flagIdxTable   = flag.String("clickhouse-idx-table", "certs_idx", "cert_index->domain lookup table (empty = direct scan)")
	flagUser       = flag.String("clickhouse-user", "ctscan", "clickhouse user")
	flagCHPassFile = flag.String("clickhouse-password-file", "", "file containing the clickhouse password")
	flagCHPass     = flag.String("clickhouse-password", "", "clickhouse password")
	flagBase       = flag.String("base", "/ct/", "URL base path the app is mounted under")
	flagLimit      = flag.Int("limit", 100, "rows per page")
)

var chConn driver.Conn
var base string

type row struct {
	Index       uint64
	Seen        time.Time
	NotBefore   uint64
	NotAfter    uint64
	CN          string
	Domain      string
	Serial      string
	O           string
	Hostnames   string
	Fingerprint string
	CertLink    string
	AKI         string
	SigAlg      string
}

type resultPage struct {
	Query string
	Err   string
	Base  string
}

// --- query parsing ---------------------------------------------------------

type parsed struct {
	where string
	args  []any
	kind  string
	// single marks predicates whose match set is inherently small (point
	// lookups on bloom-indexed columns or the domain PK). Those run as one
	// query - ORDER BY + LIMIT uses a bounded heap - instead of the
	// two-phase index-then-fetch dance, which would scan the same granules
	// twice.
	single bool
}

func likeEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// parseQuery maps crt.sh-style queries onto the certs schema:
//
//	%.example.com   names ending in .example.com (any depth, incl. *.example.com)
//	example.com     exact identity "example.com" in SAN/CN set
//	fp:<hex>        fingerprint match
//	serial:<n>      serial number match
//	cn:<name>       subject CN exact match
//	idx:<n> / <n>   cert_index
func parseQuery(q string) parsed {
	q = strings.TrimSpace(q)
	low := strings.ToLower(q)

	switch {
	case strings.HasPrefix(low, "fp:") || strings.HasPrefix(low, "fingerprint:"):
		v := q[strings.Index(q, ":")+1:]
		return parsed{`fingerprint = ?`, []any{v}, "fingerprint", true}
	case strings.HasPrefix(low, "serial:"):
		return parsed{`serial_number = ?`, []any{q[7:]}, "serial", true}
	case strings.HasPrefix(low, "cn:"):
		return parsed{`cn = ?`, []any{q[3:]}, "subject CN", true}
	case strings.HasPrefix(low, "idx:"):
		n, _ := strconv.ParseUint(q[4:], 10, 64)
		return idxPred(n)
	}

	if n, err := strconv.ParseUint(q, 10, 64); err == nil {
		return idxPred(n)
	}
	if isHex64(q) {
		return parsed{`fingerprint = ?`, []any{low}, "fingerprint", true}
	}

	if strings.HasPrefix(q, "%.") || strings.HasPrefix(q, "*.") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(q, "%."), "*.")
		return suffixQuery(suffix)
	}
	if strings.HasPrefix(q, "%") && len(q) > 1 {
		// arbitrary suffix - no index can help, honest full scan
		return parsed{`domain LIKE ?`, []any{"%" + likeEsc(q[1:])}, "name suffix", false}
	}
	if strings.ContainsAny(q, "%*") {
		// wildcard anywhere else: * and % are wildcards, _ and \ escape.
		// a literal prefix makes it a PK range scan (single phase);
		// a leading wildcard (handled above) stays two-phase.
		pat := strings.ReplaceAll(low, "*", "%")
		pat = strings.ReplaceAll(pat, `\`, `\\`)
		pat = strings.ReplaceAll(pat, `_`, `\_`)
		return parsed{`domain LIKE ?`, []any{pat}, "name pattern", true}
	}
	// plain name: one row per SAN, so domain = ? covers every cert identity
	return parsed{`domain = ?`, []any{low}, "exact identity", true}
}

// idxPred builds the cert_index predicate. With the certs_idx lookup
// table the outer query only touches granules whose domain is one of the
// few SAN names of that cert (PK seek) instead of bloom-scanning every
// granule in the table.
func idxPred(n uint64) parsed {
	if idxTbl := flagIdxOr(); idxTbl != "" {
		w := fmt.Sprintf(
			`domain IN (SELECT domain FROM %s WHERE cert_index = %d) AND cert_index = %d`,
			idxTbl, n, n)
		return parsed{w, nil, "cert index", true}
	}
	return parsed{`cert_index = ?`, []any{n}, "cert index", true}
}

// suffixQuery handles %.example.com - the root_domain bloom index skips
// granules, then endsWith on the surviving rows filters precisely.
// Matches crt.sh %.x semantics: the suffix itself plus names under it.
func suffixQuery(suffix string) parsed {
	cands := rootCands(strings.ToLower(suffix))
	where := `root_domain IN (` + placeholders(cands) + `) AND ` +
		`(domain = ? OR endsWith(domain, ?))`
	args := append(toAnys(cands), suffix, "."+suffix)
	return parsed{where, args, "subdomain names", false}
}

// rootCands returns the input and its first two label-stripped variants
// (each with at least two labels) - cheap guesses for the eTLD+1.
func rootCands(name string) []string {
	out := []string{}
	rest := name
	for i := 0; i < 3; i++ {
		if strings.Count(rest, ".") < 1 {
			break
		}
		out = append(out, rest)
		rest = rest[strings.Index(rest, ".")+1:]
	}
	return out
}

func placeholders(v []string) string {
	return strings.TrimSuffix(strings.Repeat("?,", len(v)), ",")
}

func phAny(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toAnys(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// --- http ------------------------------------------------------------------

var headTpl = template.Must(template.New("head").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ct search</title>
<style>
body{font-family:monospace;font-size:13px;margin:2em auto;padding:0 12px;max-width:1400px;box-sizing:border-box}
input[type=text]{width:50%;min-width:12em;font-family:monospace;font-size:14px;padding:4px;box-sizing:border-box}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin-top:1em}
th,td{border:1px solid #999;padding:3px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#ddd}
tr:nth-child(even){background:#f4f4f4}
a{color:#005}
.err{color:#a00}
.hint{color:#666}
td.idx{white-space:nowrap}
#ld{margin:1em 0;padding:.5em .8em;background:#ffc;border:1px solid #cc6}
.spin{display:inline-block;width:12px;height:12px;border:2px solid #999;
border-top-color:#222;border-radius:50%;animation:sp .8s linear infinite;
vertical-align:-2px;margin-right:.4em}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
<base href="{{.Base}}"></head><body>
<h3>ct search</h3>
<form method="get" action="search">
<input type="text" name="q" value="{{.Query}}" autofocus placeholder="%.example.com | example.com | fp: | serial: | cn: | idx:">
<input type="submit" value="Search">
</form>
<p class="hint">
%.example.com = subdomains &nbsp;&middot;&nbsp; example.com = exact name &nbsp;&middot;&nbsp;
% and * wildcards anywhere (foo%) &nbsp;&middot;&nbsp;
fp:&lt;sha256&gt; &middot; serial:&lt;n&gt; &middot; cn:&lt;name&gt; &middot; idx:&lt;n&gt;
</p>`))

var rowTpl = template.Must(template.New("row").Funcs(
	template.FuncMap{"ts": tsFormat}).Parse(`<tr>
<td class="idx"><a href="cert/{{.Index}}">{{.Index}}</a></td>
<td>{{.Seen.Format "2006-01-02"}}</td>
<td>{{ts .NotBefore}}</td>
<td>{{ts .NotAfter}}</td>
<td>{{.CN}}</td>
<td>{{.Hostnames}}</td>
<td>{{.Serial}}</td>
<td>{{.O}}</td>
</tr>
`))

var footTpl = template.Must(template.New("foot").Funcs(
	template.FuncMap{"urlquery": url.QueryEscape}).Parse(`</table></div>
<p>{{.Kind}}: {{.Count}} row(s){{if .HaveNext}}+ (page limit){{end}} in {{.Elapsed}}
{{if .HaveNext}}&nbsp; <a href="search?q={{urlquery .Query}}&amp;after={{.NextAfter}}{{if .NextDom}}&amp;afterd={{urlquery .NextDom}}{{end}}">next page &rarr;</a>{{end}}</p>`))

var certTpl = template.Must(template.New("cert").Funcs(
	template.FuncMap{"ts": tsFormat}).Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>cert {{.Index}}</title>
<style>
body{font-family:monospace;font-size:13px;margin:2em auto;padding:0 12px;max-width:1200px;box-sizing:border-box}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #999;padding:3px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#ddd;width:220px}
pre{white-space:pre-wrap;word-break:break-all;margin:0}
</style><base href="{{.Base}}"></head><body>
<p><a href="">&larr; search</a></p>
{{if .Err}}<p>{{.Err}}</p>{{else}}
<div class="tw"><table>
<tr><th>cert_index</th><td>{{.Index}}</td></tr>
<tr><th>seen (inserted)</th><td>{{.Seen}}</td></tr>
<tr><th>not_before</th><td>{{ts .NotBefore}}</td></tr>
<tr><th>not_after</th><td>{{ts .NotAfter}}</td></tr>
<tr><th>subject CN</th><td>{{.CN}}</td></tr>
<tr><th>subject O / L / ST / C / OU</th><td>{{.O}} / {{.L}} / {{.ST}} / {{.C}} / {{.OU}}</td></tr>
<tr><th>email_address</th><td>{{.Email}}</td></tr>
<tr><th>names (hostnames)</th><td><pre>{{.NamesPretty}}</pre></td></tr>
<tr><th>subject_alt_name (raw)</th><td><pre>{{.SAN}}</pre></td></tr>
<tr><th>serial_number</th><td>{{.Serial}}</td></tr>
<tr><th>fingerprint (sha256)</th><td>{{.Fingerprint}}</td></tr>
<tr><th>signature_algorithm</th><td>{{.SigAlg}}</td></tr>
<tr><th>authority_key_identifier</th><td>{{.AKI}}</td></tr>
<tr><th>subject_key_identifier</th><td>{{.SKI}}</td></tr>
<tr><th>authority_info_access</th><td><pre>{{.AIA}}</pre></td></tr>
<tr><th>key_usage</th><td>{{.KU}}</td></tr>
<tr><th>extended_key_usage</th><td>{{.EKU}}</td></tr>
<tr><th>basic_constraints</th><td>{{.BC}}</td></tr>
<tr><th>certificate_policies</th><td>{{.CP}}</td></tr>
<tr><th>scts</th><td><pre>{{.SCT}}</pre></td></tr>
<tr><th>tld / root_domain</th><td>{{.TLD}} / {{.RootDomain}}</td></tr>
<tr><th>cert_link</th><td><a href="{{.CertLink}}">{{.CertLink}}</a></td></tr>
</table></div>
<p class="hint">issuer CN/O not stored - only AKI. DER fetch: <a href="{{.CertLink}}">cert_link</a></p>
{{end}}
</body></html>`))

func tsFormat(v uint64) string {
	if v == 0 {
		return ""
	}
	// not_before/not_after are unix seconds (may be ms on some feeds - detect)
	if v > 1e12 {
		v /= 1000
	}
	return time.Unix(int64(v), 0).UTC().Format("2006-01-02 15:04:05")
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	afterd := r.URL.Query().Get("afterd")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no") // let rows trickle through nginx
	headTpl.Execute(w, struct{ Query, Base string }{q, base})
	if q == "" {
		io.WriteString(w, "</body></html>")
		return
	}
	fl, _ := w.(http.Flusher)
	pq := parseQuery(q)
	fmt.Fprintf(w, "<p>%s:</p>\n", template.HTMLEscapeString(pq.kind))
	io.WriteString(w, `<div id="ld"><span class="spin"></span>`+
		`querying clickhouse&hellip; <span id="elt">0.0</span>s`+
		` &mdash; rows stream in below</div>`+"\n"+
		`<script>var _t0=Date.now(),_tm=setInterval(function(){`+
		`var e=document.getElementById('elt');`+
		`if(!e){clearInterval(_tm);return}`+
		`e.textContent=((Date.now()-_t0)/1000).toFixed(1)},100);</script>`+"\n"+
		`<div class="tw"><table>`+"\n<tr><th>cert_index</th><th>seen</th><th>not_before</th><th>not_after</th>"+
		"<th>cn</th><th>names</th><th>serial</th><th>subject O</th></tr>\n")
	if fl != nil {
		fl.Flush() // show the table skeleton while the query scans
	}

	where := "(" + pq.where + ")"
	args := append([]any{}, pq.args...)
	if after > 0 {
		if pq.single && afterd != "" {
			// row-level cursor: rows share cert_index across SANs, so a
			// cert_index-only cursor would drop siblings at the boundary
			where += " AND (cert_index, domain) > (?, ?)"
			args = append(args, after, afterd)
		} else {
			where += " AND cert_index > ?"
			args = append(args, after)
		}
	}
	args = append(args, *flagLimit+1)

	start := time.Now()
	var qErr string
	var count int
	var lastIdx uint64
	var lastDom string
	haveNext := false

	const cols = `cert_index, timestamp, not_before, not_after, cn, domain, serial_number, o, hostnames`
	emit := func(rows driver.Rows, capRows bool) {
		defer rows.Close()
		for rows.Next() {
			var rw row
			if err := rows.Scan(&rw.Index, &rw.Seen, &rw.NotBefore, &rw.NotAfter,
				&rw.CN, &rw.Domain, &rw.Serial, &rw.O, &rw.Hostnames); err != nil {
				qErr = "scan: " + err.Error()
				return
			}
			if capRows && count == *flagLimit {
				haveNext = true // extra row only signals the next page
				continue
			}
			lastIdx, lastDom = rw.Index, rw.Domain
			rw.Hostnames = shortNames(rw.Hostnames, 200)
			rowTpl.Execute(w, rw)
			count++
			if fl != nil && count%16 == 0 {
				fl.Flush()
			}
		}
		if qErr == "" {
			if err := rows.Err(); err != nil {
				qErr = err.Error()
			}
		}
	}

	if pq.single {
		// bounded match set - ORDER BY+LIMIT keeps a small heap server-side,
		// and one scan beats find-indexes-then-refetch on the same granules
		rows, err := chConn.Query(r.Context(),
			`SELECT `+cols+` FROM `+flagDBOr()+`.`+flagTableOr()+`
			 WHERE `+where+` ORDER BY cert_index, domain LIMIT ?`, args...)
		if err != nil {
			qErr = err.Error()
		} else {
			emit(rows, true)
		}
	} else {
		// Phase 1: pick matching cert_index values (sorts only UInt64s - the
		// ORDER BY over giant hostnames strings blows server memory otherwise)
		idxRows, err := chConn.Query(r.Context(),
			`SELECT cert_index FROM `+flagDBOr()+`.`+flagTableOr()+`
			 WHERE `+where+`
			 ORDER BY cert_index ASC
			 LIMIT ?`, args...)
		var indexes []uint64
		if err != nil {
			qErr = err.Error()
		} else {
			for idxRows.Next() {
				var ix uint64
				if err := idxRows.Scan(&ix); err != nil {
					qErr = "scan: " + err.Error()
					break
				}
				if len(indexes) == 0 || indexes[len(indexes)-1] != ix {
					indexes = append(indexes, ix)
				}
			}
			if qErr == "" {
				if err := idxRows.Err(); err != nil {
					qErr = err.Error()
				}
			}
			idxRows.Close()
		}
		if qErr == "" && len(indexes) > *flagLimit {
			haveNext = true
			indexes = indexes[:*flagLimit]
		}
		if len(indexes) > 0 {
			lastIdx = indexes[len(indexes)-1]
		}

		// Phase 2: fetch the display columns for just those indices. Route
		// through certs_idx when configured: the (cert_index, domain) lookup
		// turns this into domain-PK seeks instead of a wide-table bloom
		// rescan on cert_index.
		if qErr == "" && len(indexes) > 0 {
			// inline the uint64 list - parameter binds are not 'constant' for IN
			var sb strings.Builder
			for i, v := range indexes {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(strconv.FormatUint(v, 10))
			}
			pred := `cert_index IN (` + sb.String() + `)`
			if idxTbl := flagIdxOr(); idxTbl != "" {
				pred = `domain IN (SELECT domain FROM ` + idxTbl +
					` WHERE cert_index IN (` + sb.String() + `)) AND ` + pred
			}
			rows, err := chConn.Query(r.Context(),
				`SELECT `+cols+` FROM `+flagDBOr()+`.`+flagTableOr()+`
				 WHERE `+pred+`
				 ORDER BY cert_index, domain`)
			if err != nil {
				qErr = err.Error()
			} else {
				// all rows of the selected indexes belong to this page -
				// the index count already limited it
				emit(rows, false)
			}
		}
	}
	if qErr != "" {
		fmt.Fprintf(w, `</table></div><p class="err">%s</p>`, template.HTMLEscapeString(qErr))
	} else {
		footTpl.Execute(w, struct {
			Kind      string
			Count     int
			HaveNext  bool
			NextAfter uint64
			NextDom   string
			Elapsed   string
			Query     string
		}{pq.kind, count, haveNext, lastIdx, lastDom, time.Since(start).String(), q})
	}
	io.WriteString(w, `<script>clearInterval(_tm);`+
		`var _l=document.getElementById('ld');if(_l)_l.remove();</script>`)
	io.WriteString(w, "</body></html>")
}

func shortNames(js string, max int) string {
	var names []string
	if json.Unmarshal([]byte(js), &names) == nil {
		js = strings.Join(names, ", ")
	}
	if len(js) > max {
		return js[:max] + "..."
	}
	return js
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "" {
		http.NotFound(w, r)
		return
	}
	headTpl.Execute(w, struct{ Query, Base string }{"", base})
	io.WriteString(w, "</body></html>")
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/cert/")
	n, err := strconv.ParseUint(idStr, 10, 64)
	p := struct {
		resultPage
		Index                                         uint64
		Seen                                          string
		NotBefore, NotAfter                           uint64
		CN, O, L, ST, C, OU, Email                    string
		NamesPretty, SAN, Serial, Fingerprint, SigAlg string
		AKI, SKI, AIA, KU, EKU, BC, CP, SCT           string
		TLD, RootDomain, CertLink                     string
	}{resultPage: resultPage{Base: base}}
	if err != nil {
		p.Err = "bad cert index"
		certTpl.Execute(w, p)
		return
	}
	var (
		nb, na                                                                                              uint64
		ts                                                                                                  time.Time
		cn, o, l, st, c, ou, email, hn, san, ser, fp, alg, aki, ski, aia, ku, eku, bc, cp, sct, tld, rd, cl string
	)
	pw := idxPred(n)
	row := chConn.QueryRow(r.Context(),
		`SELECT cert_index, timestamp, not_before, not_after, cn, o, l, st, c, ou,
		        email_address, hostnames, subject_alt_name, serial_number, fingerprint,
		        signature_algorithm, authority_key_identifier, subject_key_identifier,
		        authority_info_access, key_usage, extended_key_usage, basic_constraints,
		        certificate_policies, ctl_signed_certificate_timestamp, tld, root_domain, cert_link
		 FROM `+flagDBOr()+`.`+flagTableOr()+` WHERE `+pw.where+` LIMIT 1`, pw.args...)
	if err := row.Scan(&p.Index, &ts, &nb, &na, &cn, &o, &l, &st, &c, &ou,
		&email, &hn, &san, &ser, &fp, &alg, &aki, &ski, &aia, &ku, &eku, &bc,
		&cp, &sct, &tld, &rd, &cl); err != nil {
		p.Err = "not found: " + err.Error()
		certTpl.Execute(w, p)
		return
	}
	p.Index, p.Seen = n, ts.UTC().Format("2006-01-02 15:04:05 UTC")
	p.NotBefore, p.NotAfter = nb, na
	p.CN, p.O, p.L, p.ST, p.C, p.OU, p.Email = cn, o, l, st, c, ou, email
	var names []string
	if json.Unmarshal([]byte(hn), &names) == nil {
		p.NamesPretty = strings.Join(names, "\n")
	} else {
		p.NamesPretty = hn
	}
	p.SAN, p.Serial, p.Fingerprint, p.SigAlg = san, ser, fp, alg
	p.AKI, p.SKI, p.AIA, p.KU, p.EKU, p.BC, p.CP, p.SCT = aki, ski, aia, ku, eku, bc, cp, sct
	p.TLD, p.RootDomain, p.CertLink = tld, rd, cl
	certTpl.Execute(w, p)
}

func flagDBOr() string    { return *flagDB }
func flagTableOr() string { return *flagTable }
func flagIdxOr() string {
	if *flagIdxTable == "" {
		return ""
	}
	return flagDBOr() + "." + *flagIdxTable
}

func main() {
	flag.Parse()
	base = *flagBase
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}

	chPass := *flagCHPass
	if *flagCHPassFile != "" {
		b, err := os.ReadFile(*flagCHPassFile)
		if err != nil {
			log.Fatalf("read password file: %v", err)
		}
		chPass = strings.TrimSpace(string(b))
	}

	var err error
	chConn, err = clickhouse.Open(&clickhouse.Options{
		Addr:            []string{strings.TrimPrefix(strings.TrimPrefix(*flagDSN, "tcp://"), "clickhouse://")},
		Auth:            clickhouse.Auth{Database: *flagDB, Username: *flagUser, Password: chPass},
		DialTimeout:     20 * time.Second,
		MaxOpenConns:    8,
		MaxIdleConns:    4,
		ConnMaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/cert/", certHandler)

	srv := &http.Server{
		Addr:              *flagListen,
		Handler:           stripPrefix(base, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ctsearch on %s (base %s)", *flagListen, base)
	log.Fatal(srv.ListenAndServe())
}

// stripPrefix makes the app mountable under a non-root path without
// rewriting every route - nginx does proxy_pass with a trailing slash,
// which already strips the prefix, so this just handles direct access.
func stripPrefix(base string, h http.Handler) http.Handler {
	if base == "/" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, base[:len(base)-1]) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, base[:len(base)-1])
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		h.ServeHTTP(w, r)
	})
}
