// ctsearch - crt.sh-style web UI over certstream.certs in ClickHouse.
// Read-only; deploy behind a reverse proxy that terminates TLS + auth.
package main

import (
	"encoding/json"
	"flag"
	"html/template"
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
	Query     string
	Kind      string
	Rows      []row
	Truncated bool
	NextAfter uint64
	HaveNext  bool
	After     uint64
	Err       string
	Elapsed   string
	Base      string
}

// --- query parsing ---------------------------------------------------------

type parsed struct {
	where string
	args  []any
	kind  string
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
		return parsed{`fingerprint = ?`, []any{v}, "fingerprint"}
	case strings.HasPrefix(low, "serial:"):
		return parsed{`serial_number = ?`, []any{q[7:]}, "serial"}
	case strings.HasPrefix(low, "cn:"):
		return parsed{`cn = ?`, []any{q[3:]}, "subject CN"}
	case strings.HasPrefix(low, "idx:"):
		n, _ := strconv.ParseUint(q[4:], 10, 64)
		return parsed{`cert_index = ?`, []any{n}, "cert index"}
	}

	if n, err := strconv.ParseUint(q, 10, 64); err == nil {
		return parsed{`cert_index = ?`, []any{n}, "cert index"}
	}
	if isHex64(q) {
		return parsed{`fingerprint = ?`, []any{low}, "fingerprint"}
	}

	if strings.HasPrefix(q, "%.") || strings.HasPrefix(q, "*.") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(q, "%."), "*.")
		return suffixQuery(suffix)
	}
	if strings.HasPrefix(q, "%") && len(q) > 1 {
		pat := "%" + likeEsc(q[1:]) + `"%`
		return parsed{`hostnames LIKE ?`, []any{pat}, "name suffix"}
	}
	// plain name: exact match on primary name OR inside the SAN list.
	// root_domain IN (candidates) narrows the hostnames scan via skip index.
	return parsed{
		`domain = ? OR (root_domain IN (` + placeholders(rootCands(low)) + `) AND hostnames LIKE ?)`,
		append(append([]any{low}, toAnys(rootCands(low))...), `%"`+likeEsc(low)+`"%`),
		"exact identity",
	}
}

// suffixQuery handles %.example.com - matches the suffix itself plus names
// under it (crt.sh %.-semantics). root_domain IN (cands) drives granule
// skipping; it only reflects the first SAN's root, so certs whose matching
// names are secondary SANs under a different primary root are missed -
// documented limitation of the schema.
func suffixQuery(suffix string) parsed {
	cands := rootCands(strings.ToLower(suffix))
	s := likeEsc(suffix)
	where := `root_domain IN (` + placeholders(cands) + `) AND ` +
		`(domain = ? OR domain LIKE ? OR hostnames LIKE ? OR hostnames LIKE ?)`
	args := append(toAnys(cands), suffix, "%."+s, `%"`+s+`"%`, "%."+s+`"%`)
	return parsed{where, args, "subdomain names"}
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

var tpl = template.Must(template.New("page").Funcs(
	template.FuncMap{"ts": tsFormat, "urlquery": url.QueryEscape}).Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ct search</title>
<style>
body{font-family:monospace;font-size:13px;margin:2em auto;max-width:1400px}
input[type=text]{width:50%;font-family:monospace;font-size:14px;padding:4px}
table{border-collapse:collapse;width:100%;margin-top:1em}
th,td{border:1px solid #999;padding:3px 6px;text-align:left;vertical-align:top}
th{background:#ddd}
tr:nth-child(even){background:#f4f4f4}
a{color:#005}
.err{color:#a00}
.hint{color:#666}
td.idx{white-space:nowrap}
</style>
<base href="{{.Base}}"></head><body>
<h3>ct search</h3>
<form method="get" action="search">
<input type="text" name="q" value="{{.Query}}" autofocus placeholder="%.example.com | example.com | fp: | serial: | cn: | idx:">
<input type="submit" value="Search">
</form>
<p class="hint">
%.example.com = subdomains &amp; wildcard &nbsp;&middot;&nbsp; example.com = exact name &nbsp;&middot;&nbsp;
fp:&lt;sha256&gt; &middot; serial:&lt;n&gt; &middot; cn:&lt;name&gt; &middot; idx:&lt;n&gt;
</p>
{{if .Err}}<p class="err">{{.Err}}</p>{{end}}
{{if .Rows}}
<p>{{.Kind}}: {{len .Rows}} row(s){{if .Truncated}}+ (page limit){{end}} &nbsp; <span class="hint">{{.Elapsed}}</span></p>
<table>
<tr><th>cert_index</th><th>seen</th><th>not_before</th><th>not_after</th><th>cn</th><th>names</th><th>serial</th><th>subject O</th></tr>
{{range .Rows}}<tr>
<td class="idx"><a href="cert/{{.Index}}">{{.Index}}</a></td>
<td>{{.Seen.Format "2006-01-02"}}</td>
<td>{{ts .NotBefore}}</td>
<td>{{ts .NotAfter}}</td>
<td>{{.CN}}</td>
<td>{{.Hostnames}}</td>
<td>{{.Serial}}</td>
<td>{{.O}}</td>
</tr>{{end}}
</table>
{{if .HaveNext}}<p><a href="search?q={{urlquery .Query}}&amp;after={{.NextAfter}}">next page &rarr;</a></p>{{end}}
{{end}}
</body></html>`))

var certTpl = template.Must(template.New("cert").Funcs(
	template.FuncMap{"ts": tsFormat}).Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>cert {{.Index}}</title>
<style>
body{font-family:monospace;font-size:13px;margin:2em auto;max-width:1200px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #999;padding:3px 6px;text-align:left;vertical-align:top}
th{background:#ddd;width:220px}
pre{white-space:pre-wrap;word-break:break-all;margin:0}
</style><base href="{{.Base}}"></head><body>
<p><a href="">&larr; search</a></p>
{{if .Err}}<p>{{.Err}}</p>{{else}}
<table>
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
</table>
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
	p := resultPage{Query: q, Base: base}
	if q == "" {
		tpl.Execute(w, p)
		return
	}
	pq := parseQuery(q)
	p.Kind = pq.kind

	where := "(" + pq.where + ")"
	if after > 0 {
		where += " AND cert_index > ?"
		pq.args = append(pq.args, after)
	}
	args := append([]any{}, pq.args...)

	start := time.Now()
	rows, err := chConn.Query(r.Context(),
		`SELECT cert_index, timestamp, not_before, not_after, cn, domain, serial_number, o, hostnames
		 FROM `+flagDBOr()+`.`+flagTableOr()+`
		 WHERE `+where+`
		 ORDER BY cert_index ASC
		 LIMIT ?`, append(args, *flagLimit+1)...)
	if err != nil {
		p.Err = err.Error()
		tpl.Execute(w, p)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rw row
		if err := rows.Scan(&rw.Index, &rw.Seen, &rw.NotBefore, &rw.NotAfter,
			&rw.CN, &rw.Domain, &rw.Serial, &rw.O, &rw.Hostnames); err != nil {
			p.Err = "scan: " + err.Error()
			tpl.Execute(w, p)
			return
		}
		rw.Hostnames = shortNames(rw.Hostnames, 200)
		p.Rows = append(p.Rows, rw)
	}
	if err := rows.Err(); err != nil {
		p.Err = err.Error()
		tpl.Execute(w, p)
		return
	}
	if len(p.Rows) > *flagLimit {
		p.Rows = p.Rows[:*flagLimit]
		p.Truncated = true
		p.HaveNext = true
		p.NextAfter = p.Rows[len(p.Rows)-1].Index
	}
	p.Elapsed = time.Since(start).String()
	tpl.Execute(w, p)
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
	tpl.Execute(w, resultPage{Base: base})
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
	row := chConn.QueryRow(r.Context(),
		`SELECT cert_index, timestamp, not_before, not_after, cn, o, l, st, c, ou,
		        email_address, hostnames, subject_alt_name, serial_number, fingerprint,
		        signature_algorithm, authority_key_identifier, subject_key_identifier,
		        authority_info_access, key_usage, extended_key_usage, basic_constraints,
		        certificate_policies, ctl_signed_certificate_timestamp, tld, root_domain, cert_link
		 FROM `+flagDBOr()+`.`+flagTableOr()+` WHERE cert_index = ? LIMIT 1`, n)
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
