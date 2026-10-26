// ctsearch - crt.sh-style web UI over certstream.certs in ClickHouse.
// Read-only; deploy behind a reverse proxy that terminates TLS + auth.
package main

import (
	"context"
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
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"golang.org/x/net/publicsuffix"
)

var (
	flagListen     = flag.String("listen", "127.0.0.1:8088", "listen address")
	flagDSN        = flag.String("clickhouse-dsn", "127.0.0.1:9000", "clickhouse host:port (native protocol)")
	flagDB         = flag.String("clickhouse-db", "certstream", "clickhouse database")
	flagTable      = flag.String("clickhouse-table", "certs", "clickhouse table")
	flagIdxTable   = flag.String("clickhouse-idx-table", "certs_idx", "cert_index->domain lookup table (empty = direct scan)")
	flagDomTable   = flag.String("clickhouse-dom-table", "certs_dom", "domain_rev->(domain,cert_index) table ordered by domain_rev (empty = disabled)")
	flagUser       = flag.String("clickhouse-user", "ctscan", "clickhouse user")
	flagCHPassFile = flag.String("clickhouse-password-file", "", "file containing the clickhouse password")
	flagCHPass     = flag.String("clickhouse-password", "", "clickhouse password")
	flagBase       = flag.String("base", "/ct/", "URL base path the app is mounted under")
	flagLimit      = flag.Int("limit", 100, "rows per page")
	flagQTimeout   = flag.Duration("query-timeout", 285*time.Second, "per-query timeout - keep under the proxy read timeout so errors render")
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
	// names marks distinct-name aggregation queries (names:x) answered by
	// GROUP BY domain on certs_idx.
	names bool
	// p1where/p1args optionally give a domain-only predicate evaluated
	// against certs_idx in phase 1. The narrow (cert_index, domain) table
	// is ~3x cheaper to scan than the wide certs table, and its sort order
	// lets ORDER BY cert_index early-terminate at the LIMIT. Only set for
	// two-phase queries whose predicate touches domain columns alone.
	p1where string
	p1args  []any
	// domwhere/domargs give the equivalent predicate on certs_dom, which
	// is ordered by domain_rev: suffix scopes turn into prefix ranges and
	// seek instead of scanning. Takes precedence over p1where when the
	// dom table is configured.
	domwhere string
	domargs  []any
	// p2where/p2args optionally replace where for the phase-2 row
	// re-application. Domain-scope queries keep where = root_domain = ?
	// (bloom-pruned fallback phase 1) but must filter phase-2 rows by the
	// exact domain predicate - a bare subdomain like www.x.com has no
	// root_domain value and would return empty otherwise.
	p2where string
	p2args  []any
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
		return parsed{`fingerprint = ?`, []any{v}, "fingerprint", true, false, "", nil, "", nil, "", nil}
	case strings.HasPrefix(low, "serial:"):
		return parsed{`serial_number = ?`, []any{q[7:]}, "serial", true, false, "", nil, "", nil, "", nil}
	case strings.HasPrefix(low, "cn:"):
		return parsed{`cn = ?`, []any{q[3:]}, "subject CN", true, false, "", nil, "", nil, "", nil}
	case strings.HasPrefix(low, "idx:"):
		n, _ := strconv.ParseUint(q[4:], 10, 64)
		return idxPred(n)
	case strings.HasPrefix(low, "names:"):
		return namesQuery(strings.TrimSpace(q[6:]))
	case strings.HasPrefix(low, "domain:"):
		// explicit root_domain field search: matches the eTLD+1 value
		// literally. When the input is itself a valid eTLD+1,
		// root_domain(d)=X is exactly domScope(X) - certs_dom can find the
		// cert indexes and phase 2 re-applies root_domain = ? verbatim.
		// Otherwise (public suffix like co.uk, or a deeper name) the
		// scopes differ, so phase 1 falls back to the certs bloom index.
		v := strings.ToLower(strings.TrimSpace(q[7:]))
		p := parsed{`root_domain = ?`, []any{v}, "root domain",
			false, false, "", nil, "", nil, `root_domain = ?`, []any{v}}
		if e1, err := publicsuffix.EffectiveTLDPlusOne(v); err == nil && e1 == v {
			p.domwhere, p.domargs = domScope(v)
		}
		return p
	}

	if n, err := strconv.ParseUint(q, 10, 64); err == nil {
		return idxPred(n)
	}
	if isHex64(q) {
		return parsed{`fingerprint = ?`, []any{low}, "fingerprint", true, false, "", nil, "", nil, "", nil}
	}

	if strings.HasPrefix(q, "%.") || strings.HasPrefix(q, "*.") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(q, "%."), "*.")
		if !strings.Contains(suffix, ".") {
			// bare TLD (%.de) - 'de' is a public suffix, never an eTLD+1, so
			// root_domain can't help; tld='de' covers it on the main table.
			// Phase-1 scans certs_idx's narrow domain column instead.
			sfx := "." + strings.ToLower(suffix)
			return parsed{
				`tld = ?`, []any{strings.ToLower(suffix)}, "TLD suffix", false, false,
				`endsWith(domain, ?)`, []any{sfx},
				`startsWith(domain_rev, ?)`, []any{revStr(sfx)},
				`endsWith(domain, ?)`, []any{sfx},
			}
		}
		return suffixQuery(suffix)
	}
	if strings.HasPrefix(q, "%") || strings.HasPrefix(q, "*") {
		rest := q[1:]
		if strings.ContainsAny(rest, "%*") {
			// leading wildcard + more wildcards: substring match.
			// user-typed % and * stay wildcards; \ and _ are escaped
			pat := strings.ReplaceAll(strings.ToLower(rest), "*", "%")
			pat = strings.ReplaceAll(pat, `\`, `\\`)
			pat = strings.ReplaceAll(pat, `_`, `\_`)
			return parsed{`domain LIKE ?`, []any{"%" + pat}, "name substring", false, false,
				`domain LIKE ?`, []any{"%" + pat}, "", nil, "", nil}
		}
		// plain leading wildcard: domain suffix - no PK prefix to seek on,
		// but as a reversed prefix it seeks on certs_dom
		return parsed{`domain LIKE ?`, []any{"%" + likeEsc(strings.ToLower(rest))},
			"name suffix", false, false, `endsWith(domain, ?)`, []any{strings.ToLower(rest)},
			`startsWith(domain_rev, ?)`, []any{revStr(strings.ToLower(rest))}, "", nil}
	}
	if strings.ContainsAny(q, "%*") {
		// wildcard anywhere else: * and % are wildcards, _ and \ escape.
		// a literal prefix makes it a PK range scan (single phase);
		// a leading wildcard (handled above) stays two-phase.
		pat := strings.ReplaceAll(low, "*", "%")
		pat = strings.ReplaceAll(pat, `\`, `\\`)
		pat = strings.ReplaceAll(pat, `_`, `\_`)
		return parsed{`domain LIKE ?`, []any{pat}, "name pattern", true, false, "", nil, "", nil, "", nil}
	}
	// plain name: root_domain = ? covers apex + all subdomains (apex rows
	// have root_domain = themselves) - single bloom-indexed predicate.
	// An OR with domain = ? here would defeat granule pruning entirely.
	// two-phase: a bare domain can match millions of certs (example.com
	// style), so sorting whole rows in one pass blows up - phase-1 sorts
	// only cert_index UInt64s, phase-2 refetches the few display rows
	dw, da := domScope(low)
	return parsed{`root_domain = ?`, []any{low}, "domain + subdomains", false, false, "", nil,
		dw, da, `domain = ? OR endsWith(domain, ?)`, []any{low, "." + low}}
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
		return parsed{w, nil, "cert index", true, false, "", nil, "", nil, "", nil}
	}
	return parsed{`cert_index = ?`, []any{n}, "cert index", true, false, "", nil, "", nil, "", nil}
}

// suffixQuery handles %.example.com - the root_domain bloom index skips
// granules, then a prefix match on the materialized reverse(domain)
// filters precisely. Matches crt.sh %.x semantics: the suffix itself
// plus names under it.
func suffixQuery(suffix string) parsed {
	suffix = strings.ToLower(suffix)
	// root_domain is always the last two labels, so the bloom prefilter
	// needs exactly one candidate: the last two labels of the suffix.
	// (rootCands' guessing misses for suffixes deeper than 3 labels.)
	root := suffix
	if i := strings.LastIndex(suffix, "."); i >= 0 {
		if j := strings.LastIndex(suffix[:i], "."); j >= 0 {
			root = suffix[j+1:]
		}
	}
	rev := likeEsc(revStr(suffix))
	where := `root_domain = ? AND ` +
		`(domain_rev = ? OR domain_rev LIKE ?)`
	args := []any{root, rev, rev + ".%"}
	// no p1where: rare suffixes early-terminate badly on certs_idx since it
	// is ordered by cert_index - a sparse match forces a full-table scan.
	// certs_dom's domain_rev ordering turns the suffix into a prefix range.
	dw, da := domScope(suffix)
	return parsed{where, args, "subdomain names", false, false, "", nil, dw, da, "", nil}
}

// namesQuery handles names:x - a domain-only predicate evaluated
// against certs (PK: domain). Boundary-aligned suffixes get a
// root_domain bloom prefilter: domains whose last two labels equal
// last2(sfx) are exactly the apex + subdomain set when sfx has 2
// labels, and a strict superset otherwise. Mid-label suffixes and
// substrings can't use it and stay column scans.
func namesQuery(sub string) parsed {
	s := strings.ToLower(strings.TrimSpace(sub))
	mk := func(w string, args ...any) parsed {
		return parsed{w, args, "distinct names", false, true, "", nil, "", nil, "", nil}
	}
	suffixPred := func(sfx string) parsed {
		// labels(sfx)>=2: root_domain=last2 prunes granules, then
		// domain/domain_rev finishes the job. When sfx itself is 2
		// labels, root_domain alone is already equivalent.
		if n := strings.Count(sfx, "."); n >= 2 {
			l2 := lastTwoLabels(sfx)
			return mk(`root_domain = ? AND (domain = ? OR endsWith(domain, ?))`,
				l2, sfx, "."+sfx)
		} else if n == 1 {
			return mk(`root_domain = ?`, sfx)
		}
		// single-label suffix (%.de) - no root_domain value possible
		return mk(`domain = ? OR endsWith(domain, ?)`, sfx, "."+sfx)
	}
	switch {
	case s == "":
		return mk(`domain != ''`)
	case strings.HasPrefix(s, "%.") || strings.HasPrefix(s, "*."):
		return suffixPred(s[2:])
	case strings.HasPrefix(s, "%") || strings.HasPrefix(s, "*"):
		rest := s[1:]
		if strings.ContainsAny(rest, "%*") {
			pat := strings.ReplaceAll(rest, "*", "%")
			pat = strings.ReplaceAll(pat, `\`, `\\`)
			pat = strings.ReplaceAll(pat, `_`, `\_`)
			return mk(`domain LIKE ?`, "%"+pat)
		}
		return mk(`endsWith(domain, ?)`, rest)
	case strings.ContainsAny(s, "%*"):
		pat := strings.ReplaceAll(s, "*", "%")
		pat = strings.ReplaceAll(pat, `\`, `\\`)
		pat = strings.ReplaceAll(pat, `_`, `\_`)
		return mk(`domain LIKE ?`, pat)
	default:
		return suffixPred(s)
	}
}

// lastTwoLabels returns the final two dot-separated labels of s.
func lastTwoLabels(s string) string {
	if i := strings.LastIndex(s, "."); i > 0 {
		if j := strings.LastIndex(s[:i], "."); j >= 0 {
			return s[j+1:]
		}
	}
	return s
}

// domScope builds the certs_dom predicate covering apex and all
// subdomains of d: the reversed name itself plus its "."-prefixed
// extension. Bounded ranges - no false positives from hyphenated
// lookalikes (moc.buhtig-x is outside both ranges).
func domScope(d string) (string, []any) {
	r := revStr(d)
	return `domain_rev = ? OR startsWith(domain_rev, ?)`, []any{r, r + "."}
}

// revStr reverses a domain string: "x.example.com" -> "moc.elpmaxe.x"
func revStr(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
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
%.example.com = subdomains &nbsp;&middot;&nbsp; example.com = name + subdomains &nbsp;&middot;&nbsp;
% and * wildcards anywhere (foo%, %brand%) &nbsp;&middot;&nbsp;
names:&lt;filter&gt; = distinct names &nbsp;&middot;&nbsp; domain:&lt;d&gt; = root_domain field &nbsp;&middot;&nbsp;
fp:&lt;sha256&gt; &middot; serial:&lt;n&gt; &middot; cn:&lt;name&gt; &middot; idx:&lt;n&gt;
</p>
<script>
// cursor stack for prev-page navigation - cursors are forward-only, so
// each page's entry cursor is stashed under its page number, keyed by
// path + query.
(function(){
var u=new URL(location),q=u.searchParams.get('q');if(!q)return;
var p=parseInt(u.searchParams.get('page'))||1;
var k='ctcur:'+location.pathname+'|'+q,st=[];
try{st=JSON.parse(sessionStorage.getItem(k)||'[]')}catch(e){}
st[p]={a:u.searchParams.get('after')||'0',d:u.searchParams.get('afterd')||''};
st.length=p+1;
try{sessionStorage.setItem(k,JSON.stringify(st))}catch(e){}
})();
function goPrev(){
var u=new URL(location),q=u.searchParams.get('q'),p=parseInt(u.searchParams.get('page'))||1;
if(p<=1)return false;
var v='search?q='+encodeURIComponent(q)+'&page='+(p-1);
if(p>2){
var c=null;
try{c=JSON.parse(sessionStorage.getItem('ctcur:'+location.pathname+'|'+q)||'[]')[p-1]}catch(e){}
if(c&&(+c.a>0||c.d)){v+='&after='+c.a;if(c.d)v+='&afterd='+encodeURIComponent(c.d)}
else{history.back();return false}
}
location.href=v;
return false}
</script>`))

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

// nameRow is one row of a names: result - a distinct domain with the
// newest cert_index carrying it (linked to the cert page) and how many
// SAN rows that name appears in.
type nameRow struct {
	Domain string
	Index  uint64
	Count  uint64
}

var nameRowTpl = template.Must(template.New("nrow").Parse(`<tr>
<td>{{.Domain}}</td>
<td class="idx"><a href="cert/{{.Index}}">{{.Index}}</a></td>
<td>{{.Count}}</td>
</tr>`))

var footTpl = template.Must(template.New("foot").Funcs(
	template.FuncMap{"urlquery": url.QueryEscape}).Parse(`<p>{{.Kind}}: {{.Count}} row(s){{if .HaveNext}}+ (page limit){{end}} in {{.Elapsed}} &middot; page {{.Page}}
{{if .PrevOK}}&nbsp; <a href="#" onclick="return goPrev()">&larr; prev</a>{{end}}
{{if .HaveNext}}&nbsp; <a href="search?q={{urlquery .Query}}&amp;after={{.NextAfter}}{{if .NextDom}}&amp;afterd={{urlquery .NextDom}}{{end}}&amp;page={{.NextPage}}">next page &rarr;</a>{{end}}</p>`))

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

// sseWriter frames output as server-sent events. Cloudflare and other
// buffering proxies pass text/event-stream through live, unlike HTML
// bodies which they hold until the response completes.
type sseWriter struct {
	w  io.Writer
	fl http.Flusher
	mu sync.Mutex
}

// send emits one event; multi-line data is split into separate data:
// lines per the SSE spec.
func (s *sseWriter) send(event, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event != "" {
		fmt.Fprintf(s.w, "event: %s\n", event)
	}
	for _, l := range strings.Split(data, "\n") {
		fmt.Fprintf(s.w, "data: %s\n", l)
	}
	io.WriteString(s.w, "\n")
	if s.fl != nil {
		s.fl.Flush()
	}
}

// beat emits a comment heartbeat so idle phases (long scans producing
// no rows) do not trip proxy idle timeouts (~100s on Cloudflare).
func (s *sseWriter) beat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	io.WriteString(s.w, ": hb\n\n")
	if s.fl != nil {
		s.fl.Flush()
	}
}

// tplStr renders a template into a string for SSE payloads.
func tplStr(t *template.Template, data any) string {
	var sb strings.Builder
	t.Execute(&sb, data)
	return sb.String()
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	acc := r.Header.Get("Accept")
	switch {
	case strings.Contains(acc, "text/event-stream"):
		searchSSE(w, r)
	case strings.Contains(acc, "text/html"):
		searchShell(w, r)
	default:
		searchInline(w, r) // curl/API clients: inline rows as before
	}
}

// runSearch executes the parsed query and calls emitRow per display
// row; emitStatus (may be nil) reports phase progress for streamed UIs.
// Returns the error text, row count, and pagination cursor.
func runSearch(qctx context.Context, pq parsed, after uint64, afterd string,
	emitRow func(row), emitName func(nameRow), emitStatus func(string)) (qErr string, count int, haveNext bool, lastIdx uint64, lastDom string) {

	var lastSt time.Time
	status := func(s string) {
		// throttle to one update per 2s - scans emit no rows, so these
		// are the only signs of life during a long phase-1
		if emitStatus != nil && time.Since(lastSt) > 2*time.Second {
			emitStatus(s)
			lastSt = time.Now()
		}
	}

	if pq.names {
		// distinct-name aggregation on certs - domain is its leading PK,
		// so exact/prefix filters seek and GROUP BY domain aggregates in
		// order (rows stream out progressively). Pages are alphabetical;
		// afterd carries the domain cursor.
		nwhere := "(" + pq.where + ")"
		nargs := append([]any{}, pq.args...)
		if afterd != "" {
			nwhere += " AND domain > ?"
			nargs = append(nargs, afterd)
		}
		nargs = append(nargs, *flagLimit+1)
		status("aggregating distinct names")
		nr, err := chConn.Query(qctx,
			`SELECT domain, max(cert_index) AS mi, count() AS c
			 FROM `+flagDBOr()+`.`+flagTableOr()+`
			 WHERE `+nwhere+`
			 GROUP BY domain
			 ORDER BY domain ASC
			 LIMIT ?`, nargs...)
		if err != nil {
			qErr = err.Error()
			return
		}
		defer nr.Close()
		for nr.Next() {
			var v nameRow
			if err := nr.Scan(&v.Domain, &v.Index, &v.Count); err != nil {
				qErr = "scan: " + err.Error()
				return
			}
			if count == *flagLimit {
				haveNext = true
				continue
			}
			lastDom = v.Domain
			emitName(v)
			count++
		}
		if err := nr.Err(); err != nil {
			qErr = err.Error()
		}
		return
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
			// phase-2 emits rows unsorted - the cursor must track the max
			// index seen (with its last-seen domain for the row-level
			// tiebreak), not whatever row happened to arrive last
			if rw.Index >= lastIdx {
				lastIdx, lastDom = rw.Index, rw.Domain
			}
			rw.Hostnames = shortNames(rw.Hostnames, 200)
			emitRow(rw)
			count++
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
		status("single scan running")
		rows, err := chConn.Query(qctx,
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
		p1table := flagDBOr() + "." + flagTableOr()
		p1where, p1args := where, args
		switch {
		case pq.domwhere != "" && flagDomOr() != "":
			// domain-scope predicates seek on certs_dom: the domain_rev
			// ordering turns suffix scopes into bounded prefix ranges
			p1table = flagDomOr()
			p1where = "(" + pq.domwhere + ")"
			p1args = append([]any{}, pq.domargs...)
			if after > 0 {
				p1where += " AND cert_index > ?"
				p1args = append(p1args, after)
			}
			p1args = append(p1args, *flagLimit+1)
		case pq.p1where != "" && flagIdxOr() != "":
			// domain-only predicates scan the narrow certs_idx instead - its
			// (cert_index, domain) sort order also lets ORDER BY cert_index
			// early-terminate at the LIMIT
			p1table = flagIdxOr()
			p1where = "(" + pq.p1where + ")"
			p1args = append([]any{}, pq.p1args...)
			if after > 0 {
				p1where += " AND cert_index > ?"
				p1args = append(p1args, after)
			}
			p1args = append(p1args, *flagLimit+1)
		}
		status("phase 1: finding matching cert_index values")
		idxRows, err := chConn.Query(qctx,
			`SELECT cert_index FROM `+p1table+`
			 WHERE `+p1where+`
			 ORDER BY cert_index ASC
			 LIMIT ?`, p1args...)
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
		if qErr == "" {
			if emitStatus != nil {
				emitStatus(fmt.Sprintf(
					"phase 2: fetching %d certificate(s)", len(indexes)))
			}
		}
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
			// re-apply the user's predicate: each row is one SAN, and a cert
			// covering both the searched name and unrelated SANs would else
			// show those siblings too. Domain-scope queries substitute the
			// SAN-exact p2where here - a bare subdomain has no root_domain
			// value and would match nothing otherwise. No ORDER BY - sorting
			// would make CH buffer every row before emitting the first;
			// granule order is fine and lets rows stream out as they are read.
			p2, p2a := where, args[:len(args)-1]
			if pq.p2where != "" {
				p2 = "(" + pq.p2where + ")"
				p2a = append([]any{}, pq.p2args...)
				if after > 0 {
					p2 += " AND cert_index > ?"
					p2a = append(p2a, after)
				}
			}
			pred = p2 + ` AND ` + pred
			rows, err := chConn.Query(qctx,
				`SELECT `+cols+` FROM `+flagDBOr()+`.`+flagTableOr()+`
				 WHERE `+pred, p2a...)
			if err != nil {
				qErr = err.Error()
			} else {
				// all rows of the selected indexes belong to this page -
				// the index count already limited it
				emit(rows, false)
			}
		}
	}
	if qErr != "" && qctx.Err() == context.DeadlineExceeded {
		qErr = fmt.Sprintf("query exceeded the %s server-side budget - too broad or too much load; try a narrower name", flagQTimeout)
	}
	return
}

// searchArgs pulls the query params shared by all response modes.
func searchArgs(r *http.Request) (q string, after uint64, afterd string, page int, pq parsed) {
	q = r.URL.Query().Get("q")
	after, _ = strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	afterd = r.URL.Query().Get("afterd")
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pq = parseQuery(q)
	return
}

type footData struct {
	Kind      string
	Count     int
	HaveNext  bool
	NextAfter uint64
	NextDom   string
	Elapsed   string
	Query     string
	Page      int
	PrevOK    bool
	NextPage  int
}

// searchShell serves the instant-loading page for browsers: markup and
// the loading widget only. A small script then opens an EventSource on
// the same URL (Accept: text/event-stream) and rows stream in live -
// this survives response-buffering proxies such as Cloudflare, which
// would otherwise hold the whole page until the query finishes.
func searchShell(w http.ResponseWriter, r *http.Request) {
	q, _, _, _, pq := searchArgs(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	headTpl.Execute(w, struct{ Query, Base string }{q, base})
	if q == "" {
		io.WriteString(w, "</body></html>")
		return
	}
	fmt.Fprintf(w, "<p>%s:</p>\n", template.HTMLEscapeString(pq.kind))
	header := `<tr><th>cert_index</th><th>seen</th><th>not_before</th><th>not_after</th>` +
		"<th>cn</th><th>names</th><th>serial</th><th>subject O</th></tr>"
	if pq.names {
		header = `<tr><th>name</th><th>latest cert_index</th><th>rows</th></tr>`
	}
	io.WriteString(w, `<div id="ld"><span class="spin"></span>`+
		`querying clickhouse&hellip; <span id="elt">0.0</span>s`+
		` &mdash; <span id="st">starting</span></div>`+"\n"+
		`<div class="tw" id="tw"><table>`+"\n"+header+"\n<tbody id=\"rt\"></tbody></table></div>\n"+
		`<script>var _t0=Date.now(),_tm=setInterval(function(){`+
		`var e=document.getElementById('elt');`+
		`if(!e){clearInterval(_tm);return}`+
		`e.textContent=((Date.now()-_t0)/1000).toFixed(1)},100);`+
		`var es=new EventSource(location.href),tb=document.getElementById('rt'),`+
		`tw=document.getElementById('tw');`+
		`function fin(){clearInterval(_tm);var l=document.getElementById('ld');`+
		`if(l)l.remove();es.close();}`+
		`es.addEventListener('row',function(e){tb.insertAdjacentHTML('beforeend',e.data)});`+
		`es.addEventListener('status',function(e){`+
		`var s=document.getElementById('st');if(s)s.textContent=e.data});`+
		`es.addEventListener('end',function(e){`+
		`tw.insertAdjacentHTML('afterend',e.data);fin()});`+
		`es.addEventListener('err',function(e){`+
		`tw.insertAdjacentHTML('afterend','<p class="err">'+`+
		`e.data.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</p>');fin()});`+
		`es.onerror=function(){`+
		`tw.insertAdjacentHTML('afterend','<p class="err">connection lost - the query may have died server-side; retry</p>');`+
		`fin()};</script>`+"\n</body></html>")
}

// searchSSE runs the query and streams one `row` event per result row
// plus a final `end` (footer html) or `err` event. Heartbeat comments
// keep the connection alive through proxies during long scans.
func searchSSE(w http.ResponseWriter, r *http.Request) {
	q, after, afterd, page, pq := searchArgs(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	sse := &sseWriter{w: w, fl: fl}

	qctx, qcancel := context.WithTimeout(r.Context(), *flagQTimeout)
	defer qcancel()

	hb := time.NewTicker(15 * time.Second)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-hb.C:
				sse.beat()
			}
		}
	}()
	defer hb.Stop()

	start := time.Now()
	qErr, count, haveNext, lastIdx, lastDom := runSearch(qctx, pq, after, afterd,
		func(rw row) { sse.send("row", tplStr(rowTpl, rw)) },
		func(nr nameRow) { sse.send("row", tplStr(nameRowTpl, nr)) },
		func(s string) { sse.send("status", s) })
	if qErr != "" {
		sse.send("err", qErr)
		return
	}
	sse.send("end", tplStr(footTpl, footData{
		pq.kind, count, haveNext, lastIdx, lastDom,
		time.Since(start).String(), q, page, page > 1, page + 1}))
}

// searchInline streams the plain-HTML page as before - for curl and
// other non-browser clients that cannot consume SSE.
func searchInline(w http.ResponseWriter, r *http.Request) {
	q, after, afterd, page, pq := searchArgs(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no") // let rows trickle through nginx
	headTpl.Execute(w, struct{ Query, Base string }{q, base})
	if q == "" {
		io.WriteString(w, "</body></html>")
		return
	}
	fl, _ := w.(http.Flusher)
	fmt.Fprintf(w, "<p>%s:</p>\n", template.HTMLEscapeString(pq.kind))
	header := `<tr><th>cert_index</th><th>seen</th><th>not_before</th><th>not_after</th>` +
		"<th>cn</th><th>names</th><th>serial</th><th>subject O</th></tr>"
	if pq.names {
		header = `<tr><th>name</th><th>latest cert_index</th><th>rows</th></tr>`
	}
	io.WriteString(w, `<div class="tw"><table>`+"\n"+header+"\n")
	if fl != nil {
		fl.Flush() // show the table skeleton while the query scans
	}

	qctx, qcancel := context.WithTimeout(r.Context(), *flagQTimeout)
	defer qcancel()

	start := time.Now()
	var n int
	qErr, count, haveNext, lastIdx, lastDom := runSearch(qctx, pq, after, afterd,
		func(rw row) {
			rowTpl.Execute(w, rw)
			if n++; fl != nil && n%16 == 0 {
				fl.Flush()
			}
		},
		func(nr nameRow) {
			nameRowTpl.Execute(w, nr)
			if n++; fl != nil && n%16 == 0 {
				fl.Flush()
			}
		}, nil)

	if qErr != "" {
		fmt.Fprintf(w, `</table></div><p class="err">%s</p>`, template.HTMLEscapeString(qErr))
	} else {
		io.WriteString(w, "</table></div>")
		footTpl.Execute(w, footData{
			pq.kind, count, haveNext, lastIdx, lastDom,
			time.Since(start).String(), q, page, page > 1, page + 1})
	}
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
	qctx, qcancel := context.WithTimeout(r.Context(), *flagQTimeout)
	defer qcancel()
	row := chConn.QueryRow(qctx,
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
func flagDomOr() string {
	if *flagDomTable == "" {
		return ""
	}
	return flagDBOr() + "." + *flagDomTable
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
