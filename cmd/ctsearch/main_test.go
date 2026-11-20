package main

import (
	"strings"
	"testing"
)

func TestDomScope(t *testing.T) {
	w, args := domScope("github.com")
	if w != `domain_rev = ? OR startsWith(domain_rev, ?)` {
		t.Fatalf("unexpected predicate: %s", w)
	}
	if args[0] != "moc.buhtig" || args[1] != "moc.buhtig." {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseQueryDomScope(t *testing.T) {
	cases := []struct {
		q          string
		wantDom    bool   // domwhere must be set
		wantPrefix string // expected prefix arg for startsWith
	}{
		{"github.com", true, "moc.buhtig."},         // plain domain: apex + subdomains
		{"%.github.com", true, "moc.buhtig."},       // suffix: same coverage
		{"*.co.uk", true, "ku.oc."},                 // deeper suffix
		{"%.de", true, "ed."},                       // bare TLD
		{"%foo.github.com", true, "moc.buhtig.oof"}, // leading-wildcard suffix
		{"%foo%bar", false, ""},                     // substring: stays on certs_idx
		{"git%.com", false, ""},                     // literal prefix: PK range on certs
		{"12345", false, ""},                        // cert index
		{"cn:test", false, ""},                      // cn lookup
		{"names:github.com", false, ""},             // names aggregation on certs
	}
	for _, c := range cases {
		p := parseQuery(c.q)
		if c.wantDom {
			if p.domwhere == "" {
				t.Fatalf("%q: domwhere empty, want set", c.q)
			}
			found := false
			for _, a := range p.domargs {
				if s, ok := a.(string); ok && s == c.wantPrefix {
					found = true
				}
			}
			if !found {
				t.Fatalf("%q: domargs %v lacks prefix %q", c.q, p.domargs, c.wantPrefix)
			}
		} else if p.domwhere != "" {
			t.Fatalf("%q: domwhere %q set unexpectedly", c.q, p.domwhere)
		}
	}
}

func TestParseQuerySubdomainPhase2(t *testing.T) {
	// A bare subdomain like www.google.com has no root_domain value of
	// its own - phase 2 must filter by the SAN-exact predicate instead
	// or every result row is filtered out.
	p := parseQuery("www.google.com")
	if p.p2where != `domain = ? OR endsWith(domain, ?)` {
		t.Fatalf("p2where = %q, want SAN-exact predicate", p.p2where)
	}
	if p.p2args[0] != "www.google.com" || p.p2args[1] != ".www.google.com" {
		t.Fatalf("p2args = %v", p.p2args)
	}
	if p.domwhere == "" {
		t.Fatal("domwhere empty - phase 1 must range-seek certs_dom")
	}
}

func TestParseQueryDomainKeyword(t *testing.T) {
	// domain: searches the root_domain field literally. For a valid
	// eTLD+1 input, phase 1 can still seek certs_dom (scope is exactly
	// equivalent) while phase 2 re-applies root_domain = ? verbatim.
	p := parseQuery("domain:github.com")
	if p.where != `root_domain = ?` || p.args[0] != "github.com" {
		t.Fatalf("where/args = %q %v", p.where, p.args)
	}
	if p.p2where != `root_domain = ?` || p.p2args[0] != "github.com" {
		t.Fatalf("p2 = %q %v - root_domain must be re-applied", p.p2where, p.p2args)
	}
	if p.domwhere == "" {
		t.Fatal("eTLD+1 input should still phase-1 through certs_dom")
	}

	// A public suffix is not a valid eTLD+1 - no certs_dom shortcut or
	// co.uk would wrongly cover every domain under the suffix.
	p = parseQuery("domain:co.uk")
	if p.where != `root_domain = ?` || p.args[0] != "co.uk" {
		t.Fatalf("where/args = %q %v", p.where, p.args)
	}
	if p.domwhere != "" {
		t.Fatalf("domwhere %q set for public-suffix input", p.domwhere)
	}

	// A deeper name is not eTLD+1 either - stays literal.
	p = parseQuery("domain:www.github.com")
	if p.domwhere != "" {
		t.Fatalf("domwhere set for non-eTLD+1 input: %q", p.domwhere)
	}
	if p.args[0] != "www.github.com" {
		t.Fatalf("args = %v", p.args)
	}
}

func TestNamesQueryPublicSuffixPrefilter(t *testing.T) {
	// names:%.x.github.io - github.io is a public suffix, so the
	// root_domain prefilter must be the eTLD+1 (x.github.io), not the
	// last two labels (github.io can never be a root_domain).
	p := parseQuery("names:%.x.github.io")
	want := `root_domain = ? AND (domain = ? OR endsWith(domain, ?))`
	if p.where != want {
		t.Fatalf("where = %q", p.where)
	}
	if p.args[0] != "x.github.io" || p.args[1] != "x.github.io" || p.args[2] != ".x.github.io" {
		t.Fatalf("args = %v", p.args)
	}

	// names:%.github.io - the suffix IS a public suffix: no eTLD+1
	// exists, so no root_domain prefilter is possible (scan instead of
	// the wrong empty result lastTwoLabels produced before).
	p = parseQuery("names:%.github.io")
	if want := `domain = ? OR endsWith(domain, ?)`; p.where != want {
		t.Fatalf("where = %q, want %q", p.where, want)
	}
}

func TestParseQueryIssuer(t *testing.T) {
	p := parseQuery("issuer:Let's Encrypt")
	if p.kind != "issuer" || len(p.args) != 1 || p.args[0] != "Let's Encrypt" {
		t.Fatalf("issuer parse = %+v", p)
	}
	if !strings.Contains(p.where, "issuer") {
		t.Fatalf("where = %q", p.where)
	}
}

func TestNormKeyIDAndParse(t *testing.T) {
	cases := map[string]string{
		"90:77:92:35":       "keyid:90:77:92:35",
		"keyid:90:77:92:35": "keyid:90:77:92:35",
		"90779235":          "keyid:90:77:92:35",
		"KEYID:90:77:92:35": "keyid:90:77:92:35",
		"90-77-92-35":       "keyid:90:77:92:35",
		"90 77 92 35":       "keyid:90:77:92:35",
		"":                  "",
		"zz":                "",
		"907":               "", // odd hex count
	}
	for in, want := range cases {
		if got := normKeyID(in); got != want {
			t.Fatalf("normKeyID(%q) = %q, want %q", in, got, want)
		}
	}
	p := parseQuery("aki:90779235")
	if p.kind != "authority key id" || p.args[0] != "keyid:90:77:92:35" {
		t.Fatalf("aki parse = %+v", p)
	}
	p = parseQuery("ski:keyid:90779235")
	if p.kind != "subject key id" || p.args[0] != "keyid:90:77:92:35" {
		t.Fatalf("ski parse = %+v", p)
	}
	if p := parseQuery("aki:not-hex-ok"); p.where != `1 = 0` {
		t.Fatalf("invalid aki should match nothing, got %q", p.where)
	}
}

func TestIssuerCN(t *testing.T) {
	if got := issuerCN("/C=US/O=Let's Encrypt/CN=R11"); got != "R11" {
		t.Fatalf("got %q", got)
	}
	if got := issuerCN("/C=US/OU=ca.example"); got != "OU=ca.example" {
		t.Fatalf("no-CN fallback got %q", got)
	}
	if got := issuerCN(""); got != "" {
		t.Fatalf("empty got %q", got)
	}
}

func TestHlTermsAndText(t *testing.T) {
	// wildcard fragments become highlight terms
	p := parseQuery("*foo*bar*")
	if terms := hlTerms(p); len(terms) != 2 || terms[0] != "foo" || terms[1] != "bar" {
		t.Fatalf("terms = %v", terms)
	}
	// plain domain highlights itself
	p = parseQuery("github.com")
	if terms := hlTerms(p); len(terms) == 0 || terms[0] != "github.com" {
		t.Fatalf("terms = %v", terms)
	}
	// fingerprint queries produce no name highlights
	p = parseQuery("fp:abc")
	if terms := hlTerms(p); len(terms) != 0 {
		t.Fatalf("terms = %v", terms)
	}
	// escaping is kept, matches are case-insensitive and marked
	out := string(hlText("x<FOO.bar", []string{"foo."}))
	if out != "x&lt;<mark>FOO.</mark>bar" {
		t.Fatalf("out = %q", out)
	}
}

func TestParseQueryNewFilters(t *testing.T) {
	cases := []struct {
		q, kind, wantWhere string
	}{
		{"c:tw", "subject C", `upper(c) = ?`},
		{"o:google", "subject O", `positionCaseInsensitive(o, ?) > 0`},
		{"ou:pki", "subject OU", `positionCaseInsensitive(ou, ?) > 0`},
		{"ca:", "CA certs", `basic_constraints = 'CA:TRUE'`},
		{"ca:0", "not CA", `basic_constraints != 'CA:TRUE'`},
		{"selfsigned:", "self-signed", `issuer != '' AND issuer = aggregated`},
		{"wildcard:", "wildcard names", `domain LIKE '*%'`},
		{"valid:", "currently valid", `not_before <= ? AND not_after >= ?`},
	}
	for _, c := range cases {
		p := parseQuery(c.q)
		if p.kind != c.kind || p.where != c.wantWhere {
			t.Fatalf("%q: kind=%q where=%q", c.q, p.kind, p.where)
		}
	}
}

func TestParseQueryTimeSpec(t *testing.T) {
	p := parseQuery("exp<30d")
	if !strings.Contains(p.where, "not_after < ?") {
		t.Fatalf("exp<30d where = %q", p.where)
	}
	p = parseQuery("nb>7d")
	if !strings.Contains(p.where, "not_before > ?") {
		t.Fatalf("nb>7d where = %q", p.where)
	}
	if op, ts, ok := timeSpec("<1735689600"); !ok || op != "<" || ts != 1735689600 {
		t.Fatalf("epoch timespec = %q %d %v", op, ts, ok)
	}
	if _, _, ok := timeSpec("x30d"); ok {
		t.Fatal("invalid timespec should fail")
	}
}

func TestSplitTermsCompound(t *testing.T) {
	cases := map[string][]string{
		"a.com b.com":                  {"a.com", "b.com"},
		`issuer:"Let's Encrypt" a.com`: {"issuer:Let's Encrypt", "a.com"},
		"issuer:Let's Encrypt":         {"issuer:Let's Encrypt"},
		"issuer:R11 github.com":        {"issuer:R11", "github.com"},
		"o:Go Daddy a.com":             {"o:Go Daddy", "a.com"},
	}
	for in, want := range cases {
		got := splitTerms(in)
		if len(got) != len(want) {
			t.Fatalf("%q -> %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q -> %v, want %v", in, got, want)
			}
		}
	}
}

func TestParseQueryCompound(t *testing.T) {
	// domain + non-domain: dom index path survives, phase-2 is OR-domain AND-other
	p := parseQuery("github.com issuer:encrypt")
	if p.domwhere == "" {
		t.Fatal("compound lost domwhere")
	}
	if !strings.Contains(p.where, "OR") || !strings.Contains(p.where, "issuer") {
		t.Fatalf("compound where = %q", p.where)
	}
	// two domains: phase-1 intersects cert_index sets on certs_dom
	p = parseQuery("a.com b.com")
	if !strings.Contains(p.domwhere, "cert_index IN (SELECT") {
		t.Fatalf("multi-domain domwhere = %q", p.domwhere)
	}
	// selective term makes compound single-phase
	p = parseQuery("a.com fp:abc123")
	if !p.single {
		t.Fatal("fp: term should make compound single-phase")
	}
	// names: swallows its whole remainder before term splitting
	p = parseQuery("names:a.com")
	if !p.names {
		t.Fatal("names: should still parse as names query")
	}
}

func TestParseQuerySuffixCoversApex(t *testing.T) {
	// %.github.com keeps the certs-side predicate for phase-2 row
	// suppression AND gains the certs_dom range for phase-1.
	p := parseQuery("%.github.com")
	if p.where == "" || len(p.args) == 0 {
		t.Fatal("suffix query lost its certs-side predicate")
	}
	if p.domwhere == "" {
		t.Fatal("suffix query has no domwhere")
	}
}
