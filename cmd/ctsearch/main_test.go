package main

import "testing"

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
