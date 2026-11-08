package certificatetransparency

import (
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/crypto/cryptobyte"
)

// benchFixtures holds realistic certificates and log entries used by the
// benchmarks. Real CT entries are mostly RSA-2048 leaf certs with a 2-cert
// chain and ~2KB of DER, so the fixtures mirror that shape.
type benchFixtures struct {
	leafDER  []byte
	interDER []byte
	rootDER  []byte

	x509Entry   *ct.RawLogEntry
	precert     *ct.RawLogEntry
	tileData    []byte
	parsedEntry models.Entry
}

var (
	fixturesOnce sync.Once
	fixtures     *benchFixtures
	fixturesErr  error
)

func mustCreateCert(tb testing.TB, tmpl, parent *stdx509.Certificate, pub any, priv any) []byte {
	tb.Helper()

	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		tb.Fatalf("creating certificate: %v", err)
	}

	return der
}

func buildFixtures(tb testing.TB) *benchFixtures {
	tb.Helper()

	fixturesOnce.Do(func() {
		rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fixturesErr = err
			return
		}
		interKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fixturesErr = err
			return
		}
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fixturesErr = err
			return
		}

		notBefore := time.Unix(1700000000, 0)
		notAfter := time.Unix(1800000000, 0)

		rootTmpl := &stdx509.Certificate{
			SerialNumber:          big.NewInt(0x1000),
			Subject:               pkix.Name{CommonName: "Bench Root CA", Organization: []string{"Bench CA"}, Country: []string{"DE"}},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
			SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		}
		rootDER := mustCreateCert(tb, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

		interTmpl := &stdx509.Certificate{
			SerialNumber:          big.NewInt(0x2000),
			Subject:               pkix.Name{CommonName: "Bench Intermediate CA", Organization: []string{"Bench CA"}, Country: []string{"DE"}},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
			SubjectKeyId:          []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
			AuthorityKeyId:        rootTmpl.SubjectKeyId,
		}
		interDER := mustCreateCert(tb, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)

		leafTmpl := &stdx509.Certificate{
			SerialNumber: big.NewInt(0x0abcdef12345),
			Subject: pkix.Name{
				CommonName:   "www.bench-example.com",
				Organization: []string{"Bench Org"},
				Country:      []string{"DE"},
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			DNSNames:              []string{"www.bench-example.com", "bench-example.com", "api.bench-example.com", "cdn.bench-example.com", "mail.bench-example.com"},
			KeyUsage:              stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth, stdx509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			SubjectKeyId:          []byte{41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60},
			AuthorityKeyId:        interTmpl.SubjectKeyId,
			IssuingCertificateURL: []string{"http://ca.bench-example.com/inter.crt"},
			OCSPServer:            []string{"http://ocsp.bench-example.com"},
			PolicyIdentifiers:     []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 2}, {1, 3, 6, 1, 4, 1, 44947, 1, 1, 1}},
			CRLDistributionPoints: []string{"http://ca.bench-example.com/root.crl"},
		}
		leafDER := mustCreateCert(tb, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)

		chain := []ct.ASN1Cert{{Data: interDER}, {Data: rootDER}}

		x509Entry := makeX509RawLogEntry(leafDER, 12345678)
		x509Entry.Chain = chain

		precert := makePrecertRawLogEntry(tb, leafDER, 12345678)
		precert.Chain = chain

		tile := buildBenchTile(tb, leafDER)

		parsed, err := ParseCertstreamEntry(x509Entry, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962)
		if err != nil {
			fixturesErr = err
			return
		}

		fixtures = &benchFixtures{
			leafDER:     leafDER,
			interDER:    interDER,
			rootDER:     rootDER,
			x509Entry:   x509Entry,
			precert:     precert,
			tileData:    tile,
			parsedEntry: parsed,
		}
	})

	if fixturesErr != nil {
		tb.Fatalf("building fixtures: %v", fixturesErr)
	}

	return fixtures
}

// buildBenchTile builds a 256-leaf data tile shaped like a real static-CT
// tile: each x509 leaf carries ~2KB cert DER plus two issuer fingerprints.
func buildBenchTile(tb testing.TB, certDER []byte) []byte {
	tb.Helper()

	var fp [32]byte
	if _, err := rand.Read(fp[:]); err != nil {
		tb.Fatalf("generating fingerprint: %v", err)
	}

	var b cryptobyte.Builder
	for i := range uint64(TileSize) {
		b.AddUint64(1700000000000 + i)
		b.AddUint16(EntryTypeCert)
		b.AddUint24LengthPrefixed(func(bb *cryptobyte.Builder) { bb.AddBytes(certDER) })
		b.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
		b.AddUint16LengthPrefixed(func(bb *cryptobyte.Builder) {
			bb.AddBytes(fp[:])
			bb.AddBytes(fp[:])
		})
	}

	data, err := b.Bytes()
	if err != nil {
		tb.Fatalf("building tile: %v", err)
	}

	return data
}

// --- Parse path benchmarks ---

func BenchmarkParseCertstreamEntryFull(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := ParseCertstreamEntry(f.x509Entry, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

func BenchmarkParseCertstreamEntrySlim(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := ParseCertstreamEntrySlim(f.x509Entry, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

func BenchmarkParseCertstreamEntryPrecert(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := ParseCertstreamEntry(f.precert, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

func BenchmarkParseCertstreamEntryPrecertSlim(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := ParseCertstreamEntrySlim(f.precert, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

// BenchmarkX509ParseChainCert measures the cost a chain cache would avoid:
// one x509 parse + leafCertFromX509cert per chain element.
func BenchmarkX509ParseChainCert(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		cert, err := x509.ParseCertificate(f.interDER)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		_ = leafCertFromX509cert(*cert, true, cert.Raw)
	}
}

func BenchmarkX509ParseLeafOnly(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := x509.ParseCertificate(f.leafDER); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

// --- Tile parsing benchmarks ---

func BenchmarkParseTileData(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := ParseTileData(f.tileData); err != nil {
			b.Fatalf("ParseTileData: %v", err)
		}
	}
}

// --- Marshal path benchmarks ---

func BenchmarkEntryMarshalFull(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = f.parsedEntry.JSONNoCache()
	}
}

func BenchmarkEntryMarshalLite(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		// Mirror the dispatcher: strip chain + DER on a private copy, marshal.
		entry := f.parsedEntry
		entry.Data.Chain = nil
		entry.Data.LeafCert.AsDER = ""
		_ = entry.JSONNoCache()
	}
}

func BenchmarkEntryMarshalDomains(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = f.parsedEntry.JSONDomains()
	}
}

// BenchmarkEndToEnd approximates the per-cert CPU the server pays with all
// three client types connected: full parse + all three marshals.
func BenchmarkEndToEnd(b *testing.B) {
	f := buildFixtures(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		entry, err := ParseCertstreamEntry(f.x509Entry, "BenchOperator", "bench-log", "https://ct.bench-example.com", models.SourceIsRFC6962)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		_ = entry.JSONNoCache()
		_ = entry.JSONDomains()
		entry.Data.Chain = nil
		entry.Data.LeafCert.AsDER = ""
		_ = entry.JSONNoCache()
	}
}
