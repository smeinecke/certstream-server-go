package certificatetransparency

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

// makeTestCert creates a self-signed certificate for testing using the stdlib
// encoder, then parses it with the CT fork's x509 package (what the parser uses).
func makeTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1800000000, 0),
		DNSNames:              []string{"test.example.com", "www.test.example.com"},
		KeyUsage:              stdx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return cert
}

// makeTestCertDER returns the DER bytes of a test certificate.
func makeTestCertDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1800000000, 0),
		DNSNames:              []string{"test.example.com", "www.test.example.com"},
		KeyUsage:              stdx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	return der
}

// makeX509RawLogEntry builds a RawLogEntry wrapping the given cert DER.
func makeX509RawLogEntry(der []byte, index int64) *ct.RawLogEntry {
	return &ct.RawLogEntry{
		Index: index,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: 1700000000000,
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: der},
			},
		},
		Cert: ct.ASN1Cert{Data: der},
	}
}

// extractTBS returns the DER of the tbsCertificate inside a Certificate.
func extractTBS(t *testing.T, certDER []byte) []byte {
	t.Helper()

	var certRaw asn1.RawValue
	if _, err := asn1.Unmarshal(certDER, &certRaw); err != nil {
		t.Fatalf("unmarshaling certificate: %v", err)
	}

	var tbsRaw asn1.RawValue
	if _, err := asn1.Unmarshal(certRaw.Bytes, &tbsRaw); err != nil {
		t.Fatalf("unmarshaling tbsCertificate: %v", err)
	}

	return tbsRaw.FullBytes
}

// makePrecertRawLogEntry builds a precert RawLogEntry: the leaf carries the
// TBSCertificate, while Cert carries the submitted precert DER.
func makePrecertRawLogEntry(t *testing.T, precertDER []byte, index int64) *ct.RawLogEntry {
	t.Helper()

	tbsDER := extractTBS(t, precertDER)

	return &ct.RawLogEntry{
		Index: index,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: 1700000000000,
				EntryType: ct.PrecertLogEntryType,
				PrecertEntry: &ct.PreCert{
					IssuerKeyHash:  [32]byte{1, 2, 3},
					TBSCertificate: tbsDER,
				},
			},
		},
		Cert: ct.ASN1Cert{Data: precertDER},
	}
}

func TestCalculateHash(t *testing.T) {
	// SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
	got := calculateSHA1([]byte{})
	want := "DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09"
	if got != want {
		t.Fatalf("calculateSHA1(\"\") = %q, want %q", got, want)
	}

	// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	got = calculateSHA256([]byte("abc"))
	want = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
	if got != want {
		t.Fatalf("calculateSHA256(\"abc\") = %q, want %q", got, want)
	}
}

func TestFormatKeyID(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, "keyid:"},
		{"single byte", []byte{0xab}, "keyid:ab"},
		{"multi byte", []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, "keyid:01:23:45:67:89:ab:cd:ef"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatKeyID(tc.input)
			if got == nil {
				t.Fatal("formatKeyID returned nil")
			}
			if *got != tc.want {
				t.Fatalf("formatKeyID(%x) = %q, want %q", tc.input, *got, tc.want)
			}
		})
	}
}

func TestParseName(t *testing.T) {
	if got := parseName(nil); got != nil {
		t.Fatalf("parseName(nil) = %v, want nil", *got)
	}

	got := parseName([]string{})
	if got == nil || *got != "" {
		t.Fatalf("parseName([]) = %v, want pointer to empty string", got)
	}

	got = parseName([]string{"a"})
	if got == nil || *got != "a" {
		t.Fatalf("parseName([a]) = %v, want \"a\"", got)
	}

	got = parseName([]string{"a", "b", "c"})
	if got == nil || *got != "a,b,c" {
		t.Fatalf("parseName([a b c]) = %v, want \"a,b,c\"", got)
	}
}

func TestFormatSerialNumber(t *testing.T) {
	if got := formatSerialNumber(big.NewInt(0x1234)); got != "1234" {
		t.Fatalf("formatSerialNumber(0x1234) = %q, want \"1234\"", got)
	}

	// Odd-length hex must be zero-padded
	if got := formatSerialNumber(big.NewInt(0xabc)); got != "0ABC" {
		t.Fatalf("formatSerialNumber(0xabc) = %q, want \"0ABC\"", got)
	}
}

func TestLeafCertFromX509certUsesProvidedHashData(t *testing.T) {
	cert := makeTestCert(t)

	hashInput := []byte("deliberately-different-input")
	leaf := leafCertFromX509cert(*cert, hashInput)

	wantFP := calculateSHA1(hashInput)
	if leaf.Fingerprint != wantFP {
		t.Fatalf("leaf.Fingerprint = %q, want hash of provided input %q", leaf.Fingerprint, wantFP)
	}
	if leaf.SHA1 != wantFP {
		t.Fatalf("leaf.SHA1 = %q, want %q", leaf.SHA1, wantFP)
	}
	if leaf.SHA256 != calculateSHA256(hashInput) {
		t.Fatalf("leaf.SHA256 = %q, want %q", leaf.SHA256, calculateSHA256(hashInput))
	}

	// Must NOT equal the hash of cert.Raw - that would mean the input was ignored
	if leaf.Fingerprint == calculateSHA1(cert.Raw) {
		t.Fatal("leaf.Fingerprint was calculated from cert.Raw instead of provided hashData")
	}
}

func TestLeafCertFromX509certBasicConstraints(t *testing.T) {
	cert := makeTestCert(t)

	leaf := leafCertFromX509cert(*cert, cert.Raw)

	if leaf.Extensions.BasicConstraints == nil {
		t.Fatal("BasicConstraints extension not set")
	}
	if *leaf.Extensions.BasicConstraints != "CA:FALSE" {
		t.Fatalf("BasicConstraints = %q, want \"CA:FALSE\"", *leaf.Extensions.BasicConstraints)
	}

	if !containsAll(leaf.AllDomains, []string{"test.example.com", "www.test.example.com"}) {
		t.Fatalf("AllDomains = %v, missing test domains", leaf.AllDomains)
	}
	if leaf.SerialNumber != "1234" {
		t.Fatalf("SerialNumber = %q, want \"1234\"", leaf.SerialNumber)
	}
}

func containsAll(haystack, needles []string) bool {
	set := make(map[string]bool, len(haystack))
	for _, h := range haystack {
		set[h] = true
	}
	for _, n := range needles {
		if !set[n] {
			return false
		}
	}
	return true
}

// TestParseCertstreamEntryX509 exercises the full parse path for a regular cert.
func TestParseCertstreamEntryX509(t *testing.T) {
	der := makeTestCertDER(t)
	rawEntry := makeX509RawLogEntry(der, 12345)

	entry, err := ParseCertstreamEntry(rawEntry, "TestOperator", "test-log", "https://ct.example.com", "rfc6962")
	if err != nil {
		t.Fatalf("ParseCertstreamEntry: %v", err)
	}

	if entry.Data.CertIndex != 12345 {
		t.Fatalf("CertIndex = %d, want 12345", entry.Data.CertIndex)
	}
	if entry.MessageType != "certificate_update" {
		t.Fatalf("MessageType = %q", entry.MessageType)
	}
	if entry.Data.LeafCert.AsDER == "" {
		t.Fatal("parse produced empty AsDER")
	}
	if !containsAll(entry.Data.LeafCert.AllDomains, []string{"test.example.com", "www.test.example.com"}) {
		t.Fatalf("AllDomains = %v", entry.Data.LeafCert.AllDomains)
	}

	// For x509 entries the fingerprint hashes the raw cert DER.
	if want := calculateSHA1(der); entry.Data.LeafCert.Fingerprint != want {
		t.Fatalf("Fingerprint = %q, want %q", entry.Data.LeafCert.Fingerprint, want)
	}
}

// TestParseCertstreamEntryPrecert verifies precerts hash the submitted precert
// DER (not the TBS), matching prior behavior.
func TestParseCertstreamEntryPrecert(t *testing.T) {
	der := makeTestCertDER(t)
	rawEntry := makePrecertRawLogEntry(t, der, 999)

	entry, err := ParseCertstreamEntry(rawEntry, "TestOperator", "test-log", "https://ct.example.com", "rfc6962")
	if err != nil {
		t.Fatalf("ParseCertstreamEntry: %v", err)
	}

	// Fingerprint must be the hash of the submitted precert bytes
	if want := calculateSHA1(der); entry.Data.LeafCert.Fingerprint != want {
		t.Fatalf("Fingerprint = %q, want hash of submitted precert %q", entry.Data.LeafCert.Fingerprint, want)
	}

	// And explicitly not the TBS hash
	tbsHash := calculateSHA1(extractTBS(t, der))
	if entry.Data.LeafCert.Fingerprint == tbsHash {
		t.Fatal("Fingerprint was computed over TBS, not submitted precert data")
	}

	if !entry.Data.LeafCert.Extensions.CTLPoisonByte {
		t.Fatal("CTLPoisonByte not set for precert")
	}
}
