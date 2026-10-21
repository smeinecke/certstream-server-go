package certificatetransparency

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

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
		t.Fatal("full parse produced empty AsDER")
	}
}

// TestParseCertstreamEntrySlimEquivalence verifies slim mode produces identical
// leaf fields to the full parser, minus chain and DER materialization.
func TestParseCertstreamEntrySlimEquivalence(t *testing.T) {
	der := makeTestCertDER(t)
	rawEntry := makeX509RawLogEntry(der, 777)

	full, err := ParseCertstreamEntry(rawEntry, "op", "log", "https://ct.example.com", "rfc6962")
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}
	slim, err := ParseCertstreamEntrySlim(rawEntry, "op", "log", "https://ct.example.com", "rfc6962")
	if err != nil {
		t.Fatalf("slim parse: %v", err)
	}

	if len(slim.Data.Chain) != 0 {
		t.Fatalf("slim chain has %d entries, want 0", len(slim.Data.Chain))
	}
	if slim.Data.LeafCert.AsDER != "" {
		t.Fatal("slim leaf has AsDER set")
	}

	// Every field a lite consumer relies on must be identical.
	if slim.Data.LeafCert.Fingerprint != full.Data.LeafCert.Fingerprint {
		t.Fatal("fingerprint mismatch between slim and full parse")
	}
	if slim.Data.LeafCert.SHA256 != full.Data.LeafCert.SHA256 {
		t.Fatal("SHA256 mismatch between slim and full parse")
	}
	if slim.Data.LeafCert.SerialNumber != full.Data.LeafCert.SerialNumber {
		t.Fatal("serial mismatch between slim and full parse")
	}
	if len(slim.Data.LeafCert.AllDomains) != len(full.Data.LeafCert.AllDomains) {
		t.Fatal("AllDomains mismatch between slim and full parse")
	}
	if slim.Data.CertIndex != full.Data.CertIndex {
		t.Fatal("CertIndex mismatch")
	}
}
