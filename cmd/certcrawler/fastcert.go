package main

// Minimal DER walker for CT leaf certificates.
//
// certcrawler only stores a handful of leaf fields per entry (serial,
// validity, subject, signature algorithm, a few extensions), so walking the
// DER directly is several times cheaper than x509.ParseCertificate - no
// public-key decoding, no signature verification setup, no chain handling.

import (
	"crypto/sha1" //nolint:gosec
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	ct "github.com/google/certificate-transparency-go"
	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/net/publicsuffix"
)

var (
	oidExtSAN    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtSKID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtAKI    = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtBC     = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKU     = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtCP     = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtAIA    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	oidAttrCN    = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidAttrC     = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidAttrL     = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidAttrStreet = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidAttrO     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidAttrOU    = asn1.ObjectIdentifier{2, 5, 4, 11}

	oidAIAOCSP      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAIACaIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// hashOIDs map RSASSA-PSS hash algorithm OIDs to names.
var pssHashByOID = map[string]string{
	"1.3.14.3.2.26":          "sha1",
	"2.16.840.1.101.3.4.2.4": "sha224",
	"2.16.840.1.101.3.4.2.1": "sha256",
	"2.16.840.1.101.3.4.2.2": "sha384",
	"2.16.840.1.101.3.4.2.3": "sha512",
}

// sigAlgByOID maps signature algorithm OIDs to the same strings the full
// parser emits via parseSignatureAlgorithm.
var sigAlgByOID = map[string]string{
	"1.2.840.113549.1.1.2":   "md2, rsa",
	"1.2.840.113549.1.1.4":   "md5, rsa",
	"1.2.840.113549.1.1.5":   "sha1, rsa",
	"1.2.840.113549.1.1.11":  "sha256, rsa",
	"1.2.840.113549.1.1.12":  "sha384, rsa",
	"1.2.840.113549.1.1.13":  "sha512, rsa",
	"1.2.840.10040.4.3":      "dsa, sha1",
	"2.16.840.1.101.3.4.3.2": "dsa, sha256",
	"1.2.840.10045.4.1":      "ecdsa, sha1",
	"1.2.840.10045.4.3.2":    "ecdsa, sha256",
	"1.2.840.10045.4.3.3":    "ecdsa, sha384",
	"1.2.840.10045.4.3.4":    "ecdsa, sha512",
	"1.3.101.112":            "ed25519",
}

// fastFields holds the leaf-cert fields the crawler stores, in row-ready form.
type fastFields struct {
	sanDNS   []string
	sanEmail []string
	sanIP    []string

	subjectC, subjectL, subjectO, subjectOU, subjectST []string
	subjectCN string

	serial    string
	notBefore int64
	notAfter  int64
	sigAlg    string

	aia, aki, bc, cp, ku, san, skid string
	isCA                           bool
}

// colonHexUpper formats bytes as "AA:BB:..." (hash format used upstream).
func colonHexUpper(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b)*3 - 1)
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", c)
	}
	return sb.String()
}

// keyID formats a key identifier the same way formatKeyID does: lowercase hex
// with colon separators, prefixed with "keyid:".
func keyID(b []byte) string {
	tmp := hex.EncodeToString(b)
	var sb strings.Builder
	sb.WriteString("keyid:")
	for i := 0; i+1 < len(tmp); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(tmp[i : i+2])
	}
	return sb.String()
}

// serialToHex renders an INTEGER serial the same way formatSerialNumber does:
// uppercase hex of the magnitude, odd length padded with a leading zero.
func serialToHex(serial []byte) string {
	// INTEGER content may carry a leading 0x00 sign byte - drop it.
	for len(serial) > 1 && serial[0] == 0 {
		serial = serial[1:]
	}
	sn := strings.ToUpper(hex.EncodeToString(serial))
	if len(sn)%2 == 1 {
		sn = "0" + sn
	}
	return sn
}

func atoiN(b []byte) int {
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int(c-'0')
	}
	return v
}

// parseDERTime decodes UTCTime/GeneralizedTime content bytes to unix seconds.
func parseDERTime(b []byte) int64 {
	// UTCTime: YYMMDDHHMMSS[Z|+hhmm|-hhmm]
	// GeneralizedTime: YYYYMMDDHHMMSS[.frac][Z|offset]
	var year int
	if len(b) <= 13 { // YYMMDDHHMMSSZ
		year = atoiN(b[0:2])
		if year < 50 {
			year += 2000
		} else {
			year += 1900
		}
		b = b[2:]
	} else {
		year = atoiN(b[0:4])
		b = b[4:]
	}
	if len(b) < 10 {
		return 0
	}
	t := time.Date(year, time.Month(atoiN(b[0:2])), atoiN(b[2:4]),
		atoiN(b[4:6]), atoiN(b[6:8]), atoiN(b[8:10]), 0, time.UTC)
	return t.Unix()
}

// readStringValue decodes a DirectoryString-ish value to Go string.
// The element (tag+len+content) is consumed from s.
func readStringValue(s *cryptobyte.String) string {
	var el cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&el, &tag) {
		return ""
	}
	var content cryptobyte.String
	if !el.ReadASN1(&content, tag) {
		return ""
	}
	switch tag {
	case cbasn1.Tag(30):
		var u16 []uint16
		rb := []byte(content)
		for i := 0; i+1 < len(rb); i += 2 {
			u16 = append(u16, uint16(rb[i])<<8|uint16(rb[i+1]))
		}
		return string(utf16.Decode(u16))
	case cbasn1.Tag(28):
		var u32 []rune
		rb := []byte(content)
		for i := 0; i+3 < len(rb); i += 4 {
			u32 = append(u32, rune(uint32(rb[i])<<24|uint32(rb[i+1])<<16|
				uint32(rb[i+2])<<8|uint32(rb[i+3])))
		}
		return string(u32)
	default:
		// UTF8String, PrintableString, IA5String, T61String etc - take raw
		return string(content)
	}
}

// walkName consumes the RDNSequence content (series of SET OF AttributeTypeAndValue)
// and records the subject attributes the crawler stores.
func walkName(rdns cryptobyte.String, f *fastFields) {
	for !rdns.Empty() {
		var rdn cryptobyte.String
		if !rdns.ReadASN1(&rdn, cbasn1.SET) {
			break
		}
		for !rdn.Empty() {
			var atav cryptobyte.String
			if !rdn.ReadASN1(&atav, cbasn1.SEQUENCE) {
				break
			}
			var oid asn1.ObjectIdentifier
			if !atav.ReadASN1ObjectIdentifier(&oid) {
				break
			}
			val := readStringValue(&atav)
			switch {
			case oid.Equal(oidAttrCN):
				f.subjectCN = val
			case oid.Equal(oidAttrC):
				f.subjectC = append(f.subjectC, val)
			case oid.Equal(oidAttrL):
				f.subjectL = append(f.subjectL, val)
			case oid.Equal(oidAttrO):
				f.subjectO = append(f.subjectO, val)
			case oid.Equal(oidAttrOU):
				f.subjectOU = append(f.subjectOU, val)
			case oid.Equal(oidAttrStreet):
				f.subjectST = append(f.subjectST, val)
			}
		}
	}
}

// joinVals joins multi-valued name attributes the way parseName does (comma).
func joinVals(v []string) string {
	return strings.Join(v, ",")
}

// walkSAN parses the subjectAltName extension body: SEQUENCE OF GeneralName.
func walkSAN(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var gnSeq cryptobyte.String
	if !s.ReadASN1(&gnSeq, cbasn1.SEQUENCE) {
		return
	}
	for !gnSeq.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !gnSeq.ReadAnyASN1Element(&gn, &tag) {
			break
		}
		var content cryptobyte.String
		if !gn.ReadASN1(&content, tag) {
			continue
		}
		switch tag {
		case cbasn1.Tag(2).ContextSpecific(): // dNSName IA5String
			f.sanDNS = append(f.sanDNS, string(content))
		case cbasn1.Tag(1).ContextSpecific(): // rfc822Name IA5String
			f.sanEmail = append(f.sanEmail, string(content))
		case cbasn1.Tag(7).ContextSpecific(): // iPAddress OCTET STRING
			ip := net.IP(content)
			f.sanIP = append(f.sanIP, ip.String())
		}
	}
	var buf strings.Builder
	for _, n := range f.sanDNS {
		commaAppendS(&buf, "DNS:"+n)
	}
	for _, e := range f.sanEmail {
		commaAppendS(&buf, "email:"+e)
	}
	for _, ip := range f.sanIP {
		commaAppendS(&buf, "IP Address:"+ip)
	}
	f.san = buf.String()
}

func commaAppendS(buf *strings.Builder, s string) {
	if buf.Len() > 0 {
		buf.WriteString(", ")
	}
	buf.WriteString(s)
}

// walkAIA parses authorityInfoAccess: SEQ OF { accessMethod OID, accessLocation }.
// Upstream emits IssuingCertificateURL entries before OCSPServer entries.
func walkAIA(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return
	}
	var issuers, ocsp []string
	for !seq.Empty() {
		var ad cryptobyte.String
		if !seq.ReadASN1(&ad, cbasn1.SEQUENCE) {
			break
		}
		var oid asn1.ObjectIdentifier
		if !ad.ReadASN1ObjectIdentifier(&oid) {
			continue
		}
		var loc cryptobyte.String
		var tag cbasn1.Tag
		if !ad.ReadAnyASN1Element(&loc, &tag) || tag != cbasn1.Tag(6).ContextSpecific() {
			continue
		}
		var uri cryptobyte.String
		if !loc.ReadASN1(&uri, tag) {
			continue
		}
		switch {
		case oid.Equal(oidAIACaIssuers):
			issuers = append(issuers, string(uri))
		case oid.Equal(oidAIAOCSP):
			ocsp = append(ocsp, string(uri))
		}
	}
	var buf strings.Builder
	for _, u := range issuers {
		commaAppendS(&buf, "URI:"+u)
	}
	for _, u := range ocsp {
		commaAppendS(&buf, "URI:"+u)
	}
	f.aia = buf.String()
}

// walkAKI parses authorityKeyIdentifier: SEQ { [0] keyIdentifier OCTET STRING }.
func walkAKI(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return
	}
	var kidEl cryptobyte.String
	var tag cbasn1.Tag
	if !seq.ReadAnyASN1Element(&kidEl, &tag) || tag != cbasn1.Tag(0).ContextSpecific() {
		return
	}
	var kid cryptobyte.String
	if !kidEl.ReadASN1(&kid, tag) {
		return
	}
	f.aki = keyID(kid)
}

// walkBC parses basicConstraints: SEQ { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER }.
func walkBC(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || seq.Empty() {
		f.bc = "CA:FALSE"
		return
	}
	var bel cryptobyte.String
	var tag cbasn1.Tag
	ok := seq.ReadAnyASN1Element(&bel, &tag)
	f.isCA = false
	if ok && tag == cbasn1.BOOLEAN {
		var bv cryptobyte.String
		if bel.ReadASN1(&bv, cbasn1.BOOLEAN) {
			f.isCA = len(bv) > 0 && bv[0] != 0
		}
	}
	if f.isCA {
		f.bc = "CA:TRUE"
	} else {
		f.bc = "CA:FALSE"
	}
}

var kuNames = []string{
	"Digital Signature", "Content Commitment", "Key Encipherment", "Data Encipherment",
	"Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only", "Decipher Only",
}

// walkKU parses keyUsage: BIT STRING of flags.
func walkKU(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var bs cryptobyte.String
	if !s.ReadASN1(&bs, cbasn1.BIT_STRING) {
		return
	}
	b := []byte(bs)
	if len(b) == 0 {
		return
	}
	// ASN1_BIT_STRING content: first byte is the unused-bits count.
	bits := b[1:]
	var buf strings.Builder
	for i := 0; i < len(kuNames) && i/8 < len(bits); i++ {
		if bits[i/8]&(0x80>>uint(i%8)) != 0 {
			commaAppendS(&buf, kuNames[i])
		}
	}
	f.ku = buf.String()
}

// walkCP parses certificatePolicies: SEQ OF { policy OID, [qualifiers] }.
// Matches upstream: "Policy: <oid>\n" per policy (trailing newline kept).
func walkCP(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return
	}
	var buf strings.Builder
	for !seq.Empty() {
		var pi cryptobyte.String
		if !seq.ReadASN1(&pi, cbasn1.SEQUENCE) {
			break
		}
		var oid asn1.ObjectIdentifier
		if !pi.ReadASN1ObjectIdentifier(&oid) {
			continue
		}
		buf.WriteString("Policy: ")
		buf.WriteString(oid.String())
		buf.WriteString("\n")
	}
	f.cp = buf.String()
}

// walkSKID parses subjectKeyIdentifier: OCTET STRING.
func walkSKID(body []byte, f *fastFields) {
	s := cryptobyte.String(body)
	var kid cryptobyte.String
	if !s.ReadASN1(&kid, cbasn1.OCTET_STRING) {
		return
	}
	f.skid = keyID(kid)
}

// readSigAlg reads an AlgorithmIdentifier SEQUENCE and returns the
// parseSignatureAlgorithm-style name. For RSA-PSS it resolves the hash via
// the params' hashAlgorithm field.
func readSigAlg(algSeq cryptobyte.String) string {
	var oid asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&oid) {
		return "unknown"
	}
	if oid.String() == "1.2.840.113549.1.1.10" { // RSASSA-PSS
		hashName := "unknown"
		// params: SEQ { hashAlgorithm [0] AlgorithmIdentifier, ... }
		var params cryptobyte.String
		if algSeq.ReadASN1(&params, cbasn1.SEQUENCE) {
			var h cryptobyte.String
			if params.ReadASN1(&h, cbasn1.Tag(0).ContextSpecific().Constructed()) {
				var inner cryptobyte.String
				if h.ReadASN1(&inner, cbasn1.SEQUENCE) {
					var hoid asn1.ObjectIdentifier
					if inner.ReadASN1ObjectIdentifier(&hoid) {
						if n, ok := pssHashByOID[hoid.String()]; ok {
							hashName = n
						}
					}
				}
			}
		}
		return hashName + ", rsa-pss"
	}
	if name, ok := sigAlgByOID[oid.String()]; ok {
		return name
	}
	return "unknown"
}

// walkTBS walks a TBSCertificate SEQUENCE content and fills fastFields.
// sigAlgOverride, when non-empty, replaces the inner TBS signature field
// (x509 entries report the outer Certificate.signatureAlgorithm instead).
func walkTBS(tbs cryptobyte.String, f *fastFields, sigAlgOverride string) error {
	var inner cryptobyte.String
	if !tbs.ReadASN1(&inner, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: not a sequence")
	}
	// optional [0] EXPLICIT version
	if inner.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var v cryptobyte.String
		if !inner.ReadASN1(&v, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return fmt.Errorf("tbs: bad version tag")
		}
	}
	// serialNumber INTEGER
	var serial cryptobyte.String
	if !inner.ReadASN1(&serial, cbasn1.INTEGER) {
		return fmt.Errorf("tbs: missing serial")
	}
	f.serial = serialToHex(serial)
	// signature AlgorithmIdentifier
	var sigAlg cryptobyte.String
	if !inner.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: missing sigAlg")
	}
	f.sigAlg = readSigAlg(sigAlg)
	if sigAlgOverride != "" {
		f.sigAlg = sigAlgOverride
	}
	// issuer Name - not stored, skip
	var issuer cryptobyte.String
	if !inner.ReadASN1(&issuer, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: missing issuer")
	}
	// validity SEQUENCE { notBefore Time, notAfter Time }
	var validity cryptobyte.String
	if !inner.ReadASN1(&validity, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: missing validity")
	}
	var t1, t2 cryptobyte.String
	var tg1, tg2 cbasn1.Tag
	if !validity.ReadAnyASN1Element(&t1, &tg1) || !validity.ReadAnyASN1Element(&t2, &tg2) {
		return fmt.Errorf("tbs: bad validity")
	}
	var c1, c2 cryptobyte.String
	t1.ReadASN1(&c1, tg1)
	t2.ReadASN1(&c2, tg2)
	f.notBefore = parseDERTime(c1)
	f.notAfter = parseDERTime(c2)
	// subject Name
	var subject cryptobyte.String
	if !inner.ReadASN1(&subject, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: missing subject")
	}
	walkName(subject, f)
	// subjectPublicKeyInfo - skip (the big win: no key parsing)
	var spki cryptobyte.String
	if !inner.ReadASN1(&spki, cbasn1.SEQUENCE) {
		return fmt.Errorf("tbs: missing spki")
	}
	// optional [1] issuerUID, [2] subjectUID, [3] EXPLICIT extensions
	for !inner.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !inner.ReadAnyASN1Element(&el, &tag) {
			break
		}
		if tag == cbasn1.Tag(3).ContextSpecific().Constructed() {
			// [3] EXPLICIT wraps the Extensions SEQUENCE - unwrap both layers.
			var wrap, extSeq cryptobyte.String
			if !el.ReadASN1(&wrap, tag) {
				break
			}
			if !wrap.ReadASN1(&extSeq, cbasn1.SEQUENCE) {
				break
			}
			walkExtensions(extSeq, f)
		}
	}
	return nil
}

func walkExtensions(extSeq cryptobyte.String, f *fastFields) {
	for !extSeq.Empty() {
		var ext cryptobyte.String
		if !extSeq.ReadASN1(&ext, cbasn1.SEQUENCE) {
			break
		}
		var oid asn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&oid) {
			continue
		}
		// optional BOOLEAN critical
		if ext.PeekASN1Tag(cbasn1.BOOLEAN) {
			var crit cryptobyte.String
			ext.ReadASN1(&crit, cbasn1.BOOLEAN)
		}
		var body cryptobyte.String
		if !ext.ReadASN1(&body, cbasn1.OCTET_STRING) {
			continue
		}
		switch {
		case oid.Equal(oidExtSAN):
			walkSAN(body, f)
		case oid.Equal(oidExtAIA):
			walkAIA(body, f)
		case oid.Equal(oidExtAKI):
			walkAKI(body, f)
		case oid.Equal(oidExtBC):
			walkBC(body, f)
		case oid.Equal(oidExtKU):
			walkKU(body, f)
		case oid.Equal(oidExtCP):
			walkCP(body, f)
		case oid.Equal(oidExtSKID):
			walkSKID(body, f)
		}
	}
}

// fastRow builds a CertificateRow directly from the leaf DER, skipping the
// full x509 parse. Field formats match reformatCertFields on a fully parsed
// entry so rows are indistinguishable from the slim/full paths.
func fastRow(rawLogEntry *ct.RawLogEntry, isPrecert bool, certIndex int64, ctURL string, tiled bool) (*CertificateRow, error) {
	f := &fastFields{}

	var tbsDER []byte
	var outerSigAlg string
	var err error

	if isPrecert {
		te := rawLogEntry.Leaf.TimestampedEntry
		if te == nil || te.PrecertEntry == nil {
			return nil, fmt.Errorf("precert entry missing TBSCertificate")
		}
		tbsDER = te.PrecertEntry.TBSCertificate
	} else {
		te := rawLogEntry.Leaf.TimestampedEntry
		if te == nil || te.X509Entry == nil {
			return nil, fmt.Errorf("x509 entry missing cert")
		}
		s := cryptobyte.String(te.X509Entry.Data)
		var certSeq, tbsEl, sigAlgEl cryptobyte.String
		if !s.ReadASN1(&certSeq, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("cert: not a sequence")
		}
		if !certSeq.ReadASN1Element(&tbsEl, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("cert: missing tbs")
		}
		// outer signatureAlgorithm for the reported SignatureAlgorithm
		if certSeq.ReadASN1Element(&sigAlgEl, cbasn1.SEQUENCE) {
			var algSeq cryptobyte.String
			if sigAlgEl.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
				outerSigAlg = readSigAlg(algSeq)
			}
		}
		tbsDER = tbsEl
	}

	err = walkTBS(cryptobyte.String(tbsDER), f, outerSigAlg)
	if err != nil {
		return nil, err
	}

	// Hash input matches the upstream path: for x509 it is the cert DER
	// (rle.Cert.Data == leaf X509Entry); for precerts the submitted cert from
	// extra_data (rle.Cert.Data), falling back to TBS bytes when empty (tiled).
	hashInput := rawLogEntry.Cert.Data
	if len(hashInput) == 0 {
		hashInput = tbsDER
	}
	fingerprint := colonHexSHA1(hashInput)

	// AllDomains = SAN DNS names + CN appended when non-CA and not present.
	allDomains := f.sanDNS
	if allDomains == nil {
		allDomains = []string{}
	}
	cn := f.subjectCN
	if cn != "" && !f.isCA {
		found := false
		for _, d := range allDomains {
			if d == cn {
				found = true
				break
			}
		}
		if !found {
			allDomains = append(allDomains, cn)
		}
	}

	domain := ""
	if len(allDomains) > 0 {
		domain = allDomains[0]
	} else if cn != "" {
		domain = cn
	}
	domain = strings.TrimPrefix(domain, "*.")

	hostnamesSet := make(map[string]struct{}, len(allDomains)+2)
	for _, d := range f.sanDNS {
		hostnamesSet[d] = struct{}{}
	}
	for _, ip := range f.sanIP {
		hostnamesSet[ip] = struct{}{}
	}
	for _, d := range allDomains {
		hostnamesSet[d] = struct{}{}
	}
	if cn != "" {
		hostnamesSet[cn] = struct{}{}
	}
	hostnames := make([]string, 0, len(hostnamesSet))
	for h := range hostnamesSet {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)
	hostnamesJSON, _ := json.Marshal(hostnames)

	tld, rootDomain := "", ""
	if domain != "" && !isIP(domain) {
		if tldVal, _ := publicsuffix.PublicSuffix(domain); tldVal != "" {
			tld = tldVal
		}
		if rootVal, rootErr := publicsuffix.EffectiveTLDPlusOne(domain); rootErr == nil {
			rootDomain = rootVal
		}
	}

	var agg strings.Builder
	if len(f.subjectC) > 0 {
		agg.WriteString("/C=" + joinVals(f.subjectC))
	}
	// upstream always emits /CN= - the CN pointer is non-nil even when empty
	agg.WriteString("/CN=" + cn)
	if len(f.subjectL) > 0 {
		agg.WriteString("/L=" + joinVals(f.subjectL))
	}
	if len(f.subjectO) > 0 {
		agg.WriteString("/O=" + joinVals(f.subjectO))
	}
	if len(f.subjectOU) > 0 {
		agg.WriteString("/OU=" + joinVals(f.subjectOU))
	}
	if len(f.subjectST) > 0 {
		agg.WriteString("/ST=" + joinVals(f.subjectST))
	}

	certLink := ""
	if !tiled {
		certLink = fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", ctURL, certIndex, certIndex)
	}

	return &CertificateRow{
		CertIndex:                    certIndex,
		CertLink:                     certLink,
		Domain:                       domain,
		Hostnames:                    string(hostnamesJSON),
		TLD:                          tld,
		RootDomain:                   rootDomain,
		Fingerprint:                  fingerprint,
		NotAfter:                     f.notAfter,
		NotBefore:                    f.notBefore,
		SerialNumber:                 f.serial,
		C:                            joinVals(f.subjectC),
		CN:                           cn,
		L:                            joinVals(f.subjectL),
		O:                            joinVals(f.subjectO),
		OU:                           joinVals(f.subjectOU),
		ST:                           joinVals(f.subjectST),
		Aggregated:                   agg.String(),
		EmailAddress:                 "",
		AuthorityInfoAccess:          f.aia,
		AuthorityKeyIdentifier:       f.aki,
		BasicConstraints:             f.bc,
		CertificatePolicies:          f.cp,
		CtlSignedCertificateTimestamp: "",
		ExtendedKeyUsage:             "",
		KeyUsage:                     f.ku,
		SubjectAltName:               f.san,
		SubjectKeyIdentifier:         f.skid,
		SignatureAlgorithm:           f.sigAlg,
	}, nil
}

func colonHexSHA1(b []byte) string {
	h := sha1.Sum(b) //nolint:gosec
	return colonHexUpper(h[:])
}

// diffRows returns human-readable field-level differences between two rows.
func diffRows(a, b *CertificateRow) []string {
	va, vb := reflect.ValueOf(*a), reflect.ValueOf(*b)
	t := va.Type()
	var out []string
	for i := 0; i < t.NumField(); i++ {
		fa := va.Field(i).Interface()
		fb := vb.Field(i).Interface()
		if !reflect.DeepEqual(fa, fb) {
			out = append(out, fmt.Sprintf("%s: fast=%q full=%q", t.Field(i).Name, fa, fb))
		}
	}
	return out
}

// verifyEntry builds the row twice - via the DER walker and via the full slim
// parse - and logs field-level mismatches. Used by the -verify flag.
func verifyEntry(rle *ct.RawLogEntry, isPrecert bool, idx int64, st *stats, logURL, logType string, tiled bool) {
	fast, ferr := fastRow(rle, isPrecert, idx, logURL, tiled)
	entry, perr := certificatetransparency.ParseCertstreamEntrySlim(rle, "certcrawler", "certcrawler", logURL, logType)
	if perr != nil {
		st.parseErrors.Add(1)
		return
	}
	if ferr != nil {
		st.verifyMismatch.Add(1)
		if st.verifyDiffShown.Add(1) <= 10 {
			log.Printf("verify idx=%d: fastRow error=%v (full parse ok)", idx, ferr)
		}
		return
	}
	ref := reformatCertFields(&entry.Data)
	if diffs := diffRows(fast, &ref); len(diffs) > 0 {
		st.verifyMismatch.Add(1)
		if st.verifyDiffShown.Add(1) <= 10 {
			log.Printf("verify idx=%d mismatches: %s", idx, strings.Join(diffs, " | "))
		}
		return
	}
	st.parsed.Add(1)
}
