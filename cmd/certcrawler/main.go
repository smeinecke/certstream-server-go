package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	ldriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
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
func reformatCertFields(data *certificatetransparency.TransparencyRecordData) CertificateRow {
	aggMap := map[string]string{}
	if data.LeafCert.Subject.Aggregated != "" {
		aggMap = parseSubjectAggregated(data.LeafCert.Subject.Aggregated)
	}
	getField := func(key string, orig string) string {
		if orig != "" {
			return orig
		}
		if v, ok := aggMap[key]; ok {
			return v
		}
		return ""
	}
	cn := getField("CN", data.LeafCert.Subject.CN)
	subjectAltName := data.LeafCert.Extensions.SubjectAltName
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
	// Only set tld/rootDomain if at least one non-IP
	anyNonIP := false
	for _, h := range hostnames {
		if !isIP(h) {
			anyNonIP = true
			break
		}
	}
	tld, rootDomain := "", ""
	if anyNonIP {
		tldVal, tldErr := publicsuffix.PublicSuffix(domain)
		if tldErr == nil {
			tld = tldVal
		}
		rootVal, rootErr := publicsuffix.EffectiveTLDPlusOne(domain)
		if rootErr == nil {
			rootDomain = rootVal
		}
	}
	return CertificateRow{
		CertIndex:    data.CertIndex,
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
		Aggregated:   data.LeafCert.Subject.Aggregated,
		EmailAddress: getField("emailAddress", data.LeafCert.Subject.EmailAddress),
		Domain:       domain,
		Hostnames:    string(hostnamesJSON),
		TLD:          tld,
		RootDomain:   rootDomain,
		AuthorityInfoAccess:          data.LeafCert.Extensions.AuthorityInfoAccess,
		AuthorityKeyIdentifier:       data.LeafCert.Extensions.AuthorityKeyIdentifier,
		BasicConstraints:             data.LeafCert.Extensions.BasicConstraints,
		CertificatePolicies:          data.LeafCert.Extensions.CertificatePolicies,
		CtlSignedCertificateTimestamp: data.LeafCert.Extensions.CtlSignedCertificateTimestamp,
		ExtendedKeyUsage:             data.LeafCert.Extensions.ExtendedKeyUsage,
		KeyUsage:                     data.LeafCert.Extensions.KeyUsage,
		SubjectAltName:               data.LeafCert.Extensions.SubjectAltName,
		SubjectKeyIdentifier:         data.LeafCert.Extensions.SubjectKeyIdentifier,
		SignatureAlgorithm:           data.LeafCert.SignatureAlgorithm,
	}
}

func main() {
	ctLogFlag := flag.String("log", "", "URL of the CT log - e.g. ct.googleapis.com/logs/eu1/xenon2025h2")
	startFlag := flag.Int64("start", 0, "Start index of the CT log range (inclusive)")
	endFlag := flag.Int64("end", 0, "End index of the CT log range (inclusive)")
	batchSizeFlag := flag.Int64("batch-size", 1000, "Number of entries to fetch per batch")
	asDERFlag := flag.Bool("asder", false, "Include DER encoding of the certificate")
	concurrencyFlag := flag.Int("concurrency", 4, "Number of concurrent batch requests")
	clickhouseDSN := flag.String("clickhouse-dsn", "", "ClickHouse DSN, e.g. 'tcp://127.0.0.1:9000?debug=true'")
	clickhouseTable := flag.String("clickhouse-table", "certs", "ClickHouse table name")
	flag.Parse()

	ctLog := *ctLogFlag
	start := *startFlag
	end := *endFlag
	batchSize := *batchSizeFlag
	asDER := *asDERFlag
	concurrency := *concurrencyFlag

	if ctLog == "" {
		log.Fatalln("CT log URL is required")
	}
	if end < start {
		log.Fatalln("End index must be >= start index")
	}
	if !strings.HasPrefix(ctLog, "https://") {
		ctLog = "https://" + ctLog
	}

	hc := http.Client{Timeout: 60 * time.Second}
	jsonClient, err := client.New(ctLog, &hc, jsonclient.Options{UserAgent: userAgent})
	if err != nil {
		log.Fatalln("Error creating JSON client:", err)
	}

	// ClickHouse setup
	var chConn clickhouse.Conn
	if *clickhouseDSN != "" {
		chConn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{strings.TrimPrefix(strings.TrimPrefix(*clickhouseDSN, "tcp://"), "clickhouse://")},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: "default",
				Password: "",
			},
			DialTimeout: 10 * time.Second,
			Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		})
		if err != nil {
			log.Fatalf("Failed to connect to ClickHouse: %v", err)
		}
	}

	type batchJob struct {
		start int64
		end   int64
	}
	jobs := make(chan batchJob)
	results := make(chan []string)
	done := make(chan struct{})

	// Worker function
	worker := func() {
		for job := range jobs {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			entries, getEntriesErr := jsonClient.GetRawEntries(ctx, job.start, job.end)
			cancel()
			var batchResults []string
			if getEntriesErr != nil {
				log.Printf("Error getting entries %d-%d: %v", job.start, job.end, getEntriesErr)
				results <- batchResults
				continue
			}
			var workerBatch ldriver.Batch
			var batchErr error
			if *clickhouseDSN != "" && chConn != nil {
				workerBatch, batchErr = chConn.PrepareBatch(context.Background(),
					fmt.Sprintf(`INSERT INTO %s (
						cert_index, cert_link, domain, hostnames, tld, root_domain, fingerprint, not_after, not_before, serial_number, c, cn, l, o, ou, st, aggregated, email_address, authority_info_access, authority_key_identifier, basic_constraints, certificate_policies, ctl_signed_certificate_timestamp, extended_key_usage, key_usage, subject_alt_name, subject_key_identifier, signature_algorithm)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					`, *clickhouseTable))
				if batchErr != nil {
					log.Printf("Failed to prepare ClickHouse batch: %v", batchErr)
					workerBatch = nil
				}
			}
			for i, leafEntry := range entries.Entries {
				idx := job.start + int64(i)
				rawLogEntry, err := ct.RawLogEntryFromLeaf(idx, &leafEntry)
				if err != nil {
					log.Printf("Error creating raw log entry at index %d: %v", idx, err)
					continue
				}
				entry, parseErr := certificatetransparency.ParseCertstreamEntry(rawLogEntry, "N/A", "N/A", ctLog)
				if parseErr != nil {
					log.Printf("Error parsing certstream entry at index %d: %v", idx, parseErr)
					continue
				}
				if !asDER {
					entry.Data.LeafCert.AsDER = ""
					for i := range entry.Data.Chain {
						entry.Data.Chain[i].AsDER = ""
					}
				}
				// Insert into ClickHouse batch if enabled
				if workerBatch != nil {

					row := reformatCertFields(&entry.Data)
					appendErr := workerBatch.Append(
						row.CertIndex,
						row.CertLink,
						row.Domain,
						row.Hostnames,
						row.TLD,
						row.RootDomain,
						row.Fingerprint,
						row.NotAfter,
						row.NotBefore,
						row.SerialNumber,
						row.C,
						row.CN,
						row.L,
						row.O,
						row.OU,
						row.ST,
						row.Aggregated,
						row.EmailAddress,
						row.AuthorityInfoAccess,
						row.AuthorityKeyIdentifier,
						row.BasicConstraints,
						row.CertificatePolicies,
						row.CtlSignedCertificateTimestamp,
						row.ExtendedKeyUsage,
						row.KeyUsage,
						row.SubjectAltName,
						row.SubjectKeyIdentifier,
						row.SignatureAlgorithm,
					)
					if appendErr != nil {
						log.Printf("ClickHouse batch append error at index %d: %v", idx, appendErr)
					}
				}
				result, marshalErr := json.Marshal(entry)
				if marshalErr != nil {
					log.Printf("Error marshaling entry at index %d: %v", idx, marshalErr)
					continue
				}
				batchResults = append(batchResults, string(result))
			}
			if workerBatch != nil {
				if err := workerBatch.Send(); err != nil {
					log.Printf("ClickHouse batch send error: %v", err)
				}
			}
			results <- batchResults
		}
	}

	// Start workers
	for i := 0; i < concurrency; i++ {
		go worker()
	}

	// Feed jobs
	go func() {
		for batchStart := start; batchStart <= end; batchStart += batchSize {
			batchEnd := batchStart + batchSize - 1
			if batchEnd > end {
				batchEnd = end
			}
			jobs <- batchJob{batchStart, batchEnd}
		}
		close(jobs)
	}()

	// Collect results
	totalBatches := int((end-start)/batchSize) + 1
	for i := 0; i < totalBatches; i++ {
		batchResults := <-results
		for _, line := range batchResults {
			os.Stdout.Write([]byte(line))
			os.Stdout.Write([]byte("\n"))
		}
	}
	close(results)
	close(done)
}
