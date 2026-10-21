package web

import (
	"net/http"
	"sync/atomic"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

// exampleCert is updated every 1000 processed entries while HTTP handlers
// read it concurrently - a plain global would be a data race.
var exampleCert atomic.Pointer[models.Entry]

func loadExampleCert() *models.Entry {
	if e := exampleCert.Load(); e != nil {
		return e
	}
	return &models.Entry{}
}

// exampleFull handles requests to the /full-stream/example.json endpoint.
// It returns a JSON representation of the full example certificate.
func exampleFull(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(loadExampleCert().JSONNoCache()) //nolint:errcheck
}

// exampleLite handles requests to the /example.json endpoint.
// It returns a JSON representation of the lite example certificate.
func exampleLite(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(loadExampleCert().JSONLiteNoCache()) //nolint:errcheck
}

// exampleDomains handles requests to the /domains-only/example.json endpoint.
// It returns a JSON representation of the domain data.
func exampleDomains(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(loadExampleCert().JSONDomains()) //nolint:errcheck
}

// SetExampleCert sets the example certificate to be used in the example endpoints.
func SetExampleCert(cert models.Entry) {
	exampleCert.Store(&cert)
}
