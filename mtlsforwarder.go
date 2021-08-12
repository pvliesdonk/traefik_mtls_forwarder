package MTlsForwarder

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
)

type Config struct {
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return nil
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &mTlsForwarder{
		next: next,
		name: name,
	}, nil
}

type mTlsForwarder struct {
	next http.Handler
	name string
}

func (m mTlsForwarder) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	sslClientCert := "SSL_CLIENT_CERT"
	sslCertChainPrefix := "CERT_CHAIN"

	// are we using mTLS?
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {

		for i,cert := range request.TLS.PeerCertificates {

			fmt.Println("Found certificate with subject", cert.Subject, "issued by", cert.Issuer)
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			if i == 0 {
				// client cert
				request.Header.Set(sslClientCert, string(certPEM))
			} else {
				// part of chain
				headerName := sslCertChainPrefix + "_" + strconv.Itoa(i-1)
				request.Header.Set(headerName, string(certPEM))
			}
		}
	}

	// call to next plugin
	m.next.ServeHTTP(writer, request)

}
