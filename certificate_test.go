package vaultcert

import (
	"crypto/tls"
	"net/http"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func ExampleGetCertificate() {
	// new Vault client from local environment variables
	vc, _ := vault.NewClient(nil)

	// new CertificateManager for a single hostname,
	// all others will be rejected.
	sm := NewSingleCert("demo.example.org")

	// create a new crypto/tls.Config compatible GetCertificate function
	// with our Vault client, the single certificate manager we created above,
	// for a PKI secret backend mounted at `pki/` and the role `example-dot-com`
	//
	// PKI Secret Backend used in this example was created like example here:
	// https://www.vaultproject.io/docs/secrets/index.html
	getCertificate := GetCertificate(vc, sm, "pki/", "example-dot-com")

	s := &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello World!\n"))
		}),

		// pass a custom TLS Configuration with our certificate
		TLSConfig: &tls.Config{
			GetCertificate: getCertificate,
		},
	}

	// We've provided a TLS Config, cert/key arguments can safely be ignored
	s.ListenAndServeTLS("", "")
}

func TestCreateCertificateBundle(t *testing.T) {
	tests := []struct {
		Name   string
		Chain  []interface{}
		Cert   string
		Output []byte
	}{
		{"CertOnly", []interface{}{}, "Baz", []byte("Baz\n")},
		{"OneCert", []interface{}{"Bar"}, "Baz", []byte("Baz\nBar\n")},
		{"TwoCert", []interface{}{"Foo", "Bar"}, "Baz", []byte("Baz\nFoo\nBar\n")},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			bundle := createCertificateBundle(test.Chain, test.Cert)
			assert.Equal(t, test.Output, bundle)
		})
	}
}

func BenchmarkCreateCertificateBundle(b *testing.B) {
	chain := []interface{}{"Foo", "Bar"}
	cert := "Baz"

	for i := 0; i < b.N; i++ {
		createCertificateBundle(chain, cert)
	}
}
