Vault Certificate
=================

Vault Certificate (vaultcert) integrates with Hashicorp's Vault PKI backend to generate TLS certificates on the fly for Go `crypto/tls.Config`.

Currently only single certificates are implemented. Support for wildcard/glob and multiple certificates is not yet implemented.


Example
-------

```go
package main

import (
	"net/http"
	"crypto/tls"

	vault "github.com/hashicorp/vault/api"
	"github.com/jamescun/vaultcert"
)

func main() {
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

``