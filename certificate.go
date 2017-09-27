package vaultcert

import (
	"crypto/tls"
	"path"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// Certificate is a tuple of a TLS Certificate and its Lease Expiration.
type Certificate struct {
	Certificate     *tls.Certificate
	LeaseExpiration time.Time
}

// CertificateManager is responsible for the issuing, lookup and renewal of
// dynamically generated certificats from Vault.
type CertificateManager interface {
	Get(vc *vault.Client, commonName, path string) (*Certificate, error)
}

// GetCertificate returns an anonymous function compatible with `crypto/tls.Config GetCertificate`
// that will issue (and cache for lease duration) a certificate from Vault with the given Certificate
// Manager, secret backend path and role.
func GetCertificate(vc *vault.Client, cm CertificateManager, backendPath, pkiRole string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	pkiPath := path.Join(backendPath, "issue", pkiRole)

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := cm.Get(vc, hello.ServerName, pkiPath)
		if err != nil {
			return nil, err
		}

		return cert.Certificate, nil
	}
}

// SingleCertificate is a CertificateManager containing a certificate
// representing a single common name.
type SingleCertificate struct {
	CommonName string

	cert *Certificate
	mu   sync.Mutex
}

// NewSingleCert returns a SingleCertificate CertificateManager configured
// for the given common name only.
func NewSingleCert(commonName string) *SingleCertificate {
	return &SingleCertificate{
		CommonName: commonName,
	}
}

// Get returns either a cached certificate, or if none is cached/lease has expired, fetched a new
// certificate from Vault and caches that.
func (sc *SingleCertificate) Get(vc *vault.Client, commonName, path string) (cert *Certificate, err error) {
	if commonName != sc.CommonName {
		err = errors.Errorf("mismatched common name '%s", commonName)
		return
	}

	sc.mu.Lock()

	if sc.cert == nil || time.Until(sc.cert.LeaseExpiration) < 1 {
		cert, err = getCertificate(vc, sc.CommonName, path)
		if err != nil {
			return
		}

		sc.cert = cert
	}

	sc.mu.Unlock()

	return
}

func getCertificate(vc *vault.Client, commonName, path string) (*Certificate, error) {
	logical := vc.Logical()

	secret, err := logical.Write(path, map[string]interface{}{
		"common_name": commonName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "vault: issue:")
	}

	certStr := secret.Data["certificate"].(string)
	chain := secret.Data["ca_chain"].([]interface{})
	privateKey := secret.Data["private_key"].(string)

	cert, err := tls.X509KeyPair(
		createCertificateBundle(chain, certStr),
		[]byte(privateKey),
	)
	if err != nil {
		return nil, errors.Wrap(err, "vault: parse X509:")
	}

	return &Certificate{
		Certificate:     &cert,
		LeaseExpiration: time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second),
	}, nil
}

func createCertificateBundle(chain []interface{}, cert string) []byte {
	totalLen := len(cert) + 1 + len(chain)
	for _, c := range chain {
		totalLen += len(c.(string))
	}

	bundle := make([]byte, totalLen)
	offset := 0

	offset += copy(bundle[offset:], cert) + 1
	bundle[offset-1] = '\n'

	for _, c := range chain {
		offset += copy(bundle[offset:], c.(string)) + 1
		bundle[offset-1] = '\n'
	}

	return bundle
}
