package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseDERData(t *testing.T) {
	testCases := []struct {
		file string
		info Info
	}{
		{"x509/der/dsa-1024.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/der/dsa-1024.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/der/dsa-1024-dsa.key", Info{
			Description: "DSA private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "DSA"},
				{Name: "Size", Value: "1024 bits"},
			}},
		},
		{"x509/der/rsa-512.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/der/rsa-512-pkcs1.key", Info{
			Description: "PKCS#1 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/der/rsa-512.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/der/rsa-512-pkcs1.pub", Info{
			Description: "PKCS#1 public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "RSA"},
				{Name: "Size", Value: "512 bits"},
			}},
		},
		{"x509/der/prime256v1.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/der/prime256v1-ec.key", Info{
			Description: "EC private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/der/prime256v1-explicit.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "256 bits"},
				{Name: "Curve (inferred)", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/der/prime256v1.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/der/prime256v1-explicit.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "256 bits"},
				{Name: "Curve (inferred)", Value: "P-256 (secp256r1, prime256v1)"},
			}},
		},
		{"x509/der/secp224r1-explicit.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "224 bits"},
				{Name: "Curve (inferred)", Value: "P-224 (secp224r1)"},
			}},
		},
		{"x509/der/secp384r1-explicit.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "384 bits"},
				{Name: "Curve (inferred)", Value: "P-384 (secp384r1)"},
			}},
		},
		{"x509/der/secp521r1-explicit.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "ECDSA"},
				{Name: "Field type", Value: "prime field"},
				{Name: "Prime size", Value: "521 bits"},
				{Name: "Curve (inferred)", Value: "P-521 (secp521r1)"},
			}},
		},
		{"x509/der/ed25519.key", Info{
			Description: "PKCS#8 private key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "EdDSA"},
				{Name: "Curve", Value: "Ed25519"},
			}},
		},
		{"x509/der/ed25519.pub", Info{
			Description: "PKIX public key",
			Attributes: []Attribute{
				{Name: "Algorithm", Value: "EdDSA"},
				{Name: "Curve", Value: "Ed25519"},
			}},
		},
		{"x509/der/github.com.cer", Info{
			Description: "x.509v3 end-entity certificate",
			Attributes: []Attribute{
				{Name: "Serial", Value: "cd0a8bec632cfe645eca0a9b084fb1c"},
				{Name: "Subject", Value: "CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US"},
				{Name: "Subject key id", Value: "c707277885f29d33c94c5e567d5cd68e7267ebde"},
				{Name: "Issuer", Value: "CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc,C=US"},
				{Name: "Authority key id", Value: "0abc0829178ca5396d7a0ece33c72eb3edfbc37a"},
				{Name: "Not before", Value: "2023-02-14"},
				{Name: "Not after", Value: "2024-03-14"},
				{Name: "Key usage", Value: "digitalSignature"},
				{Name: "Extended key usage", Value: "serverAuth, clientAuth"},
				{Name: "SANs", Value: "github.com, www.github.com"},
				{Name: "Signature algorithm", Value: "ECDSA-SHA384"},
			},
			Children: []Info{
				{
					Description: "Public key",
					Attributes: []Attribute{
						{Name: "Algorithm", Value: "ECDSA"},
						{Name: "Curve", Value: "P-256 (secp256r1, prime256v1)"},
					},
				},
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data := fileContents(tc.file)
			actual := parseDERData(data)
			assert.Equal(t, tc.info, actual)
		})
	}
}
