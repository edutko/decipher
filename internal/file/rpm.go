package file

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/edutko/decipher/internal/names"
	"github.com/edutko/decipher/internal/openpgp/packet"
)

func rpmSignatureAttributes(sig []byte) []Attribute {
	var attrs []Attribute
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		attrs = append(attrs, Attribute{"Type", "unknown or malformed"})
		return attrs
	}
	switch s := p.(type) {
	case *packet.Signature:
		attrs = append(attrs, Attribute{"Algorithm", rpmSignatureAlgorithmName(s.PubKeyAlgo, s.Hash)})
		if s.IssuerKeyId != nil {
			attrs = append(attrs, Attribute{"Key id", fmt.Sprintf("%X", *s.IssuerKeyId)})
		}
	case *packet.SignatureV3:
		attrs = append(attrs, Attribute{"Algorithm", rpmSignatureAlgorithmName(s.PubKeyAlgo, s.Hash)})
		attrs = append(attrs, Attribute{"Key id", fmt.Sprintf("%X", s.IssuerKeyId)})
	}
	return attrs
}

func rpmSignatureAlgorithmName(a packet.PublicKeyAlgorithm, h crypto.Hash) string {
	switch a {
	case packet.PubKeyAlgoDSA:
		return names.DSA + "/" + names.FromCryptoHash(h)
	case packet.PubKeyAlgoECDSA:
		return names.ECDSA
	case packet.PubKeyAlgoEdDSA:
		return names.EdDSA
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		return names.RSA + "/" + names.FromCryptoHash(h)
	default:
		return "unknown"
	}
}
