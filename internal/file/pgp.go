package file

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/edutko/decipher/internal/names"
	"github.com/edutko/decipher/internal/openpgp/armor"
	"github.com/edutko/decipher/internal/openpgp/packet"
)

func readArmoredPGPData(b []byte) (*armor.Block, error) {
	r := bytes.NewReader(b)
	return armor.Decode(r)
}

var pubkeyAlgorithmNames = map[packet.PublicKeyAlgorithm]string{
	packet.PubKeyAlgoRSA:            names.RSA,
	packet.PubKeyAlgoRSAEncryptOnly: fmt.Sprintf("%s (encrypt only)", names.RSA),
	packet.PubKeyAlgoRSASignOnly:    fmt.Sprintf("%s (sign only)", names.RSA),
	packet.PubKeyAlgoElGamal:        names.ElGamal,
	packet.PubKeyAlgoDSA:            names.DSA,
	packet.PubKeyAlgoECDH:           names.ECDH,
	packet.PubKeyAlgoECDSA:          names.ECDSA,
	packet.PubKeyAlgoEdDSA:          names.EdDSA,
}

func keyFlagsToString(s *packet.Signature) string {
	var flags []string
	if s.FlagSign {
		flags = append(flags, "sign")
	}
	if s.FlagCertify {
		flags = append(flags, "certify")
	}
	if s.FlagEncryptCommunications {
		flags = append(flags, "encrypt communications")
	}
	if s.FlagEncryptStorage {
		flags = append(flags, "encrypt storage")
	}
	if s.FlagAuthentication {
		flags = append(flags, "authentication")
	}

	if len(flags) > 0 {
		return strings.Join(flags, ", ")
	}
	return "any"
}

func pgpPublicKeyAttributes(p *packet.PublicKey) []Attribute {
	attrs := []Attribute{
		{"Key ID", p.KeyIdString()},
		{"Fingerprint", strings.ToUpper(hex.EncodeToString(p.Fingerprint[:]))},
		{"Algorithm", pubkeyAlgorithmNames[p.PubKeyAlgo]},
	}
	switch t := p.PublicKey.(type) {
	case *ecdsa.PublicKey:
		attrs = append(attrs, Attribute{"Curve", t.Curve.Params().Name})
	case ed25519.PublicKey:
		attrs = append(attrs, Attribute{"Curve", "Ed25519"})
	}
	l, err := p.BitLength()
	if err == nil {
		attrs = append(attrs, Attribute{"Size", fmt.Sprintf("%d bits", l)})
	}
	return attrs
}

func pgpPublicKeyV3Attributes(p *packet.PublicKeyV3) []Attribute {
	attrs := []Attribute{
		{"Key ID", p.KeyIdString()},
		{"Fingerprint", strings.ToUpper(hex.EncodeToString(p.Fingerprint[:]))},
		{"Algorithm", pubkeyAlgorithmNames[p.PubKeyAlgo]},
	}
	l, err := p.BitLength()
	if err == nil {
		attrs = append(attrs, Attribute{"Size", fmt.Sprintf("%d bits", l)})
	}
	if p.DaysToExpire > 0 {
		exp := time.Duration(p.DaysToExpire) * 24 * time.Hour
		attrs = append(attrs, Attribute{"Expires", p.CreationTime.Add(exp).Format("2006-01-02")})
	} else {
		attrs = append(attrs, Attribute{"Expires", "never"})
	}
	return attrs
}

func pgpPrivateKeyAttributes(p *packet.PrivateKey) []Attribute {
	attrs := []Attribute{
		{"Key ID", p.KeyIdString()},
		{"Fingerprint", strings.ToUpper(hex.EncodeToString(p.Fingerprint[:]))},
		{"Algorithm", pubkeyAlgorithmNames[p.PubKeyAlgo]},
	}
	switch t := p.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		attrs = append(attrs, Attribute{"Curve", t.Curve.Params().Name})
	case ed25519.PrivateKey:
		attrs = append(attrs, Attribute{"Curve", "Ed25519"})
	}
	l, err := p.BitLength()
	if err == nil {
		attrs = append(attrs, Attribute{"Size", fmt.Sprintf("%d bits", l)})
	}
	return attrs
}

func pgpSignatureAttributes(s *packet.Signature, keyCreationTime time.Time) []Attribute {
	attrs := []Attribute{
		{"Usage", keyFlagsToString(s)},
		{"Algorithm", pubkeyAlgorithmNames[s.PubKeyAlgo]},
		{"Hash", s.Hash.String()},
		{"Created", s.CreationTime.Format("2006-01-02")},
	}
	if l := s.KeyLifetimeSecs; l != nil {
		exp := time.Duration(*l) * time.Second
		attrs = append(attrs, Attribute{"Expires", keyCreationTime.Add(exp).Format("2006-01-02")})
	} else {
		attrs = append(attrs, Attribute{"Expires", "never"})
	}
	return attrs
}

func pgpSignatureV3Attributes(s *packet.SignatureV3) []Attribute {
	return []Attribute{
		{"Algorithm", pubkeyAlgorithmNames[s.PubKeyAlgo]},
		{"Hash", s.Hash.String()},
		{"Created", s.CreationTime.Format("2006-01-02")},
	}
}
