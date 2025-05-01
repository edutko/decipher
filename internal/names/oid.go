package names

import (
	"encoding/asn1"

	"github.com/edutko/decipher/internal/oid"
)

func FromOID(o asn1.ObjectIdentifier) string {
	switch {
	case o.Equal(oid.DSA):
		return DSA
	case o.Equal(oid.ECPublicKey):
		return ECDSA
	case o.Equal(oid.Ed25519):
		return Ed25519
	case o.Equal(oid.Ed448):
		return Ed448
	case o.Equal(oid.RSAEncryption):
		return RSA
	case o.Equal(oid.ECDSAWithSHA1):
		return ECDSAWithSHA1
	case o.Equal(oid.ECDSAWithSHA256):
		return ECDSAWithSHA256
	case o.Equal(oid.ECDSAWithSHA384):
		return ECDSAWithSHA384
	case o.Equal(oid.ECDSAWithSHA512):
		return ECDSAWithSHA512
	case o.Equal(oid.ML_KEM_512), o.Equal(oid.ML_KEM_512_ipd):
		return ML_KEM_512
	case o.Equal(oid.ML_KEM_768), o.Equal(oid.ML_KEM_768_ipd):
		return ML_KEM_768
	case o.Equal(oid.ML_KEM_1024), o.Equal(oid.ML_KEM_1024_ipd):
		return ML_KEM_1024
	case o.Equal(oid.ML_DSA_44), o.Equal(oid.ML_DSA_44_ipd):
		return ML_DSA_44
	case o.Equal(oid.ML_DSA_65), o.Equal(oid.ML_DSA_65_ipd):
		return ML_DSA_65
	case o.Equal(oid.ML_DSA_87), o.Equal(oid.ML_DSA_87_ipd):
		return ML_DSA_87
	case o.Equal(oid.SLH_DSA_SHA2_128s), o.Equal(oid.SLH_DSA_SHA2_128s_ipd):
		return SLH_DSA_SHA2_128s
	case o.Equal(oid.SLH_DSA_SHA2_128f), o.Equal(oid.SLH_DSA_SHA2_128f_ipd):
		return SLH_DSA_SHA2_128f
	case o.Equal(oid.SLH_DSA_SHA2_192s), o.Equal(oid.SLH_DSA_SHA2_192s_ipd):
		return SLH_DSA_SHA2_192s
	case o.Equal(oid.SLH_DSA_SHA2_192f), o.Equal(oid.SLH_DSA_SHA2_192f_ipd):
		return SLH_DSA_SHA2_192f
	case o.Equal(oid.SLH_DSA_SHA2_256s), o.Equal(oid.SLH_DSA_SHA2_256s_ipd):
		return SLH_DSA_SHA2_256s
	case o.Equal(oid.SLH_DSA_SHA2_256f), o.Equal(oid.SLH_DSA_SHA2_256f_ipd):
		return SLH_DSA_SHA2_256f
	case o.Equal(oid.SLH_DSA_SHAKE_128s), o.Equal(oid.SLH_DSA_SHAKE_128s_ipd):
		return SLH_DSA_SHAKE_128s
	case o.Equal(oid.SLH_DSA_SHAKE_128f), o.Equal(oid.SLH_DSA_SHAKE_128f_ipd):
		return SLH_DSA_SHAKE_128f
	case o.Equal(oid.SLH_DSA_SHAKE_192s), o.Equal(oid.SLH_DSA_SHAKE_192s_ipd):
		return SLH_DSA_SHAKE_192s
	case o.Equal(oid.SLH_DSA_SHAKE_192f), o.Equal(oid.SLH_DSA_SHAKE_192f_ipd):
		return SLH_DSA_SHAKE_192f
	case o.Equal(oid.SLH_DSA_SHAKE_256s), o.Equal(oid.SLH_DSA_SHAKE_256s_ipd):
		return SLH_DSA_SHAKE_256s
	case o.Equal(oid.SLH_DSA_SHAKE_256f), o.Equal(oid.SLH_DSA_SHAKE_256f_ipd):
		return SLH_DSA_SHAKE_256f
	case o.Equal(oid.Kyber512_aes):
		return Kyber512_aes
	case o.Equal(oid.Kyber768_aes):
		return Kyber768_aes
	case o.Equal(oid.Kyber1024_aes):
		return Kyber1024_aes
	case o.Equal(oid.Kyber512_shake):
		return Kyber512_shake
	case o.Equal(oid.Kyber768_shake):
		return Kyber768_shake
	case o.Equal(oid.Kyber1024_shake):
		return Kyber1024_shake
	case o.Equal(oid.Dilithium2):
		return Dilithium2
	case o.Equal(oid.Dilithium3):
		return Dilithium3
	case o.Equal(oid.Dilithium5):
		return Dilithium5
	case o.Equal(oid.DilithiumAES2):
		return DilithiumAES2
	case o.Equal(oid.DilithiumAES3):
		return DilithiumAES3
	case o.Equal(oid.DilithiumAES5):
		return DilithiumAES5
	case o.Equal(oid.Falcon_512):
		return Falcon_512
	case o.Equal(oid.Falcon_1024):
		return Falcon_1024
	case o.Equal(oid.SPHINCSPLUS_SHA256_128f_robust):
		return SPHINCSPLUS_SHA256_128f_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_128f_simple):
		return SPHINCSPLUS_SHA256_128f_simple
	case o.Equal(oid.SPHINCSPLUS_SHA256_128s_robust):
		return SPHINCSPLUS_SHA256_128s_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_128s_simple):
		return SPHINCSPLUS_SHA256_128s_simple
	case o.Equal(oid.SPHINCSPLUS_SHA256_192f_robust):
		return SPHINCSPLUS_SHA256_192f_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_192f_simple):
		return SPHINCSPLUS_SHA256_192f_simple
	case o.Equal(oid.SPHINCSPLUS_SHA256_192s_robust):
		return SPHINCSPLUS_SHA256_192s_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_192s_simple):
		return SPHINCSPLUS_SHA256_192s_simple
	case o.Equal(oid.SPHINCSPLUS_SHA256_256f_robust):
		return SPHINCSPLUS_SHA256_256f_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_256f_simple):
		return SPHINCSPLUS_SHA256_256f_simple
	case o.Equal(oid.SPHINCSPLUS_SHA256_256s_robust):
		return SPHINCSPLUS_SHA256_256s_robust
	case o.Equal(oid.SPHINCSPLUS_SHA256_256s_simple):
		return SPHINCSPLUS_SHA256_256s_simple
	}
	return o.String()
}
