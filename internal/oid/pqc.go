package oid

import "encoding/asn1"

// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
var (
	ML_KEM_512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	ML_KEM_768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	ML_KEM_1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}

	ML_DSA_44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	ML_DSA_65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	ML_DSA_87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	SLH_DSA_SHA2_128s  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	SLH_DSA_SHA2_128f  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	SLH_DSA_SHA2_192s  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	SLH_DSA_SHA2_192f  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	SLH_DSA_SHA2_256s  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	SLH_DSA_SHA2_256f  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}
	SLH_DSA_SHAKE_128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}
	SLH_DSA_SHAKE_128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}
	SLH_DSA_SHAKE_192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}
	SLH_DSA_SHAKE_192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}
	SLH_DSA_SHAKE_256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}
	SLH_DSA_SHAKE_256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}

	ML_KEM_512_ipd  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 1}
	ML_KEM_768_ipd  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 2}
	ML_KEM_1024_ipd = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 3}

	ML_DSA_44_ipd = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 4}
	ML_DSA_65_ipd = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5}
	ML_DSA_87_ipd = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 7}

	SLH_DSA_SHA2_128s_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 16}
	SLH_DSA_SHAKE_128s_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 16}
	SLH_DSA_SHA2_128f_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 13}
	SLH_DSA_SHAKE_128f_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 13}
	SLH_DSA_SHA2_192s_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 12}
	SLH_DSA_SHAKE_192s_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 8, 12}
	SLH_DSA_SHA2_192f_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 10}
	SLH_DSA_SHAKE_192f_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 8, 10}
	SLH_DSA_SHA2_256s_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 12}
	SLH_DSA_SHAKE_256s_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 12}
	SLH_DSA_SHA2_256f_ipd  = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 10}
	SLH_DSA_SHAKE_256f_ipd = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 10}

	Kyber512_aes    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 4}
	Kyber768_aes    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 5}
	Kyber1024_aes   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 6}
	Kyber512_shake  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 7}
	Kyber768_shake  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 8}
	Kyber1024_shake = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 5, 6, 9}

	Dilithium2    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	Dilithium3    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5}
	Dilithium5    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}
	DilithiumAES2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 4, 4}
	DilithiumAES3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 6, 5}
	DilithiumAES5 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 8, 7}

	Falcon_512  = asn1.ObjectIdentifier{1, 3, 9999, 3, 1}
	Falcon_1024 = asn1.ObjectIdentifier{1, 3, 9999, 3, 4}

	SPHINCSPLUS_SHA256_128f_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 1}
	SPHINCSPLUS_SHA256_128f_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 4}
	SPHINCSPLUS_SHA256_128s_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 7}
	SPHINCSPLUS_SHA256_128s_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 10}
	SPHINCSPLUS_SHA256_192f_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 1}
	SPHINCSPLUS_SHA256_192f_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 3}
	SPHINCSPLUS_SHA256_192s_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 5}
	SPHINCSPLUS_SHA256_192s_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 5, 7}
	SPHINCSPLUS_SHA256_256f_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 1}
	SPHINCSPLUS_SHA256_256f_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 3}
	SPHINCSPLUS_SHA256_256s_robust = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 5}
	SPHINCSPLUS_SHA256_256s_simple = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 7}
)
