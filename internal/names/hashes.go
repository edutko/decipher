package names

import (
	"crypto"
)

func FromCryptoHash(h crypto.Hash) string {
	return h.String()
}
