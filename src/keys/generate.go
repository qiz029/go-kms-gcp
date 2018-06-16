package keys

import (
	"crypto/sha256"

	"github.com/qiz029/go-kms-gcp/src/utils"
)

/*
Crude fake key generation; a sha256 of the ident.
*/
func GetKey() [32]byte {

	return sha256.Sum256([]byte(utils.Gen32()))
}
