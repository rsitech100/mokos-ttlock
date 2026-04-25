package hashutil

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5Hex returns lowercase hex MD5 for the provided text.
func MD5Hex(text string) string {
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:])
}
