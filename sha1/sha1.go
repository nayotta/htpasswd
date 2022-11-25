package sha1

import (
	"crypto/sha1"
	"encoding/base64"
)

func Match(encodedPassword, password string) bool {
	pw := Encode(password)
	return pw == encodedPassword
}

func Encode(password string) string {
	sum := sha1.Sum([]byte(password))
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return "{SHA}" + b64
}
