package apr1

import (
	"bytes"
	"crypto/md5"
	"math/rand"
	"strings"
)

const coding = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base64(sum [16]byte) string {
	buf := bytes.NewBuffer(make([]byte, 0))

	fill := func(n int, bytes ...byte) {
		var v uint
		for _, b := range bytes {
			v = v<<8 + uint(b)
		}
		for i := 0; i < n; i++ {
			buf.WriteByte(coding[v&0x3f])
			v >>= 6
		}
	}

	fill(4, sum[0], sum[6], sum[12])
	fill(4, sum[1], sum[7], sum[13])
	fill(4, sum[2], sum[8], sum[14])
	fill(4, sum[3], sum[9], sum[15])
	fill(4, sum[4], sum[10], sum[5])
	fill(2, sum[11])

	return buf.String()
}

func Match(encodedPassword, password string) bool {
	elem := strings.Split(encodedPassword, "$")
	if len(elem) != 4 {
		return false
	}
	if elem[0] != "" || elem[1] != "apr1" {
		return false
	}

	salt := elem[2]

	pw := encode(password, salt)
	return pw == encodedPassword
}

func encode(password, salt string) string {
	sum := md5.Sum([]byte(password + salt + password))

	buf := bytes.NewBufferString(password + "$apr1$" + salt)
	for i := len(password); i > 0; i -= 16 {
		n := i
		if n > 16 {
			n = 16
		}
		buf.Write(sum[:n])
	}
	for i := len(password); i > 0; i >>= 1 {
		if (i & 1) != 0 {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(password[0])
		}
	}

	sum = md5.Sum(buf.Bytes())

	buf = bytes.NewBuffer(make([]byte, 0))
	for i := 0; i < 1000; i++ {
		buf.Reset()

		if (i & 1) != 0 {
			buf.WriteString(password)
		} else {
			buf.Write(sum[:])
		}

		if i%3 != 0 {
			buf.WriteString(salt)
		}

		if i%7 != 0 {
			buf.WriteString(password)
		}

		if (i & 1) != 0 {
			buf.Write(sum[:])
		} else {
			buf.WriteString(password)
		}

		sum = md5.Sum(buf.Bytes())
	}

	return "$apr1$" + salt + "$" + base64(sum)
}

func Encode(password string) string {
	salt := make([]byte, 8)
	for i := 0; i < 8; i++ {
		r := rand.Intn(len(coding))
		salt[i] = coding[r]
	}
	return encode(password, string(salt))
}
