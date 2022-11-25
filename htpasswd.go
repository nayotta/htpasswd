package htpasswd

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nayotta/htpasswd/apr1"
	"github.com/nayotta/htpasswd/bcrypt"
	"github.com/nayotta/htpasswd/sha1"
)

type HTPasswd struct {
	m sync.Map
}

func Load(path string) (*HTPasswd, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	htpw := new(HTPasswd)

	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		elem := strings.SplitN(line, ":", 2)
		if len(elem) != 2 {
			return nil, fmt.Errorf("parse error at line %d", i+1)
		}
		htpw.m.Store(elem[0], elem[1])
	}

	return htpw, nil
}

func (htpw *HTPasswd) Save(path string) error {
	buf := bytes.NewBuffer(make([]byte, 0))

	htpw.m.Range(func(key, value any) bool {
		name := key.(string)
		encodedPassword := value.(string)
		buf.WriteString(fmt.Sprintf("%s:%s\n", name, encodedPassword))
		return true
	})

	return os.WriteFile(path, buf.Bytes(), os.ModePerm)
}

func (htpw *HTPasswd) Match(name, password string) bool {
	value, ok := htpw.m.Load(name)
	if !ok {
		return false
	}
	encodedPassword := value.(string)

	// [Moduler Crypt Format](https://passlib.readthedocs.io/en/stable/modular_crypt_format.html)

	elems := strings.Split(encodedPassword, "$")
	switch len(elems) {
	case 4:
		switch elems[1] {
		case "2", "2a", "2b", "2x", "2y": // different bcrypt versions
			return bcrypt.Match(encodedPassword, password)
		case "apr1":
			return apr1.Match(encodedPassword, password)
		}
	}

	if strings.HasPrefix(encodedPassword, "{SHA}") {
		return sha1.Match(encodedPassword, password)
	}

	return false
}

func (htpw *HTPasswd) Set(name, password string) error {
	encodedPassword, err := bcrypt.Encode(password)
	if err != nil {
		return err
	}

	htpw.m.Store(name, encodedPassword)

	return nil
}

func (htpw *HTPasswd) Has(name string) bool {
	_, ok := htpw.m.Load(name)
	return ok
}

func (htpw *HTPasswd) Remove(name string) {
	htpw.m.Delete(name)
}
