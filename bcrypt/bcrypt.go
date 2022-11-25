package bcrypt

import "golang.org/x/crypto/bcrypt"

func Match(encodedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(password))
	return err == nil
}

func Encode(password string) (string, error) {
	data, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(data), err
}
