package secure

import "golang.org/x/crypto/bcrypt"

// GenerateBcryptHash generates a new hash from a password at the given cost.
func GenerateBcryptHash(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

// CompareBcryptHash compares an hashed password with its plain equivalent.
func CompareBcryptHash(hashedPassword []byte, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}
