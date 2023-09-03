package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// BcryptGenerateHash generates a new hash from a plain password at the given cost.
func BcryptGenerateHash(plainPassword []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(plainPassword, cost)
}

// BcryptCompareHash compares an hashed password with its plain equivalent.
func BcryptCompareHash(hashedPassword []byte, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// Argon2idGenerateHash generates a new hash from a plain password with the given parameters.
func Argon2idGenerateHash(plainPassword []byte, memory uint32, time uint32, threads uint8, saltLength int, keyLength uint32) ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey(plainPassword, salt, time, memory, threads, keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encoded := []byte(fmt.Sprintf(format, argon2.Version, memory, time, threads, b64Salt, b64Hash))

	return encoded, nil
}

// Argon2idCompareHash compares an hashed password with its plain equivalent.
func Argon2idCompareHash(hashedPassword []byte, password []byte) error {
	parts := strings.Split(string(hashedPassword), "$")

	c := struct {
		memory    uint32
		time      uint32
		threads   uint8
		keyLength uint32
	}{}

	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads)
	if err != nil {
		return err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return err
	}

	c.keyLength = uint32(len(decodedHash))

	comparisonHash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLength)
	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return errors.New("password does not match")
}
