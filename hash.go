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

// GenerateBcryptHash generates a new hash from a password at the given cost.
func GenerateBcryptHash(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

// CompareBcryptHash compares an hashed password with its plain equivalent.
func CompareBcryptHash(hashedPassword []byte, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// GenerateArgon2IDHash generates a new hash from a password with the given parameters.
func GenerateArgon2IDHash(password []byte, memory uint32, time uint32, threads uint8, saltLen int, keyLen uint32) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encoded := []byte(fmt.Sprintf(format, argon2.Version, memory, time, threads, b64Salt, b64Hash))

	return encoded, nil
}

// CompareArgon2IDHash compares an hashed password with its plain equivalent.
func CompareArgon2IDHash(hashedPassword []byte, password []byte) error {
	parts := strings.Split(string(hashedPassword), "$")

	c := struct {
		memory  uint32
		time    uint32
		threads uint8
		keyLen  uint32
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

	c.keyLen = uint32(len(decodedHash))

	comparisonHash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLen)
	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return errors.New("secure: password does not match")
}
