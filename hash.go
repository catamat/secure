package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id verification safety caps. A compliant hash carries small parameters;
// these limits stop a maliciously crafted hash from turning a single Compare
// call into a multi-GiB / multi-minute DoS.
const (
	argon2idMaxMemoryKiB = 1 << 22 // 4 GiB
	argon2idMaxTime      = 100
	argon2idMaxThreads   = 16
	argon2idMaxSaltLen   = 1024
	argon2idMaxKeyLength = 1024
)

// bcryptPreHash returns a fixed-length representation of the password so that
// bcrypt's 72-byte truncation cannot silently make two long passwords collide.
func bcryptPreHash(password []byte) []byte {
	sum := sha256.Sum256(password)
	return []byte(base64.RawStdEncoding.EncodeToString(sum[:]))
}

// BcryptGenerateHash generates a new hash from a plain password at the given cost.
// The password is pre-hashed with SHA-256 and base64-encoded before being passed
// to bcrypt to avoid the 72-byte truncation. A cost of 0 selects bcrypt.DefaultCost.
func BcryptGenerateHash(plainPassword []byte, cost int) ([]byte, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return bcrypt.GenerateFromPassword(bcryptPreHash(plainPassword), cost)
}

// BcryptCompareHash compares an hashed password with its plain equivalent.
func BcryptCompareHash(hashedPassword []byte, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, bcryptPreHash(password))
}

// Argon2idGenerateHash generates a new hash from a plain password with the given parameters.
func Argon2idGenerateHash(plainPassword []byte, memory uint32, time uint32, threads uint8, saltLength int, keyLength uint32) ([]byte, error) {
	if saltLength <= 0 || keyLength == 0 || memory == 0 || time == 0 || threads == 0 {
		return nil, errors.New("invalid argon2id parameters")
	}

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
	if len(parts) != 6 || parts[0] != "" {
		return errors.New("invalid argon2id hash: malformed encoding")
	}

	if parts[1] != "argon2id" {
		return errors.New("invalid argon2id hash: unexpected algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return errors.New("invalid argon2id hash: cannot parse version")
	}
	if version != argon2.Version {
		return fmt.Errorf("invalid argon2id hash: unsupported version %d", version)
	}

	c := struct {
		memory    uint32
		time      uint32
		threads   uint8
		keyLength uint32
	}{}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads); err != nil {
		return errors.New("invalid argon2id hash: cannot parse parameters")
	}
	if c.memory == 0 || c.time == 0 || c.threads == 0 {
		return errors.New("invalid argon2id hash: zero parameters")
	}
	if c.memory > argon2idMaxMemoryKiB || c.time > argon2idMaxTime || uint32(c.threads) > argon2idMaxThreads {
		return errors.New("invalid argon2id hash: parameters exceed safety limits")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("invalid argon2id hash: cannot decode salt")
	}
	if len(salt) > argon2idMaxSaltLen {
		return errors.New("invalid argon2id hash: salt exceeds safety limits")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("invalid argon2id hash: cannot decode hash")
	}

	c.keyLength = uint32(len(decodedHash))
	if c.keyLength == 0 {
		return errors.New("invalid argon2id hash: empty hash")
	}
	if c.keyLength > argon2idMaxKeyLength {
		return errors.New("invalid argon2id hash: key length exceeds safety limits")
	}

	comparisonHash := argon2.IDKey(password, salt, c.time, c.memory, c.threads, c.keyLength)
	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return errors.New("password does not match")
}
