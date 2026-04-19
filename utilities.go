package secure

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// EncodeBase64 encodes data in base64 format.
func EncodeBase64(data []byte) []byte {
	enc := base64.StdEncoding
	buf := make([]byte, enc.EncodedLen(len(data)))
	enc.Encode(buf, data)
	return buf
}

// DecodeBase64 decodes data in base64 format.
func DecodeBase64(data []byte) ([]byte, error) {
	enc := base64.StdEncoding
	dbuf := make([]byte, enc.DecodedLen(len(data)))
	n, err := enc.Decode(dbuf, data)
	if err != nil {
		return nil, err
	}
	return dbuf[:n], nil
}

// ScryptDeriveKey derives a 32-byte key from a variable length password.
// Parameters follow OWASP 2024 guidance for scrypt as a KDF (N=2^17, r=8, p=1).
// If salt is nil or empty, a fresh 32-byte random salt is generated.
func ScryptDeriveKey(password []byte, salt []byte) ([]byte, []byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1<<17, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// RSAGenerateKeyPair generates an RSA key pair of the given bit size.
// bits must be at least 2048.
func RSAGenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, errors.New("RSA key size must be at least 2048 bits")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	return privKey, &privKey.PublicKey, nil
}

// RSAExportPrivateKeyAsPEM encodes a private key in a PKCS#8 PEM block.
func RSAExportPrivateKeyAsPEM(privKey *rsa.PrivateKey) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key is nil")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), nil
}

// RSAParsePrivateKeyFromPEM decodes a private key from a PEM block.
// Both PKCS#8 ("PRIVATE KEY") and legacy PKCS#1 ("RSA PRIVATE KEY") encodings
// are accepted.
func RSAParsePrivateKeyFromPEM(privPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key type is not RSA")
		}
		return rsaKey, nil
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Ed25519GenerateKeyPair generates an Ed25519 key pair.
func Ed25519GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// Ed25519ExportPrivateKeyAsPEM encodes an Ed25519 private key as PKCS#8 PEM.
func Ed25519ExportPrivateKeyAsPEM(privKey ed25519.PrivateKey) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), nil
}

// Ed25519ParsePrivateKeyFromPEM decodes an Ed25519 private key from PKCS#8 PEM.
func Ed25519ParsePrivateKeyFromPEM(privPem []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(privPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key type is not Ed25519")
	}
	return edKey, nil
}

// Ed25519ExportPublicKeyAsPEM encodes an Ed25519 public key as PKIX PEM.
func Ed25519ExportPublicKeyAsPEM(pubKey ed25519.PublicKey) ([]byte, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key size")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}), nil
}

// Ed25519ParsePublicKeyFromPEM decodes an Ed25519 public key from PKIX PEM.
func Ed25519ParsePublicKeyFromPEM(pubPem []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pubPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("key type is not Ed25519")
	}
	return edKey, nil
}

// X25519GenerateKeyPair generates an X25519 key pair for ECDH.
func X25519GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// X25519ExportPrivateKeyAsPEM encodes an X25519 private key as PKCS#8 PEM.
func X25519ExportPrivateKeyAsPEM(privKey *ecdh.PrivateKey) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key is nil")
	}
	if privKey.Curve() != ecdh.X25519() {
		return nil, errors.New("private key is not on X25519 curve")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), nil
}

// X25519ParsePrivateKeyFromPEM decodes an X25519 private key from PKCS#8 PEM.
func X25519ParsePrivateKeyFromPEM(privPem []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(privPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdhKey, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("key type is not X25519")
	}
	if ecdhKey.Curve() != ecdh.X25519() {
		return nil, errors.New("private key is not on X25519 curve")
	}
	return ecdhKey, nil
}

// X25519ExportPublicKeyAsPEM encodes an X25519 public key as PKIX PEM.
func X25519ExportPublicKeyAsPEM(pubKey *ecdh.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key is nil")
	}
	if pubKey.Curve() != ecdh.X25519() {
		return nil, errors.New("public key is not on X25519 curve")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}), nil
}

// X25519ParsePublicKeyFromPEM decodes an X25519 public key from PKIX PEM.
func X25519ParsePublicKeyFromPEM(pubPem []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(pubPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdhKey, ok := key.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("key type is not X25519")
	}
	if ecdhKey.Curve() != ecdh.X25519() {
		return nil, errors.New("public key is not on X25519 curve")
	}
	return ecdhKey, nil
}

// RSAExportPublicKeyAsPEM encodes a public key in a PEM block.
func RSAExportPublicKeyAsPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key is nil")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)

	return pubPem, nil
}

// RSAParsePublicKeyFromPEM decodes a public key from a PEM block.
func RSAParsePublicKeyFromPEM(pubPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		return rsaKey, nil
	}

	return nil, errors.New("key type is not RSA")
}

// GenerateRandomBytes generates securely random bytes.
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("length must be positive")
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString generates a random string of the requested length using
// the chosen character classes. At least two character classes' worth of
// distinct characters must be selected.
func GenerateRandomString(length int, upperCase bool, lowerCase bool, digits bool, symbols bool) (string, error) {
	if length < 0 {
		return "", errors.New("length must be non-negative")
	}

	var chars = ""

	if upperCase {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}

	if lowerCase {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}

	if digits {
		chars += "0123456789"
	}

	if symbols {
		chars += "[]!\"#$%&'()*+,-./:;<=>?@\\^_`{|}~"
	}

	if length == 0 {
		length = 16
	}

	clen := len(chars)
	if clen < 2 || clen > 256 {
		return "", errors.New("wrong charset length")
	}

	maxrb := 255 - (256 % clen)
	b := make([]byte, length)
	r := make([]byte, length+(length/4)+1)
	i := 0

	for {
		if _, err := rand.Read(r); err != nil {
			return "", errors.New("error reading random bytes")
		}

		for _, rb := range r {
			c := int(rb)
			if c > maxrb {
				continue
			}

			b[i] = chars[c%clen]
			i++

			if i == length {
				return string(b), nil
			}
		}
	}
}

// GenerateRandomStringURLSafe generates a URL-safe random string built from
// `length` bytes of entropy (the resulting string is longer because of base64).
// Uses unpadded base64url so the output is safe in URLs and filenames.
func GenerateRandomStringURLSafe(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateHumanPassword generates a human readable password.
//
// WARNING: the alphabet is restricted to lowercase letters and digits with an
// alternating vowel/consonant pattern, so entropy per character is far below a
// fully random string. Do not use this as a production password by default —
// either pick a high `letters`/`digits` count or use GenerateRandomString.
func GenerateHumanPassword(letters int, digits int) (string, error) {
	if letters < 0 || digits < 0 {
		return "", errors.New("letters and digits must be non-negative")
	}

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"

	if letters == 0 && digits == 0 {
		letters = 4
		digits = 4
	}

	length := letters + digits

	clen := len(chars)
	if clen < 2 || clen > 256 {
		return "", errors.New("wrong charset length")
	}

	maxrb := 255 - (256 % clen)
	bl := make([]byte, letters)
	bn := make([]byte, digits)
	r := make([]byte, length+(length/4)+1)
	il := 0
	in := 0
	last := 0

	for {
		if _, err := rand.Read(r); err != nil {
			return "", errors.New("error reading random bytes")
		}

		for _, rb := range r {
			c := int(rb)
			if c > maxrb {
				continue
			}

			cc := chars[c%clen]
			last = c

			switch charType(cc) {
			case "vowel":
				if il > 0 {
					if (charType(bl[il-1])) != "vowel" && il < letters {
						bl[il] = cc
						il++
					}
				} else {
					if letters > 0 {
						bl[0] = cc
						il++
					}
				}
			case "digit":
				if in < digits {
					bn[in] = cc
					in++
				}
			case "consonant":
				if il > 0 {
					if (charType(bl[il-1])) != "consonant" && il < letters {
						bl[il] = cc
						il++
					}
				} else {
					if letters > 0 {
						bl[0] = cc
						il++
					}
				}
			}

			if il+in == length {
				b := string(bl) + string(bn)

				if last%2 == 0 {
					b = string(bn) + string(bl)
				}

				return b, nil
			}
		}
	}
}

// charType returns if a char is a vowel, a consonant or a digit.
func charType(char byte) string {
	const vowels = "aeiou"
	const digits = "0123456789"

	if strings.Contains(vowels, string(char)) {
		return "vowel"
	} else if strings.Contains(digits, string(char)) {
		return "digit"
	} else {
		return "consonant"
	}
}
