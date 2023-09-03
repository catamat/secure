package secure

import (
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
	n, err := enc.Decode(dbuf, []byte(data))
	return dbuf[:n], err
}

// ScryptDeriveKey derives a 32-bytes key from a variable length password.
func ScryptDeriveKey(password []byte, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// RSAGenerateKeyPair generates a key pair from a variable bit size.
func RSAGenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, _ := rsa.GenerateKey(rand.Reader, bits)
	return privKey, &privKey.PublicKey
}

// RSAExportPrivateKeyAsPEM encodes a private key in a PEM block.
func RSAExportPrivateKeyAsPEM(privKey *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)

	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)

	return privPem
}

// RSAParsePrivateKeyFromPEM decodes a private key from a PEM block.
func RSAParsePrivateKeyFromPEM(privPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// RSAExportPublicKeyAsPEM encodes a public key in a PEM block.
func RSAExportPublicKeyAsPEM(pubKey *rsa.PublicKey) ([]byte, error) {
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

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return pubKey, nil
	default:
		break
	}

	return nil, errors.New("key type is not RSA")
}

// GenerateRandomBytes generates securely random bytes.
func GenerateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString generates a random string.
func GenerateRandomString(length int, upperCase bool, lowerCase bool, digits bool, symbols bool) (string, error) {
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
	r := make([]byte, length+(length/4))
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

// GenerateRandomStringURLSafe generates a URL-safe, base64 encoded, random string.
func GenerateRandomStringURLSafe(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateHumanPassword generates a human readable password.
func GenerateHumanPassword(letters int, digits int) (string, error) {
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
	r := make([]byte, length+(length/4))
	il := 0
	in := 0

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

				if c%2 == 0 {
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
