package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// EncryptAesAEAD encrypts a decrypted text using the key.
func EncryptAesAEAD(decryptedText []byte, key []byte) ([]byte, error) {
	key, salt, err := DeriveScryptKey(key, nil)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	encryptedText := gcm.Seal(nonce, nonce, decryptedText, nil)
	encryptedText = append(encryptedText, salt...)

	et := EncodeBase64(encryptedText)

	return et, nil
}

// DecryptAesAEAD decrypts an encrypted text using the key.
func DecryptAesAEAD(encryptedText []byte, key []byte) ([]byte, error) {
	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	salt, data := et[len(et)-32:], et[:len(et)-32]

	key, _, err = DeriveScryptKey(key, salt)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(et) < nonceSize {
		return nil, errors.New("secure: text too short")
	}

	nonce, et := data[:nonceSize], data[nonceSize:]
	decryptedText, err := gcm.Open(nil, nonce, et, nil)
	if err != nil {
		return nil, err
	}

	return decryptedText, nil
}

// EncryptRsaOAEP encrypts a decrypted text using a public key.
func EncryptRsaOAEP(decryptedText []byte, pubKey *rsa.PublicKey, label []byte) ([]byte, error) {
	rng := rand.Reader

	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rng, pubKey, decryptedText, label)
	if err != nil {
		return nil, err
	}

	et := EncodeBase64(encryptedText)

	return et, nil
}

// DecryptRsaOAEP decrypts an encrypted text using a private key.
func DecryptRsaOAEP(encryptedText []byte, privKey *rsa.PrivateKey, label []byte) ([]byte, error) {
	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	rng := rand.Reader

	decryptedText, err := rsa.DecryptOAEP(sha256.New(), rng, privKey, et, label)
	if err != nil {
		return nil, err
	}

	return decryptedText, nil
}
