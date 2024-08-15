package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// AESEncryptWithGCM encrypts a plain text using the key.
func AESEncryptWithGCM(plainText []byte, key []byte) ([]byte, error) {
	key, salt, err := ScryptDeriveKey(key, nil)
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

	encryptedText := gcm.Seal(nonce, nonce, plainText, nil)
	encryptedText = append(encryptedText, salt...)

	et := EncodeBase64(encryptedText)

	return et, nil
}

// AESDecryptWithGCM decrypts an encrypted text using the key.
func AESDecryptWithGCM(encryptedText []byte, key []byte) ([]byte, error) {
	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	if len(et) < 32 {
		return nil, errors.New("encrypted text is too short")
	}

	salt, data := et[len(et)-32:], et[:len(et)-32]

	key, _, err = ScryptDeriveKey(key, salt)
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
	if len(data) < nonceSize {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	decryptedText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return decryptedText, nil
}

// RSAEncryptWithOAEP encrypts a plain text using a public key.
func RSAEncryptWithOAEP(plainText []byte, pubKey *rsa.PublicKey, label []byte) ([]byte, error) {
	rng := rand.Reader

	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rng, pubKey, plainText, label)
	if err != nil {
		return nil, err
	}

	et := EncodeBase64(encryptedText)

	return et, nil
}

// RSADecryptWithOAEP decrypts an encrypted text using a private key.
func RSADecryptWithOAEP(encryptedText []byte, privKey *rsa.PrivateKey, label []byte) ([]byte, error) {
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
