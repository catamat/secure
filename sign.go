package secure

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// RSASignWithPSS signs a plain text using a private key.
func RSASignWithPSS(plainText []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	textHash := sha256.New()
	_, err := textHash.Write(plainText)
	if err != nil {
		return nil, err
	}

	textHashSum := textHash.Sum(nil)
	rng := rand.Reader

	signature, err := rsa.SignPSS(rng, privKey, crypto.SHA256, textHashSum, nil)
	if err != nil {
		return nil, err
	}

	s := EncodeBase64(signature)

	return s, nil
}

// RSAVerifyWithPSS verifies a signed text using a public key.
func RSAVerifyWithPSS(signedText []byte, signature []byte, pubKey *rsa.PublicKey) error {
	s, err := DecodeBase64(signature)
	if err != nil {
		return err
	}

	textHash := sha256.New()
	_, err = textHash.Write(signedText)
	if err != nil {
		return err
	}

	textHashSum := textHash.Sum(nil)

	return rsa.VerifyPSS(pubKey, crypto.SHA256, textHashSum, s, nil)
}
