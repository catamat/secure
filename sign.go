package secure

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// RSASignWithPSS signs a plain text using a private key.
func RSASignWithPSS(plainText []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key is nil")
	}

	textHash := sha256.New()
	_, err := textHash.Write(plainText)
	if err != nil {
		return nil, err
	}

	textHashSum := textHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, textHashSum, nil)
	if err != nil {
		return nil, err
	}

	return EncodeBase64(signature), nil
}

// RSAVerifyWithPSS verifies a signed text using a public key.
func RSAVerifyWithPSS(signedText []byte, signature []byte, pubKey *rsa.PublicKey) error {
	if pubKey == nil {
		return errors.New("public key is nil")
	}

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

// Ed25519Sign signs a message using an Ed25519 private key.
// Ed25519 is deterministic, so two signatures over the same message are equal.
func Ed25519Sign(message []byte, privKey ed25519.PrivateKey) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	signature := ed25519.Sign(privKey, message)
	return EncodeBase64(signature), nil
}

// Ed25519Verify verifies a signature over a message using an Ed25519 public key.
func Ed25519Verify(message []byte, signature []byte, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key size")
	}

	s, err := DecodeBase64(signature)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, message, s) {
		return errors.New("invalid signature")
	}
	return nil
}
