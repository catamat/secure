package secure

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSASignWithPSSAndVerify(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pubKey := &privKey.PublicKey
	plainText := []byte("This is a message to sign")

	signature, err := RSASignWithPSS(plainText, privKey)
	if err != nil {
		t.Fatalf("RSASignWithPSS failed: %v", err)
	}

	err = RSAVerifyWithPSS(plainText, signature, pubKey)
	if err != nil {
		t.Errorf("RSAVerifyWithPSS failed: %v", err)
	}
}

func TestRSAVerifyWithPSSInvalidSignature(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pubKey := &privKey.PublicKey
	plainText := []byte("This is a message to sign")

	_, err = RSASignWithPSS(plainText, privKey)
	if err != nil {
		t.Fatalf("RSASignWithPSS failed: %v", err)
	}

	invalidSignature := []byte("invalidsignature")

	err = RSAVerifyWithPSS(plainText, invalidSignature, pubKey)
	if err == nil {
		t.Errorf("Expected error for invalid signature, got nil")
	}
}

func TestRSAVerifyWithPSSModifiedText(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pubKey := &privKey.PublicKey
	plainText := []byte("This is a message to sign")

	signature, err := RSASignWithPSS(plainText, privKey)
	if err != nil {
		t.Fatalf("RSASignWithPSS failed: %v", err)
	}

	modifiedText := []byte("This is a modified message")

	err = RSAVerifyWithPSS(modifiedText, signature, pubKey)
	if err == nil {
		t.Errorf("Expected error for modified text, got nil")
	}
}
