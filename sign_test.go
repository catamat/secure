package secure

import (
	"crypto/ed25519"
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

func TestEd25519SignAndVerify(t *testing.T) {
	privKey, pubKey, err := Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("Ed25519GenerateKeyPair failed: %v", err)
	}

	message := []byte("verifiable message")

	signature, err := Ed25519Sign(message, privKey)
	if err != nil {
		t.Fatalf("Ed25519Sign failed: %v", err)
	}

	if err := Ed25519Verify(message, signature, pubKey); err != nil {
		t.Errorf("Ed25519Verify failed: %v", err)
	}
}

func TestEd25519VerifyRejectsModifiedMessage(t *testing.T) {
	privKey, pubKey, err := Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("Ed25519GenerateKeyPair failed: %v", err)
	}

	signature, err := Ed25519Sign([]byte("original"), privKey)
	if err != nil {
		t.Fatalf("Ed25519Sign failed: %v", err)
	}

	if err := Ed25519Verify([]byte("tampered"), signature, pubKey); err == nil {
		t.Errorf("expected error for tampered message")
	}
}

func TestEd25519VerifyRejectsInvalidSignature(t *testing.T) {
	_, pubKey, err := Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("Ed25519GenerateKeyPair failed: %v", err)
	}

	if err := Ed25519Verify([]byte("msg"), []byte("!!!notbase64"), pubKey); err == nil {
		t.Errorf("expected error for non-base64 signature")
	}

	bogus := EncodeBase64(make([]byte, ed25519.SignatureSize))
	if err := Ed25519Verify([]byte("msg"), bogus, pubKey); err == nil {
		t.Errorf("expected error for wrong signature bytes")
	}
}

func TestEd25519SignRejectsWrongKeySize(t *testing.T) {
	if _, err := Ed25519Sign([]byte("msg"), ed25519.PrivateKey("tooshort")); err == nil {
		t.Errorf("expected error for invalid private key size")
	}
	if err := Ed25519Verify([]byte("msg"), []byte("AAAA"), ed25519.PublicKey("tooshort")); err == nil {
		t.Errorf("expected error for invalid public key size")
	}
}

func TestRSASignVerifyRejectNilKeys(t *testing.T) {
	if _, err := RSASignWithPSS([]byte("msg"), nil); err == nil {
		t.Fatalf("expected error for nil RSA private key")
	}
	if err := RSAVerifyWithPSS([]byte("msg"), []byte("AAAA"), nil); err == nil {
		t.Fatalf("expected error for nil RSA public key")
	}
}
