package secure

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAESEncryptWithGCMAndDecrypt(t *testing.T) {
	key := []byte("supersecretkey")
	plainText := []byte("yourpassword1234")

	encryptedText, err := AESEncryptWithGCM(plainText, key)
	if err != nil {
		t.Fatalf("AESEncryptWithGCM failed: %v", err)
	}

	decryptedText, err := AESDecryptWithGCM(encryptedText, key)
	if err != nil {
		t.Fatalf("AESDecryptWithGCM failed: %v", err)
	}

	if !bytes.Equal(plainText, decryptedText) {
		t.Errorf("Decrypted text does not match the original. Got: %s, want: %s", decryptedText, plainText)
	}
}

func TestAESDecryptWithGCMShortInput(t *testing.T) {
	key := []byte("supersecretkey")

	shortEncryptedText1 := []byte("yourpassword1234")
	_, err := AESDecryptWithGCM(shortEncryptedText1, key)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "encrypted text is too short" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "encrypted text is too short")
	}

	shortEncryptedText2 := []byte("yourpassword1234yourpassword1234")
	_, err = AESDecryptWithGCM(shortEncryptedText2, key)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "encrypted text is too short" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "encrypted text is too short")
	}

	shortEncryptedText3 := []byte("yourpassword1234yourpassword1234yourpassword1234")
	_, err = AESDecryptWithGCM(shortEncryptedText3, key)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "data is shorter than the required nonce size" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "data is shorter than the required nonce size")
	}

	shortEncryptedText4 := []byte("yourpassword1234yourpassword1234yourpassword1234yourpassword1234")
	_, err = AESDecryptWithGCM(shortEncryptedText4, key)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "cipher: message authentication failed" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "cipher: message authentication failed")
	}
}

func TestRSAEncryptWithOAEPAndDecrypt(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pubKey := &privKey.PublicKey
	plainText := []byte("This is a secret message")

	encryptedText, err := RSAEncryptWithOAEP(plainText, pubKey, nil)
	if err != nil {
		t.Fatalf("RSAEncryptWithOAEP failed: %v", err)
	}

	decryptedText, err := RSADecryptWithOAEP(encryptedText, privKey, nil)
	if err != nil {
		t.Fatalf("RSADecryptWithOAEP failed: %v", err)
	}

	if !bytes.Equal(plainText, decryptedText) {
		t.Errorf("Decrypted text does not match the original. Got: %s, want: %s", decryptedText, plainText)
	}
}

func TestRSADecryptWithOAEPInvalidInput(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	invalidEncryptedText := []byte("invalidtext")

	_, err = RSADecryptWithOAEP(invalidEncryptedText, privKey, nil)
	if err == nil {
		t.Fatalf("Expected error for invalid encrypted input, but got none")
	}

	expectedError := "illegal base64 data at input byte 8"
	if err.Error() != expectedError {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, expectedError)
	}
}
