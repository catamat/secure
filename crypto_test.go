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

	// Below the minimum length (salt + nonce + tag = 60 bytes).
	// Everything under that must be rejected before scrypt runs so an attacker
	// can't use short ciphertexts to force the expensive KDF.
	for _, size := range []int{0, 5, 32, 32 + 12, 32 + 12 + 15} {
		_, err := AESDecryptWithGCM(EncodeBase64(make([]byte, size)), key)
		if err == nil || err.Error() != "encrypted text is too short" {
			t.Fatalf("size=%d: expected 'encrypted text is too short', got %v", size, err)
		}
	}

	// Exactly salt + nonce + tag-sized garbage: passes length check, GCM auth
	// must then fail.
	garbage := EncodeBase64(make([]byte, 32+12+16))
	if _, err := AESDecryptWithGCM(garbage, key); err == nil {
		t.Fatalf("expected GCM authentication failure")
	}
}

func TestAESDecryptWithGCMWrongPassword(t *testing.T) {
	encryptedText, err := AESEncryptWithGCM([]byte("hello"), []byte("rightpw"))
	if err != nil {
		t.Fatalf("AESEncryptWithGCM failed: %v", err)
	}
	if _, err := AESDecryptWithGCM(encryptedText, []byte("wrongpw")); err == nil {
		t.Fatalf("expected error decrypting with wrong password")
	}
}

func TestAESEncryptWithGCMKeyRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	plainText := []byte("hello world")

	ct, err := AESEncryptWithGCMKey(plainText, key)
	if err != nil {
		t.Fatalf("AESEncryptWithGCMKey failed: %v", err)
	}
	pt, err := AESDecryptWithGCMKey(ct, key)
	if err != nil {
		t.Fatalf("AESDecryptWithGCMKey failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}
}

func TestAESEncryptWithGCMKeyInvalidKeyLength(t *testing.T) {
	if _, err := AESEncryptWithGCMKey([]byte("x"), []byte("tooshort")); err == nil {
		t.Errorf("expected error for invalid key length")
	}
	if _, err := AESDecryptWithGCMKey([]byte("aaaa"), []byte("tooshort")); err == nil {
		t.Errorf("expected error for invalid key length")
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

	if _, err = RSADecryptWithOAEP([]byte("invalidtext"), privKey, nil); err == nil {
		t.Fatalf("Expected error for invalid encrypted input, but got none")
	}
}

func TestRSAEncryptDecryptRejectNilKeys(t *testing.T) {
	if _, err := RSAEncryptWithOAEP([]byte("msg"), nil, nil); err == nil {
		t.Fatalf("expected error for nil RSA public key")
	}
	if _, err := RSADecryptWithOAEP([]byte("AAAA"), nil, nil); err == nil {
		t.Fatalf("expected error for nil RSA private key")
	}
}

func TestChaCha20Poly1305KeyRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	plainText := []byte("hello xchacha")

	ct, err := ChaCha20Poly1305EncryptWithKey(plainText, key)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305EncryptWithKey failed: %v", err)
	}
	pt, err := ChaCha20Poly1305DecryptWithKey(ct, key)
	if err != nil {
		t.Fatalf("ChaCha20Poly1305DecryptWithKey failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}
}

func TestChaCha20Poly1305InvalidKeyLength(t *testing.T) {
	if _, err := ChaCha20Poly1305EncryptWithKey([]byte("x"), make([]byte, 16)); err == nil {
		t.Errorf("expected error for 16-byte key")
	}
	if _, err := ChaCha20Poly1305DecryptWithKey([]byte("aaaa"), make([]byte, 16)); err == nil {
		t.Errorf("expected error for 16-byte key")
	}
}

func TestChaCha20Poly1305DecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	if _, err := ChaCha20Poly1305DecryptWithKey(EncodeBase64([]byte("short")), key); err == nil {
		t.Errorf("expected error for too-short ciphertext")
	}
}

func TestX25519EncryptDecryptRoundtrip(t *testing.T) {
	privKey, pubKey, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}

	plainText := []byte("asymmetric message")

	ct, err := X25519EncryptWithChaCha20Poly1305(plainText, pubKey)
	if err != nil {
		t.Fatalf("X25519EncryptWithChaCha20Poly1305 failed: %v", err)
	}
	pt, err := X25519DecryptWithChaCha20Poly1305(ct, privKey)
	if err != nil {
		t.Fatalf("X25519DecryptWithChaCha20Poly1305 failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}
}

func TestX25519DecryptWithWrongKeyFails(t *testing.T) {
	_, pubKey, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}
	otherPriv, _, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}

	ct, err := X25519EncryptWithChaCha20Poly1305([]byte("msg"), pubKey)
	if err != nil {
		t.Fatalf("X25519EncryptWithChaCha20Poly1305 failed: %v", err)
	}
	if _, err := X25519DecryptWithChaCha20Poly1305(ct, otherPriv); err == nil {
		t.Errorf("expected error when decrypting with wrong private key")
	}
}

func TestX25519DecryptTooShort(t *testing.T) {
	privKey, _, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}
	if _, err := X25519DecryptWithChaCha20Poly1305(EncodeBase64([]byte("short")), privKey); err == nil {
		t.Errorf("expected error for too-short ciphertext")
	}
}

func TestX25519RejectsNilKeys(t *testing.T) {
	if _, err := X25519EncryptWithChaCha20Poly1305([]byte("x"), nil); err == nil {
		t.Errorf("expected error for nil recipient public key")
	}
	if _, err := X25519DecryptWithChaCha20Poly1305([]byte("aaaa"), nil); err == nil {
		t.Errorf("expected error for nil recipient private key")
	}
}

func TestX25519DecryptTamperedCiphertext(t *testing.T) {
	privKey, pubKey, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}
	ct, err := X25519EncryptWithChaCha20Poly1305([]byte("message"), pubKey)
	if err != nil {
		t.Fatalf("X25519EncryptWithChaCha20Poly1305 failed: %v", err)
	}

	raw, err := DecodeBase64(ct)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := EncodeBase64(raw)

	if _, err := X25519DecryptWithChaCha20Poly1305(tampered, privKey); err == nil {
		t.Errorf("expected AEAD failure on tampered ciphertext")
	}
}
