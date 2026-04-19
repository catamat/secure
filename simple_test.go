package secure

import (
	"bytes"
	"testing"
)

func TestSimpleGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestSimpleSignVerifyRoundtrip(t *testing.T) {
	priv, pub, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}

	message := []byte("simple signing message")
	sig, err := Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if err := Verify(message, sig, pub); err != nil {
		t.Errorf("Verify failed on valid signature: %v", err)
	}

	if err := Verify([]byte("tampered"), sig, pub); err == nil {
		t.Errorf("Verify accepted a tampered message")
	}
}

func TestSimpleEncryptDecryptRoundtrip(t *testing.T) {
	priv, pub, err := GenerateEncryptionKeyPair()
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyPair failed: %v", err)
	}

	plainText := []byte("asymmetric hello")
	ct, err := Encrypt(plainText, pub)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	pt, err := Decrypt(ct, priv)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}
}

func TestSimpleEncryptRejectsNilRecipient(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Errorf("expected error for nil recipient public key")
	}
	if _, err := Decrypt([]byte("aaaa"), nil); err == nil {
		t.Errorf("expected error for nil recipient private key")
	}
}

func TestSimpleEncryptWithKeyRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	plainText := []byte("symmetric hello")

	ct, err := EncryptWithKey(plainText, key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	pt, err := DecryptWithKey(ct, key)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}
}

func TestSimpleEncryptWithKeyRejectsWrongSize(t *testing.T) {
	if _, err := EncryptWithKey([]byte("x"), make([]byte, 16)); err == nil {
		t.Errorf("expected error for non-32-byte key")
	}
}

func TestSimpleEncryptWithPasswordRoundtrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	plainText := []byte("password-based hello")

	ct, err := EncryptWithPassword(plainText, password)
	if err != nil {
		t.Fatalf("EncryptWithPassword failed: %v", err)
	}
	pt, err := DecryptWithPassword(ct, password)
	if err != nil {
		t.Fatalf("DecryptWithPassword failed: %v", err)
	}
	if !bytes.Equal(pt, plainText) {
		t.Errorf("got %s, want %s", pt, plainText)
	}

	if _, err := DecryptWithPassword(ct, []byte("wrong password")); err == nil {
		t.Errorf("expected error decrypting with wrong password")
	}
}

func TestSimpleHashVerifyPasswordRoundtrip(t *testing.T) {
	password := []byte("my precious password")

	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if err := VerifyPassword(hashed, password); err != nil {
		t.Errorf("VerifyPassword failed on the right password: %v", err)
	}
	if err := VerifyPassword(hashed, []byte("wrong password")); err == nil {
		t.Errorf("VerifyPassword accepted a wrong password")
	}
}

func TestSimpleCrossContracts(t *testing.T) {
	// GenerateKey must be accepted by EncryptWithKey / DecryptWithKey.
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	ct, err := EncryptWithKey([]byte("a"), k)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	if _, err := DecryptWithKey(ct, k); err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}

	// GenerateEncryptionKeyPair must be accepted by Encrypt / Decrypt.
	priv, pub, err := GenerateEncryptionKeyPair()
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyPair failed: %v", err)
	}
	ct, err = Encrypt([]byte("b"), pub)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := Decrypt(ct, priv); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// GenerateSigningKeyPair must be accepted by Sign / Verify.
	sPriv, sPub, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}
	sig, err := Sign([]byte("c"), sPriv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if err := Verify([]byte("c"), sig, sPub); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}
