package secure

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestEncodeDecodeBase64(t *testing.T) {
	originalText := []byte("This is a test string")

	encoded := EncodeBase64(originalText)
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}

	if !bytes.Equal(originalText, decoded) {
		t.Errorf("Decoded text does not match original. Got: %s, want: %s", decoded, originalText)
	}
}

func TestScryptDeriveKey(t *testing.T) {
	password := []byte("supersecretpassword")
	salt := []byte("somesaltvalue")

	key, derivedSalt, err := ScryptDeriveKey(password, salt)
	if err != nil {
		t.Fatalf("ScryptDeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Derived key has incorrect length. Got: %d, want: %d", len(key), 32)
	}

	if !bytes.Equal(salt, derivedSalt) {
		t.Errorf("Salt used in key derivation does not match provided salt. Got: %s, want: %s", derivedSalt, salt)
	}
}

func TestRSAGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := RSAGenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("RSAGenerateKeyPair failed: %v", err)
	}
	if privKey == nil || pubKey == nil {
		t.Fatalf("RSAGenerateKeyPair returned nil keys")
	}
}

func TestRSAGenerateKeyPairRejectsSmallSizes(t *testing.T) {
	for _, bits := range []int{0, 512, 1024, 2047} {
		if _, _, err := RSAGenerateKeyPair(bits); err == nil {
			t.Errorf("expected error for bits=%d", bits)
		}
	}
}

func TestRSAExportPrivateKeyAsPEMAndParse(t *testing.T) {
	privKey, _, err := RSAGenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("RSAGenerateKeyPair failed: %v", err)
	}
	pemKey, err := RSAExportPrivateKeyAsPEM(privKey)
	if err != nil {
		t.Fatalf("RSAExportPrivateKeyAsPEM failed: %v", err)
	}

	parsedKey, err := RSAParsePrivateKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("RSAParsePrivateKeyFromPEM failed: %v", err)
	}

	if !privKey.Equal(parsedKey) {
		t.Errorf("Parsed private key does not match the original key")
	}

	_, err = RSAParsePrivateKeyFromPEM([]byte("invalid pem block"))
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "failed to parse PEM block containing the key" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "failed to parse PEM block containing the key")
	}
}

func TestRSAParsePrivateKeyFromPEMAcceptsPKCS1(t *testing.T) {
	// Backward compatibility: existing keys exported as PKCS#1 must still parse.
	privKey, _, err := RSAGenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("RSAGenerateKeyPair failed: %v", err)
	}

	legacy := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	parsed, err := RSAParsePrivateKeyFromPEM(legacy)
	if err != nil {
		t.Fatalf("RSAParsePrivateKeyFromPEM (PKCS#1) failed: %v", err)
	}
	if !privKey.Equal(parsed) {
		t.Errorf("Parsed private key does not match the original key")
	}
}

func TestRSAExportPublicKeyAsPEMAndParse(t *testing.T) {
	_, pubKey, err := RSAGenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("RSAGenerateKeyPair failed: %v", err)
	}
	pemKey, err := RSAExportPublicKeyAsPEM(pubKey)
	if err != nil {
		t.Fatalf("RSAExportPublicKeyAsPEM failed: %v", err)
	}

	parsedKey, err := RSAParsePublicKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("RSAParsePublicKeyFromPEM failed: %v", err)
	}

	if !pubKey.Equal(parsedKey) {
		t.Errorf("Parsed public key does not match the original key")
	}

	_, err = RSAParsePublicKeyFromPEM([]byte("invalid pem block"))
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if err.Error() != "failed to parse PEM block containing the key" {
		t.Errorf("Unexpected error message. Got: %v, want: %v", err, "failed to parse PEM block containing the key")
	}
}

func TestRSAExportRejectsNilKeys(t *testing.T) {
	if _, err := RSAExportPrivateKeyAsPEM(nil); err == nil {
		t.Fatalf("expected error for nil RSA private key")
	}
	if _, err := RSAExportPublicKeyAsPEM(nil); err == nil {
		t.Fatalf("expected error for nil RSA public key")
	}
}

func TestEd25519ExportImportPrivateKey(t *testing.T) {
	privKey, _, err := Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("Ed25519GenerateKeyPair failed: %v", err)
	}
	pemKey, err := Ed25519ExportPrivateKeyAsPEM(privKey)
	if err != nil {
		t.Fatalf("Ed25519ExportPrivateKeyAsPEM failed: %v", err)
	}
	parsed, err := Ed25519ParsePrivateKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("Ed25519ParsePrivateKeyFromPEM failed: %v", err)
	}
	if !privKey.Equal(parsed) {
		t.Errorf("parsed Ed25519 private key does not match original")
	}

	if _, err := Ed25519ParsePrivateKeyFromPEM([]byte("invalid pem")); err == nil {
		t.Errorf("expected error for invalid PEM")
	}
}

func TestEd25519ExportImportPublicKey(t *testing.T) {
	_, pubKey, err := Ed25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("Ed25519GenerateKeyPair failed: %v", err)
	}
	pemKey, err := Ed25519ExportPublicKeyAsPEM(pubKey)
	if err != nil {
		t.Fatalf("Ed25519ExportPublicKeyAsPEM failed: %v", err)
	}
	parsed, err := Ed25519ParsePublicKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("Ed25519ParsePublicKeyFromPEM failed: %v", err)
	}
	if !pubKey.Equal(parsed) {
		t.Errorf("parsed Ed25519 public key does not match original")
	}

	if _, err := Ed25519ParsePublicKeyFromPEM([]byte("invalid pem")); err == nil {
		t.Errorf("expected error for invalid PEM")
	}
}

func TestX25519ExportImportPrivateKey(t *testing.T) {
	privKey, _, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}
	pemKey, err := X25519ExportPrivateKeyAsPEM(privKey)
	if err != nil {
		t.Fatalf("X25519ExportPrivateKeyAsPEM failed: %v", err)
	}
	parsed, err := X25519ParsePrivateKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("X25519ParsePrivateKeyFromPEM failed: %v", err)
	}
	if !bytes.Equal(privKey.Bytes(), parsed.Bytes()) {
		t.Errorf("parsed X25519 private key does not match original")
	}
}

func TestX25519ExportImportPublicKey(t *testing.T) {
	_, pubKey, err := X25519GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519GenerateKeyPair failed: %v", err)
	}
	pemKey, err := X25519ExportPublicKeyAsPEM(pubKey)
	if err != nil {
		t.Fatalf("X25519ExportPublicKeyAsPEM failed: %v", err)
	}
	parsed, err := X25519ParsePublicKeyFromPEM(pemKey)
	if err != nil {
		t.Fatalf("X25519ParsePublicKeyFromPEM failed: %v", err)
	}
	if !bytes.Equal(pubKey.Bytes(), parsed.Bytes()) {
		t.Errorf("parsed X25519 public key does not match original")
	}
}

func TestX25519ExportRejectsNilKeys(t *testing.T) {
	if _, err := X25519ExportPrivateKeyAsPEM(nil); err == nil {
		t.Fatalf("expected error for nil X25519 private key")
	}
	if _, err := X25519ExportPublicKeyAsPEM(nil); err == nil {
		t.Fatalf("expected error for nil X25519 public key")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	length := 16
	randomBytes, err := GenerateRandomBytes(length)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(randomBytes) != length {
		t.Errorf("Generated random bytes have incorrect length. Got: %d, want: %d", len(randomBytes), length)
	}

	if _, err := GenerateRandomBytes(0); err == nil {
		t.Errorf("expected error for zero length")
	}
	if _, err := GenerateRandomBytes(-1); err == nil {
		t.Errorf("expected error for negative length")
	}
}

func TestGenerateRandomString(t *testing.T) {
	randomString, err := GenerateRandomString(0, true, true, true, true)
	if err != nil {
		t.Fatalf("GenerateRandomString failed: %v", err)
	}

	if len(randomString) != 16 {
		t.Errorf("Generated random string has incorrect length. Got: %d, want: %d", len(randomString), 16)
	}

	if _, err := GenerateRandomString(-1, true, false, false, false); err == nil {
		t.Errorf("expected error for negative length")
	}
}

func TestGenerateHumanPasswordRejectsNegativeInputs(t *testing.T) {
	if _, err := GenerateHumanPassword(-1, 2); err == nil {
		t.Errorf("expected error for negative letters")
	}
	if _, err := GenerateHumanPassword(2, -1); err == nil {
		t.Errorf("expected error for negative digits")
	}
}

func TestScryptDeriveKeyTreatsEmptySaltAsNil(t *testing.T) {
	key, salt, err := ScryptDeriveKey([]byte("pw"), []byte{})
	if err != nil {
		t.Fatalf("ScryptDeriveKey failed: %v", err)
	}
	if len(salt) != 32 {
		t.Errorf("expected a freshly generated 32-byte salt, got %d", len(salt))
	}
	if len(key) != 32 {
		t.Errorf("expected a 32-byte key, got %d", len(key))
	}
}

func TestDecodeBase64ReturnsNilOnError(t *testing.T) {
	got, err := DecodeBase64([]byte("!!!not-base64"))
	if err == nil {
		t.Fatalf("expected error for invalid base64")
	}
	if got != nil {
		t.Errorf("expected nil data on error, got %v", got)
	}
}

func TestGenerateRandomStringURLSafe(t *testing.T) {
	length := 16
	randomString, err := GenerateRandomStringURLSafe(length)
	if err != nil {
		t.Fatalf("GenerateRandomStringURLSafe failed: %v", err)
	}

	if strings.ContainsAny(randomString, "+/=") {
		t.Errorf("URL-safe string contains forbidden chars: %q", randomString)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(randomString)
	if err != nil {
		t.Fatalf("Failed to decode generated URL-safe string: %v", err)
	}

	if len(decoded) != length {
		t.Errorf("Decoded random string has incorrect length. Got: %d, want: %d", len(decoded), length)
	}
}

func TestGenerateHumanPassword(t *testing.T) {
	letters := 4
	digits := 4
	humanPassword1, err := GenerateHumanPassword(letters, digits)
	if err != nil {
		t.Fatalf("GenerateHumanPassword failed: %v", err)
	}

	if len(humanPassword1) != letters+digits {
		t.Errorf("Generated human password has incorrect length. Got: %d, want: %d", len(humanPassword1), letters+digits)
	}

	if !strings.ContainsAny(humanPassword1, "aeiou") {
		t.Errorf("Generated human password does not contain any vowels")
	}

	humanPassword2, err := GenerateHumanPassword(0, 0)
	if err != nil {
		t.Fatalf("GenerateHumanPassword failed: %v", err)
	}

	if len(humanPassword2) != 8 {
		t.Errorf("Generated human password has incorrect length. Got: %d, want: %d", len(humanPassword2), letters+digits)
	}
}
