package secure

import (
	"bytes"
	"encoding/base64"
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
	privKey, pubKey := RSAGenerateKeyPair(2048)
	if privKey == nil || pubKey == nil {
		t.Fatalf("RSAGenerateKeyPair failed to generate keys")
	}
}

func TestRSAExportPrivateKeyAsPEMAndParse(t *testing.T) {
	privKey, _ := RSAGenerateKeyPair(2048)
	pemKey := RSAExportPrivateKeyAsPEM(privKey)

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

func TestRSAExportPublicKeyAsPEMAndParse(t *testing.T) {
	_, pubKey := RSAGenerateKeyPair(2048)
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

func TestGenerateRandomBytes(t *testing.T) {
	length := 16
	randomBytes, err := GenerateRandomBytes(length)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(randomBytes) != length {
		t.Errorf("Generated random bytes have incorrect length. Got: %d, want: %d", len(randomBytes), length)
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
}

func TestGenerateRandomStringURLSafe(t *testing.T) {
	length := 16
	randomString, err := GenerateRandomStringURLSafe(length)
	if err != nil {
		t.Fatalf("GenerateRandomStringURLSafe failed: %v", err)
	}

	decoded, err := base64.URLEncoding.DecodeString(randomString)
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

	if strings.ContainsAny(humanPassword1, "aeiou") == false {
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
