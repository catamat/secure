package secure

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptGenerateHashAndCompare(t *testing.T) {
	password := []byte("supersecretpassword")
	cost := bcrypt.DefaultCost

	hashedPassword, err := BcryptGenerateHash(password, cost)
	if err != nil {
		t.Fatalf("BcryptGenerateHash failed: %v", err)
	}

	err = BcryptCompareHash(hashedPassword, password)
	if err != nil {
		t.Errorf("BcryptCompareHash failed: %v", err)
	}

	wrongPassword := []byte("wrongpassword")
	err = BcryptCompareHash(hashedPassword, wrongPassword)
	if err == nil {
		t.Errorf("Expected error when comparing with wrong password, got nil")
	}
}

func TestArgon2idGenerateHashAndCompare(t *testing.T) {
	password := []byte("supersecretpassword")
	memory := uint32(65536)
	time := uint32(1)
	threads := uint8(2)
	saltLength := 16
	keyLength := uint32(32)

	hashedPassword, err := Argon2idGenerateHash(password, memory, time, threads, saltLength, keyLength)
	if err != nil {
		t.Fatalf("Argon2idGenerateHash failed: %v", err)
	}

	err = Argon2idCompareHash(hashedPassword, password)
	if err != nil {
		t.Errorf("Argon2idCompareHash failed: %v", err)
	}

	wrongPassword := []byte("wrongpassword")
	err = Argon2idCompareHash(hashedPassword, wrongPassword)
	if err == nil {
		t.Errorf("Expected error when comparing with wrong password, got nil")
	}
}

func TestArgon2idCompareHashInvalidFormat(t *testing.T) {
	password := []byte("supersecretpassword")
	invalidHashedPassword := []byte("$argon2id$v=19$m=65536,t=1,p=2$invalidsalt$invalidhash")

	err := Argon2idCompareHash(invalidHashedPassword, password)
	if err == nil {
		t.Errorf("Expected error for invalid hashed password format, got nil")
	}
}

func TestArgon2idCompareHashInvalidBase64(t *testing.T) {
	password := []byte("supersecretpassword")
	invalidBase64Hash := []byte("$argon2id$v=19$m=65536,t=1,p=2$invalidsalt$invalid==hash")

	err := Argon2idCompareHash(invalidBase64Hash, password)
	if err == nil {
		t.Errorf("Expected error for invalid base64 encoded hash, got nil")
	}
}
