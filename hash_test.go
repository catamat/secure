package secure

import (
	"strings"
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

	if err := BcryptCompareHash(hashedPassword, password); err != nil {
		t.Errorf("BcryptCompareHash failed: %v", err)
	}

	if err := BcryptCompareHash(hashedPassword, []byte("wrongpassword")); err == nil {
		t.Errorf("Expected error when comparing with wrong password, got nil")
	}
}

func TestBcryptDefaultCostWhenZero(t *testing.T) {
	hashedPassword, err := BcryptGenerateHash([]byte("pwd"), 0)
	if err != nil {
		t.Fatalf("BcryptGenerateHash failed: %v", err)
	}
	if err := BcryptCompareHash(hashedPassword, []byte("pwd")); err != nil {
		t.Errorf("BcryptCompareHash failed: %v", err)
	}
}

func TestBcryptLongPasswordsDoNotCollide(t *testing.T) {
	// Two passwords longer than 72 bytes that share the same prefix would
	// collide under raw bcrypt; the SHA-256 pre-hash must prevent that.
	prefix := strings.Repeat("a", 72)
	pwd1 := []byte(prefix + "X")
	pwd2 := []byte(prefix + "Y")

	hashed, err := BcryptGenerateHash(pwd1, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("BcryptGenerateHash failed: %v", err)
	}
	if err := BcryptCompareHash(hashed, pwd2); err == nil {
		t.Fatalf("expected mismatch for distinct long passwords")
	}
}

func TestArgon2idGenerateHashAndCompare(t *testing.T) {
	password := []byte("supersecretpassword")
	hashedPassword, err := Argon2idGenerateHash(password, 65536, 1, 2, 16, 32)
	if err != nil {
		t.Fatalf("Argon2idGenerateHash failed: %v", err)
	}

	if err := Argon2idCompareHash(hashedPassword, password); err != nil {
		t.Errorf("Argon2idCompareHash failed: %v", err)
	}

	if err := Argon2idCompareHash(hashedPassword, []byte("wrongpassword")); err == nil {
		t.Errorf("Expected error when comparing with wrong password, got nil")
	}
}

func TestArgon2idGenerateHashRejectsZeroParams(t *testing.T) {
	cases := [][6]any{
		{[]byte("p"), uint32(0), uint32(1), uint8(2), 16, uint32(32)},
		{[]byte("p"), uint32(64), uint32(0), uint8(2), 16, uint32(32)},
		{[]byte("p"), uint32(64), uint32(1), uint8(0), 16, uint32(32)},
		{[]byte("p"), uint32(64), uint32(1), uint8(2), 0, uint32(32)},
		{[]byte("p"), uint32(64), uint32(1), uint8(2), 16, uint32(0)},
	}
	for i, c := range cases {
		_, err := Argon2idGenerateHash(
			c[0].([]byte), c[1].(uint32), c[2].(uint32),
			c[3].(uint8), c[4].(int), c[5].(uint32),
		)
		if err == nil {
			t.Errorf("case %d: expected error for zero parameter", i)
		}
	}
}

// Argon2idCompareHash must reject parameters above safety caps so that a
// maliciously crafted hash cannot turn a single Compare call into a DoS.
func TestArgon2idCompareHashRejectsExcessiveParameters(t *testing.T) {
	cases := []string{
		"$argon2id$v=19$m=99999999,t=1,p=1$AAAA$AAAA",  // memory too large
		"$argon2id$v=19$m=65536,t=9999,p=1$AAAA$AAAA",  // time too large
		"$argon2id$v=19$m=65536,t=1,p=255$AAAA$AAAA",   // threads too large
	}
	for _, c := range cases {
		if err := Argon2idCompareHash([]byte(c), []byte("pwd")); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// Regression: malformed inputs used to panic with "index out of range".
func TestArgon2idCompareHashMalformedInputs(t *testing.T) {
	password := []byte("supersecretpassword")
	cases := []string{
		"",
		"$",
		"$$$$$",
		"$argon2id$v=19$m=65536,t=1,p=2$onlyfourparts",
		"$argon2i$v=19$m=65536,t=1,p=2$AAAA$AAAA",
		"$argon2id$v=99$m=65536,t=1,p=2$AAAA$AAAA",
		"$argon2id$v=19$broken$AAAA$AAAA",
		"$argon2id$v=19$m=0,t=1,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=1,p=2$!!!notbase64$AAAA",
		"$argon2id$v=19$m=65536,t=1,p=2$AAAA$!!!notbase64",
		"$argon2id$v=19$m=65536,t=1,p=2$AAAA$",
	}

	for _, c := range cases {
		err := Argon2idCompareHash([]byte(c), password)
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}
