package secure

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// The fuzz targets fall in three groups:
//
//  1. Input-driven (parsers, decoders, decrypt, verify). The contract is:
//     "any []byte input must either return (result, nil) or (nil, err),
//     never panic or hang."
//  2. Roundtrip invariants. For every encrypt/decrypt or sign/verify pair,
//     running the two back-to-back must recover the original input.
//  3. Parameter fuzzing of generators, to make sure they never panic on
//     hostile combinations.
//
// Run a single target with:
//   go test -run=^$ -fuzz=^FuzzDecodeBase64$ -fuzztime=10s ./...

// -----------------------------------------------------------------------------
// 1. Input-driven fuzzing: parsers, decoders, decrypt, verify
// -----------------------------------------------------------------------------

func FuzzDecodeBase64(f *testing.F) {
	f.Add([]byte("SGVsbG8gd29ybGQ="))
	f.Add([]byte(""))
	f.Add([]byte("!!!not-base64"))
	f.Add([]byte("A"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBase64(data)
	})
}

func FuzzArgon2idCompareHash(f *testing.F) {
	valid, err := Argon2idGenerateHash([]byte("pw"), 19*1024, 2, 1, 16, 32)
	if err != nil {
		f.Fatalf("seed generation failed: %v", err)
	}
	f.Add(valid, []byte("pw"))
	f.Add([]byte("$argon2id$v=19$m=65536,t=3,p=4$AAAA$AAAA"), []byte("pwd"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("$"), []byte("x"))
	f.Add([]byte("$argon2id$v=19$m=99999999,t=1,p=1$AAAA$AAAA"), []byte("pwd"))
	f.Fuzz(func(t *testing.T, hash, password []byte) {
		_ = Argon2idCompareHash(hash, password)
	})
}

func FuzzBcryptCompareHash(f *testing.F) {
	valid, err := BcryptGenerateHash([]byte("pw"), 4)
	if err != nil {
		f.Fatalf("seed generation failed: %v", err)
	}
	f.Add(valid, []byte("pw"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("$2a$notavalidhash"), []byte("x"))
	f.Fuzz(func(t *testing.T, hash, password []byte) {
		_ = BcryptCompareHash(hash, password)
	})
}

func FuzzRSAParsePrivateKeyFromPEM(f *testing.F) {
	priv, _, err := RSAGenerateKeyPair(2048)
	if err != nil {
		f.Fatalf("RSA keypair failed: %v", err)
	}
	pemBytes, err := RSAExportPrivateKeyAsPEM(priv)
	if err != nil {
		f.Fatalf("RSA export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nGARBAGE\n-----END RSA PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = RSAParsePrivateKeyFromPEM(data)
	})
}

func FuzzRSAParsePublicKeyFromPEM(f *testing.F) {
	_, pub, err := RSAGenerateKeyPair(2048)
	if err != nil {
		f.Fatalf("RSA keypair failed: %v", err)
	}
	pemBytes, err := RSAExportPublicKeyAsPEM(pub)
	if err != nil {
		f.Fatalf("RSA export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nXXX\n-----END PUBLIC KEY-----"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = RSAParsePublicKeyFromPEM(data)
	})
}

func FuzzEd25519ParsePrivateKeyFromPEM(f *testing.F) {
	priv, _, err := Ed25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("Ed25519 keypair failed: %v", err)
	}
	pemBytes, err := Ed25519ExportPrivateKeyAsPEM(priv)
	if err != nil {
		f.Fatalf("Ed25519 export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Ed25519ParsePrivateKeyFromPEM(data)
	})
}

func FuzzEd25519ParsePublicKeyFromPEM(f *testing.F) {
	_, pub, err := Ed25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("Ed25519 keypair failed: %v", err)
	}
	pemBytes, err := Ed25519ExportPublicKeyAsPEM(pub)
	if err != nil {
		f.Fatalf("Ed25519 export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Ed25519ParsePublicKeyFromPEM(data)
	})
}

func FuzzX25519ParsePrivateKeyFromPEM(f *testing.F) {
	priv, _, err := X25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("X25519 keypair failed: %v", err)
	}
	pemBytes, err := X25519ExportPrivateKeyAsPEM(priv)
	if err != nil {
		f.Fatalf("X25519 export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = X25519ParsePrivateKeyFromPEM(data)
	})
}

func FuzzX25519ParsePublicKeyFromPEM(f *testing.F) {
	_, pub, err := X25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("X25519 keypair failed: %v", err)
	}
	pemBytes, err := X25519ExportPublicKeyAsPEM(pub)
	if err != nil {
		f.Fatalf("X25519 export failed: %v", err)
	}
	f.Add(pemBytes)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = X25519ParsePublicKeyFromPEM(data)
	})
}

func FuzzAESDecryptWithGCM(f *testing.F) {
	valid, err := AESEncryptWithGCM([]byte("hello"), []byte("pw"))
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid, []byte("pw"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, ciphertext, password []byte) {
		_, _ = AESDecryptWithGCM(ciphertext, password)
	})
}

func FuzzAESDecryptWithGCMKey(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read failed: %v", err)
	}
	valid, err := AESEncryptWithGCMKey([]byte("hello"), key)
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid, key)
	f.Add([]byte(""), make([]byte, 32))
	f.Fuzz(func(t *testing.T, ciphertext, key []byte) {
		_, _ = AESDecryptWithGCMKey(ciphertext, key)
	})
}

func FuzzChaCha20Poly1305DecryptWithKey(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read failed: %v", err)
	}
	valid, err := ChaCha20Poly1305EncryptWithKey([]byte("hello"), key)
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid, key)
	f.Add([]byte(""), make([]byte, 32))
	f.Fuzz(func(t *testing.T, ciphertext, key []byte) {
		_, _ = ChaCha20Poly1305DecryptWithKey(ciphertext, key)
	})
}

func FuzzChaCha20Poly1305DecryptWithPassword(f *testing.F) {
	valid, err := ChaCha20Poly1305EncryptWithPassword([]byte("hello"), []byte("pw"))
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid, []byte("pw"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, ciphertext, password []byte) {
		_, _ = ChaCha20Poly1305DecryptWithPassword(ciphertext, password)
	})
}

func FuzzX25519DecryptWithChaCha20Poly1305(f *testing.F) {
	priv, pub, err := X25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("X25519 keypair failed: %v", err)
	}
	valid, err := X25519EncryptWithChaCha20Poly1305([]byte("hello"), pub)
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		_, _ = X25519DecryptWithChaCha20Poly1305(ciphertext, priv)
	})
}

func FuzzRSADecryptWithOAEP(f *testing.F) {
	priv, pub, err := RSAGenerateKeyPair(2048)
	if err != nil {
		f.Fatalf("RSA keypair failed: %v", err)
	}
	valid, err := RSAEncryptWithOAEP([]byte("hello"), pub, nil)
	if err != nil {
		f.Fatalf("seed encrypt failed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		_, _ = RSADecryptWithOAEP(ciphertext, priv, nil)
	})
}

func FuzzRSAVerifyWithPSS(f *testing.F) {
	priv, pub, err := RSAGenerateKeyPair(2048)
	if err != nil {
		f.Fatalf("RSA keypair failed: %v", err)
	}
	sig, err := RSASignWithPSS([]byte("msg"), priv)
	if err != nil {
		f.Fatalf("seed sign failed: %v", err)
	}
	f.Add([]byte("msg"), sig)
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, msg, signature []byte) {
		_ = RSAVerifyWithPSS(msg, signature, pub)
	})
}

func FuzzEd25519Verify(f *testing.F) {
	priv, pub, err := Ed25519GenerateKeyPair()
	if err != nil {
		f.Fatalf("Ed25519 keypair failed: %v", err)
	}
	sig, err := Ed25519Sign([]byte("msg"), priv)
	if err != nil {
		f.Fatalf("seed sign failed: %v", err)
	}
	f.Add([]byte("msg"), sig)
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, msg, signature []byte) {
		_ = Ed25519Verify(msg, signature, pub)
	})
}

// -----------------------------------------------------------------------------
// 2. Roundtrip invariants: encrypt(x) -> decrypt = x, sign -> verify = ok
// -----------------------------------------------------------------------------

func FuzzEncryptWithKeyRoundtrip(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read failed: %v", err)
	}
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte{0x00, 0xFF, 0x42, 0x7F})
	f.Fuzz(func(t *testing.T, plainText []byte) {
		ct, err := EncryptWithKey(plainText, key)
		if err != nil {
			t.Fatalf("EncryptWithKey failed: %v", err)
		}
		pt, err := DecryptWithKey(ct, key)
		if err != nil {
			t.Fatalf("DecryptWithKey failed: %v", err)
		}
		if !bytes.Equal(pt, plainText) {
			t.Errorf("roundtrip mismatch: got %x, want %x", pt, plainText)
		}
	})
}

func FuzzEncryptWithPasswordRoundtrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("pw"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, plainText, password []byte) {
		ct, err := EncryptWithPassword(plainText, password)
		if err != nil {
			t.Fatalf("EncryptWithPassword failed: %v", err)
		}
		pt, err := DecryptWithPassword(ct, password)
		if err != nil {
			t.Fatalf("DecryptWithPassword failed: %v", err)
		}
		if !bytes.Equal(pt, plainText) {
			t.Errorf("roundtrip mismatch")
		}
	})
}

func FuzzEncryptRoundtrip(f *testing.F) {
	priv, pub, err := GenerateEncryptionKeyPair()
	if err != nil {
		f.Fatalf("GenerateEncryptionKeyPair failed: %v", err)
	}
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, plainText []byte) {
		ct, err := Encrypt(plainText, pub)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		pt, err := Decrypt(ct, priv)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(pt, plainText) {
			t.Errorf("roundtrip mismatch")
		}
	})
}

func FuzzSignVerifyRoundtrip(f *testing.F) {
	priv, pub, err := GenerateSigningKeyPair()
	if err != nil {
		f.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}
	f.Add([]byte("msg"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, msg []byte) {
		sig, err := Sign(msg, priv)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if err := Verify(msg, sig, pub); err != nil {
			t.Errorf("Verify failed on valid signature: %v", err)
		}
	})
}

func FuzzHashVerifyPasswordRoundtrip(f *testing.F) {
	f.Add([]byte("pw"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, password []byte) {
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}
		if err := VerifyPassword(hash, password); err != nil {
			t.Errorf("VerifyPassword failed on the right password: %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// 3. Parameter fuzzing on generators
// -----------------------------------------------------------------------------

func FuzzGenerateRandomString(f *testing.F) {
	f.Add(16, true, true, true, false)
	f.Add(0, false, true, false, false)
	f.Add(-1, true, false, false, false)
	f.Fuzz(func(t *testing.T, length int, upper, lower, digits, symbols bool) {
		// Cap to keep iterations fast and avoid gigabyte allocations.
		if length > 4096 {
			length %= 4096
		}
		_, _ = GenerateRandomString(length, upper, lower, digits, symbols)
	})
}

func FuzzGenerateHumanPassword(f *testing.F) {
	f.Add(4, 4)
	f.Add(0, 0)
	f.Add(-1, 2)
	f.Fuzz(func(t *testing.T, letters, digits int) {
		// Keep lengths small: the vowel/consonant alternation constraint can
		// make large inputs very slow.
		if letters < -1 || letters > 64 {
			letters %= 65
		}
		if digits < -1 || digits > 64 {
			digits %= 65
		}
		_, _ = GenerateHumanPassword(letters, digits)
	})
}

func FuzzGenerateRandomBytes(f *testing.F) {
	f.Add(16)
	f.Add(0)
	f.Add(-1)
	f.Fuzz(func(t *testing.T, length int) {
		if length > 1<<16 {
			length %= 1 << 16
		}
		_, _ = GenerateRandomBytes(length)
	})
}
