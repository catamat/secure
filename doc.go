// Package secure provides a small, safe-by-default cryptographic toolbox
// for Go applications. It wraps Go's standard crypto primitives and
// golang.org/x/crypto with an API that picks modern algorithms and
// OWASP 2024-aligned parameters so callers don't have to.
//
// # Quick start
//
// The top-level functions cover the common operations without exposing
// algorithm choices:
//
//	// Password hashing (Argon2id, OWASP 2024 defaults)
//	hash, _  := secure.HashPassword(password)
//	err      := secure.VerifyPassword(hash, password)
//
//	// Symmetric encryption with a password (scrypt + XChaCha20-Poly1305)
//	ct, _ := secure.EncryptWithPassword(plainText, password)
//	pt, _ := secure.DecryptWithPassword(ct, password)
//
//	// Symmetric encryption with a random key (XChaCha20-Poly1305)
//	key, _ := secure.GenerateKey()
//	ct, _  := secure.EncryptWithKey(plainText, key)
//	pt, _  := secure.DecryptWithKey(ct, key)
//
//	// Asymmetric encryption (X25519 + XChaCha20-Poly1305)
//	priv, pub, _ := secure.GenerateEncryptionKeyPair()
//	ct, _        := secure.Encrypt(plainText, pub)
//	pt, _        := secure.Decrypt(ct, priv)
//
//	// Signing (Ed25519)
//	sPriv, sPub, _ := secure.GenerateSigningKeyPair()
//	sig, _         := secure.Sign(message, sPriv)
//	err            := secure.Verify(message, sig, sPub)
//
// # Default algorithms
//
//   - Signing:                Ed25519
//   - Asymmetric encryption:  X25519 + HKDF-SHA256 + XChaCha20-Poly1305
//   - Symmetric AEAD:         XChaCha20-Poly1305 (32-byte key)
//   - Password-based AEAD:    scrypt (N=2^17, r=8, p=1) + XChaCha20-Poly1305
//   - Password hashing:       Argon2id (m=64 MiB, t=3, p=4, salt=16 B, key=32 B)
//
// # Low-level API
//
// The package also exports the underlying primitives for callers that need
// to tune parameters or interoperate with a specific algorithm:
// AESEncryptWithGCM / AESEncryptWithGCMKey, ChaCha20Poly1305EncryptWithKey /
// ChaCha20Poly1305EncryptWithPassword, X25519EncryptWithChaCha20Poly1305,
// RSAEncryptWithOAEP / RSASignWithPSS, Ed25519Sign, Argon2idGenerateHash,
// BcryptGenerateHash, ScryptDeriveKey, plus PEM helpers for RSA, Ed25519
// and X25519 keys.
//
// # Ciphertext layout
//
// All ciphertexts are base64-encoded. The underlying binary layouts are:
//
//   - EncryptWithKey / ChaCha20Poly1305EncryptWithKey:  nonce(24) || ct || tag
//   - AESEncryptWithGCMKey:                             nonce(12) || ct || tag
//   - EncryptWithPassword / AESEncryptWithGCM:          salt(32) || nonce || ct || tag
//     (salt is bound to the ciphertext via the AEAD's additional data)
//   - Encrypt / X25519EncryptWithChaCha20Poly1305:      ephPub(32) || nonce(24) || ct || tag
package secure
