package secure

// This file exposes the "safe-by-default" top-level API of the package.
// Each function hides the choice of algorithm, mode and parameters: the
// caller only picks the shape of the operation (sign vs encrypt,
// key- vs password- vs recipient-based) and the library applies modern,
// OWASP/IETF 2024-aligned defaults.
//
// Algorithm defaults used here:
//   - Signing:                 Ed25519
//   - Asymmetric encryption:   X25519 + HKDF-SHA256 + XChaCha20-Poly1305
//   - Symmetric encryption:    XChaCha20-Poly1305 (32-byte key)
//   - Password-based encrypt:  scrypt(N=2^17,r=8,p=1) + XChaCha20-Poly1305
//   - Password hashing:        Argon2id (m=64 MiB, t=3, p=4, salt=16, key=32)
//
// The lower-level exported helpers (RSA, AES-GCM, bcrypt, etc.) stay
// available for callers who need a specific algorithm.

import (
	"crypto/ecdh"
	"crypto/ed25519"
)

// GenerateKey returns a fresh 32-byte random key suitable for EncryptWithKey /
// DecryptWithKey (XChaCha20-Poly1305).
func GenerateKey() ([]byte, error) {
	return GenerateRandomBytes(32)
}

// GenerateSigningKeyPair returns a fresh Ed25519 key pair for Sign / Verify.
func GenerateSigningKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return Ed25519GenerateKeyPair()
}

// GenerateEncryptionKeyPair returns a fresh X25519 key pair for Encrypt / Decrypt.
func GenerateEncryptionKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	return X25519GenerateKeyPair()
}

// Sign produces a detached signature for message using an Ed25519 private key.
// The returned signature is base64-encoded.
func Sign(message []byte, privKey ed25519.PrivateKey) ([]byte, error) {
	return Ed25519Sign(message, privKey)
}

// Verify checks a signature produced by Sign against the given message and
// Ed25519 public key. It returns nil iff the signature is valid.
func Verify(message, signature []byte, pubKey ed25519.PublicKey) error {
	return Ed25519Verify(message, signature, pubKey)
}

// Encrypt encrypts plainText for the holder of recipientPubKey using X25519 +
// XChaCha20-Poly1305 with an ephemeral sender key.
func Encrypt(plainText []byte, recipientPubKey *ecdh.PublicKey) ([]byte, error) {
	return X25519EncryptWithChaCha20Poly1305(plainText, recipientPubKey)
}

// Decrypt decrypts a ciphertext produced by Encrypt using the recipient's
// X25519 private key.
func Decrypt(cipherText []byte, recipientPrivKey *ecdh.PrivateKey) ([]byte, error) {
	return X25519DecryptWithChaCha20Poly1305(cipherText, recipientPrivKey)
}

// EncryptWithKey encrypts plainText with a raw 32-byte key using
// XChaCha20-Poly1305. Use GenerateKey to obtain a suitable key.
func EncryptWithKey(plainText, key []byte) ([]byte, error) {
	return ChaCha20Poly1305EncryptWithKey(plainText, key)
}

// DecryptWithKey decrypts a ciphertext produced by EncryptWithKey.
func DecryptWithKey(cipherText, key []byte) ([]byte, error) {
	return ChaCha20Poly1305DecryptWithKey(cipherText, key)
}

// EncryptWithPassword encrypts plainText using a human-chosen password,
// stretched with scrypt and combined with XChaCha20-Poly1305.
func EncryptWithPassword(plainText, password []byte) ([]byte, error) {
	return ChaCha20Poly1305EncryptWithPassword(plainText, password)
}

// DecryptWithPassword decrypts a ciphertext produced by EncryptWithPassword.
func DecryptWithPassword(cipherText, password []byte) ([]byte, error) {
	return ChaCha20Poly1305DecryptWithPassword(cipherText, password)
}

// HashPassword returns an Argon2id hash of the password using the OWASP 2024
// recommended parameters (m=64 MiB, t=3, p=4, salt=16 B, key=32 B).
// The returned value is the full encoded hash, storable as-is.
func HashPassword(password []byte) ([]byte, error) {
	return Argon2idGenerateHash(password, 64*1024, 3, 4, 16, 32)
}

// VerifyPassword checks a password against a hash produced by HashPassword.
// Returns nil iff the password matches.
func VerifyPassword(hashedPassword, password []byte) error {
	return Argon2idCompareHash(hashedPassword, password)
}
