package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const x25519HKDFInfo = "secure/x25519-xchacha20poly1305"

// scryptSaltSize is the salt length used by the password-based AES-GCM helpers.
const scryptSaltSize = 32

// AESEncryptWithGCM encrypts a plain text using a password.
// The password is stretched with scrypt; the on-wire layout is:
// base64( salt || nonce || ciphertext || tag )
// The salt is also bound to the ciphertext via GCM's additional data.
func AESEncryptWithGCM(plainText []byte, password []byte) ([]byte, error) {
	derivedKey, salt, err := ScryptDeriveKey(password, nil)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(salt)+len(nonce)+len(plainText)+gcm.Overhead())
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plainText, salt)

	return EncodeBase64(out), nil
}

// AESDecryptWithGCM decrypts a ciphertext produced by AESEncryptWithGCM.
func AESDecryptWithGCM(encryptedText []byte, password []byte) ([]byte, error) {
	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	// AES-GCM overhead: 12-byte nonce + 16-byte tag. Reject short inputs
	// before invoking scrypt so a truncated ciphertext cannot force the
	// expensive KDF to run.
	const aesGCMMinOverhead = 12 + 16
	if len(et) < scryptSaltSize+aesGCMMinOverhead {
		return nil, errors.New("encrypted text is too short")
	}

	salt, rest := et[:scryptSaltSize], et[scryptSaltSize:]

	derivedKey, _, err := ScryptDeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize+gcm.Overhead() {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := rest[:nonceSize], rest[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, salt)
}

// AESEncryptWithGCMKey encrypts a plain text using a raw 16, 24 or 32 byte key.
// Use this when you already hold a uniformly random key; for password-based
// encryption use AESEncryptWithGCM instead.
// On-wire layout: base64( nonce || ciphertext || tag )
func AESEncryptWithGCMKey(plainText []byte, key []byte) ([]byte, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, errors.New("key must be 16, 24 or 32 bytes")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	out := gcm.Seal(nonce, nonce, plainText, nil)
	return EncodeBase64(out), nil
}

// AESDecryptWithGCMKey decrypts a ciphertext produced by AESEncryptWithGCMKey.
func AESDecryptWithGCMKey(encryptedText []byte, key []byte) ([]byte, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, errors.New("key must be 16, 24 or 32 bytes")
	}

	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(et) < nonceSize+gcm.Overhead() {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := et[:nonceSize], et[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

// ChaCha20Poly1305EncryptWithKey encrypts a plain text using a raw 32-byte key
// with XChaCha20-Poly1305 (24-byte random nonce).
// On-wire layout: base64( nonce || ciphertext || tag )
func ChaCha20Poly1305EncryptWithKey(plainText []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := aead.Seal(nonce, nonce, plainText, nil)
	return EncodeBase64(out), nil
}

// ChaCha20Poly1305EncryptWithPassword encrypts plainText using a password stretched
// through scrypt and XChaCha20-Poly1305 as the AEAD.
// On-wire layout: base64( salt(32) || nonce(24) || ciphertext || tag ), with
// the salt bound to the ciphertext via the AEAD's additional data.
func ChaCha20Poly1305EncryptWithPassword(plainText []byte, password []byte) ([]byte, error) {
	derivedKey, salt, err := ScryptDeriveKey(password, nil)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(salt)+len(nonce)+len(plainText)+aead.Overhead())
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plainText, salt)

	return EncodeBase64(out), nil
}

// ChaCha20Poly1305DecryptWithPassword decrypts a ciphertext produced by ChaCha20Poly1305EncryptWithPassword.
func ChaCha20Poly1305DecryptWithPassword(encryptedText []byte, password []byte) ([]byte, error) {
	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	// XChaCha20-Poly1305 overhead: 24-byte nonce + 16-byte tag. Reject short
	// inputs before invoking scrypt so a truncated ciphertext cannot force the
	// expensive KDF to run.
	const xchachaMinOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(et) < scryptSaltSize+xchachaMinOverhead {
		return nil, errors.New("encrypted text is too short")
	}

	salt, rest := et[:scryptSaltSize], et[scryptSaltSize:]

	derivedKey, _, err := ScryptDeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(rest) < nonceSize+aead.Overhead() {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := rest[:nonceSize], rest[nonceSize:]
	return aead.Open(nil, nonce, cipherText, salt)
}

// ChaCha20Poly1305DecryptWithKey decrypts a ciphertext produced by
// ChaCha20Poly1305EncryptWithKey.
func ChaCha20Poly1305DecryptWithKey(encryptedText []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(et) < nonceSize+aead.Overhead() {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := et[:nonceSize], et[nonceSize:]
	return aead.Open(nil, nonce, cipherText, nil)
}

// X25519EncryptWithChaCha20Poly1305 encrypts a plain text for the recipient
// using an ephemeral X25519 key, HKDF-SHA256 for key derivation and
// XChaCha20-Poly1305 as the AEAD.
// On-wire layout: base64( ephPub(32) || nonce(24) || ciphertext || tag )
func X25519EncryptWithChaCha20Poly1305(plainText []byte, recipientPubKey *ecdh.PublicKey) ([]byte, error) {
	if recipientPubKey == nil {
		return nil, errors.New("recipient public key is nil")
	}
	if recipientPubKey.Curve() != ecdh.X25519() {
		return nil, errors.New("recipient key is not on X25519 curve")
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	shared, err := ephPriv.ECDH(recipientPubKey)
	if err != nil {
		return nil, err
	}

	ephPubBytes := ephPriv.PublicKey().Bytes()

	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha256.New, shared, ephPubBytes, []byte(x25519HKDFInfo))
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ephPubBytes)+len(nonce)+len(plainText)+aead.Overhead())
	out = append(out, ephPubBytes...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plainText, ephPubBytes)

	return EncodeBase64(out), nil
}

// X25519DecryptWithChaCha20Poly1305 decrypts a ciphertext produced by
// X25519EncryptWithChaCha20Poly1305.
func X25519DecryptWithChaCha20Poly1305(encryptedText []byte, recipientPrivKey *ecdh.PrivateKey) ([]byte, error) {
	if recipientPrivKey == nil {
		return nil, errors.New("recipient private key is nil")
	}
	if recipientPrivKey.Curve() != ecdh.X25519() {
		return nil, errors.New("recipient key is not on X25519 curve")
	}

	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}

	const ephPubSize = 32
	if len(et) < ephPubSize {
		return nil, errors.New("encrypted text is too short")
	}

	ephPubBytes, rest := et[:ephPubSize], et[ephPubSize:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, err
	}

	shared, err := recipientPrivKey.ECDH(ephPub)
	if err != nil {
		return nil, err
	}

	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha256.New, shared, ephPubBytes, []byte(x25519HKDFInfo))
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(rest) < nonceSize+aead.Overhead() {
		return nil, errors.New("data is shorter than the required nonce size")
	}

	nonce, cipherText := rest[:nonceSize], rest[nonceSize:]
	return aead.Open(nil, nonce, cipherText, ephPubBytes)
}

// RSAEncryptWithOAEP encrypts a plain text using a public key.
// The plaintext length is limited to keySize - 2*hashSize - 2 bytes
// (190 bytes for a 2048-bit key with SHA-256, 446 for 4096-bit).
func RSAEncryptWithOAEP(plainText []byte, pubKey *rsa.PublicKey, label []byte) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key is nil")
	}

	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plainText, label)
	if err != nil {
		return nil, err
	}
	return EncodeBase64(encryptedText), nil
}

// RSADecryptWithOAEP decrypts an encrypted text using a private key.
func RSADecryptWithOAEP(encryptedText []byte, privKey *rsa.PrivateKey, label []byte) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key is nil")
	}

	et, err := DecodeBase64(encryptedText)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, et, label)
}
