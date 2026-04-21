# Secure
[![License](https://img.shields.io/github/license/catamat/secure.svg)](https://github.com/catamat/secure/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/catamat/secure)](https://goreportcard.com/report/github.com/catamat/secure)
[![Go Reference](https://pkg.go.dev/badge/github.com/catamat/secure.svg)](https://pkg.go.dev/github.com/catamat/secure)
[![Version](https://img.shields.io/github/tag/catamat/secure.svg?color=blue&label=version)](https://github.com/catamat/secure/releases)

Secure is a package that makes it easy to work with the most common cryptographic functions. 

## Installation:
```
go install github.com/catamat/secure@latest
```

## Quick start (safe-by-default API):
The top-level functions pick modern algorithms and OWASP 2024 parameters for
you — just choose the *shape* of the operation and the library does the rest.

| You want to…                           | Call                               | Uses                                           |
|----------------------------------------|------------------------------------|------------------------------------------------|
| Sign a message                         | `Sign` / `Verify`                  | Ed25519                                        |
| Encrypt for someone's public key       | `Encrypt` / `Decrypt`              | X25519 + XChaCha20-Poly1305                    |
| Encrypt with a shared random key       | `EncryptWithKey` / `DecryptWithKey`| XChaCha20-Poly1305                             |
| Encrypt with a human-chosen password   | `EncryptWithPassword` / `DecryptWithPassword` | scrypt + XChaCha20-Poly1305       |
| Store a password                       | `HashPassword` / `VerifyPassword`  | Argon2id (64 MiB, t=3, p=4)                    |
| Generate a random key                  | `GenerateKey`                      | 32 random bytes                                |
| Generate a signing key pair            | `GenerateSigningKeyPair`           | Ed25519                                        |
| Generate an encryption key pair        | `GenerateEncryptionKeyPair`        | X25519                                         |

```golang
package main

import (
	"fmt"

	"github.com/catamat/secure"
)

func main() {
	// Password hashing
	h, _ := secure.HashPassword([]byte("correct horse battery staple"))
	_ = secure.VerifyPassword(h, []byte("correct horse battery staple"))

	// Asymmetric encryption
	priv, pub, _ := secure.GenerateEncryptionKeyPair()
	ct, _ := secure.Encrypt([]byte("hello"), pub)
	pt, _ := secure.Decrypt(ct, priv)
	fmt.Println(string(pt))

	// Signing
	sPriv, sPub, _ := secure.GenerateSigningKeyPair()
	sig, _ := secure.Sign([]byte("msg"), sPriv)
	_ = secure.Verify([]byte("msg"), sig, sPub)
}
```

The lower-level exported helpers (`RSA*`, `AES*`, `Bcrypt*`, `Argon2id*`, …)
stay available when you need to pick a specific algorithm or tune parameters.

## Full example:
```golang
package main

import (
	"fmt"
	"os"

	"github.com/catamat/secure"
)

func main() {
	asymmetric()
	fmt.Println("---")
	signing()
	fmt.Println("---")
	modernAsymmetric()
	fmt.Println("---")
	modernSigning()
	fmt.Println("---")
	hashing()
	fmt.Println("---")
	symmetric()
	fmt.Println("---")
	utilities()
}

func asymmetric() {
	var privFile bool
	var pubFile bool

	if _, err := os.Stat("private.pem"); err == nil {
		privFile = true
	}

	if _, err := os.Stat("public.pem"); err == nil {
		pubFile = true
	}

	if !privFile || !pubFile {
		// Create the keys
		privKey, pubKey, err := secure.RSAGenerateKeyPair(4096)
		if err != nil {
			fmt.Println("Error: Can't generate RSA key pair:", err)
			return
		}

		// Export the keys to PEM
		privPem, err := secure.RSAExportPrivateKeyAsPEM(privKey)
		if err != nil {
			fmt.Println("Error: Can't export private key:", err)
			return
		}
		pubPem, _ := secure.RSAExportPublicKeyAsPEM(pubKey)

		if err := os.WriteFile("private.pem", privPem, 0600); err != nil {
			fmt.Println("Error: Can't write private.pem file")
			return
		}

		if err := os.WriteFile("public.pem", pubPem, 0644); err != nil {
			fmt.Println("Error: Can't write public.pem file")
			return
		}
	}

	// Load the keys
	privPem, err := os.ReadFile("private.pem")
	if err != nil {
		fmt.Println("Error: Can't read private.pem file")
		return
	}

	pubPem, err := os.ReadFile("public.pem")
	if err != nil {
		fmt.Println("Error: Can't read public.pem file")
		return
	}

	// Import the keys from PEM
	privKey, _ := secure.RSAParsePrivateKeyFromPEM(privPem)
	pubKey, _ := secure.RSAParsePublicKeyFromPEM(pubPem)
	text := []byte("This is super secret message!")

	// Encrypt RSA with OAEP message
	encryptedMessage, _ := secure.RSAEncryptWithOAEP(text, pubKey, nil)
	fmt.Println("Asymmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt RSA with OAEP message
	decryptedMessage, _ := secure.RSADecryptWithOAEP(encryptedMessage, privKey, nil)
	fmt.Println("Asymmetric Decrypted Message:", string(decryptedMessage))
}

func hashing() {
	password := []byte("supersecretpassword")

	// Generate Bcrypt hash
	hashedPassword, _ := secure.BcryptGenerateHash(password, 0)
	fmt.Println("Hashed password:", string(hashedPassword))

	// Compare Bcrypt hash
	err := secure.BcryptCompareHash(hashedPassword, password)
	if err != nil {
		fmt.Println("Invalid password")
	} else {
		fmt.Println("Valid password")
	}

	// Generate Argon2 hash
	hashedPassword, _ = secure.Argon2idGenerateHash(password, 64*1024, 1, 2, 16, 32)
	fmt.Println("Hashed password:", string(hashedPassword))

	// Compare Argon2 hash
	err = secure.Argon2idCompareHash(hashedPassword, password)
	if err != nil {
		fmt.Println("Invalid password")
	} else {
		fmt.Println("Valid password")
	}
}

func signing() {
	// Load the keys
	privPem, err := os.ReadFile("private.pem")
	if err != nil {
		fmt.Println("Error: Can't read private.pem file")
		return
	}

	pubPem, err := os.ReadFile("public.pem")
	if err != nil {
		fmt.Println("Error: Can't read public.pem file")
		return
	}

	// Import the keys from PEM
	privKey, _ := secure.RSAParsePrivateKeyFromPEM(privPem)
	pubKey, _ := secure.RSAParsePublicKeyFromPEM(pubPem)
	text := []byte("Verifiable message!")

	// Sign RSA with PSS message
	signedMessage, _ := secure.RSASignWithPSS(text, privKey)
	fmt.Println("Signed Message:", string(signedMessage))

	// Verify RSA with PSS message
	err = secure.RSAVerifyWithPSS(text, signedMessage, pubKey)
	if err != nil {
		fmt.Println("Invalid message")
	} else {
		fmt.Println("Valid message")
	}
}

func symmetric() {
	key := []byte("supersecretpassword")
	text := []byte("This is super secret message!")

	// Encrypt AES with GCM message (password-based, scrypt KDF)
	encryptedMessage, _ := secure.AESEncryptWithGCM(text, key)
	fmt.Println("Symmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt AES with GCM message
	decryptedMessage, _ := secure.AESDecryptWithGCM(encryptedMessage, key)
	fmt.Println("Symmetric Decrypted Message:", string(decryptedMessage))

	// Encrypt with a raw 32-byte key (XChaCha20-Poly1305)
	rawKey, _ := secure.GenerateRandomBytes(32)
	ct, _ := secure.ChaCha20Poly1305EncryptWithKey(text, rawKey)
	pt, _ := secure.ChaCha20Poly1305DecryptWithKey(ct, rawKey)
	fmt.Println("XChaCha20 Decrypted:", string(pt))
}

func modernAsymmetric() {
	// Generate an X25519 key pair for the recipient
	privKey, pubKey, err := secure.X25519GenerateKeyPair()
	if err != nil {
		fmt.Println("Error: Can't generate X25519 key pair:", err)
		return
	}

	text := []byte("This is super secret message!")

	// Encrypt with X25519 + XChaCha20-Poly1305
	encryptedMessage, _ := secure.X25519EncryptWithChaCha20Poly1305(text, pubKey)
	fmt.Println("X25519 Encrypted Message:", string(encryptedMessage))

	// Decrypt with the recipient private key
	decryptedMessage, _ := secure.X25519DecryptWithChaCha20Poly1305(encryptedMessage, privKey)
	fmt.Println("X25519 Decrypted Message:", string(decryptedMessage))
}

func modernSigning() {
	privKey, pubKey, err := secure.Ed25519GenerateKeyPair()
	if err != nil {
		fmt.Println("Error: Can't generate Ed25519 key pair:", err)
		return
	}

	text := []byte("Verifiable message!")

	// Sign with Ed25519
	signedMessage, _ := secure.Ed25519Sign(text, privKey)
	fmt.Println("Ed25519 Signed Message:", string(signedMessage))

	// Verify with Ed25519
	if err := secure.Ed25519Verify(text, signedMessage, pubKey); err != nil {
		fmt.Println("Invalid message")
	} else {
		fmt.Println("Valid message")
	}
}

func utilities() {
	// Generate random tokens
	t1, _ := secure.GenerateRandomString(32, false, true, false, false)
	fmt.Println("Token 1:", string(t1))

	t2, _ := secure.GenerateRandomString(32, true, false, false, false)
	fmt.Println("Token 2:", string(t2))

	t3, _ := secure.GenerateRandomString(32, true, true, false, false)
	fmt.Println("Token 3:", string(t3))

	t4, _ := secure.GenerateRandomString(32, true, true, true, false)
	fmt.Println("Token 4:", string(t4))

	t5, _ := secure.GenerateRandomString(32, true, true, true, true)
	fmt.Println("Token 5:", string(t5))

	// Generate human passwords
	p1, _ := secure.GenerateHumanPassword(0, 0)
	fmt.Println("Password 1:", string(p1))

	p2, _ := secure.GenerateHumanPassword(5, 2)
	fmt.Println("Password 2:", string(p2))
}
```