# Secure
[![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/catamat/secure/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/catamat/secure.svg?branch=master)](https://travis-ci.org/catamat/secure)
[![Go Report Card](https://goreportcard.com/badge/github.com/catamat/secure)](https://goreportcard.com/report/github.com/catamat/secure)
[![Go Reference](https://pkg.go.dev/badge/github.com/catamat/secure.svg)](https://pkg.go.dev/github.com/catamat/secure)
[![Version](https://img.shields.io/github/tag/catamat/secure.svg?color=blue&label=version)](https://github.com/catamat/secure/releases)

Secure is a simple package to easily work with the most common cryptography functions.

## Installation:
```
go get -u github.com/catamat/secure
```
## Example:
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
		privKey, pubKey := RSAGenerateKeyPair(4096)

		// Export the keys to PEM
		privPem := RSAExportPrivateKeyAsPEM(privKey)
		pubPem, _ := RSAExportPublicKeyAsPEM(pubKey)

		if err := os.WriteFile("private.pem", privPem, 0644); err != nil {
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
	privKey, _ := RSAParsePrivateKeyFromPEM(privPem)
	pubKey, _ := RSAParsePublicKeyFromPEM(pubPem)
	text := []byte("This is super secret message!")

	// Encrypt RSA with OAEP message
	encryptedMessage, _ := RSAEncryptWithOAEP(text, pubKey, nil)
	fmt.Println("Asymmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt RSA with OAEP message
	decryptedMessage, _ := RSADecryptWithOAEP(encryptedMessage, privKey, nil)
	fmt.Println("Asymmetric Decrypted Message:", string(decryptedMessage))
}

func hashing() {
	password := []byte("supersecretpassword")

	// Generate Bcrypt hash
	hashedPassword, _ := BcryptGenerateHash(password, 0)
	fmt.Println("Hashed password:", string(hashedPassword))

	// Compare Bcrypt hash
	err := BcryptCompareHash(hashedPassword, password)
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
	privKey, _ := RSAParsePrivateKeyFromPEM(privPem)
	pubKey, _ := RSAParsePublicKeyFromPEM(pubPem)
	text := []byte("Verifiable message!")

	// Sign RSA with PSS message
	signedMessage, _ := RSASignWithPSS(text, privKey)
	fmt.Println("Signed Message:", string(signedMessage))

	// Verify RSA with PSS message
	err = RSAVerifyWithPSS(text, signedMessage, pubKey)
	if err != nil {
		fmt.Println("Invalid message")
	} else {
		fmt.Println("Valid message")
	}
}

func symmetric() {
	key := []byte("supersecretpassword")
	text := []byte("This is super secret message!")

	// Encrypt AES with GCM message
	encryptedMessage, _ := AESEncryptWithGCM(text, key)
	fmt.Println("Symmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt AES with GCM message
	decryptedMessage, _ := AESDecryptWithGCM(encryptedMessage, key)
	fmt.Println("Symmetric Decrypted Message:", string(decryptedMessage))
}

func utilities() {
	// Generate random tokens
	t1, _ := GenerateRandomToken(32, false, true, false, false)
	fmt.Println("Token 1:", string(t1))

	t2, _ := GenerateRandomToken(32, true, false, false, false)
	fmt.Println("Token 2:", string(t2))

	t3, _ := GenerateRandomToken(32, true, true, false, false)
	fmt.Println("Token 3:", string(t3))

	t4, _ := GenerateRandomToken(32, true, true, true, false)
	fmt.Println("Token 4:", string(t4))

	t5, _ := GenerateRandomToken(32, true, true, true, true)
	fmt.Println("Token 5:", string(t5))

	// Generate human passwords
	p1, _ := GenerateHumanPassword(0, 0)
	fmt.Println("Password 1:", string(p1))

	p2, _ := GenerateHumanPassword(5, 2)
	fmt.Println("Password 2:", string(p2))
}

```