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
		privKey, pubKey := secure.GenerateRsaKeyPair(4096)

		// Export the keys to pem
		privPem := secure.ExportRsaPrivateKeyAsPem(privKey)
		pubPem, _ := secure.ExportRsaPublicKeyAsPem(pubKey)

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

	// Import the keys from pem
	privKey, _ := secure.ParseRsaPrivateKeyFromPem(privPem)
	pubKey, _ := secure.ParseRsaPublicKeyFromPem(pubPem)
	text := []byte("This is super secret message!")

	// Encrypt message
	encryptedMessage, _ := secure.EncryptRsaOAEP(text, pubKey, nil)
	fmt.Println("Asymmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt message
	decryptedMessage, _ := secure.DecryptRsaOAEP(encryptedMessage, privKey, nil)
	fmt.Println("Asymmetric Decrypted Message:", string(decryptedMessage))
}

func hashing() {
	password := []byte("supersecretpassword")

	// Generate hash
	hashedPassword, _ := secure.GenerateBcryptHash(password, 0)
	fmt.Println("Hashed password:", string(hashedPassword))

	// Compare hash
	err := secure.CompareBcryptHash(hashedPassword, password)
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

	// Import the keys from pem
	privKey, _ := secure.ParseRsaPrivateKeyFromPem(privPem)
	pubKey, _ := secure.ParseRsaPublicKeyFromPem(pubPem)
	text := []byte("Verifiable message!")

	// Sign message
	signedMessage, _ := secure.SignRsaPSS(text, privKey)
	fmt.Println("Signed Message:", string(signedMessage))

	// Verify message
	err = secure.VerifyRsaPSS(text, signedMessage, pubKey)
	if err != nil {
		fmt.Println("Invalid message")
	} else {
		fmt.Println("Valid message")
	}
}

func symmetric() {
	key := []byte("supersecretpassword")
	text := []byte("This is super secret message!")

	// Encrypt message
	encryptedMessage, _ := secure.EncryptAesAEAD(text, key)
	fmt.Println("Symmetric Encrypted Message:", string(encryptedMessage))

	// Decrypt message
	decryptedMessage, _ := secure.DecryptAesAEAD(encryptedMessage, key)
	fmt.Println("Symmetric Decrypted Message:", string(decryptedMessage))
}

func utilities() {
	// Generate random tokens
	t1, _ := secure.GenerateRandomToken(32, false, true, false, false)
	fmt.Println("Token 1:", string(t1))

	t2, _ := secure.GenerateRandomToken(32, true, false, false, false)
	fmt.Println("Token 2:", string(t2))

	t3, _ := secure.GenerateRandomToken(32, true, true, false, false)
	fmt.Println("Token 3:", string(t3))

	t4, _ := secure.GenerateRandomToken(32, true, true, true, false)
	fmt.Println("Token 4:", string(t4))

	t5, _ := secure.GenerateRandomToken(32, true, true, true, true)
	fmt.Println("Token 5:", string(t5))

	// Generate human passwords
	p1, _ := secure.GenerateHumanPassword(0, 0)
	fmt.Println("Password 1:", string(p1))

	p2, _ := secure.GenerateHumanPassword(5, 2)
	fmt.Println("Password 2:", string(p2))
}

```