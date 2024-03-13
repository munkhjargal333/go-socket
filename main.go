package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func main() {
	// Generate keys for server and user
	serverPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	userPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serverPublicKey := serverPrivateKey.PublicKey
	userPublicKey := userPrivateKey.PublicKey

	// Display keys
	fmt.Printf("Private key (server): %x\n", serverPrivateKey.D)
	fmt.Printf("Private key (client): %x\n\n", userPrivateKey.D)

	fmt.Printf("Public key (server): (%x, %x)\n", serverPublicKey.X, serverPublicKey.Y)
	fmt.Printf("Public key (client): (%x, %x)\n\n", userPublicKey.X, userPublicKey.Y)

	// Compute shared secrets
	sharedSecret1X, _ := serverPublicKey.Curve.ScalarMult(serverPublicKey.X, serverPublicKey.Y, userPrivateKey.D.Bytes())
	sharedSecret1 := sha256.Sum256(sharedSecret1X.Bytes())

	sharedSecret2X, _ := userPublicKey.Curve.ScalarMult(userPublicKey.X, userPublicKey.Y, serverPrivateKey.D.Bytes())
	sharedSecret2 := sha256.Sum256(sharedSecret2X.Bytes())

	fmt.Printf("Shared key (server): %x\n", sharedSecret1)
	fmt.Printf("Shared key (client): %x\n\n", sharedSecret2)

	// Encrypting a message using AES
	plaintext := []byte("Hello, Bob!")
	paddedPlaintext := addPadding(plaintext, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	block, _ := aes.NewCipher(sharedSecret1[:])
	ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPlaintext)

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypting the message using AES
	block2, _ := aes.NewCipher(sharedSecret2[:])
	mode2 := cipher.NewCBCDecrypter(block2, iv)
	decrypted := make([]byte, len(ciphertext)-aes.BlockSize)
	mode2.CryptBlocks(decrypted, ciphertext[aes.BlockSize:])

	fmt.Printf("Decrypted message: %s\n", removePadding(decrypted))
}

func addPadding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func removePadding(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
