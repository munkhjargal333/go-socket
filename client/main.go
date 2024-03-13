package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"

	socketio "github.com/zhouhui8915/go-socket.io-client"
)

func main() {
	opts := &socketio.Options{
		Transport: "websocket",
		Query:     make(map[string]string),
	}
	opts.Query["EIO"] = "3"
	client, err := socketio.NewClient("http://localhost:5090", opts)
	if err != nil {
		log.Fatal(err)
	}

	userPrivateKey, publicKey := generateKeyPair()
	publicKeyBase64, err := encodePublicKey(&publicKey)
	if err != nil {
		log.Fatal("Error encoding public key:", err)
	}

	client.Emit("exchangeKeys", []byte(publicKeyBase64))

	client.On("exchangeKeys", func(serverPublicKeyBase64 []byte) {
		fmt.Println("Server public key:", string(serverPublicKeyBase64))

		serverPublicKey, err := decodePublicKey(string(serverPublicKeyBase64))
		if err != nil {
			log.Fatal("Error decoding server public key:", err)
		}
		fmt.Println("Server public key:", serverPublicKey)

		sharedSecret := SharedKeyGenerator(userPrivateKey, serverPublicKey)

		fmt.Println("Shared secret:", sharedSecret)
	})
}

func generateKeyPair() (*ecdsa.PrivateKey, ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating key pair:", err)
	}
	return privateKey, privateKey.PublicKey
}

func encodePublicKey(publicKey *ecdsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

func decodePublicKey(publicKeyBase64 string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPublicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse ECDSA public key")
	}
	return ecdsaPublicKey, nil
}

func SharedKeyGenerator(userPrivateKey *ecdsa.PrivateKey, serverPublicKey *ecdsa.PublicKey) []byte {
	sharedSecret1X, _ := serverPublicKey.Curve.ScalarMult(serverPublicKey.X, serverPublicKey.Y, userPrivateKey.D.Bytes())
	sharedSecret1 := sha256.Sum256(sharedSecret1X.Bytes())
	return sharedSecret1[:]
}
