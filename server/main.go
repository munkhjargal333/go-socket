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
	"net/http"

	socketio "github.com/googollee/go-socket.io"
)

func main() {
	server := socketio.NewServer(nil)

	server.OnConnect("/", func(s socketio.Conn) error {
		fmt.Println("Client connected:", s.ID())
		return nil
	})

	server.OnEvent("/", "exchangeKeys", func(s socketio.Conn, clientPublicKeyString []byte) {
		log.Println("Received client public key:", string(clientPublicKeyString))

		serverPrivateKey, serverPublicKey := generateKeyPair()

		// !!! server key to client
		publicKeyString, err := encodePublicKey(&serverPublicKey)
		if err != nil {
			log.Println("Error encoding public key:", err)
			return
		}

		s.Emit("exchangeKeys", []byte(publicKeyString))

		// !!! get client key
		clientPublicKey, err := decodePublicKeyPEM2(string(clientPublicKeyString))
		if err != nil {
			log.Println("Error decoding client public key:", err)
			return
		}

		secretKey := SharedKeyGenerator(serverPrivateKey, clientPublicKey)
		fmt.Printf("Shared key (server): %x\n\n", secretKey)
		log.Println("Shared secret key:", secretKey)
	})

	server.OnDisconnect("/", func(s socketio.Conn, reason string) {
		fmt.Println("Client disconnected:", s.ID(), reason)
	})

	go server.Serve()
	defer server.Close()

	http.Handle("/socket.io/", server)
	http.Handle("/", http.FileServer(http.Dir("./static")))

	log.Println("Server started on :5090")
	log.Fatal(http.ListenAndServe(":5090", nil))
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

func decodePublicKeyPEM2(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyPEM)
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

func decodePublicKeyPEM(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Decode the base64-encoded public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(string(block.Bytes))
	if err != nil {
		return nil, err
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse ECDSA public key")
	}

	return ecdsaPublicKey, nil
}

func SharedKeyGenerator(serverPrivateKey *ecdsa.PrivateKey, userPublicKey *ecdsa.PublicKey) []byte {
	sharedSecretX, _ := userPublicKey.Curve.ScalarMult(userPublicKey.X, userPublicKey.Y, serverPrivateKey.D.Bytes())
	sharedSecret := sha256.Sum256(sharedSecretX.Bytes())
	return sharedSecret[:]
}
