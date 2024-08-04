package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/ethangrant/mage-crypt/encryption"
	"golang.org/x/crypto/chacha20poly1305"
	"math/big"
	"strings"
)

// latest encyrption method used in Magento 2
func chacha20poly1305Encrypt(value string, key string, keyVersion string) (string, error) {
	// Magento 2 const CIPHER_AEAD_CHACHA20POLY1305
	cipherVersion := "3"

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return "", nil
	}

	// Generate a nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)

	// encrypt
	cipherText := aead.Seal(nil, nonce, []byte(value), nonce)

	// nonce must be prepended onto the cipher string manually
	cipherText = append(nonce, cipherText...)

	// base64 encode the cipher text as Magento does
	cipherTextEncoded := base64.StdEncoding.EncodeToString(cipherText)

	// return in magneto 2 formatting
	return fmt.Sprintf("%s:%s:%s", keyVersion, cipherVersion, cipherTextEncoded), nil
}

func chacha20poly1305Decrypt(value string, key string) (string, error) {
	// get cipher text from ':' separated value
	parts := strings.Split(value, ":")
	cipherText := parts[2]

	// cipher text is base64 encoded after encyption so we need to decode it
	decodedValue, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return "", nil
	}

	// nonce is prepended to the cipher text, we need to pull this to decrypt
	nonce := decodedValue[:chacha20poly1305.NonceSize]
	ciphertext := decodedValue[chacha20poly1305.NonceSize:]

	decrypted, err := aead.Open(nil, nonce, ciphertext, nonce)
	if err != nil {
		return "", nil
	}

	return string(decrypted), nil
}

// Magento encrypted data will be formatted like 'keyversion:cipherversion:iv:encrypteddata'
func rijandel256Decrypt(encryptedData string, key string) (string, error) {
	// extract iv and cipher text from magento encrypted value
	parts := strings.Split(encryptedData, ":")
	iv := parts[2]
	ciphertext := parts[3]
	keyByteSlice := []byte(key)

	// Rijndael256CBCDecrypt32 decodes and then decrypts.
	decrypt, err := encryption.Rijndael256CBCDecrypt32(keyByteSlice, []byte(iv), ciphertext)
	if err != nil {
		return "", err
	}

	return decrypt, nil
}

func rijandel256Encrypt(value string, key string, keyVersion string) (string, error) {
	cipherVersion := "2"

	iv, err := generateInitVector(32, []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
	if err != nil {
		return "", nil
	}

	// magento encrypts then base64 encodes. Rijndael256CBCEncrypt32 does both of these actions.
	encrypt, err := encryption.Rijndael256CBCEncrypt32([]byte(key), iv, value)
	if err != nil {
		return "", err
	}

	// return in magento 2 ':' separated format
	return fmt.Sprintf("%s:%s:%s:%s", keyVersion, cipherVersion, string(iv), encrypt), nil
}

// Generates a random init vector string used in encryption
func generateInitVector(length int, charSet []byte) ([]byte, error) {
	iv := make([]byte, length)

	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return nil, err
		}

		iv[i] = charSet[index.Int64()]
	}

	// iv = []byte("TUdKrDJ8GB0PJYkHLUcjS4RGylFfU4CR")

	return iv, nil
}
