package cipher

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethangrant/mage-crypt/encryption"
	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher interface {
	Encrypt(plaintext string, key string, keyVersion string) (string, error)
	Decrypt(value string, key string) (string, error)
}

type Chacha20poly1305 struct {
}

type Rijandel256 struct {
	generateInitVectorFunc func(int, []byte) ([]byte, error)
}

// attempt to get appropriate cipher to decrypt value
func GetCipherByValue(value string) (Cipher, error) {
	parts := strings.Split(value, ":")
	partsCount := len(parts)
	var cipherVersion string

	// keyversion:cipherversion:initvector:ciphertext
	if partsCount == 4 {
		return Rijandel256{generateInitVectorFunc: generateInitVector}, nil
		// keyversion:cipherversion:ciphertext
	} else if partsCount == 3 {
		cipherVersion = parts[1]
		// cipherversion:ciphertext
	} else if partsCount == 2 {
		cipherVersion = parts[0]
		// ciphertext
	} else if partsCount == 1 {
		// blowfish
		return nil, fmt.Errorf("blowfish decrypt currently unavailable to decrypt value: %s", value)
	} else {
		return nil, fmt.Errorf("no cipher available to decrypt the value: %s", value)
	}

	if len(parts) < 2 {
		return nil, fmt.Errorf("no cipher available to decrypt the value: %s", value)
	}

	switch cipherVersion {
	case "2":
		return Rijandel256{generateInitVectorFunc: generateInitVector}, nil
	case "3":
		return Chacha20poly1305{}, nil
	}

	return nil, fmt.Errorf("no cipher available to decrypt the value: %s", value)
}

// latest cipher used by magento to encrypt all new values
func GetLatestCipher() Cipher {
	return Chacha20poly1305{}
}

// latest encyrption method used in Magento 2
func (c Chacha20poly1305) Encrypt(plaintext string, key string, keyVersion string) (string, error) {
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
	cipherText := aead.Seal(nil, nonce, []byte(plaintext), nonce)

	// nonce must be prepended onto the cipher string manually
	cipherText = append(nonce, cipherText...)

	// base64 encode the cipher text as Magento does
	cipherTextEncoded := base64.StdEncoding.EncodeToString(cipherText)

	// return in magneto 2 formatting
	return fmt.Sprintf("%s:%s:%s", keyVersion, cipherVersion, cipherTextEncoded), nil
}

func (c Chacha20poly1305) Decrypt(value string, key string) (string, error) {
	// get cipher text from ':' separated value
	parts, err := getParts(value, 3)
	if err != nil {
		return "", err
	}

	cipherText := parts[2]

	// cipher text is base64 encoded after encyption so we need to decode it
	decodedValue, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return "", err
	}

	// nonce is prepended to the cipher text, we need to pull this to decrypt
	nonce := decodedValue[:chacha20poly1305.NonceSize]
	decodedCiphertext := decodedValue[chacha20poly1305.NonceSize:]

	decrypted, err := aead.Open(nil, nonce, decodedCiphertext, nonce)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func NewRijandel256() Rijandel256 {
	return Rijandel256{generateInitVectorFunc: generateInitVector}
}

func (r Rijandel256) Encrypt(plaintext string, key string, keyVersion string) (string, error) {
	cipherVersion := "2"

	iv, err := r.generateInitVectorFunc(32, []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
	if err != nil {
		return "", nil
	}

	// magento encrypts then base64 encodes. Rijndael256CBCEncrypt32 does both of these actions.
	encrypt, err := encryption.Rijndael256CBCEncrypt32([]byte(key), iv, plaintext)
	if err != nil {
		return "", err
	}

	// return in magento 2 ':' separated format
	return fmt.Sprintf("%s:%s:%s:%s", keyVersion, cipherVersion, string(iv), encrypt), nil
}

func (r Rijandel256) Decrypt(value string, key string) (string, error) {
	var ciphertext string
	parts := strings.Split(value, ":")
	partCount := len(parts)

	// when dealing with a value that does not have an init vector we will default to nil byte slice
	nilIv := make([]byte, 32)
	iv := string(nilIv)

	if partCount == 3 {
		ciphertext = parts[2]
	}

	if partCount == 4 {
		iv = parts[2]
		ciphertext = parts[3]
	}

	keyByteSlice := []byte(key)

	if len(iv) != 32 {
		return "", errors.New("init vector must be a string of 32 bytes")
	}

	// Rijndael256CBCDecrypt32 decodes and then decrypts.
	decrypt, err := encryption.Rijndael256CBCDecrypt32(keyByteSlice, []byte(iv), ciphertext)
	if err != nil {
		return "", err
	}

	return decrypt, nil
}

// extract value into individual parts
func getParts(value string, expected int) ([]string, error) {
	parts := strings.Split(value, ":")

	if len(parts) < expected {
		return nil, fmt.Errorf("invalid format for encrypted valeu, %d parts expected", expected)
	}

	return parts, nil
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

	return iv, nil
}
