// Source https://gist.githubusercontent.com/slifer2015/0d182d99280758a154e3fe12e48664d4/raw/365cacea779e3e733abd1b1d6f3669816d5272a7/cbc.go
// AES 256 CBC 32byte block size IV support golang implementation
package encryption

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

func Rijndael256CBCEncrypt32(key, iv []byte, src string) (string, error) {
	ciph, err := NewCipher(key)
	if err != nil {
		return "", err
	}
	origData := addPadding([]byte(src), ciph.BlockSize())
	blockMode := NewCBCEncrypter(ciph, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	finalResult := base64.StdEncoding.EncodeToString(crypted)
	return finalResult, nil
}

func Rijndael256CBCDecrypt32(key, iv []byte, cipherText string) (string, error) {
	ciph, err := NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherTextFinal, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	blockMode := NewCBCDecrypter(ciph, iv)

	origData := make([]byte, len(cipherTextFinal))
	if len(cipherTextFinal)%blockMode.BlockSize() != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	blockMode.CryptBlocks(origData, cipherTextFinal)
	origData = unpadNullBytes(origData)

	return string(origData), nil
}

// Adjusted padding to use null bytes mimicking PHP mcrypt
// Pads with \0 in phpseclib_mcrypt_generic_helper()
func addPadding(src []byte, blockLen int) []byte {
	padding := blockLen - len(src)%blockLen
	padtext := bytes.Repeat([]byte{0x00}, padding)
	return append(src, padtext...)
}

// Added a new function just to remove the null byte padding
func unpadNullBytes(data []byte) []byte {
	return bytes.Trim(data, "\x00")
}

// TODO: Remove after further testing
func unpad(data []byte, blockLen int) ([]byte, error) {
	if blockLen <= 0 {
		return nil, fmt.Errorf("invalid blockLen %d", blockLen)
	}
	if len(data)%blockLen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blockLen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
