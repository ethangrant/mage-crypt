package main

import (
	"fmt"
)

func main() {
	value := "0:3:nl3G7UCCRRFKLj7jXP4PD/mZtapjrB+TG/en3ibvwc5xJ9iVsqcKpSHFCwTs"
	key := "REDACTED"
	plaintext, err := chacha20poly1305Decrypt(value, key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("chacha decrypted value: ", plaintext)

	value = "1:3:1gMFWajKGlh++/+DGL/ZHFvsVTvBV/LgkeABsJgFTPfbOhilGYA="
	key = "REDACTED"
	plaintext, err = chacha20poly1305Decrypt(value, key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Another cha cha decrypt: ", plaintext)

	plaintext = "chacha encryption text"
	key = "46e07bc0e824c4edaa4212739b438a60"

	enc, err := chacha20poly1305Encrypt(plaintext, key, "1")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("chacha encrypted value: ", enc)

	plaintext, err = chacha20poly1305Decrypt(enc, key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("chacha dec value: ", plaintext)

	plaintext = "The quick brown fox jumps over the lazy dog. Ethan TEST"
	key = "46e07bc0e824c4edaa4212739b438a60"

	enc, err = rijandel256Encrypt(plaintext, key, "1")
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println("encrypted value: ", enc)

	dec, err := rijandel256Decrypt(enc, key)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println("decrypted value: ", dec)

	// rijandel 128 mode ECB (1)
}
